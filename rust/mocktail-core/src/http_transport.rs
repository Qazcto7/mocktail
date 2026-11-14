use std::env;
use std::ffi::{c_char, c_void};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use flate2::write::{GzDecoder, ZlibDecoder};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::ring;
use rustls::{
    CertificateError, ClientConfig, ClientConnection, DigitallySignedStruct, Error as TlsError,
    RootCertStore, SignatureScheme, StreamOwned,
};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use url::Url;
use zeroize::Zeroizing;

use crate::http_download::{HttpAttemptOutcome, HttpAttemptSink, HttpAttemptSpec};
use crate::storage_paths::slice_to_str;
use crate::update_json::MocktailRustStrSlice;
use crate::{is_redirect_status_code, percent_decode_helper};

pub(crate) const MAX_CA_BUNDLE_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_PROXY_CONNECT_HEADER_BYTES: usize = 8192;
const MAX_RESPONSE_HEADERS_BYTES: usize = 64 * 1024;
const MAX_CHUNK_LINE_BYTES: usize = 4096;
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_IO_TIMEOUT: Duration = Duration::from_secs(15);
const LOCAL_SOCKS5_PROBE_TIMEOUT: Duration = Duration::from_millis(50);
const DEFAULT_SERVICE_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

// CURLE-compatible numeric codes expected by `http_download.rs` and retry classifiers.
const CODE_OK: i32 = 0;
const CODE_COULDNT_RESOLVE_PROXY: i32 = 5;
const CODE_COULDNT_RESOLVE_HOST: i32 = 6;
const CODE_COULDNT_CONNECT: i32 = 7;
const CODE_PARTIAL_FILE: i32 = 18;
const CODE_WRITE_ERROR: i32 = 23;
const CODE_OPERATION_TIMEDOUT: i32 = 28;
const CODE_RANGE_ERROR: i32 = 33;
const CODE_SSL_CONNECT_ERROR: i32 = 35;
const CODE_TOO_MANY_REDIRECTS: i32 = 47;
const CODE_GOT_NOTHING: i32 = 52;
const CODE_SEND_ERROR: i32 = 55;
const CODE_RECV_ERROR: i32 = 56;
const CODE_PEER_FAILED_VERIFICATION: i32 = 60;
const CODE_BAD_CONTENT_ENCODING: i32 = 61;
const CODE_SSL_CACERT_BADFILE: i32 = 77;

const SYSTEM_CA_BUNDLE_CANDIDATES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
];

#[derive(Debug, Clone)]
pub(crate) struct HttpTransportError {
    pub curl_code: i32,
    pub message: String,
}

impl HttpTransportError {
    fn new(curl_code: i32, message: impl Into<String>) -> Self {
        Self {
            curl_code,
            message: message.into(),
        }
    }
}

pub(crate) fn is_loopback_host(host: &str) -> bool {
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    trimmed.eq_ignore_ascii_case("localhost") || trimmed == "127.0.0.1" || trimmed == "::1"
}

pub(crate) fn parse_pem_certificates(
    pem_bytes: &[u8],
) -> Result<Vec<CertificateDer<'static>>, String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = std::str::from_utf8(pem_bytes)
        .map_err(|_| "CA bundle must be valid UTF-8/ASCII PEM".to_string())?;
    let mut certs = Vec::new();
    let mut rest = text;
    while let Some(start_idx) = rest.find(BEGIN) {
        let after_begin = &rest[start_idx + BEGIN.len()..];
        let end_idx = after_begin
            .find(END)
            .ok_or_else(|| "unterminated PEM certificate block in CA bundle".to_string())?;
        let b64: String = after_begin[..end_idx]
            .chars()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        let der = BASE64_STANDARD
            .decode(b64.as_bytes())
            .map_err(|_| "invalid base64 certificate data in CA bundle".to_string())?;
        certs.push(CertificateDer::from(der));
        rest = &after_begin[end_idx + END.len()..];
    }
    Ok(certs)
}

fn read_pem_certs_file(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut file =
        File::open(path).map_err(|e| format!("cannot open CA bundle {}: {}", path.display(), e))?;
    let mut buf = Vec::new();
    (&mut file)
        .take((MAX_CA_BUNDLE_BYTES + 1) as u64)
        .read_to_end(&mut buf)
        .map_err(|e| format!("cannot read CA bundle {}: {}", path.display(), e))?;
    if buf.len() > MAX_CA_BUNDLE_BYTES {
        return Err("CA bundle exceeds 4 MiB limit".to_string());
    }
    parse_pem_certificates(&buf)
}

fn parse_der_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = data.split_first()?;
    let (&len_byte, after_len) = rest.split_first()?;
    let (len, body_start) = if len_byte < 0x80 {
        (len_byte as usize, after_len)
    } else {
        let num_bytes = (len_byte & 0x7f) as usize;
        if num_bytes == 0 || num_bytes > 4 || after_len.len() < num_bytes {
            return None;
        }
        let mut val = 0usize;
        for &b in &after_len[..num_bytes] {
            val = (val << 8) | (b as usize);
        }
        (val, &after_len[num_bytes..])
    };
    if body_start.len() < len {
        return None;
    }
    Some((tag, &body_start[..len], &body_start[len..]))
}

fn dns_name_matches_pattern(host: &str, pattern: &str) -> bool {
    let h = host.trim_end_matches('.');
    let p = pattern.trim_end_matches('.');
    if h.is_empty() || p.is_empty() {
        return false;
    }
    if h.eq_ignore_ascii_case(p) {
        return true;
    }
    if let Some(rest_pat) = p.strip_prefix("*.") {
        if let Some((_, rest_host)) = h.split_once('.') {
            return !rest_pat.contains('*') && rest_host.eq_ignore_ascii_case(rest_pat);
        }
    }
    false
}

fn der_cert_matches_server_name(cert_der: &[u8], server_name: &ServerName<'_>) -> bool {
    let Some((0x30, cert_seq, _)) = parse_der_tlv(cert_der) else {
        return false;
    };
    let Some((0x30, mut tbs, _)) = parse_der_tlv(cert_seq) else {
        return false;
    };
    // Optional [0] version
    if tbs.first() == Some(&0xa0) {
        let Some((_, _, rest)) = parse_der_tlv(tbs) else {
            return false;
        };
        tbs = rest;
    }
    // Skip serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo (6 TLVs)
    for _ in 0..6 {
        let Some((_, _, rest)) = parse_der_tlv(tbs) else {
            return false;
        };
        tbs = rest;
    }
    // Optional issuerUniqueID (0x81), subjectUniqueID (0x82), and extensions (0xa3)
    while let Some((tag, val, rest)) = parse_der_tlv(tbs) {
        tbs = rest;
        if tag != 0xa3 {
            continue;
        }
        let Some((0x30, mut exts, _)) = parse_der_tlv(val) else {
            return false;
        };
        while let Some((0x30, mut ext, next_ext)) = parse_der_tlv(exts) {
            exts = next_ext;
            let Some((0x06, oid, after_oid)) = parse_der_tlv(ext) else {
                continue;
            };
            if oid != [0x55, 0x1d, 0x11] {
                continue;
            }
            ext = after_oid;
            if ext.first() == Some(&0x01) {
                let Some((_, _, after_crit)) = parse_der_tlv(ext) else {
                    return false;
                };
                ext = after_crit;
            }
            let Some((0x04, octets, _)) = parse_der_tlv(ext) else {
                return false;
            };
            let Some((0x30, mut names, _)) = parse_der_tlv(octets) else {
                return false;
            };
            while let Some((ntag, nval, next_name)) = parse_der_tlv(names) {
                names = next_name;
                match (server_name, ntag) {
                    (ServerName::DnsName(dns), 0x82) => {
                        if let Ok(pat) = std::str::from_utf8(nval) {
                            if dns_name_matches_pattern(dns.as_ref(), pat) {
                                return true;
                            }
                        }
                    }
                    (ServerName::IpAddress(ip), 0x87) => {
                        let net_ip = std::net::IpAddr::from(*ip);
                        let matched = match net_ip {
                            std::net::IpAddr::V4(v4) => nval == v4.octets(),
                            std::net::IpAddr::V6(v6) => nval == v6.octets(),
                        };
                        if matched {
                            return true;
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    false
}

#[derive(Debug)]
struct PinnedAwareServerCertVerifier {
    inner: Arc<WebPkiServerVerifier>,
    pinned_certs: Vec<CertificateDer<'static>>,
}

impl ServerCertVerifier for PinnedAwareServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(ok) => Ok(ok),
            Err(TlsError::InvalidCertificate(CertificateError::Other(ref other)))
                if format!("{:?}", other).contains("CaUsedAsEndEntity")
                    && self.pinned_certs.iter().any(|c| c.as_ref() == end_entity.as_ref())
                    && der_cert_matches_server_name(end_entity.as_ref(), server_name) =>
            {
                Ok(ServerCertVerified::assertion())
            }
            Err(err) => Err(err),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Builds a `rustls::ClientConfig`.
///
/// When `strict_ca_only` is true and `ca_bundle` is `Some`, ONLY the certificates
/// in `ca_bundle` are trusted (matching OpenSSL `CURLOPT_CAINFO`). Otherwise the
/// bundle supplements `webpki_roots` (plus readable system CA stores when `None`).
pub(crate) fn build_tls_config(
    ca_bundle: Option<&Path>,
    strict_ca_only: bool,
) -> Result<Arc<ClientConfig>, String> {
    let mut roots = if strict_ca_only && ca_bundle.is_some() {
        RootCertStore::empty()
    } else {
        RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        }
    };

    let mut pinned_certs = Vec::new();
    if let Some(path) = ca_bundle {
        let certs = read_pem_certs_file(path)?;
        pinned_certs = certs.clone();
        let (added, _) = roots.add_parsable_certificates(certs);
        if added == 0 {
            return Err(format!(
                "no valid PEM certificates found in CA bundle {}",
                path.display()
            ));
        }
    } else {
        if let Some(ssl_cert_file) = env::var_os("SSL_CERT_FILE") {
            if !ssl_cert_file.is_empty() {
                if let Ok(certs) = read_pem_certs_file(Path::new(&ssl_cert_file)) {
                    let _ = roots.add_parsable_certificates(certs);
                }
            }
        }
        for candidate in SYSTEM_CA_BUNDLE_CANDIDATES {
            let p = Path::new(candidate);
            if p.is_file() {
                if let Ok(certs) = read_pem_certs_file(p) {
                    let _ = roots.add_parsable_certificates(certs);
                }
                break;
            }
        }
    }

    let provider = Arc::new(ring::default_provider());
    let config_builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("cannot configure TLS versions: {}", e))?;

    let config = if pinned_certs.is_empty() {
        config_builder
            .with_root_certificates(roots)
            .with_no_client_auth()
    } else {
        let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .map_err(|e| format!("cannot build WebPKI verifier: {}", e))?;
        let verifier = Arc::new(PinnedAwareServerCertVerifier {
            inner,
            pinned_certs,
        });
        config_builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth()
    };
    Ok(Arc::new(config))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProxyScheme {
    Http,
    Https,
    Socks5 { remote_dns: bool },
}

#[derive(Clone)]
pub(crate) struct ProxyEndpoint {
    pub scheme: ProxyScheme,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Zeroizing<String>,
}

impl ProxyEndpoint {
    pub fn parse_url(raw: &str, username_override: &str, password_override: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("empty proxy URL".to_string());
        }
        let normalized = if trimmed.contains("://") {
            trimmed.to_string()
        } else {
            format!("http://{}", trimmed)
        };
        let url = Url::parse(&normalized).map_err(|e| format!("invalid proxy URL: {}", e))?;
        let scheme = match url.scheme().to_ascii_lowercase().as_str() {
            "http" => ProxyScheme::Http,
            "https" => ProxyScheme::Https,
            "socks5" | "socks" => ProxyScheme::Socks5 { remote_dns: false },
            "socks5h" => ProxyScheme::Socks5 { remote_dns: true },
            other => return Err(format!("unsupported proxy scheme: {}", other)),
        };
        let host = url
            .host_str()
            .ok_or_else(|| "proxy URL missing host".to_string())?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        if host.is_empty() {
            return Err("proxy URL has empty host".to_string());
        }
        let default_port = match scheme {
            ProxyScheme::Http => 8080,
            ProxyScheme::Https => 443,
            ProxyScheme::Socks5 { .. } => 1080,
        };
        let port = url.port().unwrap_or(default_port);

        let username = if !username_override.is_empty() {
            username_override.to_string()
        } else if !url.username().is_empty() {
            percent_decode_helper(url.username(), false)
                .map_err(|_| "proxy username contains invalid percent encoding".to_string())?
        } else {
            String::new()
        };
        let password = if !password_override.is_empty() {
            Zeroizing::new(password_override.to_string())
        } else if let Some(p) = url.password() {
            Zeroizing::new(
                percent_decode_helper(p, false)
                    .map_err(|_| "proxy password contains invalid percent encoding".to_string())?,
            )
        } else {
            Zeroizing::new(String::new())
        };

        Ok(Self {
            scheme,
            host,
            port,
            username,
            password,
        })
    }
}

pub(crate) fn connect_tcp_with_timeout(
    host: &str,
    port: u16,
    connect_timeout: Duration,
    io_timeout: Duration,
    is_proxy: bool,
) -> Result<TcpStream, HttpTransportError> {
    let clean_host = host.trim_start_matches('[').trim_end_matches(']');
    let addrs: Vec<_> = (clean_host, port)
        .to_socket_addrs()
        .map_err(|e| {
            HttpTransportError::new(
                if is_proxy {
                    CODE_COULDNT_RESOLVE_PROXY
                } else {
                    CODE_COULDNT_RESOLVE_HOST
                },
                format!("DNS resolution failed for {}:{}: {}", clean_host, port, e),
            )
        })?
        .collect();
    if addrs.is_empty() {
        return Err(HttpTransportError::new(
            if is_proxy {
                CODE_COULDNT_RESOLVE_PROXY
            } else {
                CODE_COULDNT_RESOLVE_HOST
            },
            format!("no addresses resolved for {}:{}", clean_host, port),
        ));
    }

    let mut last_err = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, connect_timeout) {
            Ok(stream) => {
                let _ = stream.set_read_timeout(Some(io_timeout));
                let _ = stream.set_write_timeout(Some(io_timeout));
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(err) => last_err = Some(err),
        }
    }

    let timed_out = last_err
        .as_ref()
        .is_some_and(|e| matches!(e.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock));
    let code = if timed_out {
        CODE_OPERATION_TIMEDOUT
    } else {
        CODE_COULDNT_CONNECT
    };
    Err(HttpTransportError::new(
        code,
        format!(
            "TCP connect failed for {}:{}: {}",
            clean_host,
            port,
            last_err
                .map(|e| e.to_string())
                .unwrap_or_else(|| "unknown error".to_string())
        ),
    ))
}

fn format_authority(host: &str, port: u16) -> String {
    let clean = host.trim_start_matches('[').trim_end_matches(']');
    if clean.contains(':') {
        format!("[{}]:{}", clean, port)
    } else {
        format!("{}:{}", clean, port)
    }
}

fn connect_http_tunnel_on_stream<S: Read + Write>(
    stream: &mut S,
    username: &str,
    password: &str,
    target_host: &str,
    target_port: u16,
) -> Result<(), HttpTransportError> {
    let authority = format_authority(target_host, target_port);
    let mut req = Zeroizing::new(format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n"
    ));
    if !username.is_empty() || !password.is_empty() {
        let raw_creds = Zeroizing::new(format!("{}:{}", username, password));
        let encoded = Zeroizing::new(BASE64_STANDARD.encode(raw_creds.as_bytes()));
        req.push_str("Proxy-Authorization: Basic ");
        req.push_str(&encoded);
        req.push_str("\r\n");
    }
    req.push_str("\r\n");

    stream
        .write_all(req.as_bytes())
        .and_then(|_| stream.flush())
        .map_err(|e| HttpTransportError::new(CODE_SEND_ERROR, format!("proxy CONNECT write failed: {}", e)))?;

    // Single-byte reads guarantee we never consume subsequent TLS ServerHello bytes.
    let mut header_bytes = Vec::with_capacity(256);
    let mut one = [0u8; 1];
    while header_bytes.len() < MAX_PROXY_CONNECT_HEADER_BYTES {
        let n = stream.read(&mut one).map_err(|e| classify_io_rw_error(e, false))?;
        if n == 0 {
            return Err(HttpTransportError::new(
                CODE_GOT_NOTHING,
                "proxy closed connection during CONNECT",
            ));
        }
        header_bytes.push(one[0]);
        if header_bytes.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !header_bytes.ends_with(b"\r\n\r\n") {
        return Err(HttpTransportError::new(
            CODE_RECV_ERROR,
            "proxy CONNECT response headers exceeded limit",
        ));
    }
    let status_line = std::str::from_utf8(&header_bytes)
        .ok()
        .and_then(|s| s.lines().next())
        .unwrap_or("");
    let status_code = status_line
        .split_ascii_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    if !(200..=299).contains(&status_code) {
        return Err(HttpTransportError::new(
            CODE_COULDNT_CONNECT,
            format!("proxy CONNECT failed with status {}", status_code),
        ));
    }
    Ok(())
}

/// Shared TCP HTTP CONNECT tunnel helper used by `micup_rpc` and HTTP transport.
pub(crate) fn connect_tcp_via_http_proxy(
    proxy_url: &str,
    username: &str,
    password: &str,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> Result<TcpStream, String> {
    let endpoint = ProxyEndpoint::parse_url(proxy_url, username, password)?;
    if endpoint.scheme != ProxyScheme::Http {
        return Err(format!(
            "expected http:// proxy URL for TCP CONNECT tunnel (got {})",
            proxy_url
        ));
    }
    let mut tcp = connect_tcp_with_timeout(&endpoint.host, endpoint.port, timeout, timeout, true)
        .map_err(|e| e.message)?;
    connect_http_tunnel_on_stream(&mut tcp, &endpoint.username, &endpoint.password, target_host, target_port)
        .map_err(|e| e.message)?;
    Ok(tcp)
}

fn connect_socks5_on_stream(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
    remote_dns: bool,
    target_host: &str,
    target_port: u16,
) -> Result<(), HttpTransportError> {
    let has_auth = !username.is_empty() || !password.is_empty();
    let greeting: &[u8] = if has_auth {
        &[0x05, 0x02, 0x00, 0x02]
    } else {
        &[0x05, 0x01, 0x00]
    };
    stream
        .write_all(greeting)
        .and_then(|_| stream.flush())
        .map_err(|e| HttpTransportError::new(CODE_SEND_ERROR, format!("SOCKS5 greeting failed: {}", e)))?;

    let mut method_reply = [0u8; 2];
    stream
        .read_exact(&mut method_reply)
        .map_err(|e| classify_io_rw_error(e, false))?;
    if method_reply[0] != 0x05 {
        return Err(HttpTransportError::new(
            CODE_COULDNT_CONNECT,
            "invalid SOCKS5 version from proxy",
        ));
    }
    match method_reply[1] {
        0x00 => {}
        0x02 if has_auth => {
            if username.len() > 255 || password.len() > 255 {
                return Err(HttpTransportError::new(
                    CODE_COULDNT_CONNECT,
                    "SOCKS5 credentials exceed 255 bytes",
                ));
            }
            let mut auth = Zeroizing::new(Vec::with_capacity(3 + username.len() + password.len()));
            auth.push(0x01);
            auth.push(username.len() as u8);
            auth.extend_from_slice(username.as_bytes());
            auth.push(password.len() as u8);
            auth.extend_from_slice(password.as_bytes());
            stream
                .write_all(&auth)
                .and_then(|_| stream.flush())
                .map_err(|e| HttpTransportError::new(CODE_SEND_ERROR, format!("SOCKS5 auth failed: {}", e)))?;
            let mut auth_reply = [0u8; 2];
            stream
                .read_exact(&mut auth_reply)
                .map_err(|e| classify_io_rw_error(e, false))?;
            if auth_reply[1] != 0x00 {
                return Err(HttpTransportError::new(
                    CODE_COULDNT_CONNECT,
                    "SOCKS5 authentication rejected",
                ));
            }
        }
        _ => {
            return Err(HttpTransportError::new(
                CODE_COULDNT_CONNECT,
                "SOCKS5 proxy rejected authentication methods",
            ));
        }
    }

    let clean_host = target_host.trim_start_matches('[').trim_end_matches(']');
    let mut req = Vec::with_capacity(32 + clean_host.len());
    req.extend_from_slice(&[0x05, 0x01, 0x00]);
    if let Ok(ip) = clean_host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                req.push(0x01);
                req.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                req.push(0x04);
                req.extend_from_slice(&v6.octets());
            }
        }
    } else if remote_dns || clean_host.len() <= 255 {
        if clean_host.len() > 255 {
            return Err(HttpTransportError::new(
                CODE_COULDNT_RESOLVE_HOST,
                "target hostname exceeds SOCKS5 limit",
            ));
        }
        if !remote_dns {
            if let Some(ip) = (clean_host, target_port)
                .to_socket_addrs()
                .ok()
                .and_then(|mut it| it.next())
                .map(|sa| sa.ip())
            {
                match ip {
                    IpAddr::V4(v4) => {
                        req.push(0x01);
                        req.extend_from_slice(&v4.octets());
                    }
                    IpAddr::V6(v6) => {
                        req.push(0x04);
                        req.extend_from_slice(&v6.octets());
                    }
                }
            } else {
                req.push(0x03);
                req.push(clean_host.len() as u8);
                req.extend_from_slice(clean_host.as_bytes());
            }
        } else {
            req.push(0x03);
            req.push(clean_host.len() as u8);
            req.extend_from_slice(clean_host.as_bytes());
        }
    } else {
        return Err(HttpTransportError::new(
            CODE_COULDNT_RESOLVE_HOST,
            "target hostname exceeds SOCKS5 limit",
        ));
    }
    req.extend_from_slice(&target_port.to_be_bytes());
    stream
        .write_all(&req)
        .and_then(|_| stream.flush())
        .map_err(|e| HttpTransportError::new(CODE_SEND_ERROR, format!("SOCKS5 CONNECT failed: {}", e)))?;

    let mut hdr = [0u8; 4];
    stream
        .read_exact(&mut hdr)
        .map_err(|e| classify_io_rw_error(e, false))?;
    if hdr[0] != 0x05 || hdr[1] != 0x00 {
        return Err(HttpTransportError::new(
            CODE_COULDNT_CONNECT,
            format!("SOCKS5 proxy CONNECT rejected (rep={})", hdr[1]),
        ));
    }
    let tail_len = match hdr[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut len_byte = [0u8; 1];
            stream
                .read_exact(&mut len_byte)
                .map_err(|e| classify_io_rw_error(e, false))?;
            len_byte[0] as usize + 2
        }
        _ => {
            return Err(HttpTransportError::new(
                CODE_COULDNT_CONNECT,
                "invalid ATYP in SOCKS5 reply",
            ));
        }
    };
    let mut discard = [0u8; 258];
    stream
        .read_exact(&mut discard[..tail_len])
        .map_err(|e| classify_io_rw_error(e, false))?;
    Ok(())
}

enum TunnelSocket {
    Plain(TcpStream),
    TlsProxy(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl TunnelSocket {
    fn set_timeouts(&self, dur: Option<Duration>) {
        let tcp = match self {
            Self::Plain(s) => s,
            Self::TlsProxy(s) => &s.sock,
        };
        let _ = tcp.set_read_timeout(dur);
        let _ = tcp.set_write_timeout(dur);
    }
}

impl Read for TunnelSocket {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.read(buf),
            Self::TlsProxy(s) => s.read(buf),
        }
    }
}

impl Write for TunnelSocket {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(s) => s.write(buf),
            Self::TlsProxy(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(s) => s.flush(),
            Self::TlsProxy(s) => s.flush(),
        }
    }
}

fn matches_no_proxy(host: &str, port: u16, raw_list: &str) -> bool {
    let trimmed = raw_list.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed == "*" {
        return true;
    }
    let clean_host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    for entry in trimmed.split(',') {
        let item = entry.trim();
        if item.is_empty() {
            continue;
        }
        if item == "*" {
            return true;
        }
        let (pattern_host, pattern_port) = if let Some(idx) = item.rfind(':') {
            if !item.starts_with('[') || item[..idx].ends_with(']') {
                if let Ok(p) = item[idx + 1..].parse::<u16>() {
                    (&item[..idx], Some(p))
                } else {
                    (item, None)
                }
            } else {
                (item, None)
            }
        } else {
            (item, None)
        };
        if let Some(p) = pattern_port {
            if p != port {
                continue;
            }
        }
        let norm = pattern_host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .trim_start_matches('.')
            .to_ascii_lowercase();
        if norm.is_empty() {
            continue;
        }
        if clean_host == norm || clean_host.ends_with(&format!(".{}", norm)) {
            return true;
        }
    }
    false
}

fn env_var_nonempty(keys: &[&str]) -> Option<String> {
    for &key in keys {
        if let Ok(val) = env::var(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn is_env_enabled(name: &str) -> bool {
    env::var(name).is_ok_and(|v| !v.is_empty() && v != "0")
}

fn resolve_proxy_from_env(target_host: &str, target_port: u16) -> Result<Option<ProxyEndpoint>, HttpTransportError> {
    if let Some(no_proxy) = env_var_nonempty(&["no_proxy", "NO_PROXY"]) {
        if matches_no_proxy(target_host, target_port, &no_proxy) {
            return Ok(None);
        }
    }
    let Some(raw_proxy) = env_var_nonempty(&["https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"])
    else {
        return Ok(None);
    };
    ProxyEndpoint::parse_url(&raw_proxy, "", "")
        .map(Some)
        .map_err(|e| HttpTransportError::new(CODE_COULDNT_RESOLVE_PROXY, e))
}

fn classify_tls_io_error(err: io::Error) -> HttpTransportError {
    if let Some(tls_err) = err.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>()) {
        let cert_err = matches!(
            tls_err,
            rustls::Error::InvalidCertificate(_)
                | rustls::Error::InvalidCertRevocationList(_)
                | rustls::Error::NoCertificatesPresented
        ) || matches!(
            tls_err,
            rustls::Error::AlertReceived(
                rustls::AlertDescription::BadCertificate
                    | rustls::AlertDescription::UnsupportedCertificate
                    | rustls::AlertDescription::CertificateRevoked
                    | rustls::AlertDescription::CertificateExpired
                    | rustls::AlertDescription::CertificateUnknown
                    | rustls::AlertDescription::UnknownCA
                    | rustls::AlertDescription::AccessDenied
            )
        );
        if cert_err {
            return HttpTransportError::new(
                CODE_PEER_FAILED_VERIFICATION,
                format!("TLS certificate verification failed: {}", tls_err),
            );
        }
        return HttpTransportError::new(
            CODE_SSL_CONNECT_ERROR,
            format!("TLS handshake error: {}", tls_err),
        );
    }
    if matches!(err.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) {
        return HttpTransportError::new(CODE_OPERATION_TIMEDOUT, "TLS handshake timed out");
    }
    let msg = err.to_string();
    let lower = msg.to_ascii_lowercase();
    if lower.contains("certificate") || lower.contains("unknownissuer") || lower.contains("unknown ca") {
        HttpTransportError::new(CODE_PEER_FAILED_VERIFICATION, msg)
    } else {
        HttpTransportError::new(CODE_SSL_CONNECT_ERROR, format!("TLS connection failed: {}", msg))
    }
}

fn classify_io_rw_error(err: io::Error, is_send: bool) -> HttpTransportError {
    if matches!(err.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) {
        return HttpTransportError::new(CODE_OPERATION_TIMEDOUT, "HTTPS operation timed out");
    }
    if let Some(tls_err) = err.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>()) {
        return HttpTransportError::new(
            CODE_RECV_ERROR,
            format!("TLS stream error: {}", tls_err),
        );
    }
    HttpTransportError::new(
        if is_send { CODE_SEND_ERROR } else { CODE_RECV_ERROR },
        err.to_string(),
    )
}

fn open_tunnel_socket(
    proxy: Option<&ProxyEndpoint>,
    allow_local_socks5_fallback: bool,
    target_host: &str,
    target_port: u16,
    connect_timeout: Duration,
    io_timeout: Duration,
    tls_config: &Arc<ClientConfig>,
) -> Result<TunnelSocket, HttpTransportError> {
    if let Some(p) = proxy {
        return open_via_proxy(p, target_host, target_port, connect_timeout, io_timeout, tls_config);
    }
    if allow_local_socks5_fallback
        && !is_env_enabled("MOCKTAIL_NO_LOCAL_PROXY")
        && !is_loopback_host(target_host)
    {
        let local_addr = SocketAddr::from(([127, 0, 0, 1], 1080));
        if let Ok(mut tcp) = TcpStream::connect_timeout(&local_addr, LOCAL_SOCKS5_PROBE_TIMEOUT) {
            let _ = tcp.set_read_timeout(Some(io_timeout));
            let _ = tcp.set_write_timeout(Some(io_timeout));
            let _ = tcp.set_nodelay(true);
            connect_socks5_on_stream(&mut tcp, "", "", true, target_host, target_port)?;
            return Ok(TunnelSocket::Plain(tcp));
        }
    }
    connect_tcp_with_timeout(target_host, target_port, connect_timeout, io_timeout, false)
        .map(TunnelSocket::Plain)
}

fn open_via_proxy(
    proxy: &ProxyEndpoint,
    target_host: &str,
    target_port: u16,
    connect_timeout: Duration,
    io_timeout: Duration,
    tls_config: &Arc<ClientConfig>,
) -> Result<TunnelSocket, HttpTransportError> {
    let mut tcp =
        connect_tcp_with_timeout(&proxy.host, proxy.port, connect_timeout, io_timeout, true)?;
    match proxy.scheme {
        ProxyScheme::Http => {
            connect_http_tunnel_on_stream(
                &mut tcp,
                &proxy.username,
                &proxy.password,
                target_host,
                target_port,
            )?;
            Ok(TunnelSocket::Plain(tcp))
        }
        ProxyScheme::Https => {
            let server_name = ServerName::try_from(proxy.host.clone()).map_err(|_| {
                HttpTransportError::new(
                    CODE_COULDNT_RESOLVE_PROXY,
                    format!("invalid proxy TLS server name: {}", proxy.host),
                )
            })?;
            let conn = ClientConnection::new(Arc::clone(tls_config), server_name).map_err(|e| {
                HttpTransportError::new(
                    CODE_SSL_CONNECT_ERROR,
                    format!("cannot initialize proxy TLS connection: {}", e),
                )
            })?;
            let mut tls_proxy = StreamOwned::new(conn, tcp);
            while tls_proxy.conn.is_handshaking() {
                tls_proxy
                    .conn
                    .complete_io(&mut tls_proxy.sock)
                    .map_err(classify_tls_io_error)?;
            }
            connect_http_tunnel_on_stream(
                &mut tls_proxy,
                &proxy.username,
                &proxy.password,
                target_host,
                target_port,
            )?;
            Ok(TunnelSocket::TlsProxy(Box::new(tls_proxy)))
        }
        ProxyScheme::Socks5 { remote_dns } => {
            connect_socks5_on_stream(
                &mut tcp,
                &proxy.username,
                &proxy.password,
                remote_dns,
                target_host,
                target_port,
            )?;
            Ok(TunnelSocket::Plain(tcp))
        }
    }
}

struct DeadlineWatchdog {
    deadline: Option<Instant>,
    low_speed_bps: u64,
    low_speed_window: Duration,
    window_start: Instant,
    window_bytes: u64,
    total_received: u64,
    expected_bytes: i64,
}

impl DeadlineWatchdog {
    fn new(transfer_timeout_ms: i64, low_speed_bps: i64, low_speed_seconds: i64) -> Self {
        let now = Instant::now();
        let deadline = if transfer_timeout_ms > 0 {
            Some(now + Duration::from_millis(transfer_timeout_ms as u64))
        } else {
            None
        };
        let (bps, window) = if low_speed_bps > 0 && low_speed_seconds > 0 {
            (
                low_speed_bps as u64,
                Duration::from_secs(low_speed_seconds as u64),
            )
        } else {
            (0, Duration::ZERO)
        };
        Self {
            deadline,
            low_speed_bps: bps,
            low_speed_window: window,
            window_start: now,
            window_bytes: 0,
            total_received: 0,
            expected_bytes: 0,
        }
    }

    fn next_io_timeout(&self) -> Result<Duration, HttpTransportError> {
        let mut timeout = DEFAULT_IO_TIMEOUT;
        if let Some(dl) = self.deadline {
            let now = Instant::now();
            if now >= dl {
                return Err(HttpTransportError::new(
                    CODE_OPERATION_TIMEDOUT,
                    "HTTPS operation timed out",
                ));
            }
            timeout = timeout.min(dl.saturating_duration_since(now));
        }
        if !self.low_speed_window.is_zero() {
            timeout = timeout.min(self.low_speed_window);
        }
        Ok(timeout.max(Duration::from_millis(50)))
    }

    fn record_bytes(&mut self, bytes: usize) -> Result<(), HttpTransportError> {
        let now = Instant::now();
        if let Some(dl) = self.deadline {
            if now >= dl {
                return Err(HttpTransportError::new(
                    CODE_OPERATION_TIMEDOUT,
                    "HTTPS operation timed out",
                ));
            }
        }
        self.total_received = self.total_received.saturating_add(bytes as u64);
        if self.low_speed_bps == 0 || self.low_speed_window.is_zero() {
            return Ok(());
        }
        self.window_bytes = self.window_bytes.saturating_add(bytes as u64);
        let elapsed = now.saturating_duration_since(self.window_start);
        if elapsed >= self.low_speed_window {
            let min_required = self
                .low_speed_bps
                .saturating_mul(elapsed.as_secs().max(1));
            if self.window_bytes < min_required {
                return Err(HttpTransportError::new(
                    CODE_OPERATION_TIMEDOUT,
                    "HTTPS transfer aborted due to low speed timeout",
                ));
            }
            self.window_start = now;
            self.window_bytes = 0;
        }
        Ok(())
    }

    fn on_idle_timeout(&self, err: io::Error) -> Result<(), HttpTransportError> {
        if !matches!(err.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock) {
            return Err(classify_io_rw_error(err, false));
        }
        let now = Instant::now();
        if let Some(dl) = self.deadline {
            if now >= dl {
                return Err(HttpTransportError::new(
                    CODE_OPERATION_TIMEDOUT,
                    "HTTPS operation timed out",
                ));
            }
        }
        if !self.low_speed_window.is_zero()
            && now.saturating_duration_since(self.window_start) >= self.low_speed_window
        {
            let elapsed = now.saturating_duration_since(self.window_start);
            let min_required = self
                .low_speed_bps
                .saturating_mul(elapsed.as_secs().max(1));
            if self.window_bytes < min_required {
                return Err(HttpTransportError::new(
                    CODE_OPERATION_TIMEDOUT,
                    "HTTPS transfer aborted due to low speed timeout",
                ));
            }
        }
        Ok(())
    }
}

/// Buffered reader wrapping a `Read + Write` TLS stream with watchdog timeouts,
/// keeping already-buffered pre-read bytes after HTTP header parsing.
struct GuardedReader<'a, S: Read> {
    stream: S,
    prefix: Vec<u8>,
    prefix_pos: usize,
    watchdog: DeadlineWatchdog,
    set_timeout: &'a dyn Fn(&S, Duration),
}

impl<'a, S: Read> GuardedReader<'a, S> {
    fn new(
        stream: S,
        prefix: Vec<u8>,
        watchdog: DeadlineWatchdog,
        set_timeout: &'a dyn Fn(&S, Duration),
    ) -> Self {
        Self {
            stream,
            prefix,
            prefix_pos: 0,
            watchdog,
            set_timeout,
        }
    }

    fn read_chunk(&mut self, buf: &mut [u8]) -> Result<usize, HttpTransportError> {
        if self.prefix_pos < self.prefix.len() {
            let avail = &self.prefix[self.prefix_pos..];
            let n = avail.len().min(buf.len());
            buf[..n].copy_from_slice(&avail[..n]);
            self.prefix_pos += n;
            self.watchdog.record_bytes(n)?;
            return Ok(n);
        }
        loop {
            let io_timeout = self.watchdog.next_io_timeout()?;
            (self.set_timeout)(&self.stream, io_timeout);
            match self.stream.read(buf) {
                Ok(n) => {
                    self.watchdog.record_bytes(n)?;
                    return Ok(n);
                }
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => self.watchdog.on_idle_timeout(err)?,
            }
        }
    }

    fn read_line_crlf(&mut self, max_bytes: usize) -> Result<Vec<u8>, HttpTransportError> {
        let mut line = Vec::with_capacity(64);
        let mut one = [0u8; 1];
        loop {
            if line.len() >= max_bytes {
                return Err(HttpTransportError::new(
                    CODE_RECV_ERROR,
                    "HTTP chunk header exceeded maximum length",
                ));
            }
            let n = self.read_chunk(&mut one)?;
            if n == 0 {
                return Err(HttpTransportError::new(
                    CODE_PARTIAL_FILE,
                    "unexpected EOF while reading chunked HTTPS stream",
                ));
            }
            line.push(one[0]);
            if one[0] == b'\n' {
                return Ok(line);
            }
        }
    }
}

struct SinkWriter<'a> {
    sink: &'a mut dyn HttpAttemptSink,
    aborted: bool,
}

impl Write for SinkWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if !self.sink.on_write(buf) {
            self.aborted = true;
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "response sink aborted write",
            ));
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

enum BodyDecoder<'a> {
    Identity(SinkWriter<'a>),
    Gzip(GzDecoder<SinkWriter<'a>>),
    Deflate(ZlibDecoder<SinkWriter<'a>>),
}

impl<'a> BodyDecoder<'a> {
    fn new(encoding: &str, sink: &'a mut dyn HttpAttemptSink) -> Result<Self, HttpTransportError> {
        let last_codec = encoding
            .split(',')
            .last()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let writer = SinkWriter {
            sink,
            aborted: false,
        };
        match last_codec.as_str() {
            "" | "identity" => Ok(Self::Identity(writer)),
            "gzip" | "x-gzip" => Ok(Self::Gzip(GzDecoder::new(writer))),
            "deflate" => Ok(Self::Deflate(ZlibDecoder::new(writer))),
            other => Err(HttpTransportError::new(
                CODE_BAD_CONTENT_ENCODING,
                format!("unsupported HTTP Content-Encoding: {}", other),
            )),
        }
    }

    fn write_bytes(&mut self, data: &[u8]) -> Result<(), HttpTransportError> {
        if data.is_empty() {
            return Ok(());
        }
        let res = match self {
            Self::Identity(w) => w.write_all(data),
            Self::Gzip(d) => d.write_all(data),
            Self::Deflate(d) => d.write_all(data),
        };
        match res {
            Ok(()) => Ok(()),
            Err(e) => {
                if self.was_aborted() {
                    Err(HttpTransportError::new(
                        CODE_WRITE_ERROR,
                        "failed to write response body",
                    ))
                } else {
                    Err(HttpTransportError::new(
                        CODE_BAD_CONTENT_ENCODING,
                        format!("decompression failed: {}", e),
                    ))
                }
            }
        }
    }

    fn was_aborted(&self) -> bool {
        match self {
            Self::Identity(w) => w.aborted,
            Self::Gzip(d) => d.get_ref().aborted,
            Self::Deflate(d) => d.get_ref().aborted,
        }
    }

    fn report_progress(&mut self, expected: i64, now: i64) {
        match self {
            Self::Identity(w) => w.sink.on_progress(expected, now),
            Self::Gzip(d) => d.get_mut().sink.on_progress(expected, now),
            Self::Deflate(d) => d.get_mut().sink.on_progress(expected, now),
        }
    }

    fn finish(self) -> Result<(), HttpTransportError> {
        let res = match self {
            Self::Identity(_) => Ok(()),
            Self::Gzip(d) => d.finish().map(|_| ()),
            Self::Deflate(d) => d.finish().map(|_| ()),
        };
        res.map_err(|e| {
            HttpTransportError::new(
                CODE_BAD_CONTENT_ENCODING,
                format!("corrupt compressed HTTP response: {}", e),
            )
        })
    }
}

fn header_contains_ctl(s: &str) -> bool {
    s.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n')
}

fn serialize_http1_request(
    method: &str,
    url: &Url,
    caller_headers: &[String],
    body: &[u8],
    default_user_agent: &str,
    accept_encoding_identity: bool,
    resume_offset: Option<u64>,
) -> Result<Vec<u8>, HttpTransportError> {
    let host = url
        .host_str()
        .ok_or_else(|| HttpTransportError::new(CODE_COULDNT_RESOLVE_HOST, "HTTPS URL missing host"))?;
    let port = url.port().unwrap_or(443);
    let clean_host = host.trim_start_matches('[').trim_end_matches(']');
    let host_header = if port == 443 {
        if clean_host.contains(':') {
            format!("[{}]", clean_host)
        } else {
            clean_host.to_string()
        }
    } else {
        format_authority(clean_host, port)
    };

    let mut path_and_query = url.path().to_string();
    if path_and_query.is_empty() {
        path_and_query.push('/');
    }
    if let Some(q) = url.query() {
        path_and_query.push('?');
        path_and_query.push_str(q);
    }
    if header_contains_ctl(&path_and_query) || header_contains_ctl(&host_header) {
        return Err(HttpTransportError::new(
            CODE_SEND_ERROR,
            "HTTPS request target contains invalid control characters",
        ));
    }

    let mut out = Vec::with_capacity(512 + body.len());
    out.extend_from_slice(method.as_bytes());
    out.extend_from_slice(b" ");
    out.extend_from_slice(path_and_query.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    out.extend_from_slice(host_header.as_bytes());
    out.extend_from_slice(b"\r\nConnection: close\r\n");

    let mut has_user_agent = false;
    let mut has_accept_encoding = false;
    let mut has_accept = false;
    for raw in caller_headers {
        if header_contains_ctl(raw) {
            return Err(HttpTransportError::new(
                CODE_SEND_ERROR,
                "HTTP header contains invalid control bytes",
            ));
        }
        let Some((name, val)) = raw.split_once(':') else {
            continue;
        };
        let key = name.trim().to_ascii_lowercase();
        let trimmed_val = val.trim();
        if matches!(
            key.as_str(),
            "host" | "connection" | "transfer-encoding" | "content-length" | "range"
        ) {
            continue;
        }
        if key == "user-agent" {
            has_user_agent = true;
        } else if key == "accept-encoding" {
            if accept_encoding_identity {
                continue;
            }
            has_accept_encoding = true;
        } else if key == "accept" {
            has_accept = true;
        }
        out.extend_from_slice(name.trim().as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(trimmed_val.as_bytes());
        out.extend_from_slice(b"\r\n");
    }

    if !has_user_agent {
        out.extend_from_slice(b"User-Agent: ");
        out.extend_from_slice(default_user_agent.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if !has_accept {
        out.extend_from_slice(b"Accept: */*\r\n");
    }
    if accept_encoding_identity {
        out.extend_from_slice(b"Accept-Encoding: identity\r\n");
    } else if !has_accept_encoding {
        out.extend_from_slice(b"Accept-Encoding: gzip, deflate\r\n");
    }
    if let Some(offset) = resume_offset {
        out.extend_from_slice(format!("Range: bytes={}-\r\n", offset).as_bytes());
    }
    if method == "POST" {
        out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    if method == "POST" && !body.is_empty() {
        out.extend_from_slice(body);
    }
    Ok(out)
}

#[derive(Debug)]
struct ParsedResponseHead {
    status: i64,
    content_length: Option<u64>,
    is_chunked: bool,
    content_encoding: String,
    redirect_url: String,
    leftover: Vec<u8>,
}

fn find_header_end(buf: &[u8]) -> Option<(usize, usize)> {
    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some((pos, pos + 4));
    }
    if let Some(pos) = buf.windows(2).position(|w| w == b"\n\n") {
        return Some((pos, pos + 2));
    }
    None
}

fn read_and_parse_response_head<S: Read>(
    stream: &mut S,
    base_url: &Url,
    watchdog: &mut DeadlineWatchdog,
    set_timeout: &dyn Fn(&S, Duration),
    sink: &mut dyn HttpAttemptSink,
) -> Result<ParsedResponseHead, HttpTransportError> {
    let mut raw = Vec::with_capacity(2048);
    let mut tmp = [0u8; 4096];

    loop {
        raw.clear();
        let header_end = loop {
            let io_timeout = watchdog.next_io_timeout()?;
            set_timeout(stream, io_timeout);
            match stream.read(&mut tmp) {
                Ok(0) => {
                    return Err(HttpTransportError::new(
                        if raw.is_empty() {
                            CODE_GOT_NOTHING
                        } else {
                            CODE_PARTIAL_FILE
                        },
                        "HTTPS connection closed while reading response headers",
                    ));
                }
                Ok(n) => {
                    if raw.len() + n > MAX_RESPONSE_HEADERS_BYTES {
                        return Err(HttpTransportError::new(
                            CODE_RECV_ERROR,
                            "HTTPS response headers exceeded 64 KiB limit",
                        ));
                    }
                    raw.extend_from_slice(&tmp[..n]);
                    if let Some((_, total_len)) = find_header_end(&raw) {
                        break total_len;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    watchdog.on_idle_timeout(e)?;
                }
            }
        };

        let mut header_cap = 128;
        let (code, minor, reason, parsed_headers, parsed_len) = loop {
            let mut slots = vec![httparse::EMPTY_HEADER; header_cap];
            let mut resp = httparse::Response::new(&mut slots);
            match resp.parse(&raw[..header_end]) {
                Ok(httparse::Status::Complete(n)) => {
                    let code = resp.code.unwrap_or(0) as i64;
                    let minor = resp.version.unwrap_or(1);
                    let reason = resp.reason.unwrap_or("").to_string();
                    let collected: Vec<(String, Vec<u8>)> = resp
                        .headers
                        .iter()
                        .map(|h| (h.name.to_string(), h.value.to_vec()))
                        .collect();
                    break (code, minor, reason, collected, n);
                }
                Ok(httparse::Status::Partial) => {
                    return Err(HttpTransportError::new(
                        CODE_RECV_ERROR,
                        "malformed incomplete HTTPS response headers",
                    ));
                }
                Err(httparse::Error::TooManyHeaders) if header_cap < 512 => {
                    header_cap = 512;
                }
                Err(e) => {
                    return Err(HttpTransportError::new(
                        CODE_RECV_ERROR,
                        format!("malformed HTTPS response headers: {}", e),
                    ));
                }
            }
        };

        // Skip interim 1xx headers and read final response block.
        if (100..200).contains(&code) {
            raw.drain(..parsed_len);
            if find_header_end(&raw).is_some() {
                // Edge case: second block already arrived cleanly.
                let leftover = raw;
                raw = leftover;
            }
            continue;
        }

        let status_line = format!("HTTP/1.{} {} {}\r\n", minor, code, reason);
        if !sink.on_header(status_line.as_bytes()) {
            return Err(HttpTransportError::new(
                CODE_WRITE_ERROR,
                "HTTPS response aborted by header callback",
            ));
        }

        let mut content_length: Option<u64> = None;
        let mut is_chunked = false;
        let mut content_encoding = String::new();
        let mut redirect_url = String::new();

        for (name, value) in &parsed_headers {
            let mut line = Vec::with_capacity(name.len() + value.len() + 4);
            line.extend_from_slice(name.as_bytes());
            line.extend_from_slice(b": ");
            line.extend_from_slice(value);
            line.extend_from_slice(b"\r\n");
            if !sink.on_header(&line) {
                return Err(HttpTransportError::new(
                    CODE_WRITE_ERROR,
                    "HTTPS response aborted by header callback",
                ));
            }
            let lower = name.to_ascii_lowercase();
            let val_str = String::from_utf8_lossy(value).trim().to_string();
            if lower == "content-length" {
                let parsed = val_str.parse::<u64>().map_err(|_| {
                    HttpTransportError::new(CODE_RECV_ERROR, "invalid Content-Length header")
                })?;
                if let Some(prev) = content_length {
                    if prev != parsed {
                        return Err(HttpTransportError::new(
                            CODE_RECV_ERROR,
                            "conflicting Content-Length headers",
                        ));
                    }
                } else {
                    content_length = Some(parsed);
                }
            } else if lower == "transfer-encoding" {
                if val_str
                    .split(',')
                    .any(|tok| tok.trim().eq_ignore_ascii_case("chunked"))
                {
                    is_chunked = true;
                }
            } else if lower == "content-encoding" {
                content_encoding = val_str;
            } else if lower == "location" && redirect_url.is_empty() && !val_str.is_empty() {
                redirect_url = base_url
                    .join(&val_str)
                    .map(|u| u.to_string())
                    .unwrap_or(val_str);
            }
        }

        if !sink.on_header(b"\r\n") {
            return Err(HttpTransportError::new(
                if code == 416 {
                    CODE_RANGE_ERROR
                } else {
                    CODE_WRITE_ERROR
                },
                "HTTPS response aborted after headers",
            ));
        }

        let leftover = raw[parsed_len..].to_vec();
        return Ok(ParsedResponseHead {
            status: code,
            content_length,
            is_chunked,
            content_encoding,
            redirect_url,
            leftover,
        });
    }
}

fn stream_response_body<S: Read>(
    reader: &mut GuardedReader<'_, S>,
    head: &ParsedResponseHead,
    sink: &mut dyn HttpAttemptSink,
    enable_progress: bool,
) -> Result<(), HttpTransportError> {
    if matches!(head.status, 204 | 304) || is_redirect_status_code(head.status) {
        return Ok(());
    }

    let expected = head.content_length.unwrap_or(0) as i64;
    reader.watchdog.expected_bytes = expected;
    if enable_progress && expected > 0 {
        sink.on_progress(expected, 0);
    }

    let mut decoder = BodyDecoder::new(&head.content_encoding, sink)?;
    let mut buf = [0u8; 32 * 1024];

    if head.is_chunked {
        loop {
            let line = reader.read_line_crlf(MAX_CHUNK_LINE_BYTES)?;
            let line_str = std::str::from_utf8(&line).map_err(|_| {
                HttpTransportError::new(CODE_RECV_ERROR, "non-UTF8 chunk size line")
            })?;
            let hex_part = line_str
                .trim_end_matches(&['\r', '\n'][..])
                .split(';')
                .next()
                .unwrap_or("")
                .trim();
            let mut chunk_rem = usize::from_str_radix(hex_part, 16).map_err(|_| {
                HttpTransportError::new(CODE_RECV_ERROR, "invalid HTTP chunk length")
            })?;
            if chunk_rem == 0 {
                // Consume trailer lines until blank line.
                loop {
                    let trailer = reader.read_line_crlf(MAX_CHUNK_LINE_BYTES)?;
                    if trailer == b"\r\n" || trailer == b"\n" {
                        break;
                    }
                }
                break;
            }
            while chunk_rem > 0 {
                let to_read = chunk_rem.min(buf.len());
                let n = reader.read_chunk(&mut buf[..to_read])?;
                if n == 0 {
                    return Err(HttpTransportError::new(
                        CODE_PARTIAL_FILE,
                        "truncated chunked HTTPS response body",
                    ));
                }
                decoder.write_bytes(&buf[..n])?;
                chunk_rem -= n;
                if enable_progress {
                    decoder.report_progress(expected, reader.watchdog.total_received as i64);
                }
            }
            // Expect \r\n (or \n) delimiter after chunk data.
            let mut crlf = [0u8; 2];
            let first = reader.read_chunk(&mut crlf[..1])?;
            if first == 0 {
                return Err(HttpTransportError::new(
                    CODE_PARTIAL_FILE,
                    "truncated chunk delimiter in HTTPS response",
                ));
            }
            if crlf[0] == b'\r' {
                let second = reader.read_chunk(&mut crlf[1..2])?;
                if second == 0 || crlf[1] != b'\n' {
                    return Err(HttpTransportError::new(
                        CODE_RECV_ERROR,
                        "invalid chunk terminator in HTTPS response",
                    ));
                }
            } else if crlf[0] != b'\n' {
                return Err(HttpTransportError::new(
                    CODE_RECV_ERROR,
                    "invalid chunk terminator in HTTPS response",
                ));
            }
        }
    } else if let Some(total_len) = head.content_length {
        let mut remaining = total_len;
        while remaining > 0 {
            let max_read = (remaining as usize).min(buf.len());
            let n = reader.read_chunk(&mut buf[..max_read])?;
            if n == 0 {
                return Err(HttpTransportError::new(
                    CODE_PARTIAL_FILE,
                    format!(
                        "truncated HTTPS response: received {} of {} bytes",
                        total_len - remaining,
                        total_len
                    ),
                ));
            }
            decoder.write_bytes(&buf[..n])?;
            remaining -= n as u64;
            if enable_progress {
                decoder.report_progress(expected, (total_len - remaining) as i64);
            }
        }
    } else {
        loop {
            let n = reader.read_chunk(&mut buf)?;
            if n == 0 {
                break;
            }
            decoder.write_bytes(&buf[..n])?;
            if enable_progress {
                decoder.report_progress(0, reader.watchdog.total_received as i64);
            }
        }
    }

    decoder.finish()
}

fn execute_http1_over_stream<S: Read + Write>(
    mut stream: S,
    method: &str,
    url: &Url,
    caller_headers: &[String],
    body: &[u8],
    default_user_agent: &str,
    accept_encoding_identity: bool,
    resume_offset: Option<u64>,
    transfer_timeout_ms: i64,
    low_speed_bps: i64,
    low_speed_seconds: i64,
    enable_progress: bool,
    set_timeout: &dyn Fn(&S, Duration),
    sink: &mut dyn HttpAttemptSink,
) -> (i64, String, Result<(), HttpTransportError>) {
    let request_bytes = match serialize_http1_request(
        method,
        url,
        caller_headers,
        body,
        default_user_agent,
        accept_encoding_identity,
        resume_offset,
    ) {
        Ok(b) => b,
        Err(e) => return (0, String::new(), Err(e)),
    };

    let mut watchdog = DeadlineWatchdog::new(
        transfer_timeout_ms,
        low_speed_bps,
        low_speed_seconds,
    );
    if let Ok(t) = watchdog.next_io_timeout() {
        set_timeout(&stream, t);
    }
    if let Err(e) = stream.write_all(&request_bytes).and_then(|_| stream.flush()) {
        return (0, String::new(), Err(classify_io_rw_error(e, true)));
    }

    let head = match read_and_parse_response_head(
        &mut stream,
        url,
        &mut watchdog,
        set_timeout,
        sink,
    ) {
        Ok(h) => h,
        Err(e) => return (0, String::new(), Err(e)),
    };

    let status = head.status;
    let redirect_url = head.redirect_url.clone();
    let mut reader = GuardedReader::new(stream, head.leftover.clone(), watchdog, set_timeout);
    let res = stream_response_body(&mut reader, &head, sink, enable_progress);
    (status, redirect_url, res)
}

#[derive(Clone, Copy)]
pub(crate) enum HttpMethod {
    Get,
    Post,
}

impl HttpMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

struct SingleHopParams<'a> {
    method: HttpMethod,
    url: &'a str,
    headers: &'a [String],
    body: &'a [u8],
    ca_bundle: &'a Path,
    fallback_env_ca_bundle: bool,
    explicit_proxy: Option<&'a ProxyEndpoint>,
    allow_local_socks5_fallback: bool,
    connect_timeout_ms: i64,
    transfer_timeout_ms: i64,
    low_speed_bytes_per_second: i64,
    low_speed_seconds: i64,
    accept_encoding_identity: bool,
    resume_offset: Option<u64>,
    enable_progress: bool,
    default_user_agent: &'a str,
}

fn perform_single_hop(
    params: &SingleHopParams<'_>,
    sink: &mut dyn HttpAttemptSink,
) -> HttpAttemptOutcome {
    let Ok(parsed_url) = Url::parse(params.url) else {
        return HttpAttemptOutcome {
            configure_failed: true,
            curl_code: CODE_COULDNT_RESOLVE_HOST,
            curl_error: "invalid HTTPS URL".to_string(),
            ..HttpAttemptOutcome::default()
        };
    };
    if !parsed_url.scheme().eq_ignore_ascii_case("https") {
        return HttpAttemptOutcome {
            configure_failed: true,
            curl_code: CODE_COULDNT_CONNECT,
            curl_error: "only HTTPS URLs are permitted".to_string(),
            ..HttpAttemptOutcome::default()
        };
    }
    let Some(host) = parsed_url.host_str() else {
        return HttpAttemptOutcome {
            configure_failed: true,
            curl_code: CODE_COULDNT_RESOLVE_HOST,
            curl_error: "HTTPS URL missing host".to_string(),
            ..HttpAttemptOutcome::default()
        };
    };
    let clean_host = host.trim_start_matches('[').trim_end_matches(']');
    let port = parsed_url.port().unwrap_or(443);

    let effective_ca = if !params.ca_bundle.as_os_str().is_empty() {
        Some(params.ca_bundle.to_path_buf())
    } else if params.fallback_env_ca_bundle {
        env::var_os("MOCKTAIL_CA_BUNDLE")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    } else {
        None
    };

    let tls_config = match build_tls_config(effective_ca.as_deref(), effective_ca.is_some()) {
        Ok(cfg) => cfg,
        Err(err) => {
            return HttpAttemptOutcome {
                curl_code: CODE_SSL_CACERT_BADFILE,
                curl_error: err,
                ..HttpAttemptOutcome::default()
            };
        }
    };

    let env_proxy = if params.explicit_proxy.is_none() {
        match resolve_proxy_from_env(clean_host, port) {
            Ok(p) => p,
            Err(e) => {
                return HttpAttemptOutcome {
                    curl_code: e.curl_code,
                    curl_error: e.message,
                    ..HttpAttemptOutcome::default()
                };
            }
        }
    } else {
        None
    };
    let active_proxy = params.explicit_proxy.or(env_proxy.as_ref());

    let connect_timeout = if params.connect_timeout_ms > 0 {
        Duration::from_millis(params.connect_timeout_ms as u64)
    } else {
        DEFAULT_CONNECT_TIMEOUT
    };
    let io_timeout = if params.transfer_timeout_ms > 0 {
        Duration::from_millis(params.transfer_timeout_ms as u64).min(DEFAULT_IO_TIMEOUT)
    } else {
        DEFAULT_IO_TIMEOUT
    };

    let tunnel = match open_tunnel_socket(
        active_proxy,
        params.allow_local_socks5_fallback,
        clean_host,
        port,
        connect_timeout,
        io_timeout,
        &tls_config,
    ) {
        Ok(t) => t,
        Err(e) => {
            return HttpAttemptOutcome {
                curl_code: e.curl_code,
                curl_error: e.message,
                ..HttpAttemptOutcome::default()
            };
        }
    };

    let server_name = match ServerName::try_from(clean_host.to_string()) {
        Ok(sn) => sn,
        Err(_) => {
            return HttpAttemptOutcome {
                configure_failed: true,
                curl_code: CODE_COULDNT_RESOLVE_HOST,
                curl_error: format!("invalid TLS server name: {}", clean_host),
                ..HttpAttemptOutcome::default()
            };
        }
    };
    let conn = match ClientConnection::new(tls_config, server_name) {
        Ok(c) => c,
        Err(e) => {
            return HttpAttemptOutcome {
                curl_code: CODE_SSL_CONNECT_ERROR,
                curl_error: format!("cannot initialize TLS connection: {}", e),
                ..HttpAttemptOutcome::default()
            };
        }
    };
    let mut tls_stream = StreamOwned::new(conn, tunnel);
    while tls_stream.conn.is_handshaking() {
        if let Err(err) = tls_stream.conn.complete_io(&mut tls_stream.sock) {
            let mapped = classify_tls_io_error(err);
            return HttpAttemptOutcome {
                curl_code: mapped.curl_code,
                curl_error: mapped.message,
                ..HttpAttemptOutcome::default()
            };
        }
    }

    let set_timeout = |s: &StreamOwned<ClientConnection, TunnelSocket>, d: Duration| {
        s.sock.set_timeouts(Some(d));
    };
    let (status, redirect_url, body_res) = execute_http1_over_stream(
        tls_stream,
        params.method.as_str(),
        &parsed_url,
        params.headers,
        params.body,
        params.default_user_agent,
        params.accept_encoding_identity,
        params.resume_offset,
        params.transfer_timeout_ms,
        params.low_speed_bytes_per_second,
        params.low_speed_seconds,
        params.enable_progress,
        &set_timeout,
        sink,
    );

    match body_res {
        Ok(()) => HttpAttemptOutcome {
            curl_code: CODE_OK,
            http_status: status,
            redirect_url,
            ..HttpAttemptOutcome::default()
        },
        Err(e) => HttpAttemptOutcome {
            curl_code: e.curl_code,
            is_range_error: e.curl_code == CODE_RANGE_ERROR || status == 416,
            http_status: status,
            redirect_url,
            curl_error: e.message,
            ..HttpAttemptOutcome::default()
        },
    }
}

/// Pure-Rust implementation of a single HTTPS attempt for `http_download.rs`.
pub(crate) fn perform_http_attempt_native(
    spec: &HttpAttemptSpec<'_>,
    sink: &mut dyn HttpAttemptSink,
) -> HttpAttemptOutcome {
    perform_single_hop(
        &SingleHopParams {
            method: HttpMethod::Get,
            url: spec.url,
            headers: spec.headers,
            body: &[],
            ca_bundle: spec.ca_bundle,
            fallback_env_ca_bundle: false,
            explicit_proxy: None,
            allow_local_socks5_fallback: false,
            connect_timeout_ms: spec.connect_timeout_ms,
            transfer_timeout_ms: spec.transfer_timeout_ms,
            low_speed_bytes_per_second: spec.low_speed_bytes_per_second,
            low_speed_seconds: spec.low_speed_seconds,
            accept_encoding_identity: spec.accept_encoding_identity,
            resume_offset: spec.resume_offset,
            enable_progress: spec.enable_progress,
            default_user_agent: "Mocktail-native-updater/1",
        },
        sink,
    )
}

#[derive(Debug, Default, Clone)]
pub(crate) struct HttpServiceResponse {
    pub status_code: i32,
    pub body: String,
    pub headers: Vec<String>,
    pub error: String,
    pub tls_cert_error: bool,
}

pub(crate) struct HttpServiceRequest {
    pub method: HttpMethod,
    pub url: String,
    pub body: String,
    pub headers: Vec<String>,
    pub ca_bundle: String,
    pub timeout_ms: i64,
    pub max_redirects: i32,
    pub max_response_bytes: usize,
    pub max_attempts: i32,
    pub allow_local_socks5_fallback: bool,
    pub fallback_env_ca_bundle: bool,
    pub use_runtime_env_proxy: bool,
    pub explicit_proxy: Option<ProxyEndpoint>,
}

impl Default for HttpServiceRequest {
    fn default() -> Self {
        Self {
            method: HttpMethod::Get,
            url: String::new(),
            body: String::new(),
            headers: Vec::new(),
            ca_bundle: String::new(),
            timeout_ms: 15_000,
            max_redirects: 5,
            max_response_bytes: DEFAULT_SERVICE_RESPONSE_BYTES,
            max_attempts: 3,
            allow_local_socks5_fallback: true,
            fallback_env_ca_bundle: true,
            use_runtime_env_proxy: true,
            explicit_proxy: None,
        }
    }
}

struct VecBodySink {
    bytes: Vec<u8>,
    headers: Vec<String>,
    max_bytes: usize,
    exceeded: bool,
}

impl HttpAttemptSink for VecBodySink {
    fn on_header(&mut self, line: &[u8]) -> bool {
        let s = String::from_utf8_lossy(line);
        let trimmed = s.trim_end_matches(['\r', '\n']);
        if !trimmed.is_empty() && !trimmed.starts_with("HTTP/") {
            self.headers.push(trimmed.to_string());
        }
        true
    }

    fn on_write(&mut self, data: &[u8]) -> bool {
        if data.len() > self.max_bytes || self.bytes.len() > self.max_bytes - data.len() {
            self.exceeded = true;
            return false;
        }
        self.bytes.extend_from_slice(data);
        true
    }
}

fn read_runtime_env_proxy() -> Result<Option<ProxyEndpoint>, String> {
    let Ok(host) = env::var("MOCKTAIL_HTTP_PROXY_HOST") else {
        return Ok(None);
    };
    let host = host.trim();
    if host.is_empty() {
        return Ok(None);
    }
    let port = env::var("MOCKTAIL_HTTP_PROXY_PORT").unwrap_or_default();
    if port.trim().is_empty() {
        return Ok(None);
    }
    let scheme = env::var("MOCKTAIL_HTTP_PROXY_SCHEME")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "http".to_string());
    let username = env::var("MOCKTAIL_HTTP_PROXY_USERNAME").unwrap_or_default();
    let password = env::var("MOCKTAIL_HTTP_PROXY_PASSWORD").unwrap_or_default();
    let url = format!("{}://{}:{}", scheme.trim().to_ascii_lowercase(), host, port.trim());
    ProxyEndpoint::parse_url(&url, &username, &password).map(Some)
}

pub(crate) fn perform_service_request(req: &HttpServiceRequest) -> HttpServiceResponse {
    if !req.url.starts_with("https://") {
        return HttpServiceResponse {
            error: "only HTTPS URLs are allowed".to_string(),
            ..HttpServiceResponse::default()
        };
    }

    let explicit_proxy = if req.explicit_proxy.is_some() {
        req.explicit_proxy.clone()
    } else if req.use_runtime_env_proxy {
        match read_runtime_env_proxy() {
            Ok(p) => p,
            Err(err) => {
                return HttpServiceResponse {
                    error: format!("invalid network proxy configuration: {}", err),
                    ..HttpServiceResponse::default()
                };
            }
        }
    } else {
        None
    };

    let timeout_ms = if req.timeout_ms <= 0 {
        15_000
    } else {
        req.timeout_ms.clamp(100, 120_000)
    };
    let max_bytes = if req.max_response_bytes == 0 {
        DEFAULT_SERVICE_RESPONSE_BYTES
    } else {
        req.max_response_bytes
    };
    let max_attempts = req.max_attempts.clamp(1, 5);
    let max_redirects = req.max_redirects.clamp(0, 10);

    let mut last_error = String::new();
    let mut last_tls_error = false;

    for attempt in 0..max_attempts {
        if attempt > 0 {
            thread::sleep(Duration::from_millis((attempt as u64) * 150));
        }
        let mut current_url = req.url.clone();
        let mut current_method = req.method;
        let mut current_body = req.body.clone();
        let mut current_headers = req.headers.clone();
        let mut hops = 0;

        loop {
            let mut sink = VecBodySink {
                bytes: Vec::with_capacity(4096),
                headers: Vec::new(),
                max_bytes,
                exceeded: false,
            };
            let outcome = perform_single_hop(
                &SingleHopParams {
                    method: current_method,
                    url: &current_url,
                    headers: &current_headers,
                    body: current_body.as_bytes(),
                    ca_bundle: Path::new(&req.ca_bundle),
                    fallback_env_ca_bundle: req.fallback_env_ca_bundle,
                    explicit_proxy: explicit_proxy.as_ref(),
                    allow_local_socks5_fallback: req.allow_local_socks5_fallback,
                    connect_timeout_ms: timeout_ms,
                    transfer_timeout_ms: timeout_ms,
                    low_speed_bytes_per_second: 1024,
                    low_speed_seconds: 15,
                    accept_encoding_identity: false,
                    resume_offset: None,
                    enable_progress: false,
                    default_user_agent: "Mocktail/0.1",
                },
                &mut sink,
            );

            if sink.exceeded {
                return HttpServiceResponse {
                    error: "HTTPS response exceeds its size limit".to_string(),
                    ..HttpServiceResponse::default()
                };
            }

            if max_redirects > 0 && is_redirect_status_code(outcome.http_status) {
                if hops >= max_redirects {
                    return HttpServiceResponse {
                        status_code: outcome.http_status as i32,
                        error: "too many HTTPS redirects".to_string(),
                        ..HttpServiceResponse::default()
                    };
                }
                if outcome.redirect_url.is_empty() || !outcome.redirect_url.starts_with("https://") {
                    return HttpServiceResponse {
                        status_code: outcome.http_status as i32,
                        error: "invalid or non-HTTPS redirect target".to_string(),
                        ..HttpServiceResponse::default()
                    };
                }
                let prev_host = Url::parse(&current_url)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_ascii_lowercase));
                let next_host = Url::parse(&outcome.redirect_url)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_ascii_lowercase));
                if prev_host != next_host {
                    current_headers.retain(|h| {
                        let name = h.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
                        name != "authorization" && name != "cookie"
                    });
                }
                if matches!(outcome.http_status, 301 | 302 | 303) {
                    current_method = HttpMethod::Get;
                    current_body.clear();
                    current_headers.retain(|h| {
                        let name = h.split(':').next().unwrap_or("").trim().to_ascii_lowercase();
                        name != "content-type"
                    });
                }
                current_url = outcome.redirect_url;
                hops += 1;
                continue;
            }

            if outcome.curl_code == CODE_OK {
                return HttpServiceResponse {
                    status_code: outcome.http_status as i32,
                    body: String::from_utf8_lossy(&sink.bytes).into_owned(),
                    headers: sink.headers,
                    error: String::new(),
                    tls_cert_error: false,
                };
            }

            last_error = if outcome.curl_error.is_empty() {
                format!("HTTP request failed (code {})", outcome.curl_code)
            } else {
                outcome.curl_error
            };
            last_tls_error = matches!(
                outcome.curl_code,
                CODE_PEER_FAILED_VERIFICATION | CODE_SSL_CACERT_BADFILE
            );
            break;
        }

        // Do not retry TLS verification / CA bundle errors.
        if last_tls_error {
            break;
        }
    }

    HttpServiceResponse {
        status_code: 0,
        body: String::new(),
        headers: Vec::new(),
        error: if last_error.is_empty() {
            "HTTPS request failed".to_string()
        } else {
            last_error
        },
        tls_cert_error: last_tls_error,
    }
}

#[repr(C)]
pub struct MocktailRustServiceHttpRequestView {
    pub is_post: bool,
    pub url: MocktailRustStrSlice,
    pub body: MocktailRustStrSlice,
    pub headers_ptr: *const MocktailRustStrSlice,
    pub headers_len: usize,
    pub ca_bundle: MocktailRustStrSlice,
    pub timeout_ms: i64,
    pub max_redirects: i32,
    pub max_response_bytes: usize,
    pub max_attempts: i32,
    pub allow_local_socks5_fallback: bool,
    pub fallback_env_ca_bundle: bool,
    pub use_runtime_env_proxy: bool,
}

pub type MocktailRustServiceHttpCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        status_code: i32,
        body_ptr: *const c_char,
        body_len: usize,
        headers_ptr: *const MocktailRustStrSlice,
        headers_len: usize,
        error_ptr: *const c_char,
        error_len: usize,
        tls_cert_error: bool,
    ),
>;

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_services_http_perform(
    req_view: *const MocktailRustServiceHttpRequestView,
    on_complete: MocktailRustServiceHttpCallback,
    ctx: *mut c_void,
) -> bool {
    if req_view.is_null() {
        return false;
    }
    let view = &*req_view;
    let url = slice_to_str(view.url.ptr as *const c_char, view.url.len)
        .unwrap_or("")
        .to_string();
    let body = slice_to_str(view.body.ptr as *const c_char, view.body.len)
        .unwrap_or("")
        .to_string();
    let ca_bundle = slice_to_str(view.ca_bundle.ptr as *const c_char, view.ca_bundle.len)
        .unwrap_or("")
        .to_string();
    let mut headers = Vec::new();
    if !view.headers_ptr.is_null() && view.headers_len > 0 {
        let slice = std::slice::from_raw_parts(view.headers_ptr, view.headers_len);
        headers.reserve(slice.len());
        for item in slice {
            if let Some(h) = slice_to_str(item.ptr as *const c_char, item.len) {
                headers.push(h.to_string());
            }
        }
    }

    let req = HttpServiceRequest {
        method: if view.is_post {
            HttpMethod::Post
        } else {
            HttpMethod::Get
        },
        url,
        body,
        headers,
        ca_bundle,
        timeout_ms: view.timeout_ms,
        max_redirects: view.max_redirects,
        max_response_bytes: view.max_response_bytes,
        max_attempts: view.max_attempts,
        allow_local_socks5_fallback: view.allow_local_socks5_fallback,
        fallback_env_ca_bundle: view.fallback_env_ca_bundle,
        use_runtime_env_proxy: view.use_runtime_env_proxy,
        explicit_proxy: None,
    };

    let resp = perform_service_request(&req);
    let ok = resp.error.is_empty();
    let resp_header_slices: Vec<MocktailRustStrSlice> = resp
        .headers
        .iter()
        .map(|h| MocktailRustStrSlice::from_str(h))
        .collect();
    if let Some(cb) = on_complete {
        cb(
            ctx,
            resp.status_code,
            resp.body.as_ptr() as *const c_char,
            resp.body.len(),
            if resp_header_slices.is_empty() {
                std::ptr::null()
            } else {
                resp_header_slices.as_ptr()
            },
            resp_header_slices.len(),
            resp.error.as_ptr() as *const c_char,
            resp.error.len(),
            resp.tls_cert_error,
        );
    }
    ok
}

/// Kept as an internal no-op helper for C++ callers that previously used `curl_global_init`.
#[no_mangle]
pub extern "C" fn mocktail_rust_http_transport_init() -> i32 {
    let _ = CODE_TOO_MANY_REDIRECTS;
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::net::TcpListener;

    #[test]
    fn no_proxy_matches_domains_ports_and_wildcards() {
        assert!(matches_no_proxy("api.roblox.com", 443, "*"));
        assert!(matches_no_proxy("api.roblox.com", 443, ".roblox.com"));
        assert!(matches_no_proxy("roblox.com", 443, ".roblox.com"));
        assert!(!matches_no_proxy("notroblox.com", 443, ".roblox.com"));
        assert!(matches_no_proxy("127.0.0.1", 8443, "127.0.0.1:8443"));
        assert!(!matches_no_proxy("127.0.0.1", 443, "127.0.0.1:8443"));
    }

    #[test]
    fn proxy_url_parser_handles_credentials_and_schemes() {
        let p = ProxyEndpoint::parse_url("socks5h://u%3A1:p%40w@127.0.0.1:9050", "", "")
            .expect("socks5h parse");
        assert_eq!(p.scheme, ProxyScheme::Socks5 { remote_dns: true });
        assert_eq!(p.host, "127.0.0.1");
        assert_eq!(p.port, 9050);
        assert_eq!(p.username, "u:1");
        assert_eq!(p.password.as_str(), "p@w");
    }

    #[test]
    fn chunked_and_gzip_response_decodes_cleanly() {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(b"{\"hello\":\"mocktail\"}").unwrap();
        let gz = enc.finish().unwrap();

        let split = gz.len() / 2;
        let mut wire = Vec::new();
        wire.extend_from_slice(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n",
        );
        wire.extend_from_slice(format!("{:x}\r\n", split).as_bytes());
        wire.extend_from_slice(&gz[..split]);
        wire.extend_from_slice(b"\r\n");
        wire.extend_from_slice(format!("{:x}\r\n", gz.len() - split).as_bytes());
        wire.extend_from_slice(&gz[split..]);
        wire.extend_from_slice(b"\r\n0\r\n\r\n");

        struct MockStream {
            read: Cursor<Vec<u8>>,
            written: Vec<u8>,
        }
        impl Read for MockStream {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.read.read(buf)
            }
        }
        impl Write for MockStream {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.written.extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let stream = MockStream {
            read: Cursor::new(wire),
            written: Vec::new(),
        };
        let url = Url::parse("https://clientsettings.roblox.com/v2/settings/application/PCDesktopClient").unwrap();
        let mut sink = VecBodySink {
            bytes: Vec::new(),
            headers: Vec::new(),
            max_bytes: 65536,
            exceeded: false,
        };
        let noop_timeout = |_: &MockStream, _: Duration| {};
        let (status, _, res) = execute_http1_over_stream(
            stream,
            "GET",
            &url,
            &[],
            b"",
            "Mocktail/0.1",
            false,
            None,
            5000,
            0,
            0,
            false,
            &noop_timeout,
            &mut sink,
        );
        res.expect("chunked gzip should decode");
        assert_eq!(status, 200);
        assert_eq!(sink.bytes, b"{\"hello\":\"mocktail\"}");
    }

    #[test]
    fn truncated_content_length_returns_partial_file() {
        let wire = b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort".to_vec();
        struct MemStream(Cursor<Vec<u8>>);
        impl Read for MemStream {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.0.read(buf)
            }
        }
        impl Write for MemStream {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let url = Url::parse("https://example.com/file.bin").unwrap();
        let mut sink = VecBodySink {
            bytes: Vec::new(),
            headers: Vec::new(),
            max_bytes: 65536,
            exceeded: false,
        };
        let noop_timeout = |_: &MemStream, _: Duration| {};
        let (status, _, res) = execute_http1_over_stream(
            MemStream(Cursor::new(wire)),
            "GET",
            &url,
            &[],
            b"",
            "Mocktail/0.1",
            true,
            None,
            5000,
            0,
            0,
            false,
            &noop_timeout,
            &mut sink,
        );
        assert_eq!(status, 200);
        let err = res.expect_err("truncated body must error");
        assert_eq!(err.curl_code, CODE_PARTIAL_FILE);
    }

    #[test]
    fn socks5_client_handshake_with_auth_and_domain_connect() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let mut greeting = [0u8; 4];
            conn.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [0x05, 0x02, 0x00, 0x02]);
            conn.write_all(&[0x05, 0x02]).unwrap();

            let mut auth_hdr = [0u8; 2];
            conn.read_exact(&mut auth_hdr).unwrap();
            assert_eq!(auth_hdr, [0x01, 0x04]);
            let mut u = [0u8; 4];
            conn.read_exact(&mut u).unwrap();
            assert_eq!(&u, b"user");
            let mut plen = [0u8; 1];
            conn.read_exact(&mut plen).unwrap();
            assert_eq!(plen[0], 4);
            let mut p = [0u8; 4];
            conn.read_exact(&mut p).unwrap();
            assert_eq!(&p, b"pass");
            conn.write_all(&[0x01, 0x00]).unwrap();

            let mut req_hdr = [0u8; 5];
            conn.read_exact(&mut req_hdr).unwrap();
            assert_eq!(&req_hdr[..4], &[0x05, 0x01, 0x00, 0x03]);
            let dlen = req_hdr[4] as usize;
            let mut rest = vec![0u8; dlen + 2];
            conn.read_exact(&mut rest).unwrap();
            assert_eq!(&rest[..dlen], b"example.com");
            assert_eq!(u16::from_be_bytes([rest[dlen], rest[dlen + 1]]), 443);

            conn.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .unwrap();
            conn.write_all(b"OK").unwrap();
        });

        let mut tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
        connect_socks5_on_stream(&mut tcp, "user", "pass", true, "example.com", 443).unwrap();
        let mut tail = [0u8; 2];
        tcp.read_exact(&mut tail).unwrap();
        assert_eq!(&tail, b"OK");
        server.join().unwrap();
    }

    fn der_tlv(tag: u8, val: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if val.len() < 0x80 {
            out.push(val.len() as u8);
        } else if val.len() <= 0xff {
            out.push(0x81);
            out.push(val.len() as u8);
        } else {
            out.push(0x82);
            out.push((val.len() >> 8) as u8);
            out.push((val.len() & 0xff) as u8);
        }
        out.extend_from_slice(val);
        out
    }

    #[test]
    fn der_cert_matches_server_name_san_dns_and_ip() {
        let mut names = Vec::new();
        names.extend_from_slice(&der_tlv(0x82, b"*.example.com"));
        names.extend_from_slice(&der_tlv(0x87, &[127, 0, 0, 1]));
        let san_seq = der_tlv(0x30, &names);
        let mut san_ext_body = der_tlv(0x06, &[0x55, 0x1d, 0x11]);
        san_ext_body.extend_from_slice(&der_tlv(0x01, &[0xff]));
        san_ext_body.extend_from_slice(&der_tlv(0x04, &san_seq));
        let ext = der_tlv(0x30, &san_ext_body);
        let exts = der_tlv(0xa3, &der_tlv(0x30, &ext));

        let mut tbs_body = der_tlv(0xa0, &[0x02, 0x01, 0x02]);
        for _ in 0..6 {
            tbs_body.extend_from_slice(&der_tlv(0x05, &[]));
        }
        tbs_body.extend_from_slice(&exts);
        let cert_der = der_tlv(0x30, &der_tlv(0x30, &tbs_body));

        let dns_ok = ServerName::try_from("api.example.com").unwrap();
        let dns_bad = ServerName::try_from("other.org").unwrap();
        let ip_ok = ServerName::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST).into());
        let ip_bad = ServerName::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)).into());
        assert!(der_cert_matches_server_name(&cert_der, &dns_ok));
        assert!(!der_cert_matches_server_name(&cert_der, &dns_bad));
        assert!(der_cert_matches_server_name(&cert_der, &ip_ok));
        assert!(!der_cert_matches_server_name(&cert_der, &ip_bad));
    }
}
