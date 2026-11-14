use std::ffi::c_void;
use std::fs;
use std::os::raw::c_int;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::unix_ipc::{
    flock_exclusive_file, path_to_cstr, path_to_slice, slice_to_pathbuf, slice_to_str_lossy,
    strerror_string, write_all_fd, OwnedFd,
};
use crate::update_json::{
    read_http_resume_etag_internal, write_http_resume_state_internal, MocktailRustStrSlice,
};
use crate::{
    host_matches_bytes, is_redirect_status_code, is_retryable_curl_code_val,
    is_retryable_status_code, sha256_regular_file_strict,
};

const K_MEBIBYTE: u64 = 1024 * 1024;

#[derive(Debug, Default, Clone)]
pub(crate) struct HttpTransferRequestData {
    pub url: String,
    pub headers: Vec<String>,
    pub allowed_hosts: Vec<String>,
    pub ca_bundle: PathBuf,
    pub maximum_bytes: usize,
    pub connect_timeout_ms: i64,
    pub transfer_timeout_ms: i64,
    pub low_speed_bytes_per_second: i64,
    pub low_speed_seconds: i64,
    pub maximum_attempts: i32,
    pub retry_delay_ms: i64,
    pub maximum_redirects: i32,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct HttpBytesResultData {
    pub bytes: Vec<u8>,
    pub status_code: i64,
    pub final_url: String,
    pub error: String,
}

impl HttpBytesResultData {
    fn from_error(err: impl Into<String>) -> Self {
        Self {
            error: err.into(),
            ..Self::default()
        }
    }
}

#[derive(Debug, Default, Clone)]
pub(crate) struct HttpDownloadResultData {
    pub bytes_written: usize,
    pub sha256: String,
    pub final_url: String,
    pub error: String,
}

impl HttpDownloadResultData {
    fn from_error(err: impl Into<String>) -> Self {
        Self {
            error: err.into(),
            ..Self::default()
        }
    }
}

pub(crate) struct HttpAttemptSpec<'a> {
    pub url: &'a str,
    pub headers: &'a [String],
    pub ca_bundle: &'a Path,
    pub connect_timeout_ms: i64,
    pub transfer_timeout_ms: i64,
    pub low_speed_bytes_per_second: i64,
    pub low_speed_seconds: i64,
    pub accept_encoding_identity: bool,
    pub resume_offset: Option<u64>,
    pub enable_progress: bool,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct HttpAttemptOutcome {
    pub init_failed: bool,
    pub headers_alloc_failed: bool,
    pub configure_failed: bool,
    pub curl_code: i32,
    pub is_range_error: bool,
    pub http_status: i64,
    pub redirect_url: String,
    pub curl_error: String,
}

pub(crate) trait HttpAttemptSink {
    fn on_header(&mut self, _line: &[u8]) -> bool {
        true
    }
    fn on_write(&mut self, data: &[u8]) -> bool;
    fn on_progress(&mut self, _expected: i64, _now: i64) {}
}

pub(crate) trait HttpTransport {
    fn perform_attempt(&self, spec: &HttpAttemptSpec<'_>, sink: &mut dyn HttpAttemptSink) -> HttpAttemptOutcome;
}

pub(crate) fn is_trusted_https_url(raw_url: &str, allowed_hosts: &[String]) -> Result<(), String> {
    if raw_url.is_empty() || raw_url.bytes().any(|b| b <= 0x1f || b == 0x7f) {
        return Err("URL is malformed".to_string());
    }
    let parsed = url::Url::parse(raw_url).map_err(|_| "URL is malformed".to_string())?;
    if parsed.scheme() != "https"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
    {
        return Err("URL must be credential-free HTTPS on port 443".to_string());
    }
    let Some(raw_host) = parsed.host_str() else {
        return Err("URL must be credential-free HTTPS on port 443".to_string());
    };
    let mut normalized = raw_host.to_ascii_lowercase();
    while normalized.ends_with('.') {
        normalized.pop();
    }
    if normalized.is_empty() {
        return Err("URL must be credential-free HTTPS on port 443".to_string());
    }
    if allowed_hosts
        .iter()
        .any(|allowed| host_matches_bytes(normalized.as_bytes(), allowed.as_bytes()))
    {
        Ok(())
    } else {
        Err("URL host is not trusted".to_string())
    }
}

fn url_host(raw_url: &str) -> String {
    url::Url::parse(raw_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_ascii_lowercase()))
        .unwrap_or_default()
}

fn status_failure(action: &str, url: &str, status_code: i64) -> String {
    let host = url_host(url);
    if host.is_empty() {
        format!("HTTPS {} returned status {}", action, status_code)
    } else {
        format!("{} {} returned status {}", host, action, status_code)
    }
}

fn sleep_retry(retry_delay_ms: i64, attempt: i32) {
    if retry_delay_ms <= 0 || attempt <= 0 {
        return;
    }
    let ms = (retry_delay_ms as u64).saturating_mul(attempt as u64);
    if ms > 0 {
        thread::sleep(Duration::from_millis(ms));
    }
}

fn publish_message(descriptor: c_int, message: &str) {
    if descriptor < 0 {
        return;
    }
    let mut packet = Vec::with_capacity(1 + message.len());
    packet.push(b'P');
    packet.extend_from_slice(message.as_bytes());
    let _ = unsafe {
        libc::send(
            descriptor,
            packet.as_ptr().cast::<c_void>(),
            packet.len(),
            libc::MSG_NOSIGNAL,
        )
    };
}

fn strong_etag(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2
        && bytes[0] == b'"'
        && bytes[bytes.len() - 1] == b'"'
        && bytes.iter().all(|&b| b >= 0x21 && b != 0x7f)
}

fn parse_content_range(range: &str, expected_offset: usize, maximum: usize) -> Option<usize> {
    let rest = range.strip_prefix("bytes ")?;
    let (span, total_str) = rest.split_once('/')?;
    let (start_str, end_str) = span.split_once('-')?;
    let parse_strict = |s: &str| -> Option<usize> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        s.parse::<usize>().ok()
    };
    let start = parse_strict(start_str)?;
    let end = parse_strict(end_str)?;
    let total = parse_strict(total_str)?;
    if start == expected_offset && end >= start && end < total && end == total - 1 && total <= maximum {
        Some(total)
    } else {
        None
    }
}

struct BytesSink<'a> {
    output: &'a mut Vec<u8>,
    maximum: usize,
    exceeded: bool,
}

impl HttpAttemptSink for BytesSink<'_> {
    fn on_write(&mut self, data: &[u8]) -> bool {
        if data.len() > self.maximum || self.output.len() > self.maximum - data.len() {
            self.exceeded = true;
            return false;
        }
        self.output.extend_from_slice(data);
        true
    }
}

fn download_bytes_attempt(
    request: &HttpTransferRequestData,
    transport: &dyn HttpTransport,
) -> (HttpBytesResultData, bool) {
    let mut current = request.url.clone();
    let max_redirects = request.maximum_redirects.max(-1);
    let mut redirect = 0;
    while redirect <= max_redirects {
        let mut bytes = Vec::new();
        let mut sink = BytesSink {
            output: &mut bytes,
            maximum: request.maximum_bytes,
            exceeded: false,
        };
        let spec = HttpAttemptSpec {
            url: &current,
            headers: &request.headers,
            ca_bundle: &request.ca_bundle,
            connect_timeout_ms: request.connect_timeout_ms,
            transfer_timeout_ms: request.transfer_timeout_ms,
            low_speed_bytes_per_second: request.low_speed_bytes_per_second,
            low_speed_seconds: request.low_speed_seconds,
            accept_encoding_identity: false,
            resume_offset: None,
            enable_progress: false,
        };
        let outcome = transport.perform_attempt(&spec, &mut sink);
        if outcome.init_failed {
            return (HttpBytesResultData::from_error(outcome.curl_error), false);
        }
        if outcome.headers_alloc_failed {
            return (
                HttpBytesResultData::from_error("cannot allocate HTTP request headers"),
                false,
            );
        }
        if outcome.configure_failed {
            return (
                HttpBytesResultData::from_error("cannot configure HTTPS request"),
                false,
            );
        }
        if outcome.curl_code != 0 {
            if sink.exceeded {
                return (
                    HttpBytesResultData::from_error("HTTPS response exceeds its size limit"),
                    false,
                );
            }
            return (
                HttpBytesResultData::from_error(outcome.curl_error),
                is_retryable_curl_code_val(outcome.curl_code),
            );
        }
        if is_redirect_status_code(outcome.http_status) {
            if outcome.redirect_url.is_empty() || redirect == max_redirects {
                return (
                    HttpBytesResultData {
                        status_code: outcome.http_status,
                        error: "invalid HTTPS redirect".to_string(),
                        ..HttpBytesResultData::default()
                    },
                    false,
                );
            }
            if let Err(err) = is_trusted_https_url(&outcome.redirect_url, &request.allowed_hosts) {
                return (
                    HttpBytesResultData {
                        status_code: outcome.http_status,
                        error: err,
                        ..HttpBytesResultData::default()
                    },
                    false,
                );
            }
            current = outcome.redirect_url;
            redirect += 1;
            continue;
        }
        if outcome.http_status < 200 || outcome.http_status >= 300 {
            return (
                HttpBytesResultData {
                    bytes,
                    status_code: outcome.http_status,
                    error: status_failure("request", &current, outcome.http_status),
                    ..HttpBytesResultData::default()
                },
                is_retryable_status_code(outcome.http_status),
            );
        }
        return (
            HttpBytesResultData {
                bytes,
                status_code: outcome.http_status,
                final_url: current,
                error: String::new(),
            },
            false,
        );
    }
    (
        HttpBytesResultData::from_error("too many HTTPS redirects"),
        false,
    )
}

pub(crate) fn download_bytes(
    request: &HttpTransferRequestData,
    transport: &dyn HttpTransport,
) -> HttpBytesResultData {
    if request.maximum_bytes == 0 {
        return HttpBytesResultData::from_error("HTTP byte limit is zero");
    }
    if let Err(err) = is_trusted_https_url(&request.url, &request.allowed_hosts) {
        return HttpBytesResultData::from_error(err);
    }
    let attempts = if request.maximum_attempts > 0 {
        request.maximum_attempts
    } else {
        1
    };
    for attempt in 1.. {
        let (res, retryable) = download_bytes_attempt(request, transport);
        if res.error.is_empty() || !retryable || attempt >= attempts {
            return res;
        }
        sleep_retry(request.retry_delay_ms, attempt);
    }
    unreachable!()
}

struct TransferProgress {
    descriptor: c_int,
    resumed_bytes: u64,
    reported_at: Option<Instant>,
    reported_bytes: u64,
}

impl TransferProgress {
    fn new(descriptor: c_int, resumed_bytes: u64) -> Self {
        Self {
            descriptor,
            resumed_bytes,
            reported_at: None,
            reported_bytes: 0,
        }
    }

    fn rate_text(bytes: u64, elapsed: Duration) -> String {
        let elapsed_ms = elapsed.as_millis() as u64;
        if elapsed_ms == 0 {
            return String::new();
        }
        let per_second = bytes.saturating_mul(1000) / elapsed_ms;
        if per_second < K_MEBIBYTE {
            format!(" at {} KiB/s", per_second / 1024)
        } else {
            let tenths = per_second.saturating_mul(10) / K_MEBIBYTE;
            format!(" at {}.{} MiB/s", tenths / 10, tenths % 10)
        }
    }

    fn report(&mut self, expected: i64, now: i64) {
        if self.descriptor < 0 {
            return;
        }
        let moment = Instant::now();
        let elapsed = self
            .reported_at
            .map(|prev| moment.saturating_duration_since(prev))
            .unwrap_or(Duration::MAX);
        if self.reported_at.is_some() && elapsed < Duration::from_secs(1) {
            return;
        }
        let now_u64 = now.max(0) as u64;
        let received = self.resumed_bytes.saturating_add(now_u64);
        let total = if expected > 0 {
            self.resumed_bytes.saturating_add(expected as u64)
        } else {
            0
        };
        let mut message = format!("Downloading Roblox... {} MiB", received / K_MEBIBYTE);
        if total > 0 {
            let pct = received.saturating_mul(100) / total;
            message.push_str(&format!(" / {} MiB ({}%)", total / K_MEBIBYTE, pct));
        }
        if let Some(prev) = self.reported_at {
            if received > self.reported_bytes {
                let d = moment.saturating_duration_since(prev);
                message.push_str(&Self::rate_text(received - self.reported_bytes, d));
            }
        }
        self.reported_at = Some(moment);
        self.reported_bytes = received;
        publish_message(self.descriptor, &message);
    }
}

struct DownloadHeadersState {
    status: i64,
    etag: String,
    encoding: String,
    range: String,
    expected_etag: String,
    url: String,
    state_path: PathBuf,
    offset: usize,
    maximum: usize,
    total: usize,
    restart: bool,
    failed: bool,
    complete: bool,
}

impl DownloadHeadersState {
    fn on_line(&mut self, raw: &[u8]) -> bool {
        let line_owned = String::from_utf8_lossy(raw);
        let line = line_owned.as_ref();
        if line.starts_with("HTTP/") {
            self.complete = false;
            self.etag.clear();
            self.encoding.clear();
            self.range.clear();
            self.status = 0;
            if let Some((_, after_space)) = line.split_once(' ') {
                let digits: String = after_space
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                if let Ok(code) = digits.parse::<i64>() {
                    self.status = code;
                }
            }
            return true;
        }
        if line == "\r\n" || line == "\n" {
            self.complete = true;
            if self.offset > 0 && (self.status == 200 || self.status == 416) {
                self.restart = true;
                return false;
            }
            if self.status != 200 && self.status != 206 {
                return true;
            }
            if !self.encoding.is_empty() && self.encoding != "identity" {
                self.restart = true;
                return false;
            }
            if self.status == 206 {
                let Some(total) = parse_content_range(&self.range, self.offset, self.maximum)
                else {
                    self.restart = true;
                    return false;
                };
                if !self.expected_etag.is_empty()
                    && !self.etag.is_empty()
                    && self.expected_etag != self.etag
                {
                    self.restart = true;
                    return false;
                }
                self.total = total;
            }
            if self.offset == 0
                && strong_etag(&self.etag)
                && write_http_resume_state_internal(&self.state_path, &self.url, &self.etag)
                    .is_err()
            {
                self.failed = true;
                return false;
            }
            return true;
        }
        if !self.complete {
            if let Some((k, v)) = line.split_once(':') {
                let key = k.to_ascii_lowercase();
                let val = v
                    .trim_start_matches([' ', '\t'])
                    .trim_end_matches(['\r', '\n', ' ']);
                if key == "etag" {
                    self.etag = val.to_string();
                } else if key == "content-encoding" {
                    self.encoding = val.to_ascii_lowercase();
                } else if key == "content-range" {
                    self.range = val.to_string();
                }
            }
        }
        true
    }
}

struct FileSink<'a> {
    fd: OwnedFd,
    maximum: usize,
    written: usize,
    sha256: Option<Sha256>,
    exceeded: bool,
    write_failed: bool,
    headers: DownloadHeadersState,
    progress: &'a mut TransferProgress,
}

impl HttpAttemptSink for FileSink<'_> {
    fn on_header(&mut self, line: &[u8]) -> bool {
        self.headers.on_line(line)
    }

    fn on_write(&mut self, data: &[u8]) -> bool {
        if self.headers.status != 200 && self.headers.status != 206 {
            return true;
        }
        if data.len() > self.maximum || self.written > self.maximum - data.len() {
            self.exceeded = true;
            return false;
        }
        if !write_all_fd(self.fd.as_raw(), data) {
            self.write_failed = true;
            return false;
        }
        if let Some(ref mut hasher) = self.sha256 {
            hasher.update(data);
        }
        self.written += data.len();
        true
    }

    fn on_progress(&mut self, expected: i64, now: i64) {
        self.progress.report(expected, now);
    }
}

fn open_temporary_download_fd(temporary: &Path, resuming: bool) -> Result<OwnedFd, String> {
    let cpath = path_to_cstr(temporary)
        .ok_or_else(|| "cannot create temporary download: invalid path".to_string())?;
    let flags = libc::O_WRONLY
        | libc::O_CREAT
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | if resuming { 0 } else { libc::O_TRUNC };
    let raw_fd = unsafe { libc::open(cpath.as_ptr(), flags, 0o600) };
    if raw_fd < 0 {
        let err = crate::unix_ipc::last_errno();
        return Err(format!(
            "cannot create temporary download: {}",
            strerror_string(err)
        ));
    }
    let fd = OwnedFd::from_raw(raw_fd)
        .ok_or_else(|| "cannot create temporary download: invalid descriptor".to_string())?;
    if resuming && unsafe { libc::lseek(fd.as_raw(), 0, libc::SEEK_END) } < 0 {
        let err = crate::unix_ipc::last_errno();
        drop(fd);
        let _ = fs::remove_file(temporary);
        return Err(format!(
            "cannot resume temporary download: {}",
            strerror_string(err)
        ));
    }
    Ok(fd)
}

fn download_file_attempt(
    request: &HttpTransferRequestData,
    temporary: &Path,
    state_path: &Path,
    progress_fd: c_int,
    transport: &dyn HttpTransport,
) -> (HttpDownloadResultData, bool) {
    let mut etag = read_http_resume_etag_internal(state_path, &request.url).unwrap_or_default();
    let existing = match fs::symlink_metadata(temporary) {
        Ok(meta)
            if !meta.file_type().is_symlink()
                && meta.is_file()
                && meta.len() <= request.maximum_bytes as u64
                && strong_etag(&etag) =>
        {
            meta.len() as usize
        }
        _ => {
            let _ = fs::remove_file(temporary);
            let _ = fs::remove_file(state_path);
            etag.clear();
            0
        }
    };

    let mut progress = TransferProgress::new(progress_fd, existing as u64);
    let mut current = request.url.clone();
    let max_redirects = request.maximum_redirects.max(-1);
    let mut redirect = 0;

    while redirect <= max_redirects {
        let resuming = existing > 0;
        let fd = match open_temporary_download_fd(temporary, resuming) {
            Ok(fd) => fd,
            Err(err) => return (HttpDownloadResultData::from_error(err), false),
        };

        let mut header_values = request.headers.clone();
        if resuming {
            header_values.push(format!("If-Range: {}", etag));
        }

        let mut sink = FileSink {
            fd,
            maximum: request.maximum_bytes,
            written: existing,
            sha256: if resuming { None } else { Some(Sha256::new()) },
            exceeded: false,
            write_failed: false,
            headers: DownloadHeadersState {
                status: 0,
                etag: String::new(),
                encoding: String::new(),
                range: String::new(),
                expected_etag: etag.clone(),
                url: request.url.clone(),
                state_path: state_path.to_path_buf(),
                offset: existing,
                maximum: request.maximum_bytes,
                total: 0,
                restart: false,
                failed: false,
                complete: false,
            },
            progress: &mut progress,
        };

        let spec = HttpAttemptSpec {
            url: &current,
            headers: &header_values,
            ca_bundle: &request.ca_bundle,
            connect_timeout_ms: request.connect_timeout_ms,
            transfer_timeout_ms: request.transfer_timeout_ms,
            low_speed_bytes_per_second: request.low_speed_bytes_per_second,
            low_speed_seconds: request.low_speed_seconds,
            accept_encoding_identity: true,
            resume_offset: if resuming { Some(existing as u64) } else { None },
            enable_progress: progress_fd >= 0,
        };

        let outcome = transport.perform_attempt(&spec, &mut sink);
        let synced = unsafe { libc::fsync(sink.fd.as_raw()) } == 0;
        let written = sink.written;
        let exceeded = sink.exceeded;
        let write_failed = sink.write_failed;
        let response_restart = sink.headers.restart;
        let response_failed = sink.headers.failed;
        let response_total = sink.headers.total;
        let streaming_hasher = sink.sha256.take();
        drop(sink);

        if outcome.init_failed {
            let _ = fs::remove_file(temporary);
            return (HttpDownloadResultData::from_error(outcome.curl_error), false);
        }
        if outcome.headers_alloc_failed {
            let _ = fs::remove_file(temporary);
            return (
                HttpDownloadResultData::from_error("cannot allocate HTTP request headers"),
                false,
            );
        }
        if outcome.configure_failed {
            let _ = fs::remove_file(temporary);
            return (
                HttpDownloadResultData::from_error("cannot configure HTTPS download"),
                false,
            );
        }

        if synced && is_retryable_status_code(outcome.http_status) {
            return (
                HttpDownloadResultData::from_error(status_failure(
                    "download",
                    &current,
                    outcome.http_status,
                )),
                true,
            );
        }
        if is_redirect_status_code(outcome.http_status) {
            if outcome.redirect_url.is_empty() || redirect == max_redirects {
                let _ = fs::remove_file(temporary);
                return (
                    HttpDownloadResultData::from_error("invalid HTTPS redirect"),
                    false,
                );
            }
            if let Err(err) = is_trusted_https_url(&outcome.redirect_url, &request.allowed_hosts) {
                let _ = fs::remove_file(temporary);
                return (HttpDownloadResultData::from_error(err), false);
            }
            current = outcome.redirect_url;
            redirect += 1;
            continue;
        }
        if response_restart || (resuming && outcome.is_range_error) {
            let _ = fs::remove_file(temporary);
            let _ = fs::remove_file(state_path);
            return (
                HttpDownloadResultData::from_error(
                    "HTTPS download must restart with a complete archive",
                ),
                true,
            );
        }
        if outcome.curl_code != 0 || write_failed || response_failed || !synced {
            let (err, retryable) = if exceeded {
                ("HTTPS download exceeds its size limit".to_string(), false)
            } else if write_failed || response_failed || !synced {
                ("cannot persist HTTPS download".to_string(), false)
            } else {
                (
                    outcome.curl_error,
                    is_retryable_curl_code_val(outcome.curl_code),
                )
            };
            if !retryable {
                let _ = fs::remove_file(temporary);
            }
            return (HttpDownloadResultData::from_error(err), retryable);
        }
        if (outcome.http_status != 200 && outcome.http_status != 206) || written == 0 {
            let retryable = is_retryable_status_code(outcome.http_status);
            if !retryable {
                let _ = fs::remove_file(temporary);
            }
            return (
                HttpDownloadResultData::from_error(status_failure(
                    "download",
                    &current,
                    outcome.http_status,
                )),
                retryable,
            );
        }
        if outcome.http_status == 206 && written != response_total {
            return (
                HttpDownloadResultData::from_error(
                    "HTTPS download has an incomplete content range",
                ),
                true,
            );
        }

        let sha256 = if resuming {
            match sha256_regular_file_strict(temporary, None) {
                Ok(h) => h,
                Err(e) => {
                    let _ = fs::remove_file(temporary);
                    return (HttpDownloadResultData::from_error(e), false);
                }
            }
        } else if let Some(hasher) = streaming_hasher {
            hex::encode(hasher.finalize())
        } else {
            let _ = fs::remove_file(temporary);
            return (
                HttpDownloadResultData::from_error(
                    "cannot finalize SHA-256 digest of downloaded file",
                ),
                false,
            );
        };

        return (
            HttpDownloadResultData {
                bytes_written: written,
                sha256,
                final_url: current,
                error: String::new(),
            },
            false,
        );
    }

    let _ = fs::remove_file(temporary);
    (
        HttpDownloadResultData::from_error("too many HTTPS redirects"),
        false,
    )
}

pub(crate) fn download_file(
    request: &HttpTransferRequestData,
    destination: &Path,
    progress_fd: c_int,
    transport: &dyn HttpTransport,
) -> HttpDownloadResultData {
    if request.maximum_bytes == 0 {
        return HttpDownloadResultData::from_error("HTTP byte limit is zero");
    }
    if let Err(err) = is_trusted_https_url(&request.url, &request.allowed_hosts) {
        return HttpDownloadResultData::from_error(err);
    }
    if let Some(parent) = destination.parent().filter(|p| !p.as_os_str().is_empty()) {
        if fs::create_dir_all(parent).is_err() {
            return HttpDownloadResultData::from_error("cannot create download directory");
        }
    }

    let mut tmp_os = destination.as_os_str().to_os_string();
    tmp_os.push(".part");
    let temporary = PathBuf::from(tmp_os);

    let mut state_os = temporary.as_os_str().to_os_string();
    state_os.push(".json");
    let state_path = PathBuf::from(state_os);

    let mut lock_os = destination.as_os_str().to_os_string();
    lock_os.push(".lock");
    let lock_path = PathBuf::from(lock_os);

    let Ok(_lock_fd) = flock_exclusive_file(&lock_path) else {
        return HttpDownloadResultData::from_error("cannot lock HTTPS download");
    };

    let attempts = if request.maximum_attempts > 0 {
        request.maximum_attempts
    } else {
        1
    };
    let mut attempt = 1i32;
    let mut final_res = loop {
        let (res, retryable) =
            download_file_attempt(request, &temporary, &state_path, progress_fd, transport);
        if res.error.is_empty() {
            break res;
        }
        if !retryable || attempt >= attempts {
            if !retryable {
                let _ = fs::remove_file(&temporary);
                let _ = fs::remove_file(&state_path);
            }
            return res;
        }
        publish_message(progress_fd, "Retrying Roblox download...");
        sleep_retry(request.retry_delay_ms, attempt);
        attempt += 1;
    };

    if fs::rename(&temporary, destination).is_err() {
        final_res.error = "cannot publish completed download".to_string();
    } else {
        let _ = fs::remove_file(&state_path);
    }
    final_res
}

// ============================================================================
// C ABI Entry Points
// ============================================================================

#[repr(C)]
pub struct MocktailRustHttpTransferRequestView {
    pub url: MocktailRustStrSlice,
    pub headers_ptr: *const MocktailRustStrSlice,
    pub headers_len: usize,
    pub allowed_hosts_ptr: *const MocktailRustStrSlice,
    pub allowed_hosts_len: usize,
    pub ca_bundle: MocktailRustStrSlice,
    pub maximum_bytes: usize,
    pub connect_timeout_ms: i64,
    pub transfer_timeout_ms: i64,
    pub low_speed_bytes_per_second: i64,
    pub low_speed_seconds: i64,
    pub maximum_attempts: i32,
    pub retry_delay_ms: i64,
    pub maximum_redirects: i32,
}

#[repr(C)]
pub struct MocktailRustHttpAttemptRequestView {
    pub url: MocktailRustStrSlice,
    pub headers_ptr: *const MocktailRustStrSlice,
    pub headers_len: usize,
    pub ca_bundle: MocktailRustStrSlice,
    pub connect_timeout_ms: i64,
    pub transfer_timeout_ms: i64,
    pub low_speed_bytes_per_second: i64,
    pub low_speed_seconds: i64,
    pub accept_encoding_identity: bool,
    pub has_resume_offset: bool,
    pub resume_offset: u64,
    pub enable_progress: bool,
    pub attempt_ctx: *mut c_void,
    pub on_header: Option<unsafe extern "C" fn(ctx: *mut c_void, ptr: *const u8, len: usize) -> bool>,
    pub on_write: Option<unsafe extern "C" fn(ctx: *mut c_void, ptr: *const u8, len: usize) -> bool>,
    pub on_progress:
        Option<unsafe extern "C" fn(ctx: *mut c_void, expected: i64, now: i64) -> i32>,
}

#[repr(C)]
pub struct MocktailRustHttpAttemptOutcomeView {
    pub init_failed: bool,
    pub headers_alloc_failed: bool,
    pub configure_failed: bool,
    pub curl_code: i32,
    pub is_range_error: bool,
    pub http_status: i64,
    pub redirect_url: MocktailRustStrSlice,
    pub curl_error: MocktailRustStrSlice,
}

#[repr(C)]
pub struct MocktailRustHttpBytesResultView {
    pub bytes_ptr: *const u8,
    pub bytes_len: usize,
    pub status_code: i64,
    pub final_url: MocktailRustStrSlice,
    pub error: MocktailRustStrSlice,
}

#[repr(C)]
pub struct MocktailRustHttpDownloadResultView {
    pub bytes_written: usize,
    pub sha256: MocktailRustStrSlice,
    pub final_url: MocktailRustStrSlice,
    pub error: MocktailRustStrSlice,
}

pub type MocktailRustPerformHttpAttemptFn = Option<
    unsafe extern "C" fn(
        transport_ctx: *mut c_void,
        req: *const MocktailRustHttpAttemptRequestView,
        on_outcome: Option<
            unsafe extern "C" fn(
                ctx: *mut c_void,
                outcome: *const MocktailRustHttpAttemptOutcomeView,
            ),
        >,
        outcome_ctx: *mut c_void,
    ),
>;

struct CallbackHttpTransport {
    cb: MocktailRustPerformHttpAttemptFn,
    ctx: *mut c_void,
}

impl HttpTransport for CallbackHttpTransport {
    fn perform_attempt(
        &self,
        spec: &HttpAttemptSpec<'_>,
        sink: &mut dyn HttpAttemptSink,
    ) -> HttpAttemptOutcome {
        let Some(cb) = self.cb else {
            return HttpAttemptOutcome {
                init_failed: true,
                curl_error: "HTTP transport is unavailable".to_string(),
                ..HttpAttemptOutcome::default()
            };
        };

        struct SinkProxy<'a> {
            sink: &'a mut dyn HttpAttemptSink,
        }

        unsafe extern "C" fn on_header_cb(
            raw: *mut c_void,
            ptr: *const u8,
            len: usize,
        ) -> bool {
            if raw.is_null() {
                return false;
            }
            let data = if ptr.is_null() || len == 0 {
                &[][..]
            } else {
                std::slice::from_raw_parts(ptr, len)
            };
            (*raw.cast::<SinkProxy>()).sink.on_header(data)
        }

        unsafe extern "C" fn on_write_cb(raw: *mut c_void, ptr: *const u8, len: usize) -> bool {
            if raw.is_null() {
                return false;
            }
            let data = if ptr.is_null() || len == 0 {
                &[][..]
            } else {
                std::slice::from_raw_parts(ptr, len)
            };
            (*raw.cast::<SinkProxy>()).sink.on_write(data)
        }

        unsafe extern "C" fn on_progress_cb(
            raw: *mut c_void,
            expected: i64,
            now: i64,
        ) -> i32 {
            if !raw.is_null() {
                (*raw.cast::<SinkProxy>()).sink.on_progress(expected, now);
            }
            0
        }

        unsafe extern "C" fn on_outcome_cb(
            raw: *mut c_void,
            outcome: *const MocktailRustHttpAttemptOutcomeView,
        ) {
            if raw.is_null() || outcome.is_null() {
                return;
            }
            let o = &*outcome;
            let dst = &mut *raw.cast::<HttpAttemptOutcome>();
            dst.init_failed = o.init_failed;
            dst.headers_alloc_failed = o.headers_alloc_failed;
            dst.configure_failed = o.configure_failed;
            dst.curl_code = o.curl_code;
            dst.is_range_error = o.is_range_error;
            dst.http_status = o.http_status;
            dst.redirect_url = slice_to_str_lossy(o.redirect_url);
            dst.curl_error = slice_to_str_lossy(o.curl_error);
        }

        let header_slices: Vec<MocktailRustStrSlice> = spec
            .headers
            .iter()
            .map(|h| MocktailRustStrSlice::from_str(h))
            .collect();
        let mut proxy = SinkProxy { sink };
        let req_view = MocktailRustHttpAttemptRequestView {
            url: MocktailRustStrSlice::from_str(spec.url),
            headers_ptr: if header_slices.is_empty() {
                std::ptr::null()
            } else {
                header_slices.as_ptr()
            },
            headers_len: header_slices.len(),
            ca_bundle: path_to_slice(spec.ca_bundle),
            connect_timeout_ms: spec.connect_timeout_ms,
            transfer_timeout_ms: spec.transfer_timeout_ms,
            low_speed_bytes_per_second: spec.low_speed_bytes_per_second,
            low_speed_seconds: spec.low_speed_seconds,
            accept_encoding_identity: spec.accept_encoding_identity,
            has_resume_offset: spec.resume_offset.is_some(),
            resume_offset: spec.resume_offset.unwrap_or(0),
            enable_progress: spec.enable_progress,
            attempt_ctx: (&raw mut proxy).cast::<c_void>(),
            on_header: Some(on_header_cb),
            on_write: Some(on_write_cb),
            on_progress: Some(on_progress_cb),
        };
        let mut out = HttpAttemptOutcome::default();
        unsafe {
            cb(
                self.ctx,
                &req_view,
                Some(on_outcome_cb),
                (&raw mut out).cast::<c_void>(),
            );
        }
        out
    }
}

unsafe fn slices_to_strings(ptr: *const MocktailRustStrSlice, len: usize) -> Vec<String> {
    if ptr.is_null() || len == 0 {
        return Vec::new();
    }
    std::slice::from_raw_parts(ptr, len)
        .iter()
        .copied()
        .map(|s| slice_to_str_lossy(s))
        .collect()
}

unsafe fn transfer_request_from_ffi(
    view: *const MocktailRustHttpTransferRequestView,
) -> Option<HttpTransferRequestData> {
    if view.is_null() {
        return None;
    }
    let v = &*view;
    Some(HttpTransferRequestData {
        url: slice_to_str_lossy(v.url),
        headers: slices_to_strings(v.headers_ptr, v.headers_len),
        allowed_hosts: slices_to_strings(v.allowed_hosts_ptr, v.allowed_hosts_len),
        ca_bundle: slice_to_pathbuf(v.ca_bundle),
        maximum_bytes: v.maximum_bytes,
        connect_timeout_ms: v.connect_timeout_ms,
        transfer_timeout_ms: v.transfer_timeout_ms,
        low_speed_bytes_per_second: v.low_speed_bytes_per_second,
        low_speed_seconds: v.low_speed_seconds,
        maximum_attempts: v.maximum_attempts,
        retry_delay_ms: v.retry_delay_ms,
        maximum_redirects: v.maximum_redirects,
    })
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_http_is_trusted_https_url(
    url: MocktailRustStrSlice,
    allowed_hosts_ptr: *const MocktailRustStrSlice,
    allowed_hosts_len: usize,
    on_error: Option<unsafe extern "C" fn(ctx: *mut c_void, error: MocktailRustStrSlice)>,
    ctx: *mut c_void,
) -> bool {
    let url_str = slice_to_str_lossy(url);
    let hosts = slices_to_strings(allowed_hosts_ptr, allowed_hosts_len);
    match is_trusted_https_url(&url_str, &hosts) {
        Ok(()) => true,
        Err(err) => {
            if let Some(cb) = on_error {
                cb(ctx, MocktailRustStrSlice::from_str(&err));
            }
            false
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_http_download_bytes(
    request: *const MocktailRustHttpTransferRequestView,
    perform_attempt: MocktailRustPerformHttpAttemptFn,
    transport_ctx: *mut c_void,
    on_result: Option<
        unsafe extern "C" fn(ctx: *mut c_void, result: *const MocktailRustHttpBytesResultView),
    >,
    ctx: *mut c_void,
) {
    let res = match transfer_request_from_ffi(request) {
        Some(req) => {
            let transport = CallbackHttpTransport {
                cb: perform_attempt,
                ctx: transport_ctx,
            };
            download_bytes(&req, &transport)
        }
        None => HttpBytesResultData::from_error("invalid HTTPS request"),
    };
    if let Some(cb) = on_result {
        let view = MocktailRustHttpBytesResultView {
            bytes_ptr: if res.bytes.is_empty() {
                std::ptr::null()
            } else {
                res.bytes.as_ptr()
            },
            bytes_len: res.bytes.len(),
            status_code: res.status_code,
            final_url: MocktailRustStrSlice::from_str(&res.final_url),
            error: MocktailRustStrSlice::from_str(&res.error),
        };
        cb(ctx, &view);
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_http_download_file(
    request: *const MocktailRustHttpTransferRequestView,
    destination: MocktailRustStrSlice,
    progress_fd: c_int,
    perform_attempt: MocktailRustPerformHttpAttemptFn,
    transport_ctx: *mut c_void,
    on_result: Option<
        unsafe extern "C" fn(ctx: *mut c_void, result: *const MocktailRustHttpDownloadResultView),
    >,
    ctx: *mut c_void,
) {
    let res = match transfer_request_from_ffi(request) {
        Some(req) => {
            let transport = CallbackHttpTransport {
                cb: perform_attempt,
                ctx: transport_ctx,
            };
            download_file(&req, &slice_to_pathbuf(destination), progress_fd, &transport)
        }
        None => HttpDownloadResultData::from_error("invalid HTTPS download request"),
    };
    if let Some(cb) = on_result {
        let view = MocktailRustHttpDownloadResultView {
            bytes_written: res.bytes_written,
            sha256: MocktailRustStrSlice::from_str(&res.sha256),
            final_url: MocktailRustStrSlice::from_str(&res.final_url),
            error: MocktailRustStrSlice::from_str(&res.error),
        };
        cb(ctx, &view);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct MockAttempt {
        headers: Vec<String>,
        body: Vec<u8>,
        outcome: HttpAttemptOutcome,
    }

    struct MockTransport {
        attempts: RefCell<Vec<MockAttempt>>,
        seen_urls: RefCell<Vec<String>>,
        seen_ranges: RefCell<Vec<Option<u64>>>,
        seen_if_ranges: RefCell<Vec<Option<String>>>,
    }

    impl MockTransport {
        fn new(attempts: Vec<MockAttempt>) -> Self {
            Self {
                attempts: RefCell::new(attempts),
                seen_urls: RefCell::new(Vec::new()),
                seen_ranges: RefCell::new(Vec::new()),
                seen_if_ranges: RefCell::new(Vec::new()),
            }
        }
    }

    impl HttpTransport for MockTransport {
        fn perform_attempt(
            &self,
            spec: &HttpAttemptSpec<'_>,
            sink: &mut dyn HttpAttemptSink,
        ) -> HttpAttemptOutcome {
            self.seen_urls.borrow_mut().push(spec.url.to_string());
            self.seen_ranges.borrow_mut().push(spec.resume_offset);
            let if_range = spec
                .headers
                .iter()
                .find_map(|h| h.strip_prefix("If-Range: ").map(str::to_string));
            self.seen_if_ranges.borrow_mut().push(if_range);

            let mut queue = self.attempts.borrow_mut();
            let mock = queue.remove(0);
            for line in &mock.headers {
                if !sink.on_header(line.as_bytes()) {
                    return HttpAttemptOutcome {
                        curl_code: 23, // CURLE_WRITE_ERROR
                        curl_error: "aborted in header".to_string(),
                        http_status: mock.outcome.http_status,
                        ..mock.outcome
                    };
                }
            }
            if !mock.body.is_empty() && !sink.on_write(&mock.body) {
                return HttpAttemptOutcome {
                    curl_code: 23,
                    curl_error: "aborted in write".to_string(),
                    http_status: mock.outcome.http_status,
                    ..mock.outcome
                };
            }
            mock.outcome
        }
    }

    fn temp_dir(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let p = std::env::temp_dir().join(format!(
            "mocktail-http-download-{}-{}-{}",
            label,
            std::process::id(),
            nonce
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn is_trusted_https_url_checks_scheme_port_credentials_ipv6_and_suffixes() {
        let allowed = vec!["pureapk.com".to_string(), "download.test".to_string()];
        assert!(is_trusted_https_url("https://download.pureapk.com/a", &allowed).is_ok());
        assert!(is_trusted_https_url("https://download.test:443/a", &allowed).is_ok());
        assert!(is_trusted_https_url("https://download.test./a", &allowed).is_ok());
        assert!(is_trusted_https_url("http://download.pureapk.com/a", &allowed).is_err());
        assert!(is_trusted_https_url("https://pureapk.com.attacker.test/a", &allowed).is_err());
        assert!(is_trusted_https_url("https://user@pureapk.com/a", &allowed).is_err());
        assert!(is_trusted_https_url("https://:pass@pureapk.com/a", &allowed).is_err());
        assert!(is_trusted_https_url("https://pureapk.com:8443/a", &allowed).is_err());
        assert!(is_trusted_https_url("not a url", &allowed).is_err());
    }

    #[test]
    fn download_bytes_handles_redirects_size_limit_and_retries() {
        let transport = MockTransport::new(vec![
            MockAttempt {
                headers: Vec::new(),
                body: Vec::new(),
                outcome: HttpAttemptOutcome {
                    http_status: 503,
                    ..HttpAttemptOutcome::default()
                },
            },
            MockAttempt {
                headers: Vec::new(),
                body: b"redirect".to_vec(),
                outcome: HttpAttemptOutcome {
                    http_status: 302,
                    redirect_url: "https://cdn.download.test/v2".to_string(),
                    ..HttpAttemptOutcome::default()
                },
            },
            MockAttempt {
                headers: Vec::new(),
                body: b"hello-bytes".to_vec(),
                outcome: HttpAttemptOutcome {
                    http_status: 200,
                    ..HttpAttemptOutcome::default()
                },
            },
        ]);
        let req = HttpTransferRequestData {
            url: "https://download.test/v1".to_string(),
            allowed_hosts: vec!["download.test".to_string()],
            maximum_bytes: 1024,
            maximum_attempts: 2,
            maximum_redirects: 3,
            ..HttpTransferRequestData::default()
        };
        let res = download_bytes(&req, &transport);
        assert!(res.error.is_empty(), "unexpected error: {}", res.error);
        assert_eq!(res.bytes, b"hello-bytes");
        assert_eq!(res.final_url, "https://cdn.download.test/v2");
        assert_eq!(
            *transport.seen_urls.borrow(),
            vec![
                "https://download.test/v1",
                "https://download.test/v1",
                "https://cdn.download.test/v2"
            ]
        );
    }

    #[test]
    fn download_file_handles_resume_etag_if_range_206_416_and_publish() {
        let dir = temp_dir("resume");
        let dest = dir.join("archive.apk");
        let payload = [b"PK\x03\x04".as_slice(), &[b'a'; 100]].concat();
        let half = 40usize;

        let req = HttpTransferRequestData {
            url: "https://download.test/archive".to_string(),
            allowed_hosts: vec!["download.test".to_string()],
            maximum_bytes: 4096,
            maximum_attempts: 2,
            maximum_redirects: 3,
            ..HttpTransferRequestData::default()
        };

        // First call: drops connection midway after sending ETag and 40 bytes
        let t1 = MockTransport::new(vec![MockAttempt {
            headers: vec![
                "HTTP/1.1 200 OK\r\n".to_string(),
                "ETag: \"v1\"\r\n".to_string(),
                "\r\n".to_string(),
            ],
            body: payload[..half].to_vec(),
            outcome: HttpAttemptOutcome {
                curl_code: 18, // CURLE_PARTIAL_FILE
                curl_error: "transfer closed".to_string(),
                http_status: 200,
                ..HttpAttemptOutcome::default()
            },
        }]);
        let r1 = download_file(
            &HttpTransferRequestData {
                maximum_attempts: 1,
                ..req.clone()
            },
            &dest,
            -1,
            &t1,
        );
        assert!(!r1.error.is_empty());
        assert!(!dest.exists());
        assert_eq!(fs::read(dir.join("archive.apk.part")).unwrap(), payload[..half]);

        // Second call: resumes with 206 + Content-Range + If-Range: "v1"
        let t2 = MockTransport::new(vec![MockAttempt {
            headers: vec![
                "HTTP/1.1 206 Partial Content\r\n".to_string(),
                "ETag: \"v1\"\r\n".to_string(),
                format!("Content-Range: bytes {}-{}/{}\r\n", half, payload.len() - 1, payload.len()),
                "\r\n".to_string(),
            ],
            body: payload[half..].to_vec(),
            outcome: HttpAttemptOutcome {
                http_status: 206,
                ..HttpAttemptOutcome::default()
            },
        }]);
        let r2 = download_file(&req, &dest, -1, &t2);
        assert!(r2.error.is_empty(), "unexpected error: {}", r2.error);
        assert_eq!(r2.bytes_written, payload.len());
        assert_eq!(*transport_ranges(&t2), vec![Some(half as u64)]);
        assert_eq!(*t2.seen_if_ranges.borrow(), vec![Some("\"v1\"".to_string())]);
        assert_eq!(fs::read(&dest).unwrap(), payload);
        assert!(!dir.join("archive.apk.part").exists());
        assert!(!dir.join("archive.apk.part.json").exists());

        let _ = fs::remove_dir_all(&dir);
    }

    fn transport_ranges(t: &MockTransport) -> std::cell::Ref<'_, Vec<Option<u64>>> {
        t.seen_ranges.borrow()
    }
}
