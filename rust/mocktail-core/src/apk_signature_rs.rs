use std::ffi::CStr;
use std::os::raw::{c_char, c_int, c_void};
use std::slice;

use sha2::{Digest, Sha256, Sha512};

use crate::{copy_error, find_apk_signing_block_internal, read_u32_le};

const K_CHUNK_BYTES: usize = 1024 * 1024;
const K_MAX_SIGNERS: usize = 16;

pub const APK_DIGEST_SHA256: i32 = 0;
pub const APK_DIGEST_SHA512: i32 = 1;

struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn u32_le(&mut self) -> Option<u32> {
        if self.remaining() < 4 {
            return None;
        }
        let val = read_u32_le(&self.data[self.pos..self.pos + 4]);
        self.pos += 4;
        Some(val)
    }

    fn length_prefixed(&mut self) -> Option<&'a [u8]> {
        let len = usize::try_from(self.u32_le()?).ok()?;
        if len > self.remaining() {
            return None;
        }
        let out = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Some(out)
    }
}

#[derive(Clone, Copy)]
struct SignatureAlgorithm {
    id: u32,
    digest_kind: i32,
    pss: bool,
}

fn supported_algorithm(id: u32) -> Option<SignatureAlgorithm> {
    match id {
        0x0101 => Some(SignatureAlgorithm { id, digest_kind: APK_DIGEST_SHA256, pss: true }),
        0x0102 => Some(SignatureAlgorithm { id, digest_kind: APK_DIGEST_SHA512, pss: true }),
        0x0103 => Some(SignatureAlgorithm { id, digest_kind: APK_DIGEST_SHA256, pss: false }),
        0x0104 => Some(SignatureAlgorithm { id, digest_kind: APK_DIGEST_SHA512, pss: false }),
        0x0201 => Some(SignatureAlgorithm { id, digest_kind: APK_DIGEST_SHA256, pss: false }),
        0x0202 => Some(SignatureAlgorithm { id, digest_kind: APK_DIGEST_SHA512, pss: false }),
        0x0301 => Some(SignatureAlgorithm { id, digest_kind: APK_DIGEST_SHA256, pss: false }),
        _ => None,
    }
}

struct IdBytes<'a> {
    id: u32,
    bytes: &'a [u8],
}

fn parse_id_sequence<'a>(sequence: &'a [u8]) -> Result<Vec<IdBytes<'a>>, &'static str> {
    let mut records = ByteReader::new(sequence);
    let mut values = Vec::new();
    while records.remaining() > 0 {
        let record = records
            .length_prefixed()
            .ok_or("APK signer record is malformed")?;
        let mut fields = ByteReader::new(record);
        let id = fields
            .u32_le()
            .ok_or("APK signer algorithm record is malformed")?;
        let bytes = fields
            .length_prefixed()
            .ok_or("APK signer algorithm record is malformed")?;
        if fields.remaining() != 0 {
            return Err("APK signer algorithm record is malformed");
        }
        values.push(IdBytes { id, bytes });
    }
    if values.is_empty() {
        return Err("APK signer sequence is malformed");
    }
    Ok(values)
}

fn digest_with_prefix<D: Digest>(prefix: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut hasher = D::new();
    hasher.update(prefix);
    hasher.update(payload);
    hasher.finalize().to_vec()
}

fn compute_content_digest(
    apk: &[u8],
    block_begin: usize,
    central_directory: usize,
    eocd: usize,
    digest_kind: i32,
) -> Result<Vec<u8>, &'static str> {
    let mut patched_eocd = apk[eocd..].to_vec();
    if patched_eocd.len() < 20 || block_begin > (u32::MAX as usize) {
        return Err("APK is too large for Signature Scheme v2/v3");
    }
    patched_eocd[16..20].copy_from_slice(&(block_begin as u32).to_le_bytes());

    let sections: [&[u8]; 3] = [
        &apk[..block_begin],
        &apk[central_directory..eocd],
        &patched_eocd,
    ];

    let mut chunk_count = 0usize;
    for section in &sections {
        chunk_count = chunk_count
            .checked_add(section.len().div_ceil(K_CHUNK_BYTES))
            .ok_or("APK content chunk count is invalid")?;
    }
    if chunk_count == 0 || chunk_count > (u32::MAX as usize) {
        return Err("APK content chunk count is invalid");
    }

    let digest_len = if digest_kind == APK_DIGEST_SHA512 { 64 } else { 32 };
    let mut chunk_digests = Vec::with_capacity(chunk_count * digest_len);
    for section in &sections {
        for chunk in section.chunks(K_CHUNK_BYTES) {
            let mut prefix = [0u8; 5];
            prefix[0] = 0xa5;
            prefix[1..5].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
            let d = if digest_kind == APK_DIGEST_SHA512 {
                digest_with_prefix::<Sha512>(&prefix, chunk)
            } else {
                digest_with_prefix::<Sha256>(&prefix, chunk)
            };
            chunk_digests.extend_from_slice(&d);
        }
    }

    let mut top_prefix = [0u8; 5];
    top_prefix[0] = 0x5a;
    top_prefix[1..5].copy_from_slice(&(chunk_count as u32).to_le_bytes());
    let final_digest = if digest_kind == APK_DIGEST_SHA512 {
        digest_with_prefix::<Sha512>(&top_prefix, &chunk_digests)
    } else {
        digest_with_prefix::<Sha256>(&top_prefix, &chunk_digests)
    };
    Ok(final_digest)
}

#[inline(never)]
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

pub type MocktailApkVerifySigFn = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        pubkey: *const u8,
        pubkey_len: usize,
        signed_data: *const u8,
        signed_data_len: usize,
        signature: *const u8,
        signature_len: usize,
        digest_kind: i32,
        is_pss: i32,
        err_buf: *mut c_char,
        err_cap: usize,
    ) -> i32,
>;

pub type MocktailApkVerifyCertFn = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        encoded_cert: *const u8,
        encoded_cert_len: usize,
        is_leaf: i32,
        err_buf: *mut c_char,
        err_cap: usize,
    ) -> i32,
>;

pub type MocktailApkEmitFingerprintFn =
    Option<unsafe extern "C" fn(ctx: *mut c_void, hex_ptr: *const c_char, hex_len: usize)>;

/// Shared APK span and C verification callbacks passed to `verify_signer`.
struct SignerVerifyContext<'a> {
    apk: &'a [u8],
    block_begin: usize,
    central_directory: usize,
    eocd: usize,
    cb_ctx: *mut c_void,
    verify_sig: unsafe extern "C" fn(
        *mut c_void,
        *const u8,
        usize,
        *const u8,
        usize,
        *const u8,
        usize,
        i32,
        i32,
        *mut c_char,
        usize,
    ) -> i32,
    verify_cert: unsafe extern "C" fn(*mut c_void, *const u8, usize, i32, *mut c_char, usize) -> i32,
    err_buf: *mut c_char,
    err_cap: usize,
}

impl SignerVerifyContext<'_> {
    fn fail(&self, msg: &str) -> bool {
        copy_error(self.err_buf, self.err_cap, msg);
        false
    }
}

fn verify_signer(
    ctx: &SignerVerifyContext<'_>,
    signer: &[u8],
    v3: bool,
    certs_out: &mut Vec<String>,
) -> bool {
    let fail = |msg: &str| ctx.fail(msg);

    let mut signer_reader = ByteReader::new(signer);
    let signed_data = match signer_reader.length_prefixed() {
        Some(v) => v,
        None => return fail("APK signer has no signed data"),
    };
    let mut min_sdk = 0u32;
    let mut max_sdk = 0u32;
    if v3 {
        let Some(mn) = signer_reader.u32_le() else {
            return fail("APK v3 signer SDK range is invalid");
        };
        let Some(mx) = signer_reader.u32_le() else {
            return fail("APK v3 signer SDK range is invalid");
        };
        if mn > mx {
            return fail("APK v3 signer SDK range is invalid");
        }
        min_sdk = mn;
        max_sdk = mx;
    }
    let Some(signatures) = signer_reader.length_prefixed() else {
        return fail(&format!(
            "APK signer fields are malformed (signer={}, signed={}, remaining={})",
            signer.len(),
            signed_data.len(),
            signer_reader.remaining()
        ));
    };
    let Some(public_key_bytes) = signer_reader.length_prefixed() else {
        return fail(&format!(
            "APK signer fields are malformed (signer={}, signed={}, remaining={})",
            signer.len(),
            signed_data.len(),
            signer_reader.remaining()
        ));
    };
    if signer_reader.remaining() != 0 {
        return fail(&format!(
            "APK signer fields are malformed (signer={}, signed={}, remaining={})",
            signer.len(),
            signed_data.len(),
            signer_reader.remaining()
        ));
    }

    let mut signed_reader = ByteReader::new(signed_data);
    let Some(digests) = signed_reader.length_prefixed() else {
        return fail("APK signed-data digest list is malformed");
    };
    let Some(certificate_sequence) = signed_reader.length_prefixed() else {
        return fail("APK signed-data certificate list is malformed");
    };
    let mut signed_min_sdk = 0u32;
    let mut signed_max_sdk = 0u32;
    if v3 {
        let Some(mn) = signed_reader.u32_le() else {
            return fail("APK v3 signed-data SDK range is malformed");
        };
        let Some(mx) = signed_reader.u32_le() else {
            return fail("APK v3 signed-data SDK range is malformed");
        };
        signed_min_sdk = mn;
        signed_max_sdk = mx;
    }
    if signed_reader.length_prefixed().is_none() {
        return fail("APK signed-data attributes are malformed");
    }
    if !v3 && signed_reader.remaining() != 0 {
        let Some(reserved) = signed_reader.length_prefixed() else {
            return fail("APK v2 signed-data reserved field is malformed");
        };
        if !reserved.is_empty() {
            return fail("APK v2 signed-data reserved field is malformed");
        }
    }
    if signed_reader.remaining() != 0 {
        return fail(&format!(
            "APK signed-data has trailing fields: {}",
            signed_reader.remaining()
        ));
    }
    if v3 && (min_sdk != signed_min_sdk || max_sdk != signed_max_sdk) {
        return fail("APK signed-data has a mismatched SDK range");
    }

    let digest_records = match parse_id_sequence(digests) {
        Ok(v) => v,
        Err(msg) => return fail(msg),
    };
    let signature_records = match parse_id_sequence(signatures) {
        Ok(v) => v,
        Err(msg) => return fail(msg),
    };
    if digest_records.len() != signature_records.len()
        || !digest_records
            .iter()
            .zip(signature_records.iter())
            .all(|(d, s)| d.id == s.id)
    {
        return fail("APK signer digest and signature algorithms disagree");
    }

    let mut selected: Option<(SignatureAlgorithm, &[u8], &[u8])> = None;
    for sig in &signature_records {
        let Some(alg) = supported_algorithm(sig.id) else {
            continue;
        };
        if let Some(dig) = digest_records.iter().find(|d| d.id == alg.id) {
            selected = Some((alg, sig.bytes, dig.bytes));
            break;
        }
    }
    let Some((alg, selected_signature, selected_digest)) = selected else {
        return fail("APK signer has no supported matching signature and digest");
    };

    let sig_ok = unsafe {
        (ctx.verify_sig)(
            ctx.cb_ctx,
            public_key_bytes.as_ptr(),
            public_key_bytes.len(),
            signed_data.as_ptr(),
            signed_data.len(),
            selected_signature.as_ptr(),
            selected_signature.len(),
            alg.digest_kind,
            i32::from(alg.pss),
            ctx.err_buf,
            ctx.err_cap,
        )
    };
    if sig_ok != 0 {
        return false;
    }

    let calculated = match compute_content_digest(
        ctx.apk,
        ctx.block_begin,
        ctx.central_directory,
        ctx.eocd,
        alg.digest_kind,
    ) {
        Ok(d) => d,
        Err(msg) => return fail(msg),
    };
    if !constant_time_eq(selected_digest, &calculated) {
        return fail("APK content digest verification failed");
    }

    let mut cert_reader = ByteReader::new(certificate_sequence);
    let mut first = true;
    while cert_reader.remaining() > 0 {
        let Some(encoded) = cert_reader.length_prefixed() else {
            return fail("APK signer certificate sequence is malformed");
        };
        if encoded.is_empty() {
            return fail("APK signer certificate sequence is malformed");
        }
        let is_leaf = first;
        let cert_ok = unsafe {
            (ctx.verify_cert)(
                ctx.cb_ctx,
                encoded.as_ptr(),
                encoded.len(),
                i32::from(is_leaf),
                ctx.err_buf,
                ctx.err_cap,
            )
        };
        if cert_ok != 0 {
            return false;
        }
        if is_leaf {
            first = false;
            let sha = Sha256::digest(encoded);
            certs_out.push(hex::encode(sha));
        }
    }
    if first {
        return fail("APK signer has no certificate");
    }
    true
}

fn verify_apk_container_with_callbacks(
    apk: &[u8],
    cb_ctx: *mut c_void,
    verify_sig: unsafe extern "C" fn(
        *mut c_void,
        *const u8,
        usize,
        *const u8,
        usize,
        *const u8,
        usize,
        i32,
        i32,
        *mut c_char,
        usize,
    ) -> i32,
    verify_cert: unsafe extern "C" fn(*mut c_void, *const u8, usize, i32, *mut c_char, usize) -> i32,
    err_buf: *mut c_char,
    err_cap: usize,
) -> Result<Vec<String>, (c_int, String)> {
    let block = find_apk_signing_block_internal(apk).map_err(|(c, m)| (c, m.to_string()))?;

    let (scheme_offset, scheme_len, v3) = if block.v2_len > 0 {
        (block.v2_offset as usize, block.v2_len as usize, false)
    } else if block.v31_len > 0 {
        (block.v31_offset as usize, block.v31_len as usize, true)
    } else if block.v3_len > 0 {
        (block.v3_offset as usize, block.v3_len as usize, true)
    } else {
        return Err((-3, "APK has no Signature Scheme v2/v3 block".to_string()));
    };

    let Some(scheme_end) = scheme_offset.checked_add(scheme_len) else {
        return Err((-4, "APK signature scheme signer container is malformed".to_string()));
    };
    if scheme_end > apk.len() {
        return Err((-4, "APK signature scheme signer container is malformed".to_string()));
    }
    let scheme = &apk[scheme_offset..scheme_end];

    let mut scheme_reader = ByteReader::new(scheme);
    let Some(signer_sequence) = scheme_reader.length_prefixed() else {
        return Err((-4, "APK signature scheme signer container is malformed".to_string()));
    };
    if scheme_reader.remaining() != 0 {
        return Err((-4, "APK signature scheme signer container is malformed".to_string()));
    }

    let verify_ctx = SignerVerifyContext {
        apk,
        block_begin: block.block_begin as usize,
        central_directory: block.central_directory as usize,
        eocd: block.eocd as usize,
        cb_ctx,
        verify_sig,
        verify_cert,
        err_buf,
        err_cap,
    };
    let mut signers = ByteReader::new(signer_sequence);
    let mut signer_count = 0usize;
    let mut certs = Vec::new();
    while signers.remaining() > 0 {
        let Some(signer) = signers.length_prefixed() else {
            return Err((-5, "APK signer sequence is malformed".to_string()));
        };
        if signer.is_empty() {
            return Err((-5, "APK signer sequence is malformed".to_string()));
        }
        if !verify_signer(&verify_ctx, signer, v3, &mut certs) {
            let msg = if !err_buf.is_null() && err_cap > 0 && unsafe { *err_buf } != 0 {
                unsafe { CStr::from_ptr(err_buf) }
                    .to_string_lossy()
                    .into_owned()
            } else {
                "APK signer sequence is malformed".to_string()
            };
            return Err((-6, msg));
        }
        signer_count += 1;
        if signer_count > K_MAX_SIGNERS {
            return Err((-7, "APK contains too many signers".to_string()));
        }
    }
    if signer_count == 0 {
        return Err((-8, "APK contains no valid signers".to_string()));
    }

    certs.sort();
    certs.dedup();
    Ok(certs)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_verify_apk_signature_container(
    file_bytes: *const u8,
    file_size: usize,
    cb_ctx: *mut c_void,
    verify_sig: MocktailApkVerifySigFn,
    verify_cert: MocktailApkVerifyCertFn,
    emit_fingerprint: MocktailApkEmitFingerprintFn,
    err_buf: *mut c_char,
    err_cap: usize,
) -> c_int {
    if !err_buf.is_null() && err_cap > 0 {
        unsafe { *err_buf = 0 };
    }
    if file_bytes.is_null() || file_size < 32 {
        copy_error(err_buf, err_cap, "APK is not a bounded regular file");
        return -1;
    }
    let (Some(sig_fn), Some(cert_fn)) = (verify_sig, verify_cert) else {
        copy_error(err_buf, err_cap, "APK verification callbacks missing");
        return -1;
    };

    let apk = unsafe { slice::from_raw_parts(file_bytes, file_size) };
    let certs = match verify_apk_container_with_callbacks(
        apk,
        cb_ctx,
        sig_fn,
        cert_fn,
        err_buf,
        err_cap,
    ) {
        Ok(c) => c,
        Err((code, msg)) => {
            copy_error(err_buf, err_cap, &msg);
            return code;
        }
    };
    if let Some(emit) = emit_fingerprint {
        for hex_fp in certs {
            unsafe {
                emit(cb_ctx, hex_fp.as_ptr() as *const c_char, hex_fp.len());
            }
        }
    }
    0
}

// ============================================================================
// Pure-Rust OpenSSL (`libcrypto`) APK signature & certificate verification
// ============================================================================

#[cfg(any(test, feature = "updater"))]
mod openssl_verify {
use super::*;
use std::os::raw::c_long;
use std::path::Path;
use crate::unix_ipc::{MappedReadOnlyFile, ReadFileError};

pub(super) const RSA_PKCS1_PSS_PADDING: c_int = 6;

#[repr(C)]
pub(super) struct EvpPkeyRaw {
    _unused: [u8; 0],
}
#[repr(C)]
struct X509Raw {
    _unused: [u8; 0],
}
#[repr(C)]
pub(super) struct EvpMdCtxRaw {
    _unused: [u8; 0],
}
#[repr(C)]
pub(super) struct EvpPkeyCtxRaw {
    _unused: [u8; 0],
}
#[repr(C)]
pub(super) struct EvpMdRaw {
    _unused: [u8; 0],
}

extern "C" {
    fn d2i_PUBKEY(a: *mut *mut EvpPkeyRaw, pp: *mut *const u8, length: c_long) -> *mut EvpPkeyRaw;
    fn d2i_X509(px: *mut *mut X509Raw, in_: *mut *const u8, len: c_long) -> *mut X509Raw;
    fn X509_get0_pubkey(x: *const X509Raw) -> *mut EvpPkeyRaw;
    fn EVP_PKEY_free(pkey: *mut EvpPkeyRaw);
    fn X509_free(a: *mut X509Raw);
    fn EVP_PKEY_eq(a: *const EvpPkeyRaw, b: *const EvpPkeyRaw) -> c_int;
    pub(super) fn EVP_MD_CTX_new() -> *mut EvpMdCtxRaw;
    fn EVP_MD_CTX_free(ctx: *mut EvpMdCtxRaw);
    pub(super) fn EVP_sha256() -> *const EvpMdRaw;
    fn EVP_sha512() -> *const EvpMdRaw;
    fn EVP_DigestVerifyInit(
        ctx: *mut EvpMdCtxRaw,
        pctx: *mut *mut EvpPkeyCtxRaw,
        type_: *const EvpMdRaw,
        e: *mut c_void,
        pkey: *mut EvpPkeyRaw,
    ) -> c_int;
    fn EVP_DigestVerify(
        ctx: *mut EvpMdCtxRaw,
        sigret: *const u8,
        siglen: usize,
        tbs: *const u8,
        tbslen: usize,
    ) -> c_int;
    pub(super) fn EVP_PKEY_CTX_set_rsa_padding(ctx: *mut EvpPkeyCtxRaw, pad_mode: c_int) -> c_int;
    pub(super) fn EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx: *mut EvpPkeyCtxRaw, saltlen: c_int) -> c_int;
    pub(super) fn EVP_PKEY_CTX_set_rsa_mgf1_md(ctx: *mut EvpPkeyCtxRaw, md: *const EvpMdRaw) -> c_int;
}

pub(super) struct OwnedEvpPkey(pub(super) *mut EvpPkeyRaw);
impl Drop for OwnedEvpPkey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { EVP_PKEY_free(self.0) };
            self.0 = std::ptr::null_mut();
        }
    }
}

struct OwnedX509(*mut X509Raw);
impl Drop for OwnedX509 {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { X509_free(self.0) };
            self.0 = std::ptr::null_mut();
        }
    }
}

pub(super) struct OwnedMdCtx(pub(super) *mut EvpMdCtxRaw);
impl Drop for OwnedMdCtx {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { EVP_MD_CTX_free(self.0) };
            self.0 = std::ptr::null_mut();
        }
    }
}

#[derive(Default)]
struct OpenSslVerifyState {
    current_pubkey: Option<OwnedEvpPkey>,
}

unsafe extern "C" fn openssl_verify_sig_cb(
    ctx: *mut c_void,
    pubkey: *const u8,
    pubkey_len: usize,
    signed_data: *const u8,
    signed_data_len: usize,
    signature: *const u8,
    signature_len: usize,
    digest_kind: i32,
    is_pss: i32,
    err_buf: *mut c_char,
    err_cap: usize,
) -> i32 {
    let state = &mut *ctx.cast::<OpenSslVerifyState>();
    let Ok(pk_len_long) = c_long::try_from(pubkey_len) else {
        copy_error(err_buf, err_cap, "APK signer public key is malformed");
        return -1;
    };
    let mut pk_cursor = pubkey;
    let key = OwnedEvpPkey(d2i_PUBKEY(std::ptr::null_mut(), &mut pk_cursor, pk_len_long));
    if key.0.is_null() || pk_cursor != pubkey.add(pubkey_len) {
        copy_error(err_buf, err_cap, "APK signer public key is malformed");
        return -1;
    }

    let md = if digest_kind == APK_DIGEST_SHA512 {
        EVP_sha512()
    } else {
        EVP_sha256()
    };
    let md_ctx = OwnedMdCtx(EVP_MD_CTX_new());
    let mut pkey_ctx: *mut EvpPkeyCtxRaw = std::ptr::null_mut();
    if md_ctx.0.is_null()
        || EVP_DigestVerifyInit(md_ctx.0, &mut pkey_ctx, md, std::ptr::null_mut(), key.0) != 1
    {
        copy_error(err_buf, err_cap, "cannot initialise APK signer verification");
        return -1;
    }
    if is_pss != 0 {
        let saltlen = if digest_kind == APK_DIGEST_SHA512 { 64 } else { 32 };
        if EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0
            || EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, saltlen) <= 0
            || EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, md) <= 0
        {
            copy_error(err_buf, err_cap, "cannot configure APK RSA-PSS verification");
            return -1;
        }
    }
    if EVP_DigestVerify(md_ctx.0, signature, signature_len, signed_data, signed_data_len) != 1 {
        copy_error(err_buf, err_cap, "APK signer signature verification failed");
        return -1;
    }

    state.current_pubkey = Some(key);
    0
}

unsafe extern "C" fn openssl_verify_cert_cb(
    ctx: *mut c_void,
    encoded_cert: *const u8,
    encoded_cert_len: usize,
    is_leaf: i32,
    err_buf: *mut c_char,
    err_cap: usize,
) -> i32 {
    let state = &mut *ctx.cast::<OpenSslVerifyState>();
    let Ok(cert_len_long) = c_long::try_from(encoded_cert_len) else {
        copy_error(err_buf, err_cap, "APK signer certificate is malformed");
        return -1;
    };
    let mut cert_cursor = encoded_cert;
    let cert = OwnedX509(d2i_X509(std::ptr::null_mut(), &mut cert_cursor, cert_len_long));
    if cert.0.is_null() || cert_cursor != encoded_cert.add(encoded_cert_len) {
        copy_error(err_buf, err_cap, "APK signer certificate is malformed");
        return -1;
    }
    if is_leaf != 0 {
        let cert_key = X509_get0_pubkey(cert.0);
        let Some(ref signer_key) = state.current_pubkey else {
            copy_error(
                err_buf,
                err_cap,
                "APK signer public key does not match its certificate",
            );
            return -1;
        };
        if cert_key.is_null() || EVP_PKEY_eq(cert_key, signer_key.0) != 1 {
            copy_error(
                err_buf,
                err_cap,
                "APK signer public key does not match its certificate",
            );
            return -1;
        }
    }
    0
}

/// Verifies an APK's v2/v3 signing block and OpenSSL cryptographic signatures,
/// returning sorted lowercase SHA-256 leaf certificate fingerprints.
pub(crate) fn verify_apk_signature_openssl(apk_path: &Path) -> Result<Vec<String>, String> {
    let mapped = MappedReadOnlyFile::open_bounded(apk_path, false, 32, None).map_err(|err| match err {
        ReadFileError::NotFound | ReadFileError::OpenFailed(_) => {
            "cannot open APK for signature verification".to_string()
        }
        ReadFileError::InvalidFile => "APK is not a bounded regular file".to_string(),
        ReadFileError::ReadFailed => "cannot map APK for signature verification".to_string(),
    })?;
    let mut state = OpenSslVerifyState::default();
    let mut err_buf = [0 as c_char; 256];
    verify_apk_container_with_callbacks(
        mapped.as_slice(),
        (&mut state as *mut OpenSslVerifyState).cast::<c_void>(),
        openssl_verify_sig_cb,
        openssl_verify_cert_cb,
        err_buf.as_mut_ptr(),
        err_buf.len(),
    )
    .map_err(|(_, msg)| msg)
}
} // mod openssl_verify

#[cfg(any(test, feature = "updater"))]
pub(crate) use openssl_verify::verify_apk_signature_openssl;

#[cfg(test)]
mod tests {
    use super::*;
    use super::openssl_verify::*;
    use std::os::raw::c_long;

    fn lp(bytes: &[u8]) -> Vec<u8> {
        let mut out = (bytes.len() as u32).to_le_bytes().to_vec();
        out.extend_from_slice(bytes);
        out
    }

    fn build_synthetic_apk(scheme_id: u32, payload: &[u8]) -> Vec<u8> {
        let mut apk = vec![0x50, 0x4b, 0x03, 0x04, 0, 0, 0, 0, 0, 0, 0, 0];
        let mut pair = scheme_id.to_le_bytes().to_vec();
        pair.extend_from_slice(payload);
        let mut pairs = (pair.len() as u64).to_le_bytes().to_vec();
        pairs.extend_from_slice(&pair);

        let block_inner_size = (pairs.len() + 24) as u64;
        apk.extend_from_slice(&block_inner_size.to_le_bytes());
        apk.extend_from_slice(&pairs);
        apk.extend_from_slice(&block_inner_size.to_le_bytes());
        apk.extend_from_slice(b"APK Sig Block 42");

        let cd_offset = apk.len() as u32;
        apk.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02, 0, 0, 0, 0]);
        apk.extend_from_slice(&0x06054b50u32.to_le_bytes());
        apk.extend_from_slice(&[0u8; 12]);
        apk.extend_from_slice(&cd_offset.to_le_bytes());
        apk.extend_from_slice(&[0u8; 2]);
        apk
    }

    unsafe extern "C" fn ok_sig(
        _: *mut c_void, _: *const u8, _: usize, _: *const u8, _: usize,
        _: *const u8, _: usize, _: i32, _: i32, _: *mut c_char, _: usize,
    ) -> i32 { 0 }
    unsafe extern "C" fn ok_cert(
        _: *mut c_void, _: *const u8, _: usize, _: i32, _: *mut c_char, _: usize,
    ) -> i32 { 0 }
    unsafe extern "C" fn collect_fp(ctx: *mut c_void, ptr: *const c_char, len: usize) {
        let fps = &mut *(ctx as *mut Vec<String>);
        let s = std::str::from_utf8(slice::from_raw_parts(ptr as *const u8, len)).unwrap();
        fps.push(s.to_string());
    }

    #[test]
    fn verify_container_checks_content_digest_and_emits_leaf_sha256() {
        let fake_cert = b"FAKE_DER_CERT";
        let fake_pubkey = b"FAKE_PUBKEY";
        let sig_bytes = b"FAKE_SIG";

        // Build placeholder APK first to learn exact section offsets, then replace digest.
        let dummy_digest = vec![0u8; 32];
        let build_scheme = |digest: &[u8]| -> Vec<u8> {
            let mut dig_rec = 0x0103u32.to_le_bytes().to_vec();
            dig_rec.extend_from_slice(&lp(digest));
            let digests = lp(&lp(&dig_rec));
            let certs = lp(&lp(fake_cert));
            let attrs = lp(&[]);
            let mut signed_data = Vec::new();
            signed_data.extend_from_slice(&digests);
            signed_data.extend_from_slice(&certs);
            signed_data.extend_from_slice(&attrs);

            let mut sig_rec = 0x0103u32.to_le_bytes().to_vec();
            sig_rec.extend_from_slice(&lp(sig_bytes));
            let sigs = lp(&lp(&sig_rec));

            let mut signer = Vec::new();
            signer.extend_from_slice(&lp(&signed_data));
            signer.extend_from_slice(&sigs);
            signer.extend_from_slice(&lp(fake_pubkey));
            lp(&lp(&signer))
        };

        let placeholder_apk = build_synthetic_apk(0x7109871a, &build_scheme(&dummy_digest));
        let info = find_apk_signing_block_internal(&placeholder_apk).unwrap();
        let real_digest = compute_content_digest(
            &placeholder_apk,
            info.block_begin as usize,
            info.central_directory as usize,
            info.eocd as usize,
            APK_DIGEST_SHA256,
        )
        .unwrap();
        let apk = build_synthetic_apk(0x7109871a, &build_scheme(&real_digest));

        let mut fps: Vec<String> = Vec::new();
        let mut err = [0i8; 256];
        let rc = mocktail_rust_verify_apk_signature_container(
            apk.as_ptr(),
            apk.len(),
            &mut fps as *mut _ as *mut c_void,
            Some(ok_sig),
            Some(ok_cert),
            Some(collect_fp),
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc, 0);
        assert_eq!(fps, vec![hex::encode(Sha256::digest(fake_cert))]);

        // Corrupt a content byte and ensure digest check fails cleanly.
        let mut bad_apk = apk;
        bad_apk[4] ^= 0xff;
        let rc_bad = mocktail_rust_verify_apk_signature_container(
            bad_apk.as_ptr(),
            bad_apk.len(),
            std::ptr::null_mut(),
            Some(ok_sig),
            Some(ok_cert),
            None,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_ne!(rc_bad, 0);
    }

    #[test]
    fn verify_apk_signature_openssl_checks_rsa_pss_and_rejects_tamper() {
        const RSA_KEY_DER: &[u8] = &[48,130,4,189,2,1,0,48,13,6,9,42,134,72,134,247,13,1,1,1,5,0,4,130,4,167,48,130,4,163,2,1,0,2,130,1,1,0,174,16,180,105,67,38,54,211,213,162,255,196,248,18,42,251,7,90,119,110,133,249,129,70,100,92,2,223,131,246,130,40,234,195,196,174,227,46,152,125,30,71,227,205,106,55,41,12,169,229,111,195,43,40,85,32,47,148,160,54,211,10,224,45,126,142,58,71,133,151,109,163,10,68,69,131,133,240,90,209,22,195,188,230,23,148,203,113,193,238,251,116,44,138,141,124,177,13,189,12,5,79,15,48,192,170,231,131,90,42,122,210,180,153,243,254,68,102,168,0,246,152,126,204,111,46,4,138,6,61,50,144,201,82,144,3,104,140,207,108,120,166,200,97,45,160,201,134,174,238,176,109,178,79,191,74,7,55,33,10,242,201,210,205,172,92,133,122,197,187,57,120,227,140,131,25,226,130,59,51,41,182,65,173,234,191,250,20,169,8,14,215,16,129,7,227,80,172,32,150,182,181,144,75,26,62,32,93,119,46,0,238,4,157,216,77,9,64,237,200,204,71,168,88,216,97,214,39,249,40,45,190,203,120,96,105,122,130,99,243,217,123,149,146,223,39,45,101,196,237,207,125,58,9,160,255,2,3,1,0,1,2,130,1,0,31,147,8,38,207,247,110,154,158,118,34,207,39,240,163,187,69,106,51,159,232,205,137,149,171,62,197,134,165,249,97,66,234,210,248,42,129,43,66,157,239,144,58,210,88,34,9,96,50,177,91,196,155,95,133,145,129,16,4,191,237,40,91,225,228,195,7,239,81,92,86,150,236,149,213,198,53,213,147,163,185,237,103,166,149,64,120,102,250,54,207,134,19,78,78,187,255,161,238,88,239,221,151,115,208,127,47,223,179,203,96,220,55,198,117,107,250,28,100,253,71,190,1,194,51,168,181,73,199,161,214,67,91,134,201,193,63,111,36,41,176,3,141,90,156,27,95,177,119,108,61,63,209,13,53,235,109,22,143,112,16,23,102,214,41,68,166,254,182,1,135,71,208,63,55,200,199,168,40,113,244,124,102,237,62,159,234,148,21,126,111,194,46,110,241,219,0,199,71,65,219,59,73,130,125,184,150,109,249,42,63,148,116,115,78,247,154,200,133,81,5,160,214,188,146,49,241,175,187,133,84,45,202,218,140,70,122,91,142,144,48,11,185,80,10,89,185,221,212,167,97,67,233,222,2,1,2,129,129,0,212,242,40,13,175,22,139,39,202,132,158,138,48,21,204,220,5,115,253,132,170,233,206,196,123,143,19,221,143,178,104,0,91,97,19,119,146,143,83,148,51,0,210,95,159,3,18,140,41,234,142,248,132,92,26,170,22,50,168,98,121,20,140,111,14,202,231,219,143,247,19,215,2,242,77,163,60,109,17,162,172,177,246,85,182,15,166,108,151,192,225,201,227,183,6,125,251,223,191,140,213,67,95,87,49,18,236,218,52,141,120,182,163,45,72,57,149,57,4,100,134,175,223,181,236,196,27,15,2,129,129,0,209,66,32,203,195,136,189,92,248,75,165,38,194,64,106,40,245,101,188,234,110,224,242,160,251,53,170,140,113,246,127,180,30,167,254,201,45,141,114,154,126,12,206,243,140,189,163,95,232,118,240,59,102,173,250,4,14,39,34,104,27,145,139,89,235,74,158,156,50,91,251,171,81,248,232,110,131,254,203,14,134,110,106,104,83,230,171,156,179,166,162,91,179,118,222,141,37,61,112,127,74,184,5,119,32,239,118,75,65,22,214,80,49,57,197,176,9,74,16,97,15,69,99,165,252,66,219,17,2,129,129,0,154,37,197,106,202,112,230,64,226,176,7,215,254,160,249,79,216,62,179,169,98,211,167,146,193,226,187,189,170,52,186,102,111,191,161,8,240,182,2,9,136,182,50,147,119,151,16,201,23,218,172,174,39,154,72,207,17,12,144,169,223,254,72,254,103,213,231,235,31,150,250,236,173,60,91,137,43,199,196,121,94,203,224,135,1,40,233,15,56,247,46,59,40,53,40,100,240,124,114,187,238,241,59,69,241,199,66,95,94,165,126,89,175,91,171,41,203,228,159,82,105,209,76,126,244,42,173,111,2,129,128,70,221,112,33,209,60,19,116,210,153,59,122,158,186,21,185,125,49,81,2,203,61,222,172,233,165,200,245,250,250,17,81,60,56,132,46,57,0,247,216,157,235,84,130,98,29,46,160,162,38,245,64,8,139,206,105,101,41,151,155,78,10,193,248,87,152,83,146,109,243,124,141,14,27,143,11,46,36,49,59,224,6,176,126,88,59,123,206,123,128,104,231,73,37,110,68,186,97,206,33,45,122,152,79,57,150,30,167,105,137,132,86,111,245,50,159,100,229,242,26,12,131,225,53,42,242,177,33,2,129,128,26,182,27,77,98,175,32,148,247,30,140,157,224,136,16,216,226,194,243,1,224,47,36,101,215,101,82,25,130,47,235,134,43,198,151,213,123,23,33,149,119,220,48,96,249,84,221,255,247,202,155,150,9,178,51,241,80,184,4,238,175,202,85,70,118,204,17,181,97,0,231,135,215,105,117,151,25,236,91,102,94,117,215,151,127,65,144,144,119,146,83,80,225,92,78,177,37,231,35,213,206,119,65,89,236,67,120,81,23,147,20,32,70,36,238,180,122,243,33,31,103,45,59,195,225,148,94,153];
        const RSA_CERT_DER: &[u8] = &[48,130,2,222,48,130,1,198,160,3,2,1,2,2,20,21,148,219,240,40,146,62,243,210,36,49,224,129,97,102,206,200,151,165,244,48,13,6,9,42,134,72,134,247,13,1,1,11,5,0,48,15,49,13,48,11,6,3,85,4,3,12,4,116,101,115,116,48,30,23,13,50,54,49,49,49,52,49,55,48,49,50,57,90,23,13,50,54,49,49,49,53,49,55,48,49,50,57,90,48,15,49,13,48,11,6,3,85,4,3,12,4,116,101,115,116,48,130,1,34,48,13,6,9,42,134,72,134,247,13,1,1,1,5,0,3,130,1,15,0,48,130,1,10,2,130,1,1,0,174,16,180,105,67,38,54,211,213,162,255,196,248,18,42,251,7,90,119,110,133,249,129,70,100,92,2,223,131,246,130,40,234,195,196,174,227,46,152,125,30,71,227,205,106,55,41,12,169,229,111,195,43,40,85,32,47,148,160,54,211,10,224,45,126,142,58,71,133,151,109,163,10,68,69,131,133,240,90,209,22,195,188,230,23,148,203,113,193,238,251,116,44,138,141,124,177,13,189,12,5,79,15,48,192,170,231,131,90,42,122,210,180,153,243,254,68,102,168,0,246,152,126,204,111,46,4,138,6,61,50,144,201,82,144,3,104,140,207,108,120,166,200,97,45,160,201,134,174,238,176,109,178,79,191,74,7,55,33,10,242,201,210,205,172,92,133,122,197,187,57,120,227,140,131,25,226,130,59,51,41,182,65,173,234,191,250,20,169,8,14,215,16,129,7,227,80,172,32,150,182,181,144,75,26,62,32,93,119,46,0,238,4,157,216,77,9,64,237,200,204,71,168,88,216,97,214,39,249,40,45,190,203,120,96,105,122,130,99,243,217,123,149,146,223,39,45,101,196,237,207,125,58,9,160,255,2,3,1,0,1,163,50,48,48,48,29,6,3,85,29,14,4,22,4,20,63,176,157,159,84,221,176,162,71,46,220,245,5,188,230,253,97,112,36,171,48,15,6,3,85,29,19,1,1,255,4,5,48,3,1,1,255,48,13,6,9,42,134,72,134,247,13,1,1,11,5,0,3,130,1,1,0,73,83,103,60,73,128,220,88,219,153,72,62,154,162,30,185,116,84,231,74,250,61,219,164,81,48,94,131,2,63,208,95,30,11,2,89,185,67,194,225,220,13,77,180,212,15,205,186,28,73,194,54,72,208,98,193,135,152,93,165,6,20,96,195,113,116,87,27,233,169,206,235,48,190,252,42,4,102,3,238,164,171,184,38,30,159,90,93,147,154,209,99,1,234,247,70,31,159,88,105,78,217,222,157,27,114,214,191,3,60,175,146,231,106,198,89,99,141,79,76,219,14,222,9,112,233,249,1,147,158,120,181,198,50,202,136,131,34,209,187,125,57,245,84,178,72,191,125,175,161,81,241,163,182,249,212,192,30,231,95,57,152,193,207,243,22,65,59,119,199,21,140,193,105,60,148,141,97,102,154,89,170,136,210,136,39,182,116,183,8,245,174,35,199,52,40,28,31,155,127,183,137,192,139,183,62,59,178,110,113,82,33,126,207,216,178,6,3,46,18,165,1,202,245,4,188,115,88,233,119,34,20,160,156,71,60,198,10,107,87,52,194,42,36,145,102,106,207,31,207,106,38,108,56,50,223];

        extern "C" {
            fn d2i_AutoPrivateKey(
                a: *mut *mut EvpPkeyRaw,
                pp: *mut *const u8,
                length: c_long,
            ) -> *mut EvpPkeyRaw;
            fn i2d_PUBKEY(a: *const EvpPkeyRaw, pp: *mut *mut u8) -> c_int;
            fn EVP_DigestSignInit(
                ctx: *mut EvpMdCtxRaw,
                pctx: *mut *mut EvpPkeyCtxRaw,
                type_: *const EvpMdRaw,
                e: *mut c_void,
                pkey: *mut EvpPkeyRaw,
            ) -> c_int;
            fn EVP_DigestSign(
                ctx: *mut EvpMdCtxRaw,
                sigret: *mut u8,
                siglen: *mut usize,
                tbs: *const u8,
                tbslen: usize,
            ) -> c_int;
            fn CRYPTO_free(ptr: *mut c_void, file: *const c_char, line: c_int);
        }

        let mut priv_cur = RSA_KEY_DER.as_ptr();
        let priv_key = OwnedEvpPkey(unsafe {
            d2i_AutoPrivateKey(std::ptr::null_mut(), &mut priv_cur, RSA_KEY_DER.len() as c_long)
        });
        assert!(!priv_key.0.is_null());

        let mut spki_ptr: *mut u8 = std::ptr::null_mut();
        let spki_len = unsafe { i2d_PUBKEY(priv_key.0, &mut spki_ptr) };
        assert!(spki_len > 0 && !spki_ptr.is_null());
        let spki_bytes = unsafe { slice::from_raw_parts(spki_ptr, spki_len as usize) }.to_vec();
        unsafe { CRYPTO_free(spki_ptr.cast(), std::ptr::null(), 0) };

        let build_signed_data = |digest: &[u8]| -> Vec<u8> {
            let mut dig_rec = 0x0101u32.to_le_bytes().to_vec();
            dig_rec.extend_from_slice(&lp(digest));
            let mut sd = lp(&lp(&dig_rec));
            sd.extend_from_slice(&lp(&lp(RSA_CERT_DER)));
            sd.extend_from_slice(&lp(&[]));
            sd
        };
        let build_scheme_with_sig = |sd: &[u8], sig: &[u8]| -> Vec<u8> {
            let mut sig_rec = 0x0101u32.to_le_bytes().to_vec();
            sig_rec.extend_from_slice(&lp(sig));
            let mut signer = lp(sd);
            signer.extend_from_slice(&lp(&lp(&sig_rec)));
            signer.extend_from_slice(&lp(&spki_bytes));
            lp(&lp(&signer))
        };

        let placeholder_sd = build_signed_data(&vec![0u8; 32]);
        let placeholder_apk =
            build_synthetic_apk(0x7109871a, &build_scheme_with_sig(&placeholder_sd, &vec![0u8; 256]));
        let info = find_apk_signing_block_internal(&placeholder_apk).unwrap();
        let real_digest = compute_content_digest(
            &placeholder_apk,
            info.block_begin as usize,
            info.central_directory as usize,
            info.eocd as usize,
            APK_DIGEST_SHA256,
        )
        .unwrap();
        let signed_data = build_signed_data(&real_digest);

        let sign_ctx = OwnedMdCtx(unsafe { EVP_MD_CTX_new() });
        let mut pkey_ctx: *mut EvpPkeyCtxRaw = std::ptr::null_mut();
        assert_eq!(
            unsafe {
                EVP_DigestSignInit(
                    sign_ctx.0,
                    &mut pkey_ctx,
                    EVP_sha256(),
                    std::ptr::null_mut(),
                    priv_key.0,
                )
            },
            1
        );
        unsafe {
            assert!(EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) > 0);
            assert!(EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, 32) > 0);
            assert!(EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256()) > 0);
        }
        let mut sig_len = 0usize;
        assert_eq!(
            unsafe {
                EVP_DigestSign(
                    sign_ctx.0,
                    std::ptr::null_mut(),
                    &mut sig_len,
                    signed_data.as_ptr(),
                    signed_data.len(),
                )
            },
            1
        );
        let mut signature = vec![0u8; sig_len];
        assert_eq!(
            unsafe {
                EVP_DigestSign(
                    sign_ctx.0,
                    signature.as_mut_ptr(),
                    &mut sig_len,
                    signed_data.as_ptr(),
                    signed_data.len(),
                )
            },
            1
        );
        signature.truncate(sig_len);

        let apk_bytes = build_synthetic_apk(0x7109871a, &build_scheme_with_sig(&signed_data, &signature));
        let path = std::env::temp_dir().join(format!("mocktail_apk_ossl_{}.apk", std::process::id()));
        let bad_path = std::env::temp_dir().join(format!("mocktail_apk_ossl_bad_{}.apk", std::process::id()));
        struct Cleanup(std::path::PathBuf, std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
                let _ = std::fs::remove_file(&self.1);
            }
        }
        let _cleanup = Cleanup(path.clone(), bad_path.clone());

        std::fs::write(&path, &apk_bytes).unwrap();
        let fps = verify_apk_signature_openssl(&path).expect("valid RSA-PSS APK must verify");
        assert_eq!(fps, vec![hex::encode(Sha256::digest(RSA_CERT_DER))]);

        signature[0] ^= 0x55;
        let bad_apk = build_synthetic_apk(0x7109871a, &build_scheme_with_sig(&signed_data, &signature));
        std::fs::write(&bad_path, &bad_apk).unwrap();
        let err = verify_apk_signature_openssl(&bad_path).expect_err("tampered signature must fail");
        assert!(err.contains("signature verification failed"), "unexpected error: {err}");
    }
}
