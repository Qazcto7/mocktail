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
    let block = match find_apk_signing_block_internal(apk) {
        Ok(b) => b,
        Err((code, msg)) => {
            copy_error(err_buf, err_cap, msg);
            return code;
        }
    };

    let (scheme_offset, scheme_len, v3) = if block.v2_len > 0 {
        (block.v2_offset as usize, block.v2_len as usize, false)
    } else if block.v31_len > 0 {
        (block.v31_offset as usize, block.v31_len as usize, true)
    } else if block.v3_len > 0 {
        (block.v3_offset as usize, block.v3_len as usize, true)
    } else {
        copy_error(err_buf, err_cap, "APK has no Signature Scheme v2/v3 block");
        return -3;
    };

    let Some(scheme_end) = scheme_offset.checked_add(scheme_len) else {
        copy_error(err_buf, err_cap, "APK signature scheme signer container is malformed");
        return -4;
    };
    if scheme_end > apk.len() {
        copy_error(err_buf, err_cap, "APK signature scheme signer container is malformed");
        return -4;
    }
    let scheme = &apk[scheme_offset..scheme_end];

    let mut scheme_reader = ByteReader::new(scheme);
    let Some(signer_sequence) = scheme_reader.length_prefixed() else {
        copy_error(err_buf, err_cap, "APK signature scheme signer container is malformed");
        return -4;
    };
    if scheme_reader.remaining() != 0 {
        copy_error(err_buf, err_cap, "APK signature scheme signer container is malformed");
        return -4;
    }

    let verify_ctx = SignerVerifyContext {
        apk,
        block_begin: block.block_begin as usize,
        central_directory: block.central_directory as usize,
        eocd: block.eocd as usize,
        cb_ctx,
        verify_sig: sig_fn,
        verify_cert: cert_fn,
        err_buf,
        err_cap,
    };
    let mut signers = ByteReader::new(signer_sequence);
    let mut signer_count = 0usize;
    let mut certs = Vec::new();
    while signers.remaining() > 0 {
        let Some(signer) = signers.length_prefixed() else {
            copy_error(err_buf, err_cap, "APK signer sequence is malformed");
            return -5;
        };
        if signer.is_empty() {
            copy_error(err_buf, err_cap, "APK signer sequence is malformed");
            return -5;
        }
        if !verify_signer(&verify_ctx, signer, v3, &mut certs) {
            let err_is_empty = err_buf.is_null() || err_cap == 0 || unsafe { *err_buf } == 0;
            if err_is_empty {
                copy_error(err_buf, err_cap, "APK signer sequence is malformed");
            }
            return -6;
        }
        signer_count += 1;
        if signer_count > K_MAX_SIGNERS {
            copy_error(err_buf, err_cap, "APK contains too many signers");
            return -7;
        }
    }
    if signer_count == 0 {
        copy_error(err_buf, err_cap, "APK contains no valid signers");
        return -8;
    }

    certs.sort();
    certs.dedup();
    if let Some(emit) = emit_fingerprint {
        for hex_fp in certs {
            unsafe {
                emit(cb_ctx, hex_fp.as_ptr() as *const c_char, hex_fp.len());
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
