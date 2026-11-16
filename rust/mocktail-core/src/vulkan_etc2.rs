//! Vulkan ETC2 format mapping, upload byte accounting, and SIMD mapped-memory
//! copy helpers extracted into an isolated module.

use std::ffi::{c_char, CStr};

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_etc2_lookup_format(
    vk_format: i32,
    out_host_format: *mut i32,
    out_etc_format: *mut i32,
) -> i32 {
    const VK_FORMAT_R8G8B8A8_UNORM: i32 = 37;
    const VK_FORMAT_R8G8B8A8_SRGB: i32 = 43;
    const VK_FORMAT_R16_UNORM: i32 = 70;
    const VK_FORMAT_R16_SNORM: i32 = 71;
    const VK_FORMAT_R16G16_UNORM: i32 = 77;
    const VK_FORMAT_R16G16_SNORM: i32 = 78;

    let (host, etc) = match vk_format {
        147 => (VK_FORMAT_R8G8B8A8_UNORM, 0),
        148 => (VK_FORMAT_R8G8B8A8_SRGB, 0),
        149 => (VK_FORMAT_R8G8B8A8_UNORM, 1),
        150 => (VK_FORMAT_R8G8B8A8_SRGB, 1),
        151 => (VK_FORMAT_R8G8B8A8_UNORM, 2),
        152 => (VK_FORMAT_R8G8B8A8_SRGB, 2),
        153 => (VK_FORMAT_R16_UNORM, 3),
        154 => (VK_FORMAT_R16_SNORM, 4),
        155 => (VK_FORMAT_R16G16_UNORM, 5),
        156 => (VK_FORMAT_R16G16_SNORM, 6),
        _ => return 0,
    };
    if !out_host_format.is_null() {
        unsafe { *out_host_format = host };
    }
    if !out_etc_format.is_null() {
        unsafe { *out_etc_format = etc };
    }
    1
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_etc2_emulated_features(host_features: u32) -> u32 {
    const COMPRESSED_FEATURES: u32 =
        0x0000_0001 | 0x0000_1000 | 0x0000_0400 | 0x0000_4000 | 0x0000_8000;
    host_features & COMPRESSED_FEATURES
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_etc2_upload_byte_counts(
    block_bytes: u64,
    texel_bytes: u64,
    width: u32,
    height: u32,
    depth: u32,
    layer_count: u32,
    out_compressed: *mut u64,
    out_decoded: *mut u64,
) -> i32 {
    if width == 0
        || height == 0
        || depth != 1
        || layer_count == 0
        || out_compressed.is_null()
        || out_decoded.is_null()
    {
        return 0;
    }
    let blocks_w = (width as u64).saturating_add(3) / 4;
    let blocks_h = (height as u64).saturating_add(3) / 4;
    let compressed = blocks_w
        .checked_mul(blocks_h)
        .and_then(|b| b.checked_mul(block_bytes))
        .and_then(|b| b.checked_mul(layer_count as u64));
    let decoded = (width as u64)
        .checked_mul(height as u64)
        .and_then(|p| p.checked_mul(texel_bytes))
        .and_then(|p| p.checked_mul(layer_count as u64));
    match (compressed, decoded) {
        (Some(c), Some(d)) => {
            unsafe {
                *out_compressed = c;
                *out_decoded = d;
            }
            1
        }
        _ => 0,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_etc2_support_advertised(value: *const c_char) -> i32 {
    if value.is_null() {
        return 1;
    }
    if unsafe { CStr::from_ptr(value) }.to_bytes() != b"0" {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_etc2_small_texture_upscale(value: *const c_char) -> u32 {
    if value.is_null() {
        return 1;
    }
    let bytes = unsafe { CStr::from_ptr(value) }.to_bytes();
    if bytes.is_empty() || !bytes[0].is_ascii_digit() {
        return 1;
    }
    let mut parsed: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            break;
        }
        parsed = parsed.saturating_mul(10).saturating_add((b - b'0') as u64);
    }
    parsed.clamp(1, 8) as u32
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.1")]
unsafe fn copy_from_mapped_sse41(mut dst: *mut u8, mut src: *const u8, mut size: usize) {
    use std::arch::x86_64::{__m128i, _mm_storeu_si128, _mm_stream_load_si128};
    while size != 0 && ((src as usize) & 15) != 0 {
        *dst = *src;
        dst = dst.add(1);
        src = src.add(1);
        size -= 1;
    }
    let mut in_ptr = src as *mut __m128i;
    while size >= 64 {
        let a = _mm_stream_load_si128(in_ptr);
        let b = _mm_stream_load_si128(in_ptr.add(1));
        let c = _mm_stream_load_si128(in_ptr.add(2));
        let d = _mm_stream_load_si128(in_ptr.add(3));
        _mm_storeu_si128(dst as *mut __m128i, a);
        _mm_storeu_si128(dst.add(16) as *mut __m128i, b);
        _mm_storeu_si128(dst.add(32) as *mut __m128i, c);
        _mm_storeu_si128(dst.add(48) as *mut __m128i, d);
        in_ptr = in_ptr.add(4);
        dst = dst.add(64);
        size -= 64;
    }
    if size > 0 {
        std::ptr::copy_nonoverlapping(in_ptr as *const u8, dst, size);
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_vulkan_etc2_copy_from_mapped(
    destination: *mut u8,
    source: *const u8,
    size: usize,
) {
    if destination.is_null() || source.is_null() || size == 0 || destination as *const u8 == source
    {
        return;
    }
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("sse4.1") {
        unsafe {
            copy_from_mapped_sse41(destination, source, size);
        }
        return;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(source, destination, size);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn vulkan_etc2_lookup_upload_counts_and_mapped_copy() {
        let mut host = 0;
        let mut etc = -1;
        assert_eq!(mocktail_rust_vulkan_etc2_lookup_format(147, &mut host, &mut etc), 1);
        assert_eq!((host, etc), (37, 0));
        assert_eq!(mocktail_rust_vulkan_etc2_lookup_format(156, &mut host, &mut etc), 1);
        assert_eq!((host, etc), (78, 6));
        assert_eq!(mocktail_rust_vulkan_etc2_lookup_format(37, &mut host, &mut etc), 0);

        let masked = mocktail_rust_vulkan_etc2_emulated_features(0xffff_ffff);
        assert_eq!(masked, 0x0000_d401);

        let mut comp = 0u64;
        let mut dec = 0u64;
        assert_eq!(
            mocktail_rust_vulkan_etc2_upload_byte_counts(8, 4, 8, 4, 1, 2, &mut comp, &mut dec),
            1
        );
        assert_eq!((comp, dec), (32, 256));
        assert_eq!(
            mocktail_rust_vulkan_etc2_upload_byte_counts(
                8,
                4,
                u32::MAX,
                u32::MAX,
                1,
                1,
                &mut comp,
                &mut dec
            ),
            0
        );

        let zero = CString::new("0").unwrap();
        let one = CString::new("1").unwrap();
        let ten = CString::new("10").unwrap();
        assert_eq!(mocktail_rust_vulkan_etc2_support_advertised(std::ptr::null()), 1);
        assert_eq!(mocktail_rust_vulkan_etc2_support_advertised(zero.as_ptr()), 0);
        assert_eq!(mocktail_rust_vulkan_etc2_small_texture_upscale(one.as_ptr()), 1);
        assert_eq!(mocktail_rust_vulkan_etc2_small_texture_upscale(ten.as_ptr()), 8);

        let src: Vec<u8> = (0..137u8).collect();
        let mut dst = vec![0u8; 137];
        mocktail_rust_vulkan_etc2_copy_from_mapped(dst.as_mut_ptr(), src.as_ptr(), src.len());
        assert_eq!(dst, src);
    }
}
