// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use std::ffi::{CStr, CString};
    use std::fs::File;
    use std::os::raw::{c_char, c_int};
    use crate::*;

    fn test_env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn test_secure_zero() {
        let mut buf = [1u8, 2, 3, 4, 5];
        mocktail_rust_secure_zero(buf.as_mut_ptr(), buf.len());
        assert_eq!(buf, [0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_sha256() {
        let data = b"hello mocktail";
        let mut out = [0 as c_char; 65];
        let rc = mocktail_rust_sha256(data.as_ptr(), data.len(), out.as_mut_ptr(), out.len());
        assert_eq!(rc, 0);
        let s = unsafe { CStr::from_ptr(out.as_ptr()) }.to_str().unwrap();
        assert_eq!(s.len(), 64);
    }

    #[test]
    fn test_utf8_and_control_bytes() {
        let valid = b"hello world\0";
        assert_eq!(mocktail_rust_is_valid_utf8(valid.as_ptr(), 11), 1);
        assert_eq!(mocktail_rust_contains_control_bytes(valid.as_ptr(), 11), 0);

        let with_ctrl = b"hello\x07world\0";
        assert_eq!(mocktail_rust_contains_control_bytes(with_ctrl.as_ptr(), 11), 1);
    }

    #[test]
    fn test_percent_decode() {
        let enc = CString::new("Hello%20World%21").unwrap();
        let mut out = [0 as c_char; 32];
        let rc = mocktail_rust_percent_decode(enc.as_ptr(), 0, out.as_mut_ptr(), out.len());
        assert_eq!(rc, 0);
        let s = unsafe { CStr::from_ptr(out.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "Hello World!");

        let enc_plus = CString::new("a+b").unwrap();
        let rc2 = mocktail_rust_percent_decode(enc_plus.as_ptr(), 1, out.as_mut_ptr(), out.len());
        assert_eq!(rc2, 0);
        let s2 = unsafe { CStr::from_ptr(out.as_ptr()) }.to_str().unwrap();
        assert_eq!(s2, "a b");
    }

    #[test]
    fn test_status_memory_parsing() {
        let sample = "Name:\tmocktail\nVmRSS:\t   12345 kB\nVmSwap:\t    100 kB\n";
        let c_sample = CString::new(sample).unwrap();
        let mut rss = 0u64;
        let mut swap = 0u64;
        let ok = mocktail_rust_parse_status_memory(c_sample.as_ptr(), &mut rss, &mut swap);
        assert_eq!(ok, 1);
        assert_eq!(rss, 12345 * 1024);
        assert_eq!(swap, 100 * 1024);
    }

    #[test]
    fn test_discord_frame_builder() {
        let payload = CString::new("{\"v\": 1}").unwrap();
        let mut buf = [0u8; 64];
        let mut len = 0usize;
        let rc = mocktail_rust_build_discord_frame(
            1,
            payload.as_ptr(),
            buf.as_mut_ptr(),
            buf.len(),
            &mut len,
        );
        assert_eq!(rc, 0);
        assert_eq!(len, 8 + 8);
        assert_eq!(buf[0..4], 1u32.to_le_bytes());
        assert_eq!(buf[4..8], 8u32.to_le_bytes());
        assert_eq!(&buf[8..16], b"{\"v\": 1}");
    }

    #[test]
    fn test_safe_archive_path() {
        let safe1 = CString::new("assets/data.bin").unwrap();
        assert_eq!(mocktail_rust_is_safe_archive_path(safe1.as_ptr()), 1);

        let safe2 = CString::new("dir/subdir/").unwrap();
        assert_eq!(mocktail_rust_is_safe_archive_path(safe2.as_ptr()), 1);

        let unsafe1 = CString::new("../etc/passwd").unwrap();
        assert_eq!(mocktail_rust_is_safe_archive_path(unsafe1.as_ptr()), 0);

        let unsafe2 = CString::new("/absolute/path").unwrap();
        assert_eq!(mocktail_rust_is_safe_archive_path(unsafe2.as_ptr()), 0);

        let unsafe3 = CString::new("dir/../escape").unwrap();
        assert_eq!(mocktail_rust_is_safe_archive_path(unsafe3.as_ptr()), 0);

        let unsafe4 = CString::new("dir//escape").unwrap();
        assert_eq!(mocktail_rust_is_safe_archive_path(unsafe4.as_ptr()), 0);

        let unsafe5 = CString::new("win\\path").unwrap();
        assert_eq!(mocktail_rust_is_safe_archive_path(unsafe5.as_ptr()), 0);
    }

    #[test]
    fn test_jni_signature() {
        let valid1 = CString::new("(Ljava/lang/String;I)V").unwrap();
        assert_eq!(mocktail_rust_is_valid_jni_signature(valid1.as_ptr()), 1);

        let valid2 = CString::new("()I").unwrap();
        assert_eq!(mocktail_rust_is_valid_jni_signature(valid2.as_ptr()), 1);

        let valid3 = CString::new("([B)[Ljava/lang/String;").unwrap();
        assert_eq!(mocktail_rust_is_valid_jni_signature(valid3.as_ptr()), 1);

        let invalid1 = CString::new("invalid").unwrap();
        assert_eq!(mocktail_rust_is_valid_jni_signature(invalid1.as_ptr()), 0);

        let invalid2 = CString::new("(Ljava/lang/String)V").unwrap();
        assert_eq!(mocktail_rust_is_valid_jni_signature(invalid2.as_ptr()), 0);

        let invalid3 = CString::new("([V)V").unwrap();
        assert_eq!(mocktail_rust_is_valid_jni_signature(invalid3.as_ptr()), 0);
    }

    #[test]
    fn test_file_sha256() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let file_path = dir.join("mocktail_test_file2.txt");
        {
            let mut f = File::create(&file_path).unwrap();
            f.write_all(b"mocktail-file-test2").unwrap();
        }
        let c_path = CString::new(file_path.to_str().unwrap()).unwrap();
        let mut out = [0 as c_char; 65];
        let rc = mocktail_rust_sha256_file(c_path.as_ptr(), out.as_mut_ptr(), out.len());
        assert_eq!(rc, 0);

        let s = unsafe { CStr::from_ptr(out.as_ptr()) }.to_str().unwrap();
        assert_eq!(s.len(), 64);

        let verify_rc = mocktail_rust_verify_file_sha256(c_path.as_ptr(), out.as_ptr());
        assert_eq!(verify_rc, 1);

        let _ = std::fs::remove_file(file_path);
    }

    #[test]
    fn test_apk_signing_magic() {
        assert_eq!(mocktail_rust_verify_apk_signing_magic(b"APK Sig Block 42".as_ptr(), 16), 1);
        assert_eq!(mocktail_rust_verify_apk_signing_magic(b"WrongMagicBlock!".as_ptr(), 16), 0);
    }

    #[test]
    fn test_mutf8() {
        // Test null byte encoding: \0 -> 0xC0 0x80
        let null_u16 = [0u16];
        let mut mutf8_buf = [0u8; 8];
        let mut len = 0usize;
        assert_eq!(mocktail_rust_utf16_to_mutf8(null_u16.as_ptr(), 1, mutf8_buf.as_mut_ptr(), 8, &mut len), 0);
        assert_eq!(len, 2);
        assert_eq!(&mutf8_buf[0..2], &[0xC0, 0x80]);

        // Test decode 0xC0 0x80 back to 0u16
        let mut u16_buf = [0u16; 8];
        let mut u16_len = 0usize;
        assert_eq!(mocktail_rust_mutf8_to_utf16(mutf8_buf.as_ptr(), 2, u16_buf.as_mut_ptr(), 8, &mut u16_len), 0);
        assert_eq!(u16_len, 1);
        assert_eq!(u16_buf[0], 0);

        // Test normal string "Hello"
        let hello = b"Hello\0";
        assert_eq!(mocktail_rust_mutf8_to_utf16(hello.as_ptr(), 5, u16_buf.as_mut_ptr(), 8, &mut u16_len), 0);
        assert_eq!(u16_len, 5);
        assert_eq!(&u16_buf[0..5], &[b'H' as u16, b'e' as u16, b'l' as u16, b'l' as u16, b'o' as u16]);

        let mut utf8_buf = [0u8; 16];
        let mut utf8_len = 0usize;
        assert_eq!(mocktail_rust_mutf8_to_utf8(hello.as_ptr(), 5, utf8_buf.as_mut_ptr(), 16, &mut utf8_len), 0);
        assert_eq!(utf8_len, 5);
        assert_eq!(&utf8_buf[0..5], b"Hello");
    }

    #[test]
    fn test_cookie_parser() {
        let cookie = CString::new(".ROBLOSECURITY=\"_|WARNING:-DO-NOT-SHARE-THIS.--Sharing-this-will-allow-someone-to-log-in-as-you-and-to-steal-your-ROBUX-and-items.|_ABC1234567890XYZ\"; path=/; domain=.roblox.com").unwrap();
        let mut out = [0 as c_char; 256];
        let mut out_len = 0usize;
        let rc = mocktail_rust_parse_roblox_cookie(cookie.as_ptr(), out.as_mut_ptr(), out.len(), &mut out_len);
        assert_eq!(rc, 0);
        let s = unsafe { CStr::from_ptr(out.as_ptr()) }.to_str().unwrap();
        assert!(s.starts_with("_|WARNING:"));
        assert!(s.ends_with("ABC1234567890XYZ"));

        assert_eq!(mocktail_rust_is_valid_cookie_octet(b'A'), 1);
        assert_eq!(mocktail_rust_is_valid_cookie_octet(b' '), 0);
    }

    #[test]
    fn test_permissions_bridge() {
        assert_eq!(mocktail_rust_validate_json_depth(b"{\"a\":{\"b\":1}}\0".as_ptr() as *const c_char, 8), 1);
        assert_eq!(mocktail_rust_validate_json_depth(b"{\"a\":{\"b\":{\"c\":{\"d\":1}}}}\0".as_ptr() as *const c_char, 2), 0);

        let json = CString::new("{\"permissions\":[\"LOCAL_NETWORK\",\"MICROPHONE_ACCESS\"]}").unwrap();
        let mut has_missing = 0;
        let mut missing_buf = [0 as c_char; 256];

        // Mic enabled -> none missing
        let rc = mocktail_rust_check_permission_request(json.as_ptr(), 1, &mut has_missing, missing_buf.as_mut_ptr(), 256);
        assert_eq!(rc, 0);
        assert_eq!(has_missing, 0);

        // Mic disabled -> MICROPHONE_ACCESS missing
        let rc2 = mocktail_rust_check_permission_request(json.as_ptr(), 0, &mut has_missing, missing_buf.as_mut_ptr(), 256);
        assert_eq!(rc2, 0);
        assert_eq!(has_missing, 1);
        let missing_str = unsafe { CStr::from_ptr(missing_buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(missing_str, "[\"MICROPHONE_ACCESS\"]");
    }

    #[test]
    fn test_elf_parser() {
        let mut elf_buf = vec![0u8; 256];
        elf_buf[0..4].copy_from_slice(b"\x7fELF");
        elf_buf[4] = 2; // 64-bit
        elf_buf[5] = 1; // Little-Endian
        elf_buf[18] = 0x3E; // x86_64
        elf_buf[19] = 0x00;

        assert_eq!(mocktail_rust_verify_elf_architecture(elf_buf.as_ptr(), elf_buf.len(), 0x3E), 1);
        assert_eq!(mocktail_rust_verify_elf_architecture(elf_buf.as_ptr(), elf_buf.len(), 0xB7), 0);

        // Program headers setup: e_phoff = 64, e_phentsize = 56, e_phnum = 1
        elf_buf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf_buf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf_buf[56..58].copy_from_slice(&1u16.to_le_bytes());

        // Phdr at 64: p_type = 4 (PT_NOTE), p_offset = 120, p_filesz = 32
        elf_buf[64..68].copy_from_slice(&4u32.to_le_bytes());
        elf_buf[72..80].copy_from_slice(&120u64.to_le_bytes());
        elf_buf[96..104].copy_from_slice(&32u64.to_le_bytes());

        // Note at 120: namesz = 4, descsz = 4, type = 3
        elf_buf[120..124].copy_from_slice(&4u32.to_le_bytes());
        elf_buf[124..128].copy_from_slice(&4u32.to_le_bytes());
        elf_buf[128..132].copy_from_slice(&3u32.to_le_bytes());
        // Name: "GNU\0"
        elf_buf[132..136].copy_from_slice(b"GNU\0");
        // Desc: 0x12, 0x34, 0x56, 0x78
        elf_buf[136..140].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);

        let mut out_hex = [0 as c_char; 64];
        let rc = mocktail_rust_parse_elf_build_id(elf_buf.as_ptr(), elf_buf.len(), out_hex.as_mut_ptr(), 64);
        assert_eq!(rc, 0);
        let s = unsafe { CStr::from_ptr(out_hex.as_ptr()) }.to_str().unwrap();
        assert_eq!(s, "12345678");
    }

    #[test]
    fn test_key_mapping() {
        let mut mapping = MocktailRustKeyMapping { scan_code: 0, key_code: 0 };
        assert_eq!(mocktail_rust_map_sdl_key_to_android(4, 0, &mut mapping), 1); // SDL_SCANCODE_A
        assert_eq!(mapping.scan_code, 30);
        assert_eq!(mapping.key_code, 29);

        assert_eq!(mocktail_rust_map_sdl_key_to_android(40, 0, &mut mapping), 1); // RETURN
        assert_eq!(mapping.scan_code, 28);
        assert_eq!(mapping.key_code, 66);

        assert_eq!(mocktail_rust_map_sdl_mouse_button(1), 0);
        assert_eq!(mocktail_rust_map_sdl_mouse_button(3), 1);
        assert_eq!(mocktail_rust_map_sdl_mouse_button(2), 2);
    }

    #[test]
    fn test_system_proxy_resolver() {
        let uri = CString::new("http://127.0.0.1:8080").unwrap();
        let mut scheme = [0 as c_char; 32];
        let mut host = [0 as c_char; 64];
        let mut port: u16 = 0;
        let mut is_direct: c_int = 0;
        let mut has_auth: c_int = 0;

        let rc = mocktail_rust_parse_proxy_uri(
            uri.as_ptr(),
            scheme.as_mut_ptr(),
            32,
            host.as_mut_ptr(),
            64,
            &mut port,
            &mut is_direct,
            &mut has_auth,
        );
        assert_eq!(rc, 0);
        assert_eq!(unsafe { CStr::from_ptr(scheme.as_ptr()) }.to_str().unwrap(), "http");
        assert_eq!(unsafe { CStr::from_ptr(host.as_ptr()) }.to_str().unwrap(), "127.0.0.1");
        assert_eq!(port, 8080);
        assert_eq!(is_direct, 0);
        assert_eq!(has_auth, 0);

        // Test direct://
        let direct_uri = CString::new("direct://").unwrap();
        let rc_dir = mocktail_rust_parse_proxy_uri(
            direct_uri.as_ptr(),
            scheme.as_mut_ptr(),
            32,
            host.as_mut_ptr(),
            64,
            &mut port,
            &mut is_direct,
            &mut has_auth,
        );
        assert_eq!(rc_dir, 0);
        assert_eq!(is_direct, 1);
        assert_eq!(port, 0);

        // Test auth
        let auth_uri = CString::new("socks5://user:pass@192.168.1.1").unwrap();
        let rc_auth = mocktail_rust_parse_proxy_uri(
            auth_uri.as_ptr(),
            scheme.as_mut_ptr(),
            32,
            host.as_mut_ptr(),
            64,
            &mut port,
            &mut is_direct,
            &mut has_auth,
        );
        assert_eq!(rc_auth, 0);
        assert_eq!(has_auth, 1);
        assert_eq!(port, 1080);
    }

    #[test]
    fn test_single_instance_lock() {
        let exe = CString::new("/usr/bin/mocktail").unwrap();
        let mut key = [0 as c_char; 32];
        let rc = mocktail_rust_compute_instance_key(exe.as_ptr(), key.as_mut_ptr(), 32);
        assert_eq!(rc, 0);
        let key_str = unsafe { CStr::from_ptr(key.as_ptr()) }.to_str().unwrap();
        assert_eq!(key_str.len(), 16);

        let valid_dec = CString::new("12345").unwrap();
        let zero_dec = CString::new("0").unwrap();
        let neg_dec = CString::new("-5").unwrap();
        let text_dec = CString::new("123a").unwrap();
        assert_eq!(mocktail_rust_is_positive_decimal(valid_dec.as_ptr()), 1);
        assert_eq!(mocktail_rust_is_positive_decimal(zero_dec.as_ptr()), 0);
        assert_eq!(mocktail_rust_is_positive_decimal(neg_dec.as_ptr()), 0);
        assert_eq!(mocktail_rust_is_positive_decimal(text_dec.as_ptr()), 0);
        assert_eq!(mocktail_rust_is_positive_decimal(std::ptr::null()), 0);
    }

    #[test]
    fn test_compatibility_catalog() {
        let json = r#"{
            "schema_version": 1,
            "profiles": [
                {
                    "abi": "x86_64",
                    "version_name": "2.600.123",
                    "version_code": 600123,
                    "elf_build_id": "0123456789abcdef0123456789abcdef01234567",
                    "status": "supported",
                    "default_allowed": true,
                    "allow_legacy_binary_patches": false
                },
                {
                    "abi": "arm64-v8a",
                    "version_name": "2.600.123",
                    "version_code": 600123,
                    "elf_build_id": "abcdef0123456789abcdef0123456789abcdef01",
                    "status": "supported",
                    "default_allowed": true,
                    "allow_legacy_binary_patches": false
                }
            ]
        }"#;

        let abi = CString::new("x86_64").unwrap();
        let mut profiles = [MocktailRustPayloadProfile {
            version_name: [0; 64],
            version_code: 0,
            elf_build_id: [0; 41],
        }; 4];
        let mut count: usize = 0;
        let mut err_buf = [0 as c_char; 128];

        let rc = mocktail_rust_parse_compatibility_catalog(
            json.as_ptr(),
            json.len(),
            abi.as_ptr(),
            profiles.as_mut_ptr(),
            4,
            &mut count,
            err_buf.as_mut_ptr(),
            128,
        );
        assert_eq!(rc, 0);
        assert_eq!(count, 1);
        let vn = unsafe { CStr::from_ptr(profiles[0].version_name.as_ptr()) }.to_str().unwrap();
        assert_eq!(vn, "2.600.123");
        assert_eq!(profiles[0].version_code, 600123);
        let bid = unsafe { CStr::from_ptr(profiles[0].elf_build_id.as_ptr()) }.to_str().unwrap();
        assert_eq!(bid, "0123456789abcdef0123456789abcdef01234567");
    }

    #[test]
    fn test_crash_report_policy() {
        let base = CString::new("{\"CustomFlag\":\"123\"}").unwrap();
        let mut out_buf = [0 as c_char; 8192];
        let mut out_len: usize = 0;

        let rc = mocktail_rust_merge_crash_report_settings(
            base.as_ptr(),
            0,
            out_buf.as_mut_ptr(),
            8192,
            &mut out_len,
        );
        assert_eq!(rc, 0);
        let merged_str = unsafe { CStr::from_ptr(out_buf.as_ptr()) }.to_str().unwrap();
        assert!(merged_str.contains("\"CustomFlag\":\"123\""));
        assert!(merged_str.contains("\"DFFlagUseCrashpad\":\"False\""));
        assert!(merged_str.contains("\"EnableAppHangMonitor\":\"False\""));
    }

    #[test]
    fn test_device_profile() {
        let mut name_buf = [0 as c_char; 64];
        let pc = CString::new("pc").unwrap();
        assert_eq!(mocktail_rust_canonical_device_profile_name(pc.as_ptr(), name_buf.as_mut_ptr(), 64), 0);
        assert_eq!(unsafe { CStr::from_ptr(name_buf.as_ptr()) }.to_str().unwrap(), "pc-windows-11");

        let val_valid = CString::new("Valid_Value-1").unwrap();
        let val_invalid = CString::new("Invalid\nValue").unwrap();
        assert_eq!(mocktail_rust_is_valid_device_profile_value(val_valid.as_ptr(), 32), 1);
        assert_eq!(mocktail_rust_is_valid_device_profile_value(val_invalid.as_ptr(), 32), 0);

        let mut key_buf = [0 as c_char; 128];
        let platform = CString::new("Android").unwrap();
        let rc_key = mocktail_rust_build_device_profile_cache_key(
            pc.as_ptr(),
            platform.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            key_buf.as_mut_ptr(),
            128,
        );
        assert_eq!(rc_key, 0);
        let key_str = unsafe { CStr::from_ptr(key_buf.as_ptr()) }.to_str().unwrap();
        assert!(key_str.starts_with("pc-custom-"));
    }

    #[test]
    fn test_bionic_dns_blocker() {
        let blocked1 = CString::new("crashes.rbxinfra.com").unwrap();
        let blocked2 = CString::new("sub.crashes.rbxinfra.com.").unwrap();
        let blocked3 = CString::new("backtrace.io").unwrap();
        let safe1 = CString::new("roblox.com").unwrap();
        let safe2 = CString::new("notcrashes.rbxinfra.com").unwrap();

        assert_eq!(mocktail_rust_is_blocked_crash_host(blocked1.as_ptr()), 1);
        assert_eq!(mocktail_rust_is_blocked_crash_host(blocked2.as_ptr()), 1);
        assert_eq!(mocktail_rust_is_blocked_crash_host(blocked3.as_ptr()), 1);
        assert_eq!(mocktail_rust_is_blocked_crash_host(safe1.as_ptr()), 0);
        assert_eq!(mocktail_rust_is_blocked_crash_host(safe2.as_ptr()), 0);

        // POSIX EAI codes to Bionic error codes
        assert_eq!(mocktail_rust_bionic_eai_error(0), 0);
        assert_eq!(mocktail_rust_bionic_eai_error(-2), 8); // EAI_NONAME -> kBionicAddressInfoNameNotFound (8)
        assert_eq!(mocktail_rust_bionic_eai_error(-4), 4); // EAI_FAIL -> kBionicAddressInfoFailure (4)
        assert_eq!(mocktail_rust_bionic_eai_error(-10), 6); // EAI_MEMORY -> kBionicAddressInfoMemory (6)
    }

    #[test]
    fn test_roblox_launch_uri() {
        let uri = CString::new("roblox://experiences/start?placeId=1818&launchData=hello%20world").unwrap();
        let mut out_json = [0 as c_char; 1024];
        let mut out_err = [0 as c_char; 256];
        let mut follow_id = 0i64;

        let rc = mocktail_rust_parse_roblox_launch_uri(
            uri.as_ptr(),
            0,
            std::ptr::null(),
            out_json.as_mut_ptr(),
            1024,
            out_err.as_mut_ptr(),
            256,
            &mut follow_id,
        );
        assert_eq!(rc, 0);
        let json_str = unsafe { CStr::from_ptr(out_json.as_ptr()) }.to_str().unwrap();
        assert!(json_str.contains("\"placeId\":1818"));
        assert!(json_str.contains("\"launchData\":\"hello world\""));

        // Test classic roblox-player:
        let classic = CString::new("roblox-player:1+launchmode:play+placelauncherurl:https%3A%2F%2Fwww.roblox.com%2Fgame%2Fplacelauncher.ashx%3Frequest%3DRequestGame%26placeId%3D12345").unwrap();
        let rc_classic = mocktail_rust_parse_roblox_launch_uri(
            classic.as_ptr(),
            0,
            std::ptr::null(),
            out_json.as_mut_ptr(),
            1024,
            out_err.as_mut_ptr(),
            256,
            &mut follow_id,
        );
        assert_eq!(rc_classic, 0);
        let classic_json = unsafe { CStr::from_ptr(out_json.as_ptr()) }.to_str().unwrap();
        assert!(classic_json.contains("\"placeId\":12345"));
    }

    #[test]
    fn test_runtime_config_yaml() {
        let yaml = r#"
version: 1
graphics:
  backend: direct-vulkan
  vsync: "on"
performance:
  memory_limit_mb: 2048
runtime:
  headless: false
integrations:
  discord_rpc:
    enabled: true
    show_place_name: true
    show_elapsed_time: true
    join:
      enabled: true
      public_servers_only: true
      button_label: "Join Game"
"#;
        let mut out_env = [0 as c_char; 4096];
        let mut out_err = [0 as c_char; 256];
        let rc = mocktail_rust_parse_runtime_config_yaml(
            yaml.as_ptr(),
            yaml.len(),
            out_env.as_mut_ptr(),
            4096,
            out_err.as_mut_ptr(),
            256,
        );
        assert_eq!(rc, 0);
        let env_str = unsafe { CStr::from_ptr(out_env.as_ptr()) }.to_str().unwrap();
        assert!(env_str.contains("\"MOCKTAIL_GRAPHICS_BACKEND\":\"direct-vulkan\""));
        assert!(env_str.contains("\"MOCKTAIL_VSYNC\":\"on\""));
        assert!(env_str.contains("\"MOCKTAIL_MEMORY_LIMIT_MB\":\"2048\""));
        assert!(env_str.contains("\"MOCKTAIL_HEADLESS\":\"0\""));
        assert!(env_str.contains("\"MOCKTAIL_DISCORD_RPC_ENABLED\":\"1\""));
        assert!(env_str.contains("\"MOCKTAIL_DISCORD_RPC_JOIN_ENABLED\":\"1\""));
        assert!(env_str.contains("\"MOCKTAIL_DISCORD_RPC_PUBLIC_SERVERS_ONLY\":\"1\""));
        assert!(env_str.contains("\"MOCKTAIL_DISCORD_RPC_JOIN_BUTTON_LABEL\":\"Join Game\""));
    }

    #[test]
    fn test_startup_state_machine() {
        let req = MocktailRustStartupRequirements {
            windowed: 1,
            require_input_ready: 1,
            require_audio_ready: 0,
        };
        let sm = mocktail_rust_startup_sm_create(req);
        assert!(!sm.is_null());

        let mut state = MocktailRustStartupState::Created;
        let mut status = 0;
        let mut msg = [0 as c_char; 128];

        // Step 1: Configured
        mocktail_rust_startup_sm_record_evidence(sm, 0, &mut state, &mut status, msg.as_mut_ptr(), 128);
        assert_eq!(state, MocktailRustStartupState::Configured);
        assert_eq!(status, 0);

        // Step 2: JniRuntimeReady
        mocktail_rust_startup_sm_record_evidence(sm, 1, &mut state, &mut status, msg.as_mut_ptr(), 128);
        assert_eq!(state, MocktailRustStartupState::JniRuntimeReady);

        // Step 3: Duplicate evidence
        mocktail_rust_startup_sm_record_evidence(sm, 1, &mut state, &mut status, msg.as_mut_ptr(), 128);
        assert_eq!(status, 1); // Duplicate

        // Step 4: Snapshot
        let mut snap = MocktailRustStartupSnapshot {
            state: MocktailRustStartupState::Created,
            requirements: req,
            configured: 0,
            jni_runtime_ready: 0,
            libraries_loaded: 0,
            jni_on_load_complete: 0,
            engine_started: 0,
            data_model_loading: 0,
            lua_app_ready: 0,
            real_frame_presented: 0,
            input_ready: 0,
            audio_ready: 0,
            revision: 0,
        };
        mocktail_rust_startup_sm_snapshot(sm, &mut snap, msg.as_mut_ptr(), 128);
        assert_eq!(snap.state, MocktailRustStartupState::JniRuntimeReady);
        assert_eq!(snap.configured, 1);
        assert_eq!(snap.jni_runtime_ready, 1);

        mocktail_rust_startup_sm_destroy(sm);
    }

    #[test]
    fn test_fleasion_prepare_bundle() {
        let ca_cert = "-----BEGIN CERTIFICATE-----\nMIIBcaCAQ...\n-----END CERTIFICATE-----\n";
        let base_bundle = "-----BEGIN CERTIFICATE-----\nMIIBase...\n-----END CERTIFICATE-----\n";

        let temp_dir = std::env::temp_dir();
        let ca_file = temp_dir.join("test_ca.pem");
        let base_file = temp_dir.join("test_base.pem");
        let dest_file = temp_dir.join("test_dest.pem");

        std::fs::write(&ca_file, ca_cert).unwrap();
        std::fs::write(&base_file, base_bundle).unwrap();

        let ca_cstr = CString::new(ca_file.to_str().unwrap()).unwrap();
        let base_cstr = CString::new(base_file.to_str().unwrap()).unwrap();
        let dest_cstr = CString::new(dest_file.to_str().unwrap()).unwrap();
        let mut err_buf = [0 as c_char; 256];

        let rc = mocktail_rust_fleasion_prepare_bundle(
            ca_cstr.as_ptr(),
            base_cstr.as_ptr(),
            dest_cstr.as_ptr(),
            err_buf.as_mut_ptr(),
            256,
        );
        assert_eq!(rc, 0);

        let merged = std::fs::read_to_string(&dest_file).unwrap();
        assert!(merged.contains("MIIBase..."));
        assert!(merged.contains("MIIBcaCAQ..."));

        let _ = std::fs::remove_file(ca_file);
        let _ = std::fs::remove_file(base_file);
        let _ = std::fs::remove_file(dest_file);
    }

    #[test]
    fn test_apk_signing_block_finder() {
        let mut file = vec![0u8; 1024];
        let file_len = file.len();
        // Place EOCD at file_len - 22
        let eocd_pos = file_len - 22;
        file[eocd_pos..eocd_pos + 4].copy_from_slice(&0x06054b50u32.to_le_bytes());
        // cd_offset = 512
        file[eocd_pos + 16..eocd_pos + 20].copy_from_slice(&512u32.to_le_bytes());

        // Sig block right before CD (512)
        // Magic at 512 - 16 = 496
        file[496..512].copy_from_slice(b"APK Sig Block 42");
        // footer_size = 56: (32 bytes pair + 8 bytes footer size + 16 bytes magic)
        file[488..496].copy_from_slice(&56u64.to_le_bytes());
        // total_size = 64, block_begin = 512 - 64 = 448
        // Header size at 448..456
        file[448..456].copy_from_slice(&56u64.to_le_bytes());

        // Place a v2 pair at 456: pair_size = 24, id = 0x7109871a
        file[456..464].copy_from_slice(&24u64.to_le_bytes());
        file[464..468].copy_from_slice(&0x7109871au32.to_le_bytes());

        let mut info = MocktailRustApkSigningBlockInfo::default();
        let mut err_buf = [0 as c_char; 256];
        let rc = mocktail_rust_find_apk_signing_block(
            file.as_ptr(),
            file.len(),
            &mut info,
            err_buf.as_mut_ptr(),
            256,
        );
        assert_eq!(rc, 0);
        assert_eq!(info.central_directory, 512);
        assert_eq!(info.v2_offset, 468);
        assert_eq!(info.v2_len, 20);
    }

    #[test]
    fn test_etc2_decoder() {
        let block = [
            0x24u8, 0x35, 0x46, 0x02, 0x00, 0x00, 0x00, 0x00,
        ];
        let mut dst = [0u8; 64]; // 4x4 RGBA8
        let rc = mocktail_rust_decode_etc_image_block_rows(
            MocktailRustEtcFormat::Etc2Rgb8,
            block.as_ptr(),
            block.len(),
            4,
            4,
            0,
            1,
            dst.as_mut_ptr(),
            dst.len(),
        );
        assert_eq!(rc, 1);
        // Alpha channel should be 255 for opaque RGB8
        assert_eq!(dst[3], 255);
        assert_eq!(dst[7], 255);
    }

    #[test]
    fn test_zip_archive() {
        let temp_dir = std::env::temp_dir().join(format!("mocktail_zip_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let zip_path = temp_dir.join("test.zip");

        // Create zip archive with zip writer
        {
            let file = std::fs::File::create(&zip_path).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);

            zip.start_file("assets/test.txt", options).unwrap();
            use std::io::Write;
            zip.write_all(b"Hello Zip World!").unwrap();

            zip.add_directory("assets/sub/", options).unwrap();
            zip.start_file("assets/sub/nested.txt", options).unwrap();
            zip.write_all(b"Nested content").unwrap();

            zip.finish().unwrap();
        }

        // 1. List entries
        let zip_cstr = CString::new(zip_path.to_str().unwrap()).unwrap();
        let mut list_json = [0 as c_char; 2048];
        let mut err_buf = [0 as c_char; 256];
        let rc_list = mocktail_rust_zip_list_entries(
            zip_cstr.as_ptr(),
            100,
            list_json.as_mut_ptr(),
            2048,
            err_buf.as_mut_ptr(),
            256,
        );
        assert_eq!(rc_list, 0);
        let list_str = unsafe { CStr::from_ptr(list_json.as_ptr()) }.to_str().unwrap();
        assert!(list_str.contains("assets/test.txt"));
        assert!(list_str.contains("assets/sub/nested.txt"));

        // 2. Read entry
        let entry_cstr = CString::new("assets/test.txt").unwrap();
        let mut read_buf = [0u8; 128];
        let mut read_len = 0;
        let rc_read = mocktail_rust_zip_read_entry(
            zip_cstr.as_ptr(),
            entry_cstr.as_ptr(),
            128,
            read_buf.as_mut_ptr(),
            128,
            &mut read_len,
            err_buf.as_mut_ptr(),
            256,
        );
        assert_eq!(rc_read, 0);
        assert_eq!(&read_buf[..read_len], b"Hello Zip World!");

        // 3. Extract entry
        let dest_single = temp_dir.join("extracted_single.txt");
        let dest_single_cstr = CString::new(dest_single.to_str().unwrap()).unwrap();
        let rc_extract = mocktail_rust_zip_extract_entry(
            zip_cstr.as_ptr(),
            entry_cstr.as_ptr(),
            dest_single_cstr.as_ptr(),
            1024,
            err_buf.as_mut_ptr(),
            256,
        );
        assert_eq!(rc_extract, 0);
        assert_eq!(std::fs::read(&dest_single).unwrap(), b"Hello Zip World!");

        // 4. Extract prefix
        let dest_prefix_dir = temp_dir.join("prefix_out");
        let dest_prefix_cstr = CString::new(dest_prefix_dir.to_str().unwrap()).unwrap();
        let prefix_cstr = CString::new("assets/").unwrap();
        let mut extracted_count = 0;
        let rc_prefix = mocktail_rust_zip_extract_prefix(
            zip_cstr.as_ptr(),
            prefix_cstr.as_ptr(),
            dest_prefix_cstr.as_ptr(),
            10240,
            &mut extracted_count,
            err_buf.as_mut_ptr(),
            256,
        );
        assert_eq!(rc_prefix, 0);
        assert!(extracted_count >= 2);
        assert_eq!(std::fs::read(dest_prefix_dir.join("test.txt")).unwrap(), b"Hello Zip World!");
        assert_eq!(std::fs::read(dest_prefix_dir.join("sub/nested.txt")).unwrap(), b"Nested content");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_fflags_merger() {
        let temp_dir = std::env::temp_dir().join(format!("mocktail_fflags_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&temp_dir);
        let fflags_file = temp_dir.join("ClientAppSettings.json");

        let file_json = r#"{"FFlagTarget": true, "DFFlagCount": 120, "SFlagName": "Custom"}"#;
        std::fs::write(&fflags_file, file_json).unwrap();

        let base_json = r#"{"FFlagTarget": "False", "BasePreserved": "1"}"#;
        let file_cstr = CString::new(fflags_file.to_str().unwrap()).unwrap();
        let base_cstr = CString::new(base_json).unwrap();

        let mut out_json = [0 as c_char; 2048];
        let mut out_count = 0;
        let mut out_loaded = 0;
        let mut err_buf = [0 as c_char; 256];

        let rc = mocktail_rust_fflags_load_and_merge(
            file_cstr.as_ptr(),
            base_cstr.as_ptr(),
            out_json.as_mut_ptr(),
            2048,
            &mut out_count,
            &mut out_loaded,
            err_buf.as_mut_ptr(),
            256,
        );
        assert_eq!(rc, 0);
        assert_eq!(out_loaded, 1);
        assert_eq!(out_count, 2); // DFFlagCount and SFlagName added; FFlagTarget kept base value "False"

        let merged_str = unsafe { CStr::from_ptr(out_json.as_ptr()) }.to_str().unwrap();
        assert!(merged_str.contains("\"FFlagTarget\":\"False\""));
        assert!(merged_str.contains("\"BasePreserved\":\"1\""));
        assert!(merged_str.contains("\"DFFlagCount\":\"120\""));
        assert!(merged_str.contains("\"SFlagName\":\"Custom\""));

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_browser_tracker() {
        let mut id_buf = [0 as c_char; 32];
        let rc_gen = mocktail_rust_browser_tracker_generate_id(id_buf.as_mut_ptr(), 32);
        assert_eq!(rc_gen, 0);
        let id_str = unsafe { CStr::from_ptr(id_buf.as_ptr()) }.to_str().unwrap();
        assert!(!id_str.is_empty());
        assert!(!id_str.starts_with('0'));
        assert!(id_str.parse::<u64>().is_ok());

        let cookie = CString::new("path=/&browserid=1234567890123&domain=roblox.com").unwrap();
        let mut extract_buf = [0 as c_char; 32];
        let rc_ext = mocktail_rust_browser_tracker_extract_id(cookie.as_ptr(), extract_buf.as_mut_ptr(), 32);
        assert_eq!(rc_ext, 0);
        let ext_str = unsafe { CStr::from_ptr(extract_buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(ext_str, "1234567890123");
    }

    #[test]
    fn test_support_bundle() {
        let valid_tok = CString::new("roblox_crash_dump.1").unwrap();
        assert_eq!(mocktail_rust_is_diagnostic_token(valid_tok.as_ptr()), 1);

        let invalid_tok = CString::new("/bin/sh").unwrap();
        assert_eq!(mocktail_rust_is_diagnostic_token(invalid_tok.as_ptr()), 0);

        let raw_log = b"Starting engine...\n[FATAL] Segmentation fault in libroblox\nSecret: .ROBLOSECURITY=_|WARNING\n[compat] Loading libc.so\nhttps://evil.com/leak\n";
        let mut out_sanitized = [0 as c_char; 1024];
        let mut out_len = 0;
        let rc = mocktail_rust_sanitize_log(
            raw_log.as_ptr(),
            raw_log.len(),
            out_sanitized.as_mut_ptr(),
            1024,
            &mut out_len,
        );
        assert_eq!(rc, 0);
        let sanitized = unsafe { CStr::from_ptr(out_sanitized.as_ptr()) }.to_str().unwrap();
        assert!(sanitized.contains("[FATAL] Segmentation fault"));
        assert!(sanitized.contains("[compat] Loading libc.so"));
        assert!(!sanitized.contains(".ROBLOSECURITY"));
        assert!(!sanitized.contains("https://evil.com"));
    }

    #[test]
    fn test_client_settings_and_atomic_write() {
        let mut def_buf = [0 as c_char; 2048];
        let rc = mocktail_rust_client_settings_safe_defaults(def_buf.as_mut_ptr(), def_buf.len());
        assert_eq!(rc, 0);
        let s = unsafe { CStr::from_ptr(def_buf.as_ptr()) }.to_str().unwrap();
        assert!(s.contains("applicationSettings"));

        let app = CString::new("TestApp").unwrap();
        let mut url_buf = [0 as c_char; 256];
        let rc_url = mocktail_rust_client_settings_default_url(app.as_ptr(), url_buf.as_mut_ptr(), url_buf.len());
        assert_eq!(rc_url, 0);
        let url_s = unsafe { CStr::from_ptr(url_buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(url_s, "https://clientsettingscdn.roblox.com/v2/settings/application/TestApp");

        let valid_json = CString::new("{\"key\":\"value\"}").unwrap();
        assert_eq!(mocktail_rust_client_settings_is_valid_json(valid_json.as_ptr()), 1);

        let invalid_json = CString::new("not_json").unwrap();
        assert_eq!(mocktail_rust_client_settings_is_valid_json(invalid_json.as_ptr()), 0);

        let tmp_dir = std::env::temp_dir().join(format!("mocktail_test_{}", std::process::id()));
        let tmp_file = tmp_dir.join("test_write.txt");
        let p_c = CString::new(tmp_file.to_str().unwrap()).unwrap();
        let content = b"hello mocktail rust atomic write";
        let mut err_buf = [0 as c_char; 256];
        let rc_write = mocktail_rust_atomic_write_file(
            p_c.as_ptr(),
            content.as_ptr() as *const c_char,
            content.len(),
            err_buf.as_mut_ptr(),
            err_buf.len(),
        );
        assert_eq!(rc_write, 0);
        assert_eq!(std::fs::read(&tmp_file).unwrap(), content);
        let _ = std::fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_window_state_and_video_driver() {
        let mut fs_creation = 0;
        let mut max_constr = 0;
        mocktail_rust_window_plan_presentation(1, 0, &mut fs_creation, &mut max_constr);
        assert_eq!(fs_creation, 1);
        assert_eq!(max_constr, 0);

        mocktail_rust_window_plan_presentation(0, 1, &mut fs_creation, &mut max_constr);
        assert_eq!(fs_creation, 0);
        assert_eq!(max_constr, 1);

        // Video driver resolve
        let choice = mocktail_rust_video_driver_resolve(0, 1, 0, 0, 0, 0, 0, 0);
        assert_eq!(choice, 1); // Wayland

        let choice_nv = mocktail_rust_video_driver_resolve(0, 0, 0, 1, 1, 1, 1, 0);
        assert_eq!(choice_nv, 3); // NvidiaDirectVulkanX11

        let req = CString::new("wayland,x11").unwrap();
        let cand = CString::new("x11,kmsdrm").unwrap();
        assert_eq!(mocktail_rust_video_driver_has_candidate(req.as_ptr(), cand.as_ptr()), 1);

        // Window state storage & load
        let tmp_dir = std::env::temp_dir().join(format!("mocktail_ws_test_{}", std::process::id()));
        let ws_file = tmp_dir.join("window_state.json");
        let p_c = CString::new(ws_file.to_str().unwrap()).unwrap();
        let state = MocktailRustWindowState {
            x: 100,
            y: 200,
            width: 1280,
            height: 720,
            has_position: 1,
            fullscreen: 0,
            maximized: 1,
            configured_width: 1920,
            configured_height: 1080,
            has_configured_size: 1,
        };
        let mut err_buf = [0 as c_char; 256];
        let rc_store = mocktail_rust_window_state_store(p_c.as_ptr(), &state, err_buf.as_mut_ptr(), err_buf.len());
        assert_eq!(rc_store, 0);

        let mut loaded = MocktailRustWindowState::default();
        let mut found = 0;
        let rc_load = mocktail_rust_window_state_load(p_c.as_ptr(), &mut loaded, &mut found, err_buf.as_mut_ptr(), err_buf.len());
        assert_eq!(rc_load, 0);
        assert_eq!(found, 1);
        assert_eq!(loaded.width, 1280);
        assert_eq!(loaded.height, 720);
        assert_eq!(loaded.x, 100);
        assert_eq!(loaded.y, 200);
        assert_eq!(loaded.maximized, 1);
        assert_eq!(loaded.configured_width, 1920);

        let _ = std::fs::remove_dir_all(tmp_dir);
    }

    #[test]
    fn test_runtime_paths_rust() {
        let valid_bid = CString::new("1686400865ae0e408cd7bd67de7a439625c6fd13").unwrap();
        assert_eq!(mocktail_rust_runtime_paths_is_lower_hex_build_id(valid_bid.as_ptr()), 1);

        let invalid_bid = CString::new("1686400865ae0e408cd7bd67de7a439625c6fd1G").unwrap();
        assert_eq!(mocktail_rust_runtime_paths_is_lower_hex_build_id(invalid_bid.as_ptr()), 0);

        let short_bid = CString::new("16864008").unwrap();
        assert_eq!(mocktail_rust_runtime_paths_is_lower_hex_build_id(short_bid.as_ptr()), 0);
    }

    #[test]
    fn test_audio_pcm_and_gain() {
        assert_eq!(mocktail_rust_audio_bytes_per_sample(MocktailRustPcmFormat::Unsigned8), 1);
        assert_eq!(mocktail_rust_audio_bytes_per_sample(MocktailRustPcmFormat::Signed16LittleEndian), 2);
        assert_eq!(mocktail_rust_audio_bytes_per_sample(MocktailRustPcmFormat::Float32LittleEndian), 4);

        let mut bpf = 0;
        let mut err_buf = [0 as c_char; 128];
        let rc = mocktail_rust_audio_validate_pcm(48000, 2, MocktailRustPcmFormat::Signed16LittleEndian, &mut bpf, err_buf.as_mut_ptr(), err_buf.len());
        assert_eq!(rc, 0);
        assert_eq!(bpf, 4);

        let rc_bad = mocktail_rust_audio_validate_pcm(1000, 2, MocktailRustPcmFormat::Signed16LittleEndian, &mut bpf, err_buf.as_mut_ptr(), err_buf.len());
        assert_eq!(rc_bad, -1);

        let mut samples = [0.5f32, -0.5f32, 1.0f32];
        mocktail_rust_audio_apply_gain_f32(samples.as_mut_ptr(), samples.len(), 2.0);
        assert_eq!(samples[0], 1.0);
        assert_eq!(samples[1], -1.0);
        assert_eq!(samples[2], 1.0);

        let f32_samples = [0.0f32, 1.0f32, -1.0f32];
        let mut i16_samples = [0i16; 3];
        mocktail_rust_audio_convert_f32_to_i16(f32_samples.as_ptr(), i16_samples.as_mut_ptr(), 3);
        assert_eq!(i16_samples[0], 0);
        assert_eq!(i16_samples[1], 32767);
        assert_eq!(i16_samples[2], -32767);
    }

    #[test]
    fn test_present_mode_and_swapchain() {
        let _guard = test_env_lock();
        std::env::remove_var("MOCKTAIL_SWAPCHAIN_IMAGES");
        let vsync_auto = CString::new("auto").unwrap();
        let fps_neg1 = CString::new("-1").unwrap();
        let fps_display = CString::new("display").unwrap();
        let fps_unlimited = CString::new("unlimited").unwrap();
        let pm_fifo = CString::new("fifo").unwrap();
        let pm_mailbox = CString::new("mailbox").unwrap();
        let pm_immediate = CString::new("immediate").unwrap();
        let pm_auto = CString::new("auto").unwrap();

        assert_eq!(mocktail_rust_present_mode_resolve(vsync_auto.as_ptr(), fps_neg1.as_ptr(), pm_auto.as_ptr()), 0); // HostDefault
        assert_eq!(mocktail_rust_present_mode_resolve(vsync_auto.as_ptr(), fps_display.as_ptr(), pm_auto.as_ptr()), 1); // Vsync
        assert_eq!(mocktail_rust_present_mode_resolve(vsync_auto.as_ptr(), fps_unlimited.as_ptr(), pm_auto.as_ptr()), 2); // Unthrottled
        assert_eq!(mocktail_rust_present_mode_resolve(vsync_auto.as_ptr(), fps_display.as_ptr(), pm_fifo.as_ptr()), 3); // Fifo
        assert_eq!(mocktail_rust_present_mode_resolve(vsync_auto.as_ptr(), fps_display.as_ptr(), pm_mailbox.as_ptr()), 4); // Mailbox
        assert_eq!(mocktail_rust_present_mode_resolve(vsync_auto.as_ptr(), fps_display.as_ptr(), pm_immediate.as_ptr()), 5); // Immediate

        // Wayland HostDefault promotes to Mailbox (ede9080)
        assert_eq!(mocktail_rust_present_mode_resolve_vulkan_surface(0, 1), 4);
        assert_eq!(mocktail_rust_present_mode_resolve_vulkan_surface(0, 0), 0);
        assert_eq!(mocktail_rust_present_mode_resolve_vulkan_surface(3, 1), 3);

        let mut explicit = 0u32;
        assert_eq!(mocktail_rust_present_mode_explicit(3, &mut explicit), 1);
        assert_eq!(explicit, VK_PRESENT_MODE_FIFO_KHR);
        assert_eq!(mocktail_rust_present_mode_explicit(0, &mut explicit), 0);

        assert_eq!(mocktail_rust_present_mode_swap_interval(0, 2), 2);
        assert_eq!(mocktail_rust_present_mode_swap_interval(2, 1), 0);
        assert_eq!(mocktail_rust_present_mode_swap_interval(1, 0), 1);
        assert_eq!(mocktail_rust_present_mode_swap_interval(5, 1), 0);

        assert_eq!(mocktail_rust_present_mode_prefer_min_image_count(4 /* Mailbox */, 2, 2, 8), 3);
        // Mailbox preserves min_images + 1 headroom when min_images >= 3 (94715e3)
        assert_eq!(mocktail_rust_present_mode_prefer_min_image_count(4 /* Mailbox */, 3, 3, 8), 4);
        assert_eq!(mocktail_rust_present_mode_prefer_min_image_count(3 /* Fifo */, 2, 2, 8), 2);
        assert_eq!(mocktail_rust_present_mode_prefer_min_image_count(1 /* Vsync */, 2, 2, 8), 4);
        assert_eq!(mocktail_rust_present_mode_prefer_min_image_count(2 /* Unthrottled */, 2, 2, 8), 5);

        let host_modes = [VK_PRESENT_MODE_IMMEDIATE_KHR, VK_PRESENT_MODE_FIFO_KHR];
        let mut out_modes = [0u32; 8];
        let mut out_count = 0usize;
        let rc = mocktail_rust_present_mode_filter(1 /* Vsync */, host_modes.as_ptr(), host_modes.len(), out_modes.as_mut_ptr(), out_modes.len(), &mut out_count);
        assert_eq!(rc, 0);
        assert_eq!(out_count, 1);
        assert_eq!(out_modes[0], VK_PRESENT_MODE_FIFO_KHR);

        let khr = unsafe { CStr::from_ptr(mocktail_rust_present_mode_khr_name_ptr(VK_PRESENT_MODE_MAILBOX_KHR)) }.to_str().unwrap();
        let pol = unsafe { CStr::from_ptr(mocktail_rust_present_mode_policy_name_ptr(4)) }.to_str().unwrap();
        assert_eq!(khr, "mailbox");
        assert_eq!(pol, "mailbox");
    }

    #[test]
    fn test_frame_rate_policy() {
        let mut mode = 0;
        let mut fps = 0;

        let empty = CString::new("").unwrap();
        mocktail_rust_frame_rate_parse(empty.as_ptr(), &mut mode, &mut fps);
        assert_eq!(mode, 0); // Unmanaged

        let display = CString::new("display").unwrap();
        mocktail_rust_frame_rate_parse(display.as_ptr(), &mut mode, &mut fps);
        assert_eq!(mode, 1); // Display

        let fps144 = CString::new("144").unwrap();
        mocktail_rust_frame_rate_parse(fps144.as_ptr(), &mut mode, &mut fps);
        assert_eq!(mode, 2); // Fixed
        assert_eq!(fps, 144);

        let unlimited = CString::new("unlimited").unwrap();
        mocktail_rust_frame_rate_parse(unlimited.as_ptr(), &mut mode, &mut fps);
        assert_eq!(mode, 3); // Unlimited

        let invalid = CString::new("bad_fps").unwrap();
        mocktail_rust_frame_rate_parse(invalid.as_ptr(), &mut mode, &mut fps);
        assert_eq!(mode, 4); // Invalid

        // Merge settings
        let base_json = CString::new("{}").unwrap();
        let mut out_buf = [0 as c_char; 1024];
        let mut out_err = [0 as c_char; 256];
        let rc = mocktail_rust_frame_rate_merge_client_settings(
            2, 144, base_json.as_ptr(), out_buf.as_mut_ptr(), out_buf.len(), out_err.as_mut_ptr(), out_err.len()
        );
        assert_eq!(rc, 0);
        let out_str = unsafe { CStr::from_ptr(out_buf.as_ptr()).to_str().unwrap() };
        assert!(out_str.contains("\"DFIntTaskSchedulerTargetFps\":\"144\""));
        assert!(out_str.contains("\"FFlagGameBasicSettingsFramerateCap5\":\"True\""));
    }

    #[test]
    fn test_gamepad_and_input() {
        assert_eq!(mocktail_rust_gamepad_valid_id(1), 1);
        assert_eq!(mocktail_rust_gamepad_valid_id(0), 0);
        assert_eq!(mocktail_rust_gamepad_valid_id(-1), 0);

        assert_eq!(mocktail_rust_gamepad_family(1), 1); // Xbox
        assert_eq!(mocktail_rust_gamepad_family(4), 2); // PS4
        assert_eq!(mocktail_rust_gamepad_family(5), 3); // PS5

        assert_eq!(mocktail_rust_gamepad_button_to_android(0), 96);
        assert_eq!(mocktail_rust_gamepad_button_to_android(1), 97);
        assert_eq!(mocktail_rust_gamepad_button_to_android(255), -1);

        assert_eq!(mocktail_rust_roblox_gamepad_type(1), 3); // Xbox
        assert_eq!(mocktail_rust_roblox_gamepad_type(2), 1); // PS4
        assert_eq!(mocktail_rust_roblox_gamepad_type(3), 2); // PS5

        assert_eq!(mocktail_rust_gamepad_signed_axis(0), 0.0);
        assert_eq!(mocktail_rust_gamepad_signed_axis(32767), 1.0);
        assert_eq!(mocktail_rust_gamepad_signed_axis(-32768), -1.0);

        let mut ox = 0.0f32;
        let mut oy = 0.0f32;
        mocktail_rust_gamepad_stick(0, 0, &mut ox, &mut oy);
        assert_eq!(ox, 0.0);
        assert_eq!(oy, 0.0);

        assert_eq!(mocktail_rust_gamepad_trigger(0), 0.0);
        assert_eq!(mocktail_rust_gamepad_trigger(32767), 1.0);

        assert_eq!(mocktail_rust_sdl_finger_action(0x700), 0);
        assert_eq!(mocktail_rust_sdl_finger_action(0x701), 1);
        assert_eq!(mocktail_rust_sdl_finger_action(0x702), 2);
        assert_eq!(mocktail_rust_sdl_finger_action(0x703), 3);
        assert_eq!(mocktail_rust_sdl_finger_action(0x999), -1);
    }

    #[test]
    fn test_device_memory_and_class() {
        let mut profile = MocktailRustDeviceMemoryProfile {
            total_memory_mb: 0,
            memory_class_mb: 0,
            large_memory_class_mb: 0,
            low_memory_killer_background_threshold: 0,
            low_memory_killer_foreground_threshold: 0,
            low_ram_device: 0,
        };
        mocktail_rust_build_device_memory_profile(2 * 1024 * 1024 * 1024, &mut profile);
        assert_eq!(profile.low_ram_device, 1);
        assert_eq!(profile.total_memory_mb, 2048);

        mocktail_rust_build_device_memory_profile(8 * 1024 * 1024 * 1024, &mut profile);
        assert_eq!(profile.low_ram_device, 0);
        assert_eq!(profile.total_memory_mb, 8192);

        let mut class_buf = [0 as c_char; 32];
        mocktail_rust_device_class_name(0, class_buf.as_mut_ptr(), class_buf.len());
        assert_eq!(unsafe { CStr::from_ptr(class_buf.as_ptr()).to_str().unwrap() }, "pc");
    }

    #[test]
    fn test_payload_integrity_and_session_log_helpers() {
        let text = CString::new("hello world").unwrap();
        let mut hex_buf = [0 as c_char; 65];
        let mut err_buf = [0 as c_char; 128];
        let rc = mocktail_rust_hash_text(text.as_ptr(), 11, 0, hex_buf.as_mut_ptr(), hex_buf.len(), err_buf.as_mut_ptr(), err_buf.len());
        assert_eq!(rc, 0);
        let hex_str = unsafe { CStr::from_ptr(hex_buf.as_ptr()).to_str().unwrap() };
        assert_eq!(hex_str, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");

        let hex_valid = CString::new("0123456789abcdef").unwrap();
        assert_eq!(mocktail_rust_is_lower_hex(hex_valid.as_ptr(), 16), 1);
        let hex_invalid = CString::new("0123456789ABCDEF").unwrap();
        assert_eq!(mocktail_rust_is_lower_hex(hex_invalid.as_ptr(), 16), 0);

        let mut vendor_buf = [0 as c_char; 64];
        let vid_nvidia = CString::new("10de").unwrap();
        mocktail_rust_pci_vendor_fallback(vid_nvidia.as_ptr(), vendor_buf.as_mut_ptr(), vendor_buf.len());
        assert_eq!(unsafe { CStr::from_ptr(vendor_buf.as_ptr()).to_str().unwrap() }, "NVIDIA");

        let mut hex_id_buf = [0 as c_char; 16];
        let hid = CString::new("0x10DE").unwrap();
        mocktail_rust_hex_id(hid.as_ptr(), hex_id_buf.as_mut_ptr(), hex_id_buf.len());
        assert_eq!(unsafe { CStr::from_ptr(hex_id_buf.as_ptr()).to_str().unwrap() }, "10de");

        let meminfo = CString::new("MemTotal:        8163532 kB\nMemFree:         123456 kB\n").unwrap();
        let mut total_buf = [0 as c_char; 32];
        mocktail_rust_parse_meminfo_total(meminfo.as_ptr(), total_buf.as_mut_ptr(), total_buf.len());
        assert_eq!(unsafe { CStr::from_ptr(total_buf.as_ptr()).to_str().unwrap() }, "7972MiB");

        let cpuinfo = CString::new("processor: 0\nmodel name: Intel Core i7-4500U CPU @ 1.80GHz\n").unwrap();
        let mut model_buf = [0 as c_char; 128];
        mocktail_rust_parse_cpuinfo_model(cpuinfo.as_ptr(), model_buf.as_mut_ptr(), model_buf.len());
        assert_eq!(unsafe { CStr::from_ptr(model_buf.as_ptr()).to_str().unwrap() }, "Intel Core i7-4500U CPU @ 1.80GHz");
    }

    #[test]
    fn test_window_readiness_gates() {
        let mut flags: u32 = 0;
        let mut pending: i32 = 0;
        let r = mocktail_rust_window_fullscreen_request_from_android_flags(0x400, 0x400, &mut flags, &mut pending);
        assert_eq!(r, 1);
        assert_eq!(pending, 2);
        let mut fs: c_int = 0;
        assert_eq!(mocktail_rust_window_fullscreen_take(&mut pending, &mut fs), 1);
        assert_eq!(fs, 1);
        assert_eq!(pending, 0);

        let msg = CString::new("Maximum event re-entrancy depth exceeded for BindableEvent.Event in CoreGui.RobloxGui.Modules.Settings.Pages.GameSettings").unwrap();
        assert_eq!(mocktail_rust_roblox_fullscreen_menu_is_cycle(msg.as_ptr()), 1);

        let mut state: u32 = 0;
        let mut surf_gen: u64 = 0;
        let mut tw: u32 = 0;
        let mut th: u32 = 0;
        let mut err = [0 as c_char; 128];
        let rc = mocktail_rust_window_resize_activate(1, 1920, 1080, 1, 10, 100, 800, 600, &mut state, &mut surf_gen, &mut tw, &mut th, err.as_mut_ptr(), err.len());
        assert_eq!(rc, 0);
        assert_eq!(state, 1);
        assert_eq!(surf_gen, 10);
        assert_eq!(tw, 1920);
        assert_eq!(th, 1080);
    }

    #[test]
    fn test_text_editor_layout_and_graphemes() {
        let family = "👨‍👩‍👧‍👦é";
        let family_c = CString::new(family).unwrap();
        let mut units: i32 = 0;
        let mut bounds = [0usize; 8];
        let mut count: usize = 0;
        let valid = mocktail_rust_text_layout(family_c.as_ptr(), family.len(), &mut units, bounds.as_mut_ptr(), bounds.len(), &mut count);
        assert_eq!(valid, 1);
        assert_eq!(count, 3);
        assert_eq!(&bounds[..count], &[0, 25, 28]);
        assert_eq!(units, 13); // 7 units for family (surrogates: 👨=2, ‍=1, 👩=2, ‍=1, 👧=2, ‍=1, 👦=2 -> 11) wait chars utf16 length

        assert_eq!(mocktail_rust_text_shortcut_bit(4), 1);
        assert_eq!(mocktail_rust_text_shortcut_bit(6), 2);
        assert_eq!(mocktail_rust_text_shortcut_bit(25), 4);
        assert_eq!(mocktail_rust_text_shortcut_bit(27), 8);
        assert_eq!(mocktail_rust_text_is_password_input(5), 1);
        assert_eq!(mocktail_rust_text_is_password_input(1), 0);

        assert_eq!(mocktail_rust_text_prev_grapheme(family_c.as_ptr(), family.len(), 28), 25);
        assert_eq!(mocktail_rust_text_prev_grapheme(family_c.as_ptr(), family.len(), 25), 0);
        assert_eq!(mocktail_rust_text_next_grapheme(family_c.as_ptr(), family.len(), 0), 25);
        assert_eq!(mocktail_rust_text_next_grapheme(family_c.as_ptr(), family.len(), 25), 28);
    }

    #[test]
    fn test_external_launch_wire_protocol() {
        let json = "{\"placeId\":123}";
        let json_c = CString::new(json).unwrap();
        let mut pkt = [0 as c_char; 256];
        let len = mocktail_rust_external_launch_build_packet(json_c.as_ptr(), json.len(), pkt.as_mut_ptr(), pkt.len());
        assert!(len > 0);

        let mut off: usize = 0;
        let mut jlen: usize = 0;
        let ok = mocktail_rust_external_launch_verify_and_strip_prefix(pkt.as_ptr(), len as usize, &mut off, &mut jlen);
        assert_eq!(ok, 0);
        assert_eq!(off, 27);
        assert_eq!(jlen, json.len());

        let mut reply = [0u8; 8];
        assert_eq!(mocktail_rust_external_launch_build_reply(0, reply.as_mut_ptr(), reply.len()), 5);
        let mut code: u8 = 99;
        assert_eq!(mocktail_rust_external_launch_parse_reply(reply.as_ptr(), 5, &mut code), 0);
        assert_eq!(code, 0);
        assert_eq!(mocktail_rust_external_launch_reply_status_code(code), 0);
    }

    #[test]
    fn test_apk_bundle_and_payload_store() {
        let abi = CString::new("arm64-v8a").unwrap();
        let mut entry = [0 as c_char; 64];
        mocktail_rust_apk_guest_lib_entry_name(abi.as_ptr(), entry.as_mut_ptr(), entry.len());
        assert_eq!(unsafe { CStr::from_ptr(entry.as_ptr()).to_str().unwrap() }, "lib/arm64-v8a/libroblox.so");

        let pid_valid = CString::new("650-0123456789abcdef0123456789abcdef01234567").unwrap();
        assert_eq!(mocktail_rust_payload_store_valid_id(pid_valid.as_ptr(), 44), 1);
        let pid_invalid = CString::new("650_invalid").unwrap();
        assert_eq!(mocktail_rust_payload_store_valid_id(pid_invalid.as_ptr(), 11), 0);
    }

    #[test]
    fn test_audio_queue_and_output_device_bridge() {
        assert_eq!(mocktail_rust_opensl_result_from_status_code(0), 0);
        assert_eq!(mocktail_rust_opensl_result_from_status_code(1), 2);
        assert_eq!(mocktail_rust_opensl_result_from_status_code(2), 3);
        assert_eq!(mocktail_rust_opensl_result_from_status_code(3), 4);
        assert_eq!(mocktail_rust_opensl_result_from_status_code(4), 12);
        assert_eq!(mocktail_rust_opensl_result_from_status_code(5), 6);

        let dev_name = CString::new("Built-in Audio").unwrap();
        let mut guid_buf = [0 as c_char; 64];
        assert_eq!(mocktail_rust_audio_device_stable_guid(dev_name.as_ptr(), guid_buf.as_mut_ptr(), guid_buf.len()), 0);
        let guid = unsafe { CStr::from_ptr(guid_buf.as_ptr()).to_str().unwrap() };
        assert!(guid.starts_with("{") && guid.ends_with("}") && guid.len() == 38);
    }

    #[test]
    fn test_discord_rpc_helpers() {
        unsafe {
            assert!(mocktail_rust_discord_has_join_target(12345, std::ptr::null(), 0));
            assert!(!mocktail_rust_discord_has_join_target(0, std::ptr::null(), 0));
            assert!(!mocktail_rust_discord_has_join_target(-5, std::ptr::null(), 0));

            let valid_instance = CString::new("job-123-abc").unwrap();
            assert!(mocktail_rust_discord_has_join_target(12345, valid_instance.as_ptr(), 11));
            let invalid_ctrl = b"job\x01test";
            assert!(!mocktail_rust_discord_has_join_target(12345, invalid_ctrl.as_ptr() as *const c_char, 8));

            let sample = "Hello World UTF8 öçşğü";
            let c_sample = CString::new(sample).unwrap();
            let trunc = mocktail_rust_discord_truncate_utf8(c_sample.as_ptr(), sample.len(), 10);
            assert!(trunc <= 10);

            let tmpl = "Playing: {place_name}!";
            let c_tmpl = CString::new(tmpl).unwrap();
            let place = "Bloxburg";
            let c_place = CString::new(place).unwrap();
            let mut out = [0u8; 128];
            let mut out_len = 0usize;
            assert_eq!(mocktail_rust_discord_render_place_template(
                c_tmpl.as_ptr(), tmpl.len(),
                c_place.as_ptr(), place.len(),
                out.as_mut_ptr(), out.len(), &mut out_len
            ), 0);
            let rendered = std::str::from_utf8(&out[..out_len]).unwrap();
            assert_eq!(rendered, "Playing: Bloxburg!");

            let mut url_buf = [0u8; 512];
            let mut url_len = 0usize;
            assert_eq!(mocktail_rust_discord_build_join_url(
                9876, valid_instance.as_ptr(), 11,
                url_buf.as_mut_ptr(), url_buf.len(), &mut url_len
            ), 0);
            let join_url = std::str::from_utf8(&url_buf[..url_len]).unwrap();
            assert_eq!(join_url, "https://komaruworld.github.io/mocktail/join.html#placeId=9876&gameInstanceId=job-123-abc");
        }
    }

    #[test]
    fn test_browser_and_webview_helpers() {
        unsafe {
            let ctrl = b"abc\x07def";
            assert!(mocktail_rust_browser_has_control_byte(ctrl.as_ptr(), ctrl.len()));
            let normal = b"abc def 123";
            assert!(!mocktail_rust_browser_has_control_byte(normal.as_ptr(), normal.len()));

            let embedded_nul = b"abc\0def";
            assert!(mocktail_rust_browser_has_embedded_nul(embedded_nul.as_ptr(), embedded_nul.len()));
            assert!(!mocktail_rust_browser_has_embedded_nul(normal.as_ptr(), normal.len()));

            let challenge1 = CString::new("https://www.roblox.com/login/challenge").unwrap();
            assert!(mocktail_rust_webview_is_login_challenge_url(challenge1.as_ptr(), challenge1.as_bytes().len()));
            let challenge2 = CString::new("https://apis.roblox.com/view-generic-challenge?test=1").unwrap();
            assert!(mocktail_rust_webview_is_login_challenge_url(challenge2.as_ptr(), challenge2.as_bytes().len()));
            let non_challenge = CString::new("https://www.roblox.com/games/12345").unwrap();
            assert!(!mocktail_rust_webview_is_login_challenge_url(non_challenge.as_ptr(), non_challenge.as_bytes().len()));
        }
    }

    #[test]
    fn test_game_session_coordinator_helpers() {
        unsafe {
            let name_run = CStr::from_ptr(mocktail_rust_game_session_state_name(7)).to_str().unwrap();
            assert_eq!(name_run, "Running");
            let name_pause = CStr::from_ptr(mocktail_rust_game_session_state_name(10)).to_str().unwrap();
            assert_eq!(name_pause, "Paused");

            let backend_vk = CStr::from_ptr(mocktail_rust_game_present_backend_name(1)).to_str().unwrap();
            assert_eq!(backend_vk, "Vulkan");

            let kind_guest = CStr::from_ptr(mocktail_rust_game_session_principal_kind_name(0)).to_str().unwrap();
            assert_eq!(kind_guest, "LocalGuest");
            let kind_auth = CStr::from_ptr(mocktail_rust_game_session_principal_kind_name(1)).to_str().unwrap();
            assert_eq!(kind_auth, "Authenticated");

            assert!(mocktail_rust_game_session_valid_principal(1, 10, 0, 0));
            assert!(!mocktail_rust_game_session_valid_principal(1, 10, 0, 5));
            assert!(mocktail_rust_game_session_valid_principal(1, 10, 1, 5));
            assert!(!mocktail_rust_game_session_valid_principal(0, 10, 1, 5));

            assert!(mocktail_rust_game_session_valid_request(100, 12345, 10));
            assert!(!mocktail_rust_game_session_valid_request(0, 12345, 10));

            assert!(mocktail_rust_game_session_valid_surface(1, 0x1234, 1920, 1080));
            assert!(!mocktail_rust_game_session_valid_surface(0, 0x1234, 1920, 1080));
        }
    }

    #[test]
    fn test_audio_and_webrtc_helpers() {
        unsafe {
            assert!(mocktail_rust_fmod_is_valid_channel_count(1));
            assert!(mocktail_rust_fmod_is_valid_channel_count(2));
            assert!(mocktail_rust_fmod_is_valid_channel_count(6));
            assert!(mocktail_rust_fmod_is_valid_channel_count(8));
            assert!(!mocktail_rust_fmod_is_valid_channel_count(3));
            assert!(!mocktail_rust_fmod_is_valid_channel_count(0));

            // 48000 Hz, 10 ms, 1 channel -> 480 samples * 2 bytes = 960 bytes
            assert_eq!(mocktail_rust_webrtc_calc_frame_bytes(48000, 10, 1), 960);

            let pcm = [0x00u8, 0x00, 0x00, 0x40]; // 0, 16384
            assert_eq!(mocktail_rust_audio_calc_pcm_s16le_peak(pcm.as_ptr(), pcm.len()), 16384);

            assert!(mocktail_rust_audio_spec_equals(48000, 2, 1, 48000, 2, 1));
            assert!(!mocktail_rust_audio_spec_equals(48000, 2, 1, 44100, 2, 1));
        }
    }

    #[test]
    fn test_update_and_download_helpers() {
        unsafe {
            let host1 = CString::new("download.pureapk.com").unwrap();
            let host2 = CString::new("pureapk.com.attacker.test").unwrap();
            let allowed = CString::new("pureapk.com").unwrap();

            assert!(mocktail_rust_update_host_matches(host1.as_ptr(), 20, allowed.as_ptr(), 11));
            assert!(!mocktail_rust_update_host_matches(host2.as_ptr(), 25, allowed.as_ptr(), 11));

            assert!(mocktail_rust_update_is_redirect_status(301));
            assert!(mocktail_rust_update_is_redirect_status(302));
            assert!(!mocktail_rust_update_is_redirect_status(200));

            assert!(mocktail_rust_update_is_retryable_status(429));
            assert!(mocktail_rust_update_is_retryable_status(503));
            assert!(!mocktail_rust_update_is_retryable_status(404));

            assert!(mocktail_rust_update_is_retryable_curl_code(7)); // CURLE_COULDNT_CONNECT
            assert!(!mocktail_rust_update_is_retryable_curl_code(0));

            let mut take_latest = false;
            let mut take_preferred = false;
            assert_eq!(mocktail_rust_update_plan_evaluate(
                true, 200, true, 100, 150, &mut take_latest, &mut take_preferred
            ), 0);
            assert!(take_latest);
            assert!(take_preferred);
        }
    }

    #[test]
    fn test_memory_and_statm_helpers() {
        unsafe {
            assert_eq!(mocktail_rust_statm_pages_to_bytes(100, 4096), 409600);
            let statm = CString::new("1000 250 50 10 0 200 0\n").unwrap();
            let mut resident = 0u64;
            assert_eq!(mocktail_rust_parse_proc_statm(statm.as_ptr(), statm.as_bytes().len(), &mut resident), 0);
            assert_eq!(resident, 250);

            assert!(mocktail_rust_memory_limit_exceeded(500, 100, 550));
            assert!(!mocktail_rust_memory_limit_exceeded(500, 100, 700));

            let mut buf = [0u8; 256];
            let mut len = 0usize;
            assert_eq!(mocktail_rust_format_memory_limit_message(1024 * 1024 * 512, 1024 * 1024 * 1024, buf.as_mut_ptr(), buf.len(), &mut len), 0);
            let msg = std::str::from_utf8(&buf[..len]).unwrap();
            assert!(msg.contains("RSS+swap=512 MiB"));
            assert!(msg.contains("limit=1024 MiB"));
        }
    }

    #[test]
    fn test_preflight_and_diagnostic_helpers() {
        unsafe {
            let data = "hello world \u{1F600}".as_bytes();
            let trim = mocktail_rust_trim_to_utf8_boundary(data.as_ptr(), data.len(), data.len() - 2);
            assert_eq!(trim, 12); // Cuts at the emoji boundary

            let line = CString::new("[native-updater] signature verification failed\n").unwrap();
            let mut out = [0u8; 128];
            let mut out_len = 0usize;
            let mut is_failure = false;
            assert_eq!(mocktail_rust_parse_updater_stderr_line(line.as_ptr(), line.as_bytes().len(), out.as_mut_ptr(), out.len(), &mut out_len, &mut is_failure), 0);
            assert!(is_failure);
            let parsed_detail = std::str::from_utf8(&out[..out_len]).unwrap();
            assert_eq!(parsed_detail, "signature verification failed\n");

            let env_str = CString::new("MOCKTAIL_DEBUG=1").unwrap();
            let name_str = CString::new("MOCKTAIL_DEBUG").unwrap();
            assert!(mocktail_rust_is_env_entry(env_str.as_ptr(), env_str.as_bytes().len(), name_str.as_ptr(), name_str.as_bytes().len()));

            let mut fail_buf = [0u8; 256];
            let mut fail_len = 0usize;
            assert_eq!(mocktail_rust_format_preflight_failure(137, false, std::ptr::null(), 0, fail_buf.as_mut_ptr(), fail_buf.len(), &mut fail_len), 0);
            let formatted = std::str::from_utf8(&fail_buf[..fail_len]).unwrap();
            assert_eq!(formatted, "Updater process exited with status 137");
        }
    }

    #[test]
    fn test_desktop_app_policy_helpers() {
        unsafe {
            let base_policy = CString::new(r#"{"PlatformGroup":"Mobile"}"#).unwrap();
            let theme = CString::new("dark").unwrap();
            let mut out = [0u8; 512];
            let mut out_len = 0usize;
            assert_eq!(mocktail_rust_normalize_desktop_layout(
                base_policy.as_ptr(), base_policy.as_bytes().len(),
                theme.as_ptr(), theme.as_bytes().len(),
                out.as_mut_ptr(), out.len(), &mut out_len
            ), 0);
            let norm = std::str::from_utf8(&out[..out_len]).unwrap();
            assert!(norm.contains(r#""PlatformGroup":"Desktop""#));
            assert!(norm.contains(r#""ForceTheme":"dark""#));

            let base_settings = CString::new(r#"{"FFlagExisting":"True"}"#).unwrap();
            let mut merged = [0u8; 512];
            let mut merged_len = 0usize;
            assert_eq!(mocktail_rust_merge_desktop_app_policy_settings(
                norm.as_ptr() as *const c_char, norm.len(),
                base_settings.as_ptr(), base_settings.as_bytes().len(),
                merged.as_mut_ptr(), merged.len(), &mut merged_len
            ), 0);
            let merged_str = std::str::from_utf8(&merged[..merged_len]).unwrap();
            assert!(merged_str.contains("FStringAppConfigurationOverrideAppPolicy"));
            assert!(merged_str.contains(r#""FFlagLuaAppChartsAppPage":"False""#));
        }
    }

    #[test]
    fn test_browser_tracker_and_cookie_helpers() {
        unsafe {
            let valid_id = CString::new("123456789012345678").unwrap();
            let zero_id = CString::new("012345").unwrap();
            assert!(mocktail_rust_browser_tracker_is_valid_id(valid_id.as_ptr(), valid_id.as_bytes().len()));
            assert!(!mocktail_rust_browser_tracker_is_valid_id(zero_id.as_ptr(), zero_id.as_bytes().len()));

            let cookie_header = CString::new("a=1; RBXEventTrackerV2=browser_id:987654321; c=3").unwrap();
            let name = CString::new("RBXEventTrackerV2").unwrap();
            let mut cookie_val = [0u8; 64];
            let mut cookie_len = 0usize;
            assert_eq!(mocktail_rust_browser_tracker_extract_cookie(
                cookie_header.as_ptr(), cookie_header.as_bytes().len(),
                name.as_ptr(), name.as_bytes().len(),
                cookie_val.as_mut_ptr(), cookie_val.len(), &mut cookie_len
            ), 0);
            let extracted = std::str::from_utf8(&cookie_val[..cookie_len]).unwrap();
            assert_eq!(extracted, "browser_id:987654321");
            assert!(mocktail_rust_browser_tracker_has_cookie(
                cookie_header.as_ptr(), cookie_header.as_bytes().len(),
                name.as_ptr(), name.as_bytes().len()
            ));

            let headers = CString::new("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: RBXEventTrackerV2=from_header_token; Path=/\r\n\r\n").unwrap();
            let mut hdr_cookie = [0u8; 64];
            let mut hdr_len = 0usize;
            assert_eq!(mocktail_rust_browser_tracker_from_headers(
                headers.as_ptr(), headers.as_bytes().len(),
                hdr_cookie.as_mut_ptr(), hdr_cookie.len(), &mut hdr_len
            ), 0);
            let hdr_extracted = std::str::from_utf8(&hdr_cookie[..hdr_len]).unwrap();
            assert_eq!(hdr_extracted, "from_header_token");
        }
    }

    #[test]
    fn test_auth_service_helpers() {
        unsafe {
            let cookie_header = CString::new("Other=1; .ROBLOSECURITY = _|valid-token ; Tail=2").unwrap();
            let mut present = false;
            let mut buf = [0 as c_char; 64];
            let mut len = 0usize;
            assert_eq!(mocktail_rust_auth_extract_cookie(
                cookie_header.as_ptr(), cookie_header.as_bytes().len(),
                &mut present, buf.as_mut_ptr(), buf.len(), &mut len
            ), 0);
            assert!(present);
            let extracted = CStr::from_ptr(buf.as_ptr()).to_str().unwrap();
            assert_eq!(extracted, "_|valid-token");

            let raw_cookie = CString::new("_|raw-token; other=3").unwrap();
            assert_eq!(mocktail_rust_auth_extract_cookie(
                raw_cookie.as_ptr(), raw_cookie.as_bytes().len(),
                &mut present, buf.as_mut_ptr(), buf.len(), &mut len
            ), 0);
            assert!(present);
            let raw_extracted = CStr::from_ptr(buf.as_ptr()).to_str().unwrap();
            assert_eq!(raw_extracted, "_|raw-token");

            assert!(mocktail_rust_auth_is_safe_cookie_value(b"_|valid-token\0".as_ptr() as *const c_char, 13));
            assert!(!mocktail_rust_auth_is_safe_cookie_value(b"_|with space\0".as_ptr() as *const c_char, 12));
            assert!(!mocktail_rust_auth_is_safe_cookie_value(b"_|with;semi\0".as_ptr() as *const c_char, 11));

            let to_redact = CString::new("Other=1\n.ROBLOSECURITY=_|bad-token\nTail=2").unwrap();
            let bad_val = CString::new("_|bad-token").unwrap();
            let mut red_buf = [0 as c_char; 128];
            let mut red_len = 0usize;
            assert_eq!(mocktail_rust_auth_redact_rejected(
                to_redact.as_ptr(), to_redact.as_bytes().len(),
                bad_val.as_ptr(), bad_val.as_bytes().len(),
                red_buf.as_mut_ptr(), red_buf.len(), &mut red_len
            ), 0);
            let redacted_str = CStr::from_ptr(red_buf.as_ptr()).to_str().unwrap();
            assert!(redacted_str.starts_with("Other=1\n   "));
            assert!(redacted_str.ends_with("\nTail=2"));

            let identity_json = CString::new(r#"{"id":123456789,"name":"TestUser","displayName":"Display Name"}"#).unwrap();
            let mut user_id = 0i64;
            let mut name_buf = [0 as c_char; 32];
            let mut disp_buf = [0 as c_char; 32];
            assert_eq!(mocktail_rust_auth_parse_identity(
                identity_json.as_ptr(), identity_json.as_bytes().len(),
                &mut user_id, name_buf.as_mut_ptr(), name_buf.len(),
                disp_buf.as_mut_ptr(), disp_buf.len()
            ), 0);
            assert_eq!(user_id, 123456789);
            assert_eq!(CStr::from_ptr(name_buf.as_ptr()).to_str().unwrap(), "TestUser");
            assert_eq!(CStr::from_ptr(disp_buf.as_ptr()).to_str().unwrap(), "Display Name");
        }
    }

    #[test]
    fn test_auth_redaction_ranges() {
        unsafe {
            let orig = CString::new("a=1\nb=2\nc=3").unwrap();
            let red = CString::new("a=1\n   \nc=3").unwrap();
            let mut ranges = [MocktailRustCookieRedactionRange { begin: 0, end: 0, marker: 0 }; 8];
            let mut count = 0usize;
            assert_eq!(mocktail_rust_auth_find_redaction_ranges(
                orig.as_ptr(), orig.as_bytes().len(),
                red.as_ptr(), red.as_bytes().len(),
                ranges.as_mut_ptr(), ranges.len(), &mut count
            ), 0);
            assert_eq!(count, 1);
            assert_eq!(ranges[0].begin, 4);
            assert_eq!(ranges[0].end, 7);
            assert_eq!(ranges[0].marker, 4);
        }
    }

    #[test]
    fn test_capability_input_flags() {
        let mut presence = MocktailRustCapabilityInputSymbolsPresence::default();
        presence.has_gamepad_connect_event_with_gamepad_type = true;
        presence.has_set_gamepad_supported_key_with_gamepad_type = true;
        presence.has_set_gamepad_supported_motion_with_gamepad_type = true;
        presence.has_gamepad_axis_event = true;
        presence.has_gamepad_button_event = true;
        presence.has_gamepad_disconnect_event = true;

        let mut flags = MocktailRustCapabilityInputFlags::default();
        unsafe {
            mocktail_rust_capability_eval_input_flags(&presence, &mut flags);
        }
        assert_eq!(flags.gamepad_api, 1);
        assert!(!flags.clear_partial_gamepad);
        assert!(flags.has_gamepad_events);

        // Incomplete gamepad modern api
        presence.has_set_gamepad_supported_motion_with_gamepad_type = false;
        unsafe {
            mocktail_rust_capability_eval_input_flags(&presence, &mut flags);
        }
        assert_eq!(flags.gamepad_api, 0);
        assert!(flags.clear_partial_gamepad);
        assert!(!flags.has_gamepad_events);
    }

    #[test]
    fn test_session_log_helpers() {
        unsafe {
            // Display path
            let mut out = [0 as c_char; 128];
            let mut len = 0usize;

            let path_empty = CString::new("").unwrap();
            let home = CString::new("/home/user").unwrap();
            assert_eq!(mocktail_rust_session_log_display_path(
                path_empty.as_ptr(), 0,
                home.as_ptr(), home.as_bytes().len(),
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "unknown");

            let path_inside = CString::new("/home/user/logs/session.log").unwrap();
            assert_eq!(mocktail_rust_session_log_display_path(
                path_inside.as_ptr(), path_inside.as_bytes().len(),
                home.as_ptr(), home.as_bytes().len(),
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "~/logs/session.log");

            let path_home = CString::new("/home/user").unwrap();
            assert_eq!(mocktail_rust_session_log_display_path(
                path_home.as_ptr(), path_home.as_bytes().len(),
                home.as_ptr(), home.as_bytes().len(),
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "~/.");

            let path_outside = CString::new("/usr/bin/mocktail").unwrap();
            assert_eq!(mocktail_rust_session_log_display_path(
                path_outside.as_ptr(), path_outside.as_bytes().len(),
                home.as_ptr(), home.as_bytes().len(),
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "/usr/bin/mocktail");

            // Package kind
            assert_eq!(mocktail_rust_session_log_package_kind(
                true, false, false, std::ptr::null(), 0,
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "flatpak");

            assert_eq!(mocktail_rust_session_log_package_kind(
                false, true, false, std::ptr::null(), 0,
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "appimage");

            assert_eq!(mocktail_rust_session_log_package_kind(
                false, false, true, std::ptr::null(), 0,
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "portable");

            let sys_path = CString::new("/usr/bin/mocktail").unwrap();
            assert_eq!(mocktail_rust_session_log_package_kind(
                false, false, false, sys_path.as_ptr(), sys_path.as_bytes().len(),
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "system-install");

            let build_path = CString::new("/home/user/mocktail/build/mocktail").unwrap();
            assert_eq!(mocktail_rust_session_log_package_kind(
                false, false, false, build_path.as_ptr(), build_path.as_bytes().len(),
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "local-build");

            // Display server
            assert_eq!(mocktail_rust_session_log_display_server(
                true, false, out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "wayland");

            assert_eq!(mocktail_rust_session_log_display_server(
                false, true, out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "x11");

            assert_eq!(mocktail_rust_session_log_display_server(
                false, false, out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            assert_eq!(CStr::from_ptr(out.as_ptr()).to_str().unwrap(), "none");

            // Device node name
            assert!(mocktail_rust_session_log_device_node_name(
                b"renderD128\0".as_ptr() as *const c_char, 10,
                b"renderD\0".as_ptr() as *const c_char, 7
            ));
            assert!(!mocktail_rust_session_log_device_node_name(
                b"renderD\0".as_ptr() as *const c_char, 7,
                b"renderD\0".as_ptr() as *const c_char, 7
            ));
            assert!(!mocktail_rust_session_log_device_node_name(
                b"renderDabc\0".as_ptr() as *const c_char, 10,
                b"renderD\0".as_ptr() as *const c_char, 7
            ));
            assert!(mocktail_rust_session_log_device_node_name(
                b"card0\0".as_ptr() as *const c_char, 5,
                b"card\0".as_ptr() as *const c_char, 4
            ));
        }
    }

    #[test]
    fn test_candidate_approval_fingerprint_and_generation() {
        unsafe {
            let pid = CString::new("pay123").unwrap();
            let meta = CString::new("meta_sha").unwrap();
            let lib = CString::new("lib_sha").unwrap();
            let base = CString::new("base_sha").unwrap();
            let abi = CString::new("x86_64").unwrap();
            let split = CString::new("split_sha").unwrap();
            let assets = CString::new("assets_sha").unwrap();

            let input = MocktailRustPayloadFingerprintInput {
                payload_id: pid.as_ptr(), payload_id_len: pid.as_bytes().len(),
                metadata_sha256: meta.as_ptr(), metadata_sha256_len: meta.as_bytes().len(),
                library_sha256: lib.as_ptr(), library_sha256_len: lib.as_bytes().len(),
                base_apk_sha256: base.as_ptr(), base_apk_sha256_len: base.as_bytes().len(),
                guest_abi: abi.as_ptr(), guest_abi_len: abi.as_bytes().len(),
                split_apk_sha256: split.as_ptr(), split_apk_sha256_len: split.as_bytes().len(),
                asset_tree_sha256: assets.as_ptr(), asset_tree_sha256_len: assets.as_bytes().len(),
            };

            let mut fp_buf = [0 as c_char; 65];
            assert_eq!(mocktail_rust_candidate_approval_fingerprint(&input, fp_buf.as_mut_ptr(), fp_buf.len()), 0);
            let fp_str = CStr::from_ptr(fp_buf.as_ptr()).to_str().unwrap();
            assert_eq!(fp_str.len(), 64);

            let rbid = CString::new("1686400865ae0e408cd7bd67de7a439625c6fd13").unwrap();
            let prof = CString::new("profile_sha").unwrap();
            let compat = CString::new("compat_sha").unwrap();
            let c1 = CString::new("c1_sha").unwrap();
            let c2 = CString::new("c2_sha").unwrap();

            let mut gen_buf = [0 as c_char; 41];
            assert_eq!(mocktail_rust_candidate_approval_generation(
                rbid.as_ptr(), rbid.as_bytes().len(),
                fp_buf.as_ptr(), fp_str.len(),
                prof.as_ptr(), prof.as_bytes().len(),
                compat.as_ptr(), compat.as_bytes().len(),
                c1.as_ptr(), c1.as_bytes().len(),
                c2.as_ptr(), c2.as_bytes().len(),
                gen_buf.as_mut_ptr(), gen_buf.len()
            ), 0);
            let gen_str = CStr::from_ptr(gen_buf.as_ptr()).to_str().unwrap();
            assert_eq!(gen_str.len(), 40);
        }
    }

    #[test]
    fn test_candidate_approval_validate_binding() {
        unsafe {
            let pid = "2814-test";
            let bid = "1686400865ae0e408cd7bd67de7a439625c6fd13";
            let lib_sha = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
            let ver_name = "2.732.1043";
            let ver_code = 2814u64;

            let prof_json = format!(
                r#"{{"schema_version":1,"payload_id":"{pid}","payload_path":"payloads/{pid}","elf_build_id":"{bid}","payload_sha256":"{lib_sha}","profile":{{"elf_build_id":"{bid}"}},"reference":{{}}}}"#
            );
            let compat_json = format!(
                r#"{{"schema_version":1,"profiles":[{{"version_name":"{ver_name}","version_code":{ver_code},"elf_build_id":"{bid}","status":"experimental","default_allowed":true,"allow_legacy_binary_patches":false,"allow_host_abi_bridges":true,"allow_host_constructor_replay":true}}]}}"#
            );

            let p_c = CString::new(prof_json).unwrap();
            let c_c = CString::new(compat_json).unwrap();
            let pid_c = CString::new(pid).unwrap();
            let bid_c = CString::new(bid).unwrap();
            let lib_c = CString::new(lib_sha).unwrap();
            let ver_c = CString::new(ver_name).unwrap();

            let mut err_buf = [0 as c_char; 256];
            assert_eq!(mocktail_rust_candidate_approval_validate_binding(
                p_c.as_ptr(), p_c.as_bytes().len(),
                c_c.as_ptr(), c_c.as_bytes().len(),
                pid_c.as_ptr(), pid_c.as_bytes().len(),
                bid_c.as_ptr(), bid_c.as_bytes().len(),
                lib_c.as_ptr(), lib_c.as_bytes().len(),
                ver_c.as_ptr(), ver_c.as_bytes().len(),
                ver_code,
                err_buf.as_mut_ptr(), err_buf.len()
            ), 0);

            // Mismatched build id
            let bad_bid = CString::new("0000000000000000000000000000000000000000").unwrap();
            assert_eq!(mocktail_rust_candidate_approval_validate_binding(
                p_c.as_ptr(), p_c.as_bytes().len(),
                c_c.as_ptr(), c_c.as_bytes().len(),
                pid_c.as_ptr(), pid_c.as_bytes().len(),
                bad_bid.as_ptr(), bad_bid.as_bytes().len(),
                lib_c.as_ptr(), lib_c.as_bytes().len(),
                ver_c.as_ptr(), ver_c.as_bytes().len(),
                ver_code,
                err_buf.as_mut_ptr(), err_buf.len()
            ), 1);
            let err_str = CStr::from_ptr(err_buf.as_ptr()).to_str().unwrap();
            assert_eq!(err_str, "derived approval profile is not bound to exact payload bytes");
        }
    }

    #[test]
    fn test_candidate_approval_attestation_and_receipt() {
        unsafe {
            let run_id = CString::new("run-123").unwrap();
            let pid = CString::new("pay-456").unwrap();
            let fp = CString::new("fp-789").unwrap();
            let prof = CString::new("prof-sha").unwrap();
            let compat = CString::new("compat-sha").unwrap();
            let rsha = CString::new("run-sha").unwrap();
            let rbid = CString::new("run-bid").unwrap();
            let lsha = CString::new("log-sha").unwrap();

            let att_in = MocktailRustCanaryAttestationInput {
                run: 1,
                run_id: run_id.as_ptr(), run_id_len: run_id.as_bytes().len(),
                payload_id: pid.as_ptr(), payload_id_len: pid.as_bytes().len(),
                payload_fingerprint: fp.as_ptr(), payload_fingerprint_len: fp.as_bytes().len(),
                profile_sha256: prof.as_ptr(), profile_sha256_len: prof.as_bytes().len(),
                compatibility_manifest_sha256: compat.as_ptr(), compatibility_manifest_sha256_len: compat.as_bytes().len(),
                runtime_sha256: rsha.as_ptr(), runtime_sha256_len: rsha.as_bytes().len(),
                runtime_build_id: rbid.as_ptr(), runtime_build_id_len: rbid.as_bytes().len(),
                log_sha256: lsha.as_ptr(), log_sha256_len: lsha.as_bytes().len(),
            };

            let mut json_buf = [0 as c_char; 1024];
            let mut out_len = 0usize;
            assert_eq!(mocktail_rust_candidate_approval_build_attestation(
                &att_in, json_buf.as_mut_ptr(), json_buf.len(), &mut out_len
            ), 0);
            let att_json = CStr::from_ptr(json_buf.as_ptr()).to_str().unwrap();
            assert!(att_json.contains(r#""canary_tier": "C""#));
            assert!(att_json.contains(r#""readiness_log_sha256": "log-sha""#));
            assert!(att_json.ends_with('\n'));

            let gen = CString::new("gen-abc").unwrap();
            let ppath = CString::new("/path/to/lib").unwrap();
            let c1 = CString::new("canary1-hash").unwrap();
            let c2 = CString::new("canary2-hash").unwrap();
            let app_at = CString::new("2026-10-31T12:00:00Z").unwrap();

            let rcpt_in = MocktailRustApprovalReceiptInput {
                payload_id: pid.as_ptr(), payload_id_len: pid.as_bytes().len(),
                generation: gen.as_ptr(), generation_len: gen.as_bytes().len(),
                payload_path: ppath.as_ptr(), payload_path_len: ppath.as_bytes().len(),
                elf_build_id: rbid.as_ptr(), elf_build_id_len: rbid.as_bytes().len(),
                library_sha256: prof.as_ptr(), library_sha256_len: prof.as_bytes().len(),
                payload_fingerprint: fp.as_ptr(), payload_fingerprint_len: fp.as_bytes().len(),
                profile_sha256: prof.as_ptr(), profile_sha256_len: prof.as_bytes().len(),
                compatibility_manifest_sha256: compat.as_ptr(), compatibility_manifest_sha256_len: compat.as_bytes().len(),
                runtime_sha256: rsha.as_ptr(), runtime_sha256_len: rsha.as_bytes().len(),
                runtime_build_id: rbid.as_ptr(), runtime_build_id_len: rbid.as_bytes().len(),
                canary_1_sha256: c1.as_ptr(), canary_1_sha256_len: c1.as_bytes().len(),
                canary_2_sha256: c2.as_ptr(), canary_2_sha256_len: c2.as_bytes().len(),
                approved_at_utc: app_at.as_ptr(), approved_at_utc_len: app_at.as_bytes().len(),
            };

            assert_eq!(mocktail_rust_candidate_approval_build_receipt(
                &rcpt_in, json_buf.as_mut_ptr(), json_buf.len(), &mut out_len
            ), 0);
            let rcpt_json = CStr::from_ptr(json_buf.as_ptr()).to_str().unwrap();
            assert!(rcpt_json.contains(r#""status": "approved""#));
            assert!(rcpt_json.contains(r#""canary_attestation_sha256": ["#));
            assert!(rcpt_json.ends_with('\n'));
        }
    }

    #[test]
    fn test_game_mode_and_physics_policies() {
        unsafe {
            let mut policy = -1;
            let a = CString::new("auto").unwrap();
            assert!(mocktail_rust_game_mode_parse_policy(a.as_ptr(), a.as_bytes().len(), &mut policy));
            assert_eq!(policy, 0);

            let on = CString::new("on").unwrap();
            assert!(mocktail_rust_game_mode_parse_policy(on.as_ptr(), on.as_bytes().len(), &mut policy));
            assert_eq!(policy, 1);

            let off = CString::new("false").unwrap();
            assert!(mocktail_rust_game_mode_parse_policy(off.as_ptr(), off.as_bytes().len(), &mut policy));
            assert_eq!(policy, 2);

            let inv = CString::new("invalid_val").unwrap();
            assert!(!mocktail_rust_game_mode_parse_policy(inv.as_ptr(), inv.as_bytes().len(), &mut policy));

            assert_eq!(CStr::from_ptr(mocktail_rust_game_mode_policy_name(0)).to_str().unwrap(), "auto");
            assert_eq!(CStr::from_ptr(mocktail_rust_game_mode_policy_name(1)).to_str().unwrap(), "on");
            assert_eq!(CStr::from_ptr(mocktail_rust_game_mode_policy_name(2)).to_str().unwrap(), "off");
            assert_eq!(CStr::from_ptr(mocktail_rust_game_mode_policy_name(99)).to_str().unwrap(), "invalid");

            assert_eq!(CStr::from_ptr(mocktail_rust_game_mode_session_state_name(0)).to_str().unwrap(), "disabled");
            assert_eq!(CStr::from_ptr(mocktail_rust_game_mode_session_state_name(4)).to_str().unwrap(), "active");
            assert_eq!(CStr::from_ptr(mocktail_rust_game_mode_session_state_name(99)).to_str().unwrap(), "invalid");

            let mut mode = -1;
            let lat = CString::new("latency").unwrap();
            assert!(mocktail_rust_performance_parse_physics_worker_mode(lat.as_ptr(), lat.as_bytes().len(), &mut mode));
            assert_eq!(mode, 1);

            let tp = CString::new("throughput").unwrap();
            assert!(mocktail_rust_performance_parse_physics_worker_mode(tp.as_ptr(), tp.as_bytes().len(), &mut mode));
            assert_eq!(mode, 2);

            assert_eq!(CStr::from_ptr(mocktail_rust_performance_physics_worker_mode_name(1)).to_str().unwrap(), "latency");
            assert_eq!(mocktail_rust_performance_calculate_throughput_worker_count(8), 8);
            assert_eq!(mocktail_rust_performance_calculate_throughput_worker_count(0), 1);
        }
    }

    #[test]
    fn test_single_instance_canary_validation() {
        unsafe {
            let can = CString::new("1").unwrap();
            let skip = CString::new("1").unwrap();
            let timer = CString::new("5000").unwrap();
            let data = CString::new("/tmp/test/data").unwrap();
            let cache = CString::new("/tmp/test/cache").unwrap();
            let state = CString::new("/tmp/test/state").unwrap();

            let inp = MocktailRustCanaryPathsInput {
                canary_value: can.as_ptr(), canary_len: can.as_bytes().len(),
                has_data_root: true, has_cache_root: true, has_state_root: true,
                has_roblox_lib: true, has_asset_path: true,
                skip_update_value: skip.as_ptr(), skip_update_len: skip.as_bytes().len(),
                auto_exit_ms_value: timer.as_ptr(), auto_exit_ms_len: timer.as_bytes().len(),
                data_root: data.as_ptr(), data_root_len: data.as_bytes().len(),
                cache_root: cache.as_ptr(), cache_root_len: cache.as_bytes().len(),
                state_root: state.as_ptr(), state_root_len: state.as_bytes().len(),
            };

            let mut err = [0 as c_char; 256];
            assert_eq!(mocktail_rust_single_instance_validate_isolated_canary(&inp, err.as_mut_ptr(), err.len()), 0);

            // Missing variable
            let mut bad_inp = inp;
            bad_inp.has_roblox_lib = false;
            assert_eq!(mocktail_rust_single_instance_validate_isolated_canary(&bad_inp, err.as_mut_ptr(), err.len()), 1);

            // Non-sibling paths (different parent)
            let bad_state = CString::new("/other/test/state").unwrap();
            bad_inp.has_roblox_lib = true;
            bad_inp.state_root = bad_state.as_ptr();
            bad_inp.state_root_len = bad_state.as_bytes().len();
            assert_eq!(mocktail_rust_single_instance_validate_isolated_canary(&bad_inp, err.as_mut_ptr(), err.len()), 2);
        }
    }

    #[test]
    fn test_settings_overrides_engine() {
        unsafe {
            let base = CString::new(r#"{"ExistingKey":"123"}"#).unwrap();
            let mut out = [0 as c_char; 1024];
            let mut len = 0usize;

            assert_eq!(mocktail_rust_http_client_merge_settings_overrides(
                base.as_ptr(), base.as_bytes().len(),
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            let s1 = CStr::from_ptr(out.as_ptr()).to_str().unwrap();
            assert!(s1.contains(r#""ExistingKey":"123""#));
            assert!(s1.contains(r#""FFlagUseRuntimeMutexRvHttpClient":"False""#));

            assert_eq!(mocktail_rust_audio_device_menu_merge_overrides(
                base.as_ptr(), base.as_bytes().len(),
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            let s2 = CStr::from_ptr(out.as_ptr()).to_str().unwrap();
            assert!(s2.contains(r#""FFlagDebugUseWebRtcAudioDevices":"False""#));

            assert_eq!(mocktail_rust_audio_capture_merge_overrides(
                base.as_ptr(), base.as_bytes().len(),
                out.as_mut_ptr(), out.len(), &mut len
            ), 0);
            let s3 = CStr::from_ptr(out.as_ptr()).to_str().unwrap();
            assert!(s3.contains(r#""DFFlagVoiceChatSkipPermissionCheckForTests":"False""#));
        }
    }

    #[test]
    fn test_section67_texture_memory_policy() {
        assert_eq!(mocktail_rust_texture_memory_calculate_budget(0), 0);
        assert_eq!(mocktail_rust_texture_memory_calculate_budget(2048 * 1024 * 1024), 0);
        assert_eq!(mocktail_rust_texture_memory_calculate_budget(4096 * 1024 * 1024), 512 * 1024 * 1024);
        assert_eq!(mocktail_rust_texture_memory_calculate_budget(8192 * 1024 * 1024), 1024 * 1024 * 1024);
        assert_eq!(mocktail_rust_texture_memory_calculate_budget(65536 * 1024 * 1024), 1536 * 1024 * 1024);

        let base = CString::new(r#"{"Existing":"true"}"#).unwrap();
        let mut out = [0 as c_char; 512];
        let mut out_len = 0usize;
        let mut err = [0 as c_char; 256];

        let rc = mocktail_rust_texture_memory_merge_overrides(
            512 * 1024 * 1024,
            base.as_ptr(),
            base.as_bytes().len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc, 0);
        let s = unsafe { CStr::from_ptr(out.as_ptr()).to_str().unwrap() };
        assert!(s.contains("FIntRenderForceVideoMemorySize"));
        assert!(s.contains("536870912"));

        // Malformed json
        let bad = CString::new(r#"["not", "object"]"#).unwrap();
        let rc_bad = mocktail_rust_texture_memory_merge_overrides(
            512 * 1024 * 1024,
            bad.as_ptr(),
            bad.as_bytes().len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc_bad, -1);
    }

    #[test]
    fn test_section68_desktop_app_policy() {
        let default_policy = CString::new(r#"{"PlatformGroup":"Unknown","Existing":1}"#).unwrap();
        let theme = CString::new("dark").unwrap();
        let mut out_storage = [0 as c_char; 2048];
        let mut out_storage_len = 0usize;
        let mut out_policy = [0 as c_char; 2048];
        let mut out_policy_len = 0usize;
        let mut updated = false;
        let mut norm_count = 0usize;
        let mut err = [0 as c_char; 256];

        let rc = mocktail_rust_process_desktop_app_policy(
            std::ptr::null(),
            0,
            false,
            default_policy.as_ptr(),
            default_policy.as_bytes().len(),
            42,
            theme.as_ptr(),
            out_storage.as_mut_ptr(),
            out_storage.len(),
            &mut out_storage_len,
            out_policy.as_mut_ptr(),
            out_policy.len(),
            &mut out_policy_len,
            &mut updated,
            &mut norm_count,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc, 0);
        assert!(updated);
        let pol = unsafe { CStr::from_ptr(out_policy.as_ptr()).to_str().unwrap() };
        assert!(pol.contains(r#""PlatformGroup":"Desktop""#));
        assert!(pol.contains(r#""ForceTheme":"dark""#));
        assert!(pol.contains(r#""Existing":1"#));
    }

    #[test]
    fn test_section69_experience_launch_json() {
        let valid_json = CString::new(r#"{"placeId":17580461965,"userId":123,"gameInstanceId":"server-1"}"#).unwrap();
        let mut data = MocktailRustExperienceLaunchData {
            place_id: 0,
            user_id: 0,
            conversation_id: 0,
            referred_by_player_id: 0,
        };
        let mut can_buf = [0 as c_char; 1024];
        let mut can_len = 0usize;
        let mut err = [0 as c_char; 256];

        let rc = mocktail_rust_parse_experience_launch_json(
            valid_json.as_ptr(),
            valid_json.as_bytes().len(),
            &mut data,
            can_buf.as_mut_ptr(),
            can_buf.len(),
            &mut can_len,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc, 0);
        assert_eq!(data.place_id, 17580461965);
        assert_eq!(data.user_id, 123);

        // Missing/invalid placeId
        let invalid_json = CString::new(r#"{"placeId":0,"userId":123}"#).unwrap();
        let rc_inv = mocktail_rust_parse_experience_launch_json(
            invalid_json.as_ptr(),
            invalid_json.as_bytes().len(),
            &mut data,
            can_buf.as_mut_ptr(),
            can_buf.len(),
            &mut can_len,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc_inv, -4);

        // String placeId
        let str_place = CString::new(r#"{"placeId":"17580461965"}"#).unwrap();
        let rc_str = mocktail_rust_parse_experience_launch_json(
            str_place.as_ptr(),
            str_place.as_bytes().len(),
            &mut data,
            can_buf.as_mut_ptr(),
            can_buf.len(),
            &mut can_len,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc_str, -3);

        // Overflow placeId
        let oflow_place = CString::new(r#"{"placeId":18446744073709551615}"#).unwrap();
        let rc_oflow = mocktail_rust_parse_experience_launch_json(
            oflow_place.as_ptr(),
            oflow_place.as_bytes().len(),
            &mut data,
            can_buf.as_mut_ptr(),
            can_buf.len(),
            &mut can_len,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc_oflow, -3);
    }

    #[test]
    fn test_section70_environment_abstraction() {
        std::env::set_var("MOCKTAIL_TEST_ENV_VAR", "test_val");
        let name = CString::new("MOCKTAIL_TEST_ENV_VAR").unwrap();
        assert_eq!(mocktail_rust_env_has_non_empty(name.as_ptr()), 1);

        let mut out = [0 as c_char; 64];
        let mut len = 0usize;
        assert_eq!(mocktail_rust_env_get(name.as_ptr(), out.as_mut_ptr(), out.len(), &mut len), 0);
        let s = unsafe { CStr::from_ptr(out.as_ptr()).to_str().unwrap() };
        assert_eq!(s, "test_val");

        let missing = CString::new("MOCKTAIL_TEST_NON_EXISTENT_VAR").unwrap();
        assert_eq!(mocktail_rust_env_has_non_empty(missing.as_ptr()), 0);
        let def = CString::new("fallback").unwrap();
        assert_eq!(mocktail_rust_env_get_or(missing.as_ptr(), def.as_ptr(), out.as_mut_ptr(), out.len(), &mut len), 0);
        let s_def = unsafe { CStr::from_ptr(out.as_ptr()).to_str().unwrap() };
        assert_eq!(s_def, "fallback");
    }

    #[test]
    fn test_section71_command_line_usage() {
        let prog = CString::new("mocktail-app").unwrap();
        let abi = CString::new("x86_64").unwrap();
        let mut out = [0 as c_char; 4096];
        let mut len = 0usize;
        assert_eq!(mocktail_rust_command_line_usage(prog.as_ptr(), abi.as_ptr(), out.as_mut_ptr(), out.len(), &mut len), 0);
        let s = unsafe { CStr::from_ptr(out.as_ptr()).to_str().unwrap() };
        assert!(s.contains("Usage: mocktail-app [options] [roblox-uri]"));
        assert!(s.contains("--graphics"));
        assert!(s.contains("--allow-unverified-build"));
    }

    #[test]
    fn test_section72_frame_rate_policy_helpers() {
        let mut buf = [0 as c_char; 32];
        assert_eq!(mocktail_rust_frame_rate_policy_name(0, 0, buf.as_mut_ptr(), buf.len()), 0);
        assert_eq!(unsafe { CStr::from_ptr(buf.as_ptr()).to_str().unwrap() }, "unmanaged");

        assert_eq!(mocktail_rust_frame_rate_policy_name(2, 144, buf.as_mut_ptr(), buf.len()), 0);
        assert_eq!(unsafe { CStr::from_ptr(buf.as_ptr()).to_str().unwrap() }, "144");
    }

    #[test]
    fn test_section73_present_mode_and_wsi_extensions() {
        let mut khr_buf = [0 as c_char; 32];
        assert_eq!(mocktail_rust_present_mode_khr_name(VK_PRESENT_MODE_FIFO_KHR, khr_buf.as_mut_ptr(), khr_buf.len()), 0);
        let fifo_name = unsafe { CStr::from_ptr(khr_buf.as_ptr()).to_str().unwrap() };
        assert_eq!(fifo_name, "fifo");

        let mut pol_buf = [0 as c_char; 32];
        assert_eq!(mocktail_rust_present_mode_policy_name(1, pol_buf.as_mut_ptr(), pol_buf.len()), 0);
        let vsync_name = unsafe { CStr::from_ptr(pol_buf.as_ptr()).to_str().unwrap() };
        assert_eq!(vsync_name, "vsync");

        assert_eq!(mocktail_rust_normalize_android_swapchain_result(1000001003), 0);
        assert_eq!(mocktail_rust_normalize_android_swapchain_result(0), 0);
        assert_eq!(mocktail_rust_normalize_android_swapchain_result(-4), -4);

        let ext1 = CString::new("VK_KHR_surface").unwrap();
        let ext2 = CString::new("VK_KHR_android_surface").unwrap();
        let ext3 = CString::new("VK_EXT_debug_utils").unwrap();
        let android_ptrs = [ext1.as_ptr(), ext2.as_ptr(), ext3.as_ptr()];

        let host1 = CString::new("VK_KHR_surface").unwrap();
        let host2 = CString::new("VK_KHR_xcb_surface").unwrap();
        let host_ptrs = [host1.as_ptr(), host2.as_ptr()];

        let mut out_ptrs = [std::ptr::null_mut() as *mut c_char; 16];
        let mut out_count = 0usize;
        let mut err = [0 as c_char; 256];

        let rc = mocktail_rust_translate_android_vulkan_instance_extensions(
            android_ptrs.as_ptr(),
            android_ptrs.len(),
            host_ptrs.as_ptr(),
            host_ptrs.len(),
            out_ptrs.as_mut_ptr(),
            out_ptrs.len(),
            &mut out_count,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc, 0);
        assert_eq!(out_count, 3);
        let s0 = unsafe { CStr::from_ptr(out_ptrs[0]).to_str().unwrap() };
        let s1 = unsafe { CStr::from_ptr(out_ptrs[1]).to_str().unwrap() };
        let s2 = unsafe { CStr::from_ptr(out_ptrs[2]).to_str().unwrap() };
        assert_eq!(s0, "VK_KHR_surface");
        assert_eq!(s1, "VK_EXT_debug_utils");
        assert_eq!(s2, "VK_KHR_xcb_surface");

        for i in 0..out_count {
            mocktail_rust_free_c_string(out_ptrs[i]);
        }
    }

    #[test]
    fn test_swapchain_images_env_override() {
        let _guard = test_env_lock();
        std::env::set_var("MOCKTAIL_SWAPCHAIN_IMAGES", "3");
        assert_eq!(mocktail_rust_present_mode_prefer_min_image_count(3 /* Fifo */, 2, 2, 8), 3);
        assert_eq!(mocktail_rust_present_mode_prefer_min_image_count(1 /* Vsync */, 2, 2, 8), 3);
        std::env::remove_var("MOCKTAIL_SWAPCHAIN_IMAGES");
        assert_eq!(mocktail_rust_present_mode_prefer_min_image_count(3 /* Fifo */, 2, 2, 8), 2);
    }

    #[test]
    fn test_section74_display_refresh_capabilities() {
        let supp = [60.0f32, 144.0, 60.001, -1.0, f32::NAN, 120.0];
        let mut out = [0.0f32; 8];
        let mut count = 0usize;
        let rc = mocktail_rust_normalize_display_refresh_capabilities(
            60.0,
            supp.as_ptr(),
            supp.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut count,
        );
        assert_eq!(rc, 0);
        assert_eq!(count, 3); // 60.0 (merged with 60.001), 120.0, 144.0
        assert_eq!(out[0], 60.0);
        assert_eq!(out[1], 120.0);
        assert_eq!(out[2], 144.0);
    }

    #[test]
    fn test_section75_platform_metadata_identity() {
        let mut name = [0 as c_char; 32];
        let mut id = [0 as c_char; 64];
        let mut ty = [0 as c_char; 32];
        assert_eq!(
            mocktail_rust_platform_metadata_identity(
                name.as_mut_ptr(),
                name.len(),
                id.as_mut_ptr(),
                id.len(),
                ty.as_mut_ptr(),
                ty.len()
            ),
            0
        );
        assert_eq!(unsafe { CStr::from_ptr(name.as_ptr()).to_str().unwrap() }, "Mocktail");
        assert_eq!(unsafe { CStr::from_ptr(id.as_ptr()).to_str().unwrap() }, "space.bigrat.mocktail");
        assert_eq!(unsafe { CStr::from_ptr(ty.as_ptr()).to_str().unwrap() }, "game");
    }

    #[test]
    fn test_section76_window_icon_png_header() {
        let mut png = vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, // magic
            0x00, 0x00, 0x00, 0x0D,                         // IHDR len
            b'I', b'H', b'D', b'R',
            0x00, 0x00, 0x01, 0x00, // width 256
            0x00, 0x00, 0x01, 0x00, // height 256
            0x08, 0x06, 0x00, 0x00, 0x00,
        ];
        let mut w = 0u32;
        let mut h = 0u32;
        assert_eq!(mocktail_rust_validate_window_icon_png_header(png.as_ptr(), png.len(), &mut w, &mut h), 0);
        assert_eq!(w, 256);
        assert_eq!(h, 256);

        png[0] = 0;
        assert_eq!(mocktail_rust_validate_window_icon_png_header(png.as_ptr(), png.len(), &mut w, &mut h), -2);
    }

    #[test]
    fn test_section77_supported_launch_defaults() {
        let cnt = mocktail_rust_supported_launch_defaults_count(1);
        assert_eq!(cnt, 27);
        assert_eq!(mocktail_rust_supported_launch_defaults_count(0), 0);

        let mut key = [0 as c_char; 96];
        let mut val = [0 as c_char; 96];
        assert_eq!(
            mocktail_rust_supported_launch_default_entry(1, 0, key.as_mut_ptr(), key.len(), val.as_mut_ptr(), val.len()),
            0
        );
        assert_eq!(unsafe { CStr::from_ptr(key.as_ptr()).to_str().unwrap() }, "MOCKTAIL_ALLOW_NO_COOKIE_LUA_APP");
        assert_eq!(unsafe { CStr::from_ptr(val.as_ptr()).to_str().unwrap() }, "1");
        for i in 0..cnt {
            assert_eq!(
                mocktail_rust_supported_launch_default_entry(1, i, key.as_mut_ptr(), key.len(), val.as_mut_ptr(), val.len()),
                0
            );
            let k = unsafe { CStr::from_ptr(key.as_ptr()).to_str().unwrap() };
            assert_ne!(k, "MOCKTAIL_MAIN_THREAD_MESSAGE_PUMP");
        }
    }

    #[test]
    fn test_section78_platform_profile_and_paths() {
        let prof = CString::new("desktop").unwrap();
        let mut rev = [0 as c_char; 64];
        assert_eq!(
            mocktail_rust_build_platform_profile_revision(prof.as_ptr(), 1, 0, 1, rev.as_mut_ptr(), rev.len()),
            0
        );
        assert_eq!(unsafe { CStr::from_ptr(rev.as_ptr()).to_str().unwrap() }, "device-v1-desktop-t1-m0-k1");

        let conf = CString::new("/data/user/0/com.roblox.client/files").unwrap();
        let root = CString::new("/home/user/.mocktail/data").unwrap();
        let mut out = [0 as c_char; 256];
        assert_eq!(
            mocktail_rust_translate_android_files_path(conf.as_ptr(), root.as_ptr(), out.as_mut_ptr(), out.len()),
            0
        );
        assert_eq!(unsafe { CStr::from_ptr(out.as_ptr()).to_str().unwrap() }, "/home/user/.mocktail/data/files");
    }

    #[test]
    fn test_section79_platform_cache_fingerprint() {
        let json = CString::new(r#"{"schema_version":1,"profile_revision":"rev-123"}"#).unwrap();
        let mut rev = [0 as c_char; 64];
        assert_eq!(
            mocktail_rust_validate_platform_cache_fingerprint(json.as_ptr(), json.as_bytes().len(), rev.as_mut_ptr(), rev.len()),
            0
        );
        assert_eq!(unsafe { CStr::from_ptr(rev.as_ptr()).to_str().unwrap() }, "rev-123");
    }

    #[test]
    fn test_section80_browser_service_command() {
        let json = CString::new(r#"{"command":"open","url":"https://roblox.com/home","title":"Home","visible":true}"#).unwrap();
        let mut cmd_type = 0i32;
        let mut cmd = MocktailRustBrowserServiceOpenCommand {
            url: [0; 1024],
            title: [0; 512],
            has_title: 0,
            visible: 0,
            modal: 0,
            back_navigation_disabled: 0,
            show_domain_as_title: 0,
        };
        let mut err = [0 as c_char; 256];
        let rc = mocktail_rust_parse_browser_service_command(
            json.as_ptr(),
            json.as_bytes().len(),
            &mut cmd_type,
            &mut cmd,
            err.as_mut_ptr(),
            err.len(),
        );
        assert_eq!(rc, 0);
        assert_eq!(cmd_type, 1);
        assert_eq!(unsafe { CStr::from_ptr(cmd.url.as_ptr()).to_str().unwrap() }, "https://roblox.com/home");
        assert_eq!(unsafe { CStr::from_ptr(cmd.title.as_ptr()).to_str().unwrap() }, "Home");
        assert_eq!(cmd.visible, 1);
    }

    #[test]
    fn test_section81_text_display_state() {
        let text = CString::new("Hello 🌍!").unwrap();
        let mut cp = 0usize;
        let bytes = mocktail_rust_utf8_byte_for_utf16_cursor(text.as_ptr(), text.as_bytes().len(), 6, &mut cp);
        assert_eq!(bytes, 6); // "Hello "
        assert_eq!(cp, 6);

        assert_eq!(mocktail_rust_text_geometry_intersects_viewport(10, 10, 100, 50, 800, 600), 1);
        assert_eq!(mocktail_rust_text_geometry_intersects_viewport(900, 10, 100, 50, 800, 600), 0);
    }

    #[test]
    fn test_section82_fullscreen_setter_contract() {
        let mut code = vec![0u8; 120];
        code[0..4].copy_from_slice(&[0x55, 0x48, 0x89, 0xe5]);
        code[4..6].copy_from_slice(&[0x89, 0xf3]);
        code[20..26].copy_from_slice(&[0x38, 0x98, 0x61, 0x01, 0x00, 0x00]);
        code[30..36].copy_from_slice(&[0x88, 0x98, 0x61, 0x01, 0x00, 0x00]);
        assert_eq!(mocktail_rust_validate_fullscreen_setter_contract(code.as_ptr(), code.len()), 1);

        code[0] = 0;
        assert_eq!(mocktail_rust_validate_fullscreen_setter_contract(code.as_ptr(), code.len()), 0);
    }

    #[test]
    fn test_section83_pointer_capture_evaluate() {
        let mut cap = 0i32;
        let mut vis = 0i32;
        mocktail_rust_pointer_capture_evaluate(1, 1, 1, 0, 0, &mut cap, &mut vis);
        assert_eq!(cap, 1);
        assert_eq!(vis, 0);

        mocktail_rust_pointer_capture_evaluate(0, 1, 1, 0, 0, &mut cap, &mut vis);
        assert_eq!(cap, 0);
        assert_eq!(vis, 1);
    }

    #[test]
    fn test_section84_text_input_type_mapper() {
        assert_eq!(mocktail_rust_map_roblox_text_input_type(2), 2); // Number
        assert_eq!(mocktail_rust_map_roblox_text_input_type(3), 3); // Email
        assert_eq!(mocktail_rust_map_roblox_text_input_type(5), 4); // Password
        assert_eq!(mocktail_rust_map_roblox_text_input_type(6), 5); // Username
        assert_eq!(mocktail_rust_map_roblox_text_input_type(0), 1); // Text
    }

    #[test]
    fn test_section85_bionic_sysconf() {
        let mut std_sc = 0i32;
        let mut fix = 0i64;
        assert_eq!(mocktail_rust_bionic_sysconf_translate_name(0x0006, &mut std_sc, &mut fix), 1);
        assert_eq!(fix, 100);

        assert_eq!(mocktail_rust_bionic_sysconf_translate_name(0x0027, &mut std_sc, &mut fix), 0);
        assert_eq!(std_sc, 0x0027);
    }

    #[test]
    fn test_section86_build_profile() {
        let id = CString::new("ABCD12EF").unwrap();
        let mut out = [0 as c_char; 32];
        assert_eq!(mocktail_rust_normalize_build_id(id.as_ptr(), out.as_mut_ptr(), out.len()), 0);
        assert_eq!(unsafe { CStr::from_ptr(out.as_ptr()).to_str().unwrap() }, "abcd12ef");

        let st = CString::new("supported").unwrap();
        assert_eq!(mocktail_rust_parse_status_string(st.as_ptr()), 0);

        let rva_str = CString::new("0x1234abcd").unwrap();
        let mut rva = 0usize;
        assert_eq!(mocktail_rust_parse_hex_rva(rva_str.as_ptr(), &mut rva), 0);
        assert_eq!(rva, 0x1234abcd);
    }

    #[test]
    fn test_section87_elf_build_id() {
        let valid = CString::new("0123456789abcdef").unwrap();
        assert_eq!(mocktail_rust_is_valid_build_id(valid.as_ptr(), valid.as_bytes().len()), 1);

        let odd = CString::new("123").unwrap();
        assert_eq!(mocktail_rust_is_valid_build_id(odd.as_ptr(), odd.as_bytes().len()), 0);
    }

    #[test]
    fn test_section88_http_client_spin_limiter() {
        let mut count = 63u64;
        let mut cp = 1000u64;
        let pause = mocktail_rust_http_spin_limiter_observe(&mut count, &mut cp, 1000 + 500, 64, 1000);
        assert_eq!(pause, 500);
    }

    #[test]
    fn test_section89_owned_pthread_status_name() {
        let mut buf = [0 as c_char; 32];
        mocktail_rust_owned_pthread_status_name(0, buf.as_mut_ptr(), buf.len());
        assert_eq!(unsafe { CStr::from_ptr(buf.as_ptr()).to_str().unwrap() }, "Joined");
        assert_eq!(
            unsafe { CStr::from_ptr(mocktail_rust_owned_pthread_status_name_ptr(1)).to_str().unwrap() },
            "TimedOut"
        );
    }

    #[test]
    fn test_section90_failure_dialog() {
        assert_eq!(mocktail_rust_failure_dialogs_enabled(0, 0, 0, 1, 0), 1);
        assert_eq!(mocktail_rust_failure_dialogs_enabled(1, 0, 0, 1, 0), 0);

        let msg = CString::new("error occurred").unwrap();
        let mut pkt = [0 as c_char; 64];
        let mut len = 0usize;
        assert_eq!(
            mocktail_rust_failure_dialog_format_packet(b'M' as c_char, msg.as_ptr(), 2048, pkt.as_mut_ptr(), pkt.len(), &mut len),
            0
        );
        assert_eq!(len, 15);
        assert_eq!(pkt[0], b'M' as c_char);
    }

    #[test]
    fn test_section91_apk_provider_append_failure() {
        let ex = CString::new("prov1: err1").unwrap();
        let p2 = CString::new("prov2").unwrap();
        let e2 = CString::new("err2").unwrap();
        let mut out = [0 as c_char; 128];
        let mut len = 0usize;
        assert_eq!(
            mocktail_rust_apk_provider_append_failure(ex.as_ptr(), p2.as_ptr(), e2.as_ptr(), out.as_mut_ptr(), out.len(), &mut len),
            0
        );
        let s = unsafe { CStr::from_ptr(out.as_ptr()).to_str().unwrap() };
        assert_eq!(s, "prov1: err1; prov2: err2");
    }

    #[test]
    fn test_section92_update_config_yaml() {
        let yaml = CString::new("version: 1\nupdates:\n  automatic: true\n  launch_after_update: false\n  source: auto\n").unwrap();
        let mut auto = 0i32;
        let mut launch = 0i32;
        let mut src = [0 as c_char; 32];
        let mut err = [0 as c_char; 128];
        assert_eq!(
            mocktail_rust_parse_update_config_yaml(
                yaml.as_ptr(),
                yaml.as_bytes().len(),
                &mut auto,
                &mut launch,
                src.as_mut_ptr(),
                src.len(),
                err.as_mut_ptr(),
                err.len(),
            ),
            0
        );
        assert_eq!(auto, 1);
        assert_eq!(launch, 0);
        assert_eq!(unsafe { CStr::from_ptr(src.as_ptr()).to_str().unwrap() }, "auto");
    }

    #[test]
    fn test_section93_unsafe_latest_overrides() {
        let e1 = CString::new("ROBLOX_LIB_PATH=/path").unwrap();
        assert_eq!(mocktail_rust_is_overridden_environment_var(e1.as_ptr()), 1);

        let e2 = CString::new("PATH=/usr/bin").unwrap();
        assert_eq!(mocktail_rust_is_overridden_environment_var(e2.as_ptr()), 0);
    }

    #[test]
    fn test_section94_canary_backend_and_audio() {
        let mut b = 0i32;
        let s = CString::new("angle-vulkan").unwrap();
        assert_eq!(mocktail_rust_canary_backend_parse(s.as_ptr(), &mut b), 0);
        assert_eq!(b, 3);

        let mut buf = [0 as c_char; 32];
        mocktail_rust_canary_backend_name(3, buf.as_mut_ptr(), buf.len());
        assert_eq!(unsafe { CStr::from_ptr(buf.as_ptr()).to_str().unwrap() }, "angle-vulkan");

        let log = CString::new("[mocktail][audio] OpenSL playback activity: submitted_buffers=10\n[mocktail][audio] OpenSL playback evidence: consumed_buffers=10\n[mocktail][audio] OpenSL player shutdown: submitted=10 clean=true\n").unwrap();
        let mut err = [0 as c_char; 128];
        assert_eq!(mocktail_rust_validate_canary_audio_log(log.as_ptr(), log.as_bytes().len(), 1, err.as_mut_ptr(), err.len()), 0);

        let partial_log = CString::new("[mocktail][audio] OpenSL playback activity: submitted_buffers=10\n[mocktail][audio] OpenSL playback evidence: consumed_buffers=10\n").unwrap();
        assert_eq!(mocktail_rust_validate_canary_audio_log(partial_log.as_ptr(), partial_log.as_bytes().len(), 0, err.as_mut_ptr(), err.len()), 0);
        assert_ne!(mocktail_rust_validate_canary_audio_log(partial_log.as_ptr(), partial_log.as_bytes().len(), 1, err.as_mut_ptr(), err.len()), 0);
    }

    #[test]
    fn test_section95_game_session() {
        let ptr = mocktail_rust_game_session_state_name(1);
        assert_eq!(unsafe { CStr::from_ptr(ptr).to_str().unwrap() }, "PrincipalReady");

        assert_eq!(mocktail_rust_game_session_can_transition(0, 1), 1);
        assert_eq!(mocktail_rust_game_session_can_transition(0, 5), 0);
        assert_eq!(mocktail_rust_game_session_can_transition(3, 7), 1);
    }

    #[test]
    fn test_section96_capability_flags() {
        let mut flags = 0i32;
        mocktail_rust_evaluate_startup_flags(1, 0, 1, 0, &mut flags);
        assert_eq!(flags, (1 << 0) | (1 << 2));
    }

    #[test]
    fn test_section97_app_lifecycle_names() {
        let mut buf = [0 as c_char; 32];
        mocktail_rust_app_lifecycle_status_name(1, buf.as_mut_ptr(), buf.len());
        assert_eq!(unsafe { CStr::from_ptr(buf.as_ptr()).to_str().unwrap() }, "Ready");

        mocktail_rust_app_shutdown_status_name(1, buf.as_mut_ptr(), buf.len());
        assert_eq!(unsafe { CStr::from_ptr(buf.as_ptr()).to_str().unwrap() }, "AlreadyStopped");
        assert_eq!(
            unsafe { CStr::from_ptr(mocktail_rust_app_lifecycle_status_name_ptr(2)).to_str().unwrap() },
            "MissingRequiredSymbols"
        );
        assert_eq!(
            unsafe { CStr::from_ptr(mocktail_rust_app_shutdown_status_name_ptr(2)).to_str().unwrap() },
            "ShutdownInProgress"
        );
    }

    #[test]
    fn test_section98_fresh_game_params_utf16() {
        let s = CString::new("Hello 🌟").unwrap();
        let mut out = [0u16; 32];
        let mut len = 0usize;
        assert_eq!(
            mocktail_rust_utf8_to_utf16_surrogates(s.as_ptr(), s.as_bytes().len(), out.as_mut_ptr(), out.len(), &mut len),
            0
        );
        assert_eq!(len, 8); // "Hello " (6) + star surrogate pair (2)
    }

    #[test]
    fn test_section99_permissions_reply() {
        let req = CString::new("{}").unwrap();
        let mut body = [0 as c_char; 256];
        let mut len = 0usize;
        let mut code = 0i32;
        let mut outcome = [0 as c_char; 32];
        assert_eq!(
            mocktail_rust_format_permissions_reply(0, 1, req.as_ptr(), body.as_mut_ptr(), body.len(), &mut len, &mut code, outcome.as_mut_ptr(), outcome.len()),
            0
        );
        let b = unsafe { CStr::from_ptr(body.as_ptr()).to_str().unwrap() };
        assert!(b.contains("MICROPHONE_ACCESS"));
        assert_eq!(unsafe { CStr::from_ptr(outcome.as_ptr()).to_str().unwrap() }, "supported");
    }

    #[test]
    fn test_section100_client_settings() {
        let mut buf = [0 as c_char; 32];
        mocktail_rust_client_settings_source_name(0, buf.as_mut_ptr(), buf.len());
        assert_eq!(unsafe { CStr::from_ptr(buf.as_ptr()).to_str().unwrap() }, "explicit JSON");
        assert_eq!(
            unsafe { CStr::from_ptr(mocktail_rust_client_settings_source_name_ptr(2)).to_str().unwrap() },
            "bundled file"
        );

        let app = CString::new("RobloxStudio").unwrap();
        let mut url_buf = [0 as c_char; 128];
        mocktail_rust_client_settings_build_url(app.as_ptr(), url_buf.as_mut_ptr(), url_buf.len());
        assert_eq!(
            unsafe { CStr::from_ptr(url_buf.as_ptr()).to_str().unwrap() },
            "https://clientsettingscdn.roblox.com/v2/settings/application/RobloxStudio"
        );
    }

    #[test]
    fn test_section105_process_launch_policy() {
        let mut buf = [0 as c_char; 32];
        mocktail_rust_process_launch_format_limit(100, 0, buf.as_mut_ptr(), buf.len());
        assert_eq!(unsafe { CStr::from_ptr(buf.as_ptr()).to_str().unwrap() }, "100");

        mocktail_rust_process_launch_format_limit(0, 1, buf.as_mut_ptr(), buf.len());
        assert_eq!(unsafe { CStr::from_ptr(buf.as_ptr()).to_str().unwrap() }, "unlimited");

        let mut target = -1i32;
        let mut is_rt = -1i32;
        mocktail_rust_process_launch_eval_scheduler(0, &mut target, &mut is_rt);
        assert_eq!(is_rt, 0);
        assert_eq!(target, 0);

        mocktail_rust_process_launch_eval_scheduler(1, &mut target, &mut is_rt); // SCHED_FIFO
        assert_eq!(is_rt, 1);
        assert_eq!(target, 0);

        mocktail_rust_process_launch_eval_scheduler(2 | 0x4000_0000, &mut target, &mut is_rt); // SCHED_RR | RESET_ON_FORK
        assert_eq!(is_rt, 1);
        assert_eq!(target, 0x4000_0000);

        let mut action = -1i32;
        mocktail_rust_process_launch_eval_cpu_limit(30, 0, 0, 1, &mut action);
        assert_eq!(action, 1); // clear soft limit

        mocktail_rust_process_launch_eval_cpu_limit(30, 0, 60, 0, &mut action);
        assert_eq!(action, 2); // finite limit retained

        mocktail_rust_process_launch_eval_cpu_limit(0, 1, 0, 1, &mut action);
        assert_eq!(action, 0); // no action

        let mut diag = [0 as c_char; 2048];
        let mut written = 0usize;
        assert_eq!(
            mocktail_rust_apply_interactive_process_launch_policy(
                diag.as_mut_ptr(),
                diag.len(),
                &mut written
            ),
            0
        );
        let s = unsafe { CStr::from_ptr(diag.as_ptr()).to_str().unwrap() };
        assert!(s.contains("[process]"));
        assert!(s.contains("RLIMIT_CPU"));
    }

    #[test]
    fn test_section106_pinned_apk_provider() {
        let valid_hex = CString::new("d26d3afb9815d22f812538aca07d69fa686d10ea10aa0b466bb0203b70094d12").unwrap();
        assert_eq!(mocktail_rust_pinned_apk_hex_digest(valid_hex.as_ptr(), 64, 64), 1);
        assert_eq!(mocktail_rust_pinned_apk_hex_digest(valid_hex.as_ptr(), 63, 64), 0);

        let invalid_hex = CString::new("z26d3afb9815d22f812538aca07d69fa686d10ea10aa0b466bb0203b70094d12").unwrap();
        assert_eq!(mocktail_rust_pinned_apk_hex_digest(invalid_hex.as_ptr(), 64, 64), 0);

        let valid_fn = CString::new("base.apk").unwrap();
        assert_eq!(mocktail_rust_pinned_apk_archive_filename_valid(valid_fn.as_ptr(), 8), 1);

        let invalid_fn1 = CString::new("../base.apk").unwrap();
        assert_eq!(mocktail_rust_pinned_apk_archive_filename_valid(invalid_fn1.as_ptr(), 11), 0);

        let invalid_fn2 = CString::new("base.zip").unwrap();
        assert_eq!(mocktail_rust_pinned_apk_archive_filename_valid(invalid_fn2.as_ptr(), 8), 0);

        assert_eq!(mocktail_rust_pinned_apk_archive_limits_valid(102828147, 1024 * 1024 * 1024), 1);
        assert_eq!(mocktail_rust_pinned_apk_archive_limits_valid(0, 1024 * 1024 * 1024), 0);
        assert_eq!(mocktail_rust_pinned_apk_archive_limits_valid(2000 * 1024 * 1024, 1024 * 1024 * 1024), 0);
    }

    #[test]
    fn test_section107_vulkan_swapchain_policy() {
        let sup = [
            CString::new("VK_KHR_surface").unwrap(),
            CString::new("VK_KHR_get_surface_capabilities2").unwrap(),
            CString::new("VK_EXT_surface_maintenance1").unwrap(),
        ];
        let sup_ptrs: Vec<*const c_char> = sup.iter().map(|s| s.as_ptr()).collect();
        let en = [CString::new("VK_KHR_surface").unwrap()];
        let en_ptrs: Vec<*const c_char> = en.iter().map(|s| s.as_ptr()).collect();
        let mut out = [0 as c_char; 256];
        let mut out_len = 0usize;
        let rc = mocktail_rust_vulkan_select_surface_maintenance_exts(
            sup_ptrs.as_ptr(),
            sup_ptrs.len(),
            en_ptrs.as_ptr(),
            en_ptrs.len(),
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        );
        assert_eq!(rc, 1);
        let text = unsafe { CStr::from_ptr(out.as_ptr()) }.to_str().unwrap();
        assert_eq!(text, "VK_KHR_get_surface_capabilities2\nVK_EXT_surface_maintenance1");

        // Missing maintenance extension -> returns 0 (cannot enable)
        let rc_none = mocktail_rust_vulkan_select_surface_maintenance_exts(
            en_ptrs.as_ptr(),
            en_ptrs.len(),
            std::ptr::null(),
            0,
            out.as_mut_ptr(),
            out.len(),
            &mut out_len,
        );
        assert_eq!(rc_none, 0);
        assert_eq!(out_len, 0);

        // Image policy fallback & mailbox override
        assert_eq!(mocktail_rust_vulkan_swapchain_image_policy(3 /* Fifo */, VK_PRESENT_MODE_MAILBOX_KHR), 4 /* Mailbox */);
        assert_eq!(mocktail_rust_vulkan_swapchain_image_policy(5 /* Immediate */, VK_PRESENT_MODE_FIFO_KHR), 3 /* Fifo */);
        assert_eq!(mocktail_rust_vulkan_swapchain_image_policy(1 /* Vsync */, VK_PRESENT_MODE_FIFO_KHR), 1 /* Vsync */);
    }

    #[test]
    fn test_section108_texture_override() {
        let dir = std::env::temp_dir().join(format!("mocktail_rust_tex_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let dir_c = CString::new(dir.to_string_lossy().as_bytes()).unwrap();
        assert_eq!(mocktail_rust_texture_override_has_png(dir_c.as_ptr()), 0);
        std::fs::write(dir.join("note.txt"), b"hi").unwrap();
        assert_eq!(mocktail_rust_texture_override_has_png(dir_c.as_ptr()), 0);
        std::fs::write(dir.join("0001.png"), b"\x89PNG").unwrap();
        assert_eq!(mocktail_rust_texture_override_has_png(dir_c.as_ptr()), 1);
        let _ = std::fs::remove_dir_all(&dir);

        let h = mocktail_rust_texture_override_hash_bytes(b"abc".as_ptr(), 3);
        assert_eq!(h, 0xe71fa2190541574bu64);
        let mut name = [0 as c_char; 32];
        assert_eq!(mocktail_rust_texture_override_hash_name(h, name.as_mut_ptr(), name.len()), 0);
        let name_str = unsafe { CStr::from_ptr(name.as_ptr()) }.to_str().unwrap();
        assert_eq!(name_str, "e71fa2190541574b");

        // Nearest-neighbor 1x1 -> 2x2 integer upscale + box downsample
        let src = [10u8, 20, 30, 40];
        let mut up = [0u8; 2 * 2 * 4];
        assert_eq!(mocktail_rust_texture_override_resample_rgba(src.as_ptr(), 1, 1, 2, 2, up.as_mut_ptr()), 0);
        assert_eq!(&up[0..4], &src);
        assert_eq!(&up[12..16], &src);

        let mut down = [0u8; 4];
        assert_eq!(mocktail_rust_texture_override_resample_rgba(up.as_ptr(), 2, 2, 1, 1, down.as_mut_ptr()), 0);
        assert_eq!(down, src);
    }

    #[test]
    fn test_section109_etc1_sky_transcoder() {
        let sky = CString::new("/data/pkg/assets/android/textures/sky/day.tex").unwrap();
        let nonsky = CString::new("/data/pkg/assets/android/textures/ui/btn.tex").unwrap();
        assert_eq!(mocktail_rust_etc1_is_bundled_sky_texture(sky.as_ptr()), 1);
        assert_eq!(mocktail_rust_etc1_is_bundled_sky_texture(nonsky.as_ptr()), 0);

        // Build valid 4x4 ETC1 KTX1 file (64-byte header + 4-byte imageSize + 8-byte ETC1 block = 76 bytes)
        let mut ktx = vec![0u8; 76];
        ktx[0..12].copy_from_slice(&[0xab, 0x4b, 0x54, 0x58, 0x20, 0x31, 0x31, 0xbb, 0x0d, 0x0a, 0x1a, 0x0a]);
        ktx[12..16].copy_from_slice(&0x04030201u32.to_le_bytes()); // LE
        ktx[20..24].copy_from_slice(&1u32.to_le_bytes()); // typeSize = 1
        ktx[28..32].copy_from_slice(&0x00008d64u32.to_le_bytes()); // GL_ETC1_RGB8_OES
        ktx[32..36].copy_from_slice(&0x00001907u32.to_le_bytes()); // GL_RGB
        ktx[36..40].copy_from_slice(&4u32.to_le_bytes()); // w=4
        ktx[40..44].copy_from_slice(&4u32.to_le_bytes()); // h=4
        ktx[52..56].copy_from_slice(&1u32.to_le_bytes()); // faces=1
        ktx[56..60].copy_from_slice(&1u32.to_le_bytes()); // mips=1
        ktx[64..68].copy_from_slice(&8u32.to_le_bytes()); // imageSize=8
        assert_eq!(mocktail_rust_etc1_transcode_ktx1_for_vulkan(ktx.as_mut_ptr(), ktx.len()), 1);
        let new_fmt = u32::from_le_bytes([ktx[28], ktx[29], ktx[30], ktx[31]]);
        assert_eq!(new_fmt, 0x000083f0u32); // GL_COMPRESSED_RGB_S3TC_DXT1

        let mut bc1 = [0u8; 8];
        let etc1 = [0xffu8, 0x80, 0x00, 0x02, 0, 0, 0, 0];
        assert_eq!(mocktail_rust_etc1_convert_rgb_block_to_bc1(etc1.as_ptr(), bc1.as_mut_ptr()), 0);
        let ep0 = u16::from_le_bytes([bc1[0], bc1[1]]);
        let ep1 = u16::from_le_bytes([bc1[2], bc1[3]]);
        assert!(ep0 > ep1);
    }

    #[test]
    fn test_section111_graphics_launch_policy() {
        assert_eq!(mocktail_rust_graphics_is_haswell_intel(0x0412), 1);
        assert_eq!(mocktail_rust_graphics_is_haswell_intel(0x5916), 0);
        assert_eq!(mocktail_rust_graphics_is_legacy_intel(0x0a16), 1);
        assert_eq!(mocktail_rust_graphics_is_legacy_intel(0x1616), 1);
        assert_eq!(mocktail_rust_graphics_is_legacy_intel(0x1916), 0);
        assert_eq!(mocktail_rust_graphics_is_legacy_nvidia(0x1292), 1);
        assert_eq!(mocktail_rust_graphics_is_legacy_nvidia(0x1380), 0);

        let haswell_cpu = CString::new(
            "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 69\n",
        )
        .unwrap();
        let skylake_cpu = CString::new(
            "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 94\n",
        )
        .unwrap();
        let bulldozer_cpu = CString::new(
            "processor\t: 0\nvendor_id\t: AuthenticAMD\ncpu family\t: 21\nmodel\t\t: 2\n",
        )
        .unwrap();
        let zen_cpu = CString::new(
            "processor\t: 0\nvendor_id\t: AuthenticAMD\ncpu family\t: 23\nmodel\t\t: 113\n",
        )
        .unwrap();
        assert_eq!(mocktail_rust_graphics_is_legacy_cpu(haswell_cpu.as_ptr()), 1);
        assert_eq!(mocktail_rust_graphics_is_legacy_cpu(skylake_cpu.as_ptr()), 0);
        assert_eq!(mocktail_rust_graphics_is_legacy_cpu(bulldozer_cpu.as_ptr()), 1);
        assert_eq!(mocktail_rust_graphics_is_legacy_cpu(zen_cpu.as_ptr()), 0);
        assert_eq!(
            resolve_auto_graphics_backend_from_hardware(
                haswell_cpu.to_str().unwrap(),
                &[(0x8086, 0x0a16), (0x10de, 0x1292)],
            ),
            "opengl"
        );
        assert_eq!(
            resolve_auto_graphics_backend_from_hardware(
                skylake_cpu.to_str().unwrap(),
                &[(0x8086, 0x1912), (0x10de, 0x1380)],
            ),
            "direct-vulkan"
        );
        assert_eq!(
            resolve_auto_graphics_backend_from_hardware(
                zen_cpu.to_str().unwrap(),
                &[(0x10de, 0x1292)],
            ),
            "opengl"
        );

        let mut parsed = 0u32;
        let ok = CString::new("0x8086\n").unwrap();
        let bad = CString::new("0x10000").unwrap();
        assert_eq!(mocktail_rust_graphics_parse_pci_hex(ok.as_ptr(), &mut parsed), 1);
        assert_eq!(parsed, 0x8086);
        assert_eq!(mocktail_rust_graphics_parse_pci_hex(bad.as_ptr(), &mut parsed), 0);

        let mem_big = CString::new("MemTotal:       8388608 kB\n").unwrap();
        let mem_small = CString::new("MemTotal:       2097152 kB\n").unwrap();
        assert_eq!(mocktail_rust_graphics_anv_sys_mem_limit_percent(mem_big.as_ptr()), 75);
        assert_eq!(mocktail_rust_graphics_anv_sys_mem_limit_percent(mem_small.as_ptr()), 50);

        let f_i686 = CString::new("radeon_icd.i686.json").unwrap();
        let f_x64 = CString::new("radeon_icd.x86_64.json").unwrap();
        assert_eq!(mocktail_rust_graphics_is_foreign_icd_name(f_i686.as_ptr(), 0), 1);
        assert_eq!(mocktail_rust_graphics_is_foreign_icd_name(f_x64.as_ptr(), 0), 0);
        assert_eq!(mocktail_rust_graphics_is_foreign_icd_name(f_x64.as_ptr(), 1), 1);

        let icd_dir = std::env::temp_dir().join(format!("mocktail_rust_icd_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&icd_dir);
        std::fs::create_dir_all(&icd_dir).unwrap();
        std::fs::write(icd_dir.join("radeon_icd.i686.json"), b"{}").unwrap();
        std::fs::write(icd_dir.join("radeon_icd.x86_64.json"), b"{}").unwrap();
        let dirs_c = CString::new(icd_dir.to_string_lossy().as_bytes()).unwrap();
        let needle_c = CString::new("radeon_icd").unwrap();
        let mut selected = [0 as c_char; 512];
        assert_eq!(mocktail_rust_graphics_select_icd_manifest(dirs_c.as_ptr(), needle_c.as_ptr(), 0, selected.as_mut_ptr(), selected.len()), 0);
        let sel_str = unsafe { CStr::from_ptr(selected.as_ptr()) }.to_str().unwrap();
        assert!(sel_str.ends_with("radeon_icd.x86_64.json"));
        let sel_c = CString::new(sel_str).unwrap();
        assert_eq!(mocktail_rust_graphics_is_radv_icd_list(sel_c.as_ptr()), 1);
        let _ = std::fs::remove_dir_all(&icd_dir);
    }

    #[test]
    fn test_section112_graphics_backend() {
        let n0 = unsafe { CStr::from_ptr(mocktail_rust_graphics_backend_name_ptr(0)) }.to_str().unwrap();
        let n1 = unsafe { CStr::from_ptr(mocktail_rust_graphics_backend_name_ptr(1)) }.to_str().unwrap();
        let n2 = unsafe { CStr::from_ptr(mocktail_rust_graphics_backend_name_ptr(2)) }.to_str().unwrap();
        let n9 = unsafe { CStr::from_ptr(mocktail_rust_graphics_backend_name_ptr(9)) }.to_str().unwrap();
        assert_eq!((n0, n1, n2, n9), ("angle-vulkan", "direct-vulkan", "system-egl", "unknown"));

        let backends = [0i32, 1, 2];
        let states = [0i32, 2, 1]; // angle=unavail, direct=ready, egl=probed
        let accels = [0i32, 2, 1]; // angle=unknown, direct=hw, egl=sw
        let d0 = CString::new("no vulkan").unwrap();
        let d1 = CString::new("vk ready").unwrap();
        let d2 = CString::new("llvmpipe").unwrap();
        let details = [d0.as_ptr(), d1.as_ptr(), d2.as_ptr()];
        let mut selected = -1;
        let mut detail = [0 as c_char; 256];
        // Request angle with fallback enabled, require_hw=1, require_runtime=1 -> falls back to direct-vulkan
        let rc = mocktail_rust_graphics_backend_select(
            0, 1, 1, 1,
            backends.as_ptr(), states.as_ptr(), accels.as_ptr(), details.as_ptr(), 3,
            &mut selected, detail.as_mut_ptr(), detail.len(),
        );
        assert_eq!(rc, 0);
        assert_eq!(selected, 1);

        // Request angle without fallback -> fails with reason
        let rc_fail = mocktail_rust_graphics_backend_select(
            0, 0, 1, 1,
            backends.as_ptr(), states.as_ptr(), accels.as_ptr(), details.as_ptr(), 3,
            &mut selected, detail.as_mut_ptr(), detail.len(),
        );
        assert_eq!(rc_fail, -1);
    }

    #[test]
    fn test_section113_surface_lifecycle_and_window() {
        let eng = mocktail_rust_surface_lifecycle_new();
        assert!(!eng.is_null());
        assert_eq!(mocktail_rust_surface_lifecycle_is_active(eng), 0);
        let mut err = [0 as c_char; 128];
        // Zero or sub-minimum (<160x120) size rejected on activate, 160x120 accepted
        assert_eq!(mocktail_rust_surface_lifecycle_activate(eng, 0x100, 159, 120, 1.0, err.as_mut_ptr(), err.len()), 2);
        // Valid activate
        assert_eq!(mocktail_rust_surface_lifecycle_activate(eng, 0x100, 160, 120, 1.0, err.as_mut_ptr(), err.len()), 0);
        assert_eq!(mocktail_rust_surface_lifecycle_is_active(eng), 1);

        // Coalesce resize events on same generation
        assert_eq!(mocktail_rust_surface_lifecycle_observe(eng, 0x100, 1300, 720, 1.0, err.as_mut_ptr(), err.len()), 0);
        assert_eq!(mocktail_rust_surface_lifecycle_observe(eng, 0x100, 1400, 800, 2.0, err.as_mut_ptr(), err.len()), 0);
        let mut ev = MocktailRustSurfaceEvent::default();
        assert_eq!(mocktail_rust_surface_lifecycle_poll(eng, &mut ev), 1);
        assert_eq!((ev.event_type, ev.surface.width, ev.surface.height), (1, 1400, 800));
        assert_eq!(mocktail_rust_surface_lifecycle_poll(eng, &mut ev), 0);

        // Recreate emits Destroyed -> Created -> Changed with generation 2
        assert_eq!(mocktail_rust_surface_lifecycle_recreate(eng, err.as_mut_ptr(), err.len()), 0);
        assert_eq!(mocktail_rust_surface_lifecycle_poll(eng, &mut ev), 1);
        assert_eq!(ev.event_type, 2);
        assert_eq!(mocktail_rust_surface_lifecycle_poll(eng, &mut ev), 1);
        assert_eq!((ev.event_type, ev.surface.generation), (0, 2));
        mocktail_rust_surface_lifecycle_free(eng);

        assert_eq!(mocktail_rust_window_apply_high_dpi_flag(0x10, 1, 0x2000), 0x2010);
        assert_eq!(mocktail_rust_window_apply_high_dpi_flag(0x2010, 0, 0x2000), 0x10);
        let wl = CString::new("wayland").unwrap();
        let x11 = CString::new("x11").unwrap();
        assert_eq!(mocktail_rust_window_direct_vulkan_requires_sync(wl.as_ptr()), 1);
        assert_eq!(mocktail_rust_window_direct_vulkan_requires_sync(x11.as_ptr()), 0);
    }

    #[test]
    fn test_section114_presence_resolver() {
        let raw = CString::new("foo=1; .ROBLOSECURITY=_|WARNING:secret_val; Path=/").unwrap();
        let mut cookie = [0 as c_char; 256];
        assert_eq!(mocktail_rust_presence_extract_cookie(raw.as_ptr(), cookie.as_mut_ptr(), cookie.len()), 0);
        let cstr = unsafe { CStr::from_ptr(cookie.as_ptr()) }.to_str().unwrap();
        assert_eq!(cstr, "_|WARNING:secret_val");

        let json_ok = CString::new(r#"{"userPresences":[{"userPresenceType":2,"placeId":1818,"gameId":"job-xyz"}]}"#).unwrap();
        let mut place = 0i64;
        let mut gid = [0 as c_char; 128];
        let mut err = [0 as c_char; 256];
        assert_eq!(mocktail_rust_presence_parse_follow_response(json_ok.as_ptr(), &mut place, gid.as_mut_ptr(), gid.len(), err.as_mut_ptr(), err.len()), 0);
        assert_eq!(place, 1818);
        assert_eq!(unsafe { CStr::from_ptr(gid.as_ptr()) }.to_str().unwrap(), "job-xyz");

        let json_offline = CString::new(r#"{"userPresences":[{"userPresenceType":0}]}"#).unwrap();
        assert_eq!(mocktail_rust_presence_parse_follow_response(json_offline.as_ptr(), &mut place, gid.as_mut_ptr(), gid.len(), err.as_mut_ptr(), err.len()), -1);
    }

    #[test]
    fn test_section115_update_state_file() {
        let dir = std::env::temp_dir().join(format!("mocktail_rust_state_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let good = dir.join("state.json");
        let bad = dir.join("bad.json");
        std::fs::write(&good, br#"{"version":1}"#).unwrap();
        std::fs::write(&bad, b"[1,2,3]").unwrap();

        let good_c = CString::new(good.to_string_lossy().as_bytes()).unwrap();
        let bad_c = CString::new(bad.to_string_lossy().as_bytes()).unwrap();
        let mut out = [0 as c_char; 256];
        let mut len = 0usize;
        assert_eq!(mocktail_rust_update_state_read_json_file(good_c.as_ptr(), out.as_mut_ptr(), out.len(), &mut len), 0);
        assert_eq!(len, 13);
        assert_eq!(mocktail_rust_update_state_read_json_file(bad_c.as_ptr(), out.as_mut_ptr(), out.len(), &mut len), -1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_section116_webview_helper_policy() {
        let fbsd = CString::new("FreeBSD 14.1-RELEASE").unwrap();
        let lin = CString::new("6.8.0-generic").unwrap();
        assert_eq!(mocktail_rust_webview_should_disable_sandbox(fbsd.as_ptr(), std::ptr::null()), 1);
        assert_eq!(mocktail_rust_webview_should_disable_sandbox(lin.as_ptr(), std::ptr::null()), 0);
        assert_eq!(mocktail_rust_webview_should_disable_hw_accel(1, std::ptr::null()), 1);
        let zero = CString::new("0").unwrap();
        assert_eq!(mocktail_rust_webview_should_disable_hw_accel(1, zero.as_ptr()), 0);

        let mut ua = [0 as c_char; 256];
        let bad_ver = CString::new("2.0\nEvil").unwrap();
        assert_eq!(mocktail_rust_webview_build_user_agent(bad_ver.as_ptr(), ua.as_mut_ptr(), ua.len()), 0);
        let ua_s = unsafe { CStr::from_ptr(ua.as_ptr()) }.to_str().unwrap();
        assert!(ua_s.contains("2.725.1142"));

        let mut allowed = 0;
        let mut priv_allowed = 0;
        let mut scheme = [0 as c_char; 64];
        let mut host = [0 as c_char; 128];
        let rbx = CString::new("https://www.roblox.com/login").unwrap();
        assert_eq!(mocktail_rust_webview_evaluate_navigation_uri(rbx.as_ptr(), &mut allowed, &mut priv_allowed, scheme.as_mut_ptr(), scheme.len(), host.as_mut_ptr(), host.len()), 1);
        assert_eq!((allowed, priv_allowed), (1, 1));
        assert_eq!(mocktail_rust_webview_is_browser_login_url(rbx.as_ptr()), 1);

        let triple_slash = CString::new("https:///missing-host").unwrap();
        assert_eq!(mocktail_rust_webview_evaluate_navigation_uri(triple_slash.as_ptr(), &mut allowed, &mut priv_allowed, scheme.as_mut_ptr(), scheme.len(), host.as_mut_ptr(), host.len()), 0);
        assert_eq!((allowed, priv_allowed), (0, 0));

        let essential = CString::new("https://apis.rbxcdn.com/captcha/v1/metadata").unwrap();
        assert_eq!(mocktail_rust_webview_is_essential_resource(essential.as_ptr()), 1);

        let cmd = br#"{"moduleID":"Navigation","functionName":"navigateToFeature","callbackID":"cb\"1","params":{"params":{"feature":"CaptchaSuccess"}}}"#;
        let mut ev_type = -1;
        let mut cb = [0 as c_char; 64];
        assert_eq!(mocktail_rust_webview_parse_captcha_event(cmd.as_ptr() as *const c_char, cmd.len(), &mut ev_type, cb.as_mut_ptr(), cb.len()), 1);
        assert_eq!(ev_type, 1);
        let mut script = [0 as c_char; 512];
        let cb_len = unsafe { CStr::from_ptr(cb.as_ptr()) }.to_bytes().len();
        assert_eq!(mocktail_rust_webview_build_callback_script(cb.as_ptr(), cb_len, script.as_mut_ptr(), script.len()), 0);
        let script_s = unsafe { CStr::from_ptr(script.as_ptr()) }.to_str().unwrap();
        assert!(script_s.contains("nativeCallback(\"cb\\\"1\""));
    }

    #[test]
    fn test_section117_apkpure_provider() {
        let valid = b"2.681.812";
        assert!(mocktail_rust_apkpure_is_valid_version_name(valid.as_ptr() as *const c_char, valid.len()));
        let bad = b"../bad";
        assert!(!mocktail_rust_apkpure_is_valid_version_name(bad.as_ptr() as *const c_char, bad.len()));

        let mut meta = Vec::new();
        meta.extend_from_slice(&[0x2a, 3]);
        meta.extend_from_slice(b"812");
        meta.extend_from_slice(&[0x32, 9]);
        meta.extend_from_slice(b"2.681.812:");
        meta.extend_from_slice(b"XAPKJ\x00\x00https://user:pass@d.apkpure.com/b/APK/bad");
        meta.push(0);
        meta.extend_from_slice(b"APKJ\x00\x00https://d.apkpure.com./b/APK/com.roblox.client?versionCode=812");
        meta.push(0);

        let mut ver_buf = [0 as c_char; 64];
        let mut code = 0u64;
        let mut err_buf = [0 as c_char; 256];
        let rc = mocktail_rust_apkpure_parse_latest(
            meta.as_ptr(),
            meta.len(),
            ver_buf.as_mut_ptr(),
            ver_buf.len(),
            &mut code,
            err_buf.as_mut_ptr(),
            err_buf.len(),
        );
        assert_eq!(rc, 0);
        let ver_s = unsafe { CStr::from_ptr(ver_buf.as_ptr()) }.to_str().unwrap();
        assert_eq!(ver_s, "2.681.812");
        assert_eq!(code, 812);

        let target_ver = CString::new("2.681.812").unwrap();
        let mut urls_buf = [0 as c_char; 1024];
        let rc2 = mocktail_rust_apkpure_parse_exact_urls(
            meta.as_ptr(),
            meta.len(),
            target_ver.as_ptr(),
            812,
            urls_buf.as_mut_ptr(),
            urls_buf.len(),
            err_buf.as_mut_ptr(),
            err_buf.len(),
        );
        assert_eq!(rc2, 0);
        let urls_s = unsafe { CStr::from_ptr(urls_buf.as_ptr()) }.to_str().unwrap();
        assert!(!urls_s.contains("user:pass"));
        assert!(urls_s.contains("https://d.apkpure.com./b/APK/com.roblox.client?versionCode=812"));

        let tmp = std::env::temp_dir().join("mocktail_apkpure_zip_test.bin");
        std::fs::write(&tmp, b"PK\x03\x04rest").unwrap();
        let tmp_c = CString::new(tmp.to_string_lossy().as_bytes()).unwrap();
        assert!(mocktail_rust_apkpure_has_zip_magic(tmp_c.as_ptr()));
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_section118_roblox_text_font_resolver() {
        let mut buf = [0 as c_char; 256];
        let mut scale = 0.0f32;
        let mut exact = false;
        let rc = mocktail_rust_resolve_roblox_text_font(
            0,
            std::ptr::null(),
            0,
            buf.as_mut_ptr(),
            buf.len(),
            &mut scale,
            &mut exact,
        );
        assert!(rc >= 0);
    }

    #[test]
    fn test_section119_runtime_config() {
        let host = b"127.0.0.1";
        let port = b"8080";
        let scheme = b"http";
        let mut out_scheme = [0 as c_char; 32];
        let mut out_port = 0i32;
        assert!(mocktail_rust_network_proxy_parse(
            host.as_ptr() as *const c_char, host.len(),
            port.as_ptr() as *const c_char, port.len(),
            scheme.as_ptr() as *const c_char, scheme.len(),
            std::ptr::null(), 0,
            std::ptr::null(), 0,
            out_scheme.as_mut_ptr(), out_scheme.len(),
            &mut out_port,
        ));
        assert_eq!(out_port, 8080);

        let mut url_buf = [0 as c_char; 256];
        let url_len = mocktail_rust_network_proxy_build_url(
            scheme.as_ptr() as *const c_char, scheme.len(),
            host.as_ptr() as *const c_char, host.len(),
            out_port,
            std::ptr::null(), 0,
            std::ptr::null(), 0,
            false,
            url_buf.as_mut_ptr(), url_buf.len(),
        );
        assert!(url_len > 0);

        let vulkan = b"vulkan";
        assert_ne!(mocktail_rust_runtime_config_parse_graphics_backend(vulkan.as_ptr() as *const c_char, vulkan.len()), -1);

        let mut valid = false;
        let yes = b"true";
        assert!(mocktail_rust_runtime_config_parse_bool(yes.as_ptr() as *const c_char, yes.len(), false, &mut valid));
        assert!(valid);

        let num = b"42";
        assert_eq!(mocktail_rust_runtime_config_parse_positive_int(num.as_ptr() as *const c_char, num.len(), 10), 42);

        let app_id = b"123456789012345678";
        assert!(mocktail_rust_runtime_config_is_discord_app_id(app_id.as_ptr() as *const c_char, app_id.len()));
        let short_id = b"1234567890";
        assert!(!mocktail_rust_runtime_config_is_discord_app_id(short_id.as_ptr() as *const c_char, short_id.len()));
        let text = b"Playing Roblox";
        assert!(mocktail_rust_runtime_config_is_discord_text(text.as_ptr() as *const c_char, text.len(), 128));
    }

    #[test]
    fn test_section120_runtime_config_bootstrap() {
        let mut yaml_len = 0usize;
        let ptr = mocktail_rust_runtime_config_default_yaml_ptr(&mut yaml_len);
        assert!(!ptr.is_null() && yaml_len > 0);

        let tmp = std::env::temp_dir().join(format!("mocktail_cfg_boot_{}.yaml", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let tmp_c = CString::new(tmp.to_string_lossy().as_bytes()).unwrap();
        let mut created = false;
        let mut err = [0 as c_char; 256];
        let rc = mocktail_rust_runtime_config_ensure_file(tmp_c.as_ptr(), &mut created, err.as_mut_ptr(), err.len());
        assert_eq!(rc, 0);
        assert!(created);
        assert!(tmp.exists());
        let rc2 = mocktail_rust_runtime_config_ensure_file(tmp_c.as_ptr(), &mut created, err.as_mut_ptr(), err.len());
        assert_eq!(rc2, 0);
        assert!(!created);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn test_section121_host_allocator_bridge() {
        let p = mocktail_rust_host_allocate(64);
        assert!(!p.is_null());
        assert!(mocktail_rust_host_usable_size(p) >= 64);
        let p2 = mocktail_rust_host_reallocate(p, 128);
        assert!(!p2.is_null());
        assert!(mocktail_rust_host_usable_size(p2) >= 128);
        mocktail_rust_host_free(p2);

        let pa = mocktail_rust_host_aligned_allocate(256, 64);
        assert!(!pa.is_null());
        assert_eq!((pa as usize) % 64, 0);
        mocktail_rust_host_free(pa);
    }

    #[test]
    fn test_section122_host_abi_profile_and_experiment() {
        let ranges = [
            MocktailRustConstructorRange { begin: 1, end_exclusive: 4 },
            MocktailRustConstructorRange { begin: 6, end_exclusive: 8 },
        ];
        assert!(mocktail_rust_host_abi_has_valid_ranges(ranges.as_ptr(), ranges.len(), 8, 10));
        assert!(mocktail_rust_host_abi_allows_constructor(ranges.as_ptr(), ranges.len(), 8, 10, 2));
        assert!(!mocktail_rust_host_abi_allows_constructor(ranges.as_ptr(), ranges.len(), 8, 10, 5));
        assert_eq!(mocktail_rust_host_abi_range_begin(ranges.as_ptr(), ranges.len(), 8, 10), 1);
        assert_eq!(mocktail_rust_host_abi_range_end_exclusive(ranges.as_ptr(), ranges.len(), 8, 10), 8);
        assert!(mocktail_rust_host_abi_should_init_mimalloc_thread(ranges.as_ptr(), ranges.len(), 8, 10, 3, 3));
        assert!(!mocktail_rust_host_abi_should_init_mimalloc_thread(ranges.as_ptr(), ranges.len(), 8, 10, 3, 4));
        assert_eq!(mocktail_rust_host_abi_resolve_allocator_strategy(1, true, true), 0);
        assert_eq!(mocktail_rust_host_abi_resolve_allocator_strategy(0, true, false), 1);
        assert_eq!(mocktail_rust_host_abi_resolve_allocator_strategy(1, false, true), 1);
    }

    #[test]
    fn test_section123_window_game_surface_bridge() {
        let ev = MocktailRustSurfaceEvent {
            event_type: 0,
            surface: MocktailRustSurfaceSnapshot {
                generation: 1,
                native_window: 0x1234,
                width: 1280,
                height: 720,
                available: 1,
                dpi_scale: 1.0,
            },
        };
        let mut err = [0 as c_char; 256];
        let rc = mocktail_rust_game_surface_bridge_validate_event(&ev, err.as_mut_ptr(), err.len());
        assert_eq!(rc, 0);
        let mut snap = MocktailRustGameSurfaceBridgeSnapshot {
            accepted_events: 0,
            duplicate_events: 0,
            last_generation: 0,
            last_event_type: -1,
            failed: false,
        };
        mocktail_rust_game_surface_bridge_record_event(&ev, true, &mut snap);
        assert_eq!(snap.accepted_events, 1);
        assert_eq!(snap.last_generation, 1);
        assert!(!snap.failed);
    }

    #[test]
    fn test_graphics_vulkan_bug_fixes() {
        // 1. Overflow guard in mocktail_rust_decode_etc_image_block_rows:
        // ((u32::MAX as u64 + 3) / 4)^2 * 16 would not wrap on u64 alone only for some sizes,
        // whereas (width=0xFFFF_FFFF, height=0xFFFF_FFFF) width*height*16 wraps or exceeds tiny buffers cleanly.
        let mut src_block = [0u8; 16];
        let mut dst_pixel = [0u8; 16];
        assert_eq!(
            mocktail_rust_decode_etc_image_block_rows(
                MocktailRustEtcFormat::Etc2Rgb8,
                src_block.as_ptr(),
                src_block.len(),
                u32::MAX,
                u32::MAX,
                0,
                1,
                dst_pixel.as_mut_ptr(),
                dst_pixel.len(),
            ),
            0
        );
        // Also test 2^31 x 2^31: width * height * 4 = 2^64 (wraps u64 to 0 without checked_mul!).
        assert_eq!(
            mocktail_rust_decode_etc_image_block_rows(
                MocktailRustEtcFormat::Etc2Rgb8,
                src_block.as_ptr(),
                src_block.len(),
                1u32 << 31,
                1u32 << 31,
                0,
                1,
                dst_pixel.as_mut_ptr(),
                dst_pixel.len(),
            ),
            0
        );
        let _ = &mut src_block;

        // 2. Empty host_modes_ptr with host_count == 0 in mocktail_rust_present_mode_filter
        let mut out_mode = 99u32;
        let mut out_count = 99usize;
        let pm_rc = mocktail_rust_present_mode_filter(
            MocktailRustPresentModePolicy::Vsync as c_int,
            std::ptr::null(),
            0,
            &mut out_mode,
            1,
            &mut out_count,
        );
        assert_eq!(pm_rc, 0);
        assert_eq!(out_count, 0);
        assert_eq!(
            mocktail_rust_present_mode_filter(
                MocktailRustPresentModePolicy::Vsync as c_int,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
                &mut out_count,
            ),
            0
        );
        assert_eq!(out_count, 0);

        // 3. Null pointer guards in mocktail_rust_translate_android_vulkan_instance_extensions
        let mut ext_count = 0usize;
        let mut err = [0 as c_char; 128];
        assert_eq!(
            mocktail_rust_translate_android_vulkan_instance_extensions(
                std::ptr::null(),
                1,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                0,
                &mut ext_count,
                err.as_mut_ptr(),
                err.len(),
            ),
            -1
        );
        let android_surface = CString::new("VK_KHR_android_surface").unwrap();
        let android_exts = [android_surface.as_ptr()];
        assert_eq!(
            mocktail_rust_translate_android_vulkan_instance_extensions(
                android_exts.as_ptr(),
                android_exts.len(),
                std::ptr::null(),
                1,
                std::ptr::null_mut(),
                0,
                &mut ext_count,
                err.as_mut_ptr(),
                err.len(),
            ),
            -1
        );

        // 4. Atomic validation before in-place transcode in mocktail_rust_etc1_transcode_ktx1_for_vulkan
        let mut ktx = vec![0u8; 64 + 4 + 32 + 4];
        ktx[0..12].copy_from_slice(&[0xab, 0x4b, 0x54, 0x58, 0x20, 0x31, 0x31, 0xbb, 0x0d, 0x0a, 0x1a, 0x0a]);
        ktx[12..16].copy_from_slice(&0x0403_0201u32.to_le_bytes());
        ktx[20..24].copy_from_slice(&1u32.to_le_bytes());
        ktx[28..32].copy_from_slice(&0x0000_8d64u32.to_le_bytes());
        ktx[32..36].copy_from_slice(&0x0000_1907u32.to_le_bytes());
        ktx[36..40].copy_from_slice(&8u32.to_le_bytes()); // width = 8
        ktx[40..44].copy_from_slice(&8u32.to_le_bytes()); // height = 8
        ktx[52..56].copy_from_slice(&1u32.to_le_bytes()); // faces = 1
        ktx[56..60].copy_from_slice(&2u32.to_le_bytes()); // mip_levels = 2
        ktx[64..68].copy_from_slice(&32u32.to_le_bytes()); // mip 0 size = 32
        for (i, b) in ktx[68..100].iter_mut().enumerate() {
            *b = (i as u8) ^ 0x5a;
        }
        // mip 1 size claims 8 bytes, but no payload follows -> must fail and leave mip 0 untouched
        ktx[100..104].copy_from_slice(&8u32.to_le_bytes());
        let before = ktx.clone();
        assert_eq!(mocktail_rust_etc1_transcode_ktx1_for_vulkan(ktx.as_mut_ptr(), ktx.len()), 0);
        assert_eq!(ktx, before);

        // 5. EGL vendor manifest selector prefers sorted matching GLVND JSON
        let egl_dir = std::env::temp_dir().join(format!("mocktail_egl_vendor_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&egl_dir);
        std::fs::create_dir_all(&egl_dir).unwrap();
        std::fs::write(egl_dir.join("10_nvidia.json"), "{}").unwrap();
        std::fs::write(egl_dir.join("50_mesa.json"), "{}").unwrap();
        let dirs_c = CString::new(egl_dir.to_string_lossy().as_ref()).unwrap();
        let mesa_c = CString::new("mesa").unwrap();
        let mut egl_out = [0 as c_char; 512];
        assert_eq!(
            mocktail_rust_graphics_select_egl_vendor_manifest(
                dirs_c.as_ptr(),
                mesa_c.as_ptr(),
                egl_out.as_mut_ptr(),
                egl_out.len(),
            ),
            0
        );
        let picked = unsafe { CStr::from_ptr(egl_out.as_ptr()) }.to_string_lossy().into_owned();
        assert!(picked.ends_with("50_mesa.json"));
        let _ = std::fs::remove_dir_all(&egl_dir);
    }

}
