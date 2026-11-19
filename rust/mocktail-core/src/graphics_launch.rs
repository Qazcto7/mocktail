//! Universal GPU, Vulkan ICD, EGL GLVND vendor, graphics backend capability
//! probing, and driver policy resolution across architectures and vendors.

use std::collections::HashSet;
use std::env;
use std::ffi::{c_char, CStr};
use std::fs;
use std::path::{Path, PathBuf};
use std::ptr;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MocktailHostGpuProbe {
    pub has_legacy_intel: i32,
    pub has_modern_intel: i32,
    pub has_legacy_nvidia: i32,
    pub has_modern_nvidia: i32,
    pub has_amd: i32,
    pub has_amd_legacy_radeon: i32,
    pub has_soc_vulkan: i32,
    pub has_soc_gles_only: i32,
    pub has_discrete_gpu: i32,
    pub has_integrated_gpu: i32,
    pub has_hw_vulkan_icd: i32,
    pub has_virtual_gpu: i32,
    pub nvidia_driver_major: u32,
    pub total_ram_mb: u64,
}

const DEFAULT_ICD_DIRS: &[&str] = &[
    "/etc/vulkan/icd.d",
    "/usr/share/vulkan/icd.d",
    "/usr/local/share/vulkan/icd.d",
];

fn write_cstr_buf(s: &str, out_buf: *mut c_char, out_cap: usize) -> i32 {
    if out_buf.is_null() || out_cap == 0 {
        return -1;
    }
    let bytes = s.as_bytes();
    if bytes.len() + 1 > out_cap {
        unsafe {
            *out_buf = 0;
        }
        return -1;
    }
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf.cast::<u8>(), bytes.len());
        *out_buf.add(bytes.len()) = 0;
    }
    0
}

fn cstr_to_opt_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

pub fn parse_pci_hex_str(raw: &str) -> Option<u32> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let hex_part = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex_part.is_empty() {
        return None;
    }
    u32::from_str_radix(hex_part, 16).ok()
}

pub fn parse_total_ram_mb_from_meminfo(meminfo_content: &str) -> u64 {
    for line in meminfo_content.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|tok| tok.parse::<u64>().ok())
                .unwrap_or(0);
            if kb > 0 {
                return kb / 1024;
            }
        }
    }
    0
}

pub fn probe_total_ram_mb() -> u64 {
    fs::read_to_string("/proc/meminfo")
        .ok()
        .map(|s| parse_total_ram_mb_from_meminfo(&s))
        .unwrap_or(0)
}

pub fn parse_nvidia_driver_major_str(content: &str) -> u32 {
    // Handles both `/proc/driver/nvidia/version` ("... Kernel Module  570.124.04 ...")
    // and `/sys/module/nvidia/version` ("570.124.04").
    for token in content.split(|c: char| c.is_whitespace() || c == ':') {
        if let Some((maj_str, rest)) = token.split_once('.') {
            if !maj_str.is_empty()
                && maj_str.bytes().all(|b| b.is_ascii_digit())
                && !rest.is_empty()
                && rest.bytes().next().is_some_and(|b| b.is_ascii_digit())
            {
                if let Ok(maj) = maj_str.parse::<u32>() {
                    if maj >= 300 {
                        return maj;
                    }
                }
            }
        }
    }
    0
}

pub fn probe_nvidia_driver_major() -> u32 {
    for path in ["/proc/driver/nvidia/version", "/sys/module/nvidia/version"] {
        if let Ok(content) = fs::read_to_string(path) {
            let maj = parse_nvidia_driver_major_str(&content);
            if maj > 0 {
                return maj;
            }
        }
    }
    0
}

pub fn is_legacy_intel_device_id(device_id: u32) -> bool {
    let hi = (device_id >> 8) & 0xff;
    // Gen 4..7.5 (GMA / Ironlake / Sandy Bridge / Ivy Bridge / Haswell)
    // Broadwell (0x16xx) also relies on HasVK in Mesa; ANV dropped Gen <= 8 in newer Mesa.
    matches!(
        hi,
        0x00 | 0x01 | 0x04 | 0x0a | 0x0c | 0x0d | 0x0f | 0x16 | 0x22 | 0x2a | 0x2e
    )
}

pub fn is_discrete_intel_device_id(device_id: u32) -> bool {
    let hi = (device_id >> 8) & 0xff;
    // DG1 (0x49xx), Arc Alchemist DG2 (0x56xx), Battlemage BMG (0xe2xx).
    matches!(hi, 0x49 | 0x56 | 0xe2)
}

pub fn is_legacy_nvidia_device_id(device_id: u32) -> bool {
    // Kepler and older (< Maxwell GM107 = 0x1380): Fermi/Tesla/Kepler GK1xx/GK2xx.
    device_id != 0 && device_id < 0x1340
}

pub fn is_turing_or_newer_nvidia_device_id(device_id: u32) -> bool {
    // NVK (Mesa Nouveau Vulkan) targets Turing (TU1xx = 0x1e00+) and newer cleanly.
    device_id >= 0x1e00
}

pub fn is_foreign_icd_filename(name: &str, host_is_aarch64: bool) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower.contains("i686") || lower.contains("i386") || lower.contains("x86_32") {
        return true;
    }
    if host_is_aarch64 {
        lower.contains("x86_64")
            || lower.contains("amd64")
            || lower.contains("armhf")
            || lower.contains("armv7")
            || lower.contains("riscv")
            || lower.contains("loongarch")
            || lower.contains("ppc64")
    } else if cfg!(target_arch = "riscv64") {
        lower.contains("x86_64")
            || lower.contains("amd64")
            || lower.contains("aarch64")
            || lower.contains("arm64")
            || lower.contains("armhf")
            || lower.contains("armv7")
    } else {
        // Default x86_64 / non-aarch64 64-bit Linux host
        lower.contains("aarch64")
            || lower.contains("arm64")
            || lower.contains("armhf")
            || lower.contains("armv7")
            || lower.contains("riscv")
            || lower.contains("loongarch")
            || lower.contains("ppc64")
    }
}

pub fn is_software_icd_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("lvp_icd")
        || lower.contains("lavapipe")
        || lower.contains("swiftshader")
        || lower.contains("llvmpipe")
        || lower.contains("softpipe")
}

pub fn is_virtual_icd_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("virtio_icd")
        || lower.contains("venus")
        || lower.contains("dzn_icd")
        || lower.contains("kosmickrisp")
}

fn host_is_aarch64() -> bool {
    cfg!(target_arch = "aarch64")
}

fn collect_icd_files(dirs: &[&str], target_is_aarch64: bool) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    let mut seen_paths = HashSet::new();
    for dir in dirs {
        let dir_path = Path::new(dir);
        let Ok(entries) = fs::read_dir(dir_path) else {
            continue;
        };
        let mut dir_entries: Vec<(String, PathBuf)> = entries
            .flatten()
            .filter_map(|entry| {
                let p = entry.path();
                if !p.is_file() {
                    return None;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                if !name.ends_with(".json") {
                    return None;
                }
                if is_foreign_icd_filename(&name, target_is_aarch64) {
                    return None;
                }
                Some((name, p))
            })
            .collect();
        // Prefer arch-qualified manifests before unqualified manifests inside each directory.
        dir_entries.sort_by(|a, b| {
            let a_unqual = a.0.ends_with("_icd.json");
            let b_unqual = b.0.ends_with("_icd.json");
            a_unqual.cmp(&b_unqual).then_with(|| a.0.cmp(&b.0))
        });
        for (name, p) in dir_entries {
            if seen_paths.insert(p.clone()) {
                out.push((name, p));
            }
        }
    }
    out
}

fn find_matching_icd(files: &[(String, PathBuf)], needles: &[&str]) -> Option<String> {
    for needle in needles {
        for (name, path) in files {
            if name.to_ascii_lowercase().contains(needle) {
                return Some(path.to_string_lossy().into_owned());
            }
        }
    }
    None
}

pub fn select_universal_icd_from_dirs(
    dirs: &[&str],
    probe: &MocktailHostGpuProbe,
    target_is_aarch64: bool,
) -> Option<String> {
    let all_files = collect_icd_files(dirs, target_is_aarch64);
    let hw_files: Vec<(String, PathBuf)> = all_files
        .into_iter()
        .filter(|(name, _)| !is_software_icd_name(name) && !is_virtual_icd_name(name))
        .collect();

    if probe.has_modern_nvidia != 0 {
        if let Some(found) = find_matching_icd(&hw_files, &["nvidia_icd", "nouveau_icd", "nvk"]) {
            return Some(found);
        }
    }
    if probe.has_amd != 0 {
        if let Some(found) = find_matching_icd(&hw_files, &["radeon_icd", "amd_icd", "amdvlk"]) {
            return Some(found);
        }
    }
    if probe.has_modern_intel != 0 {
        if let Some(found) = find_matching_icd(&hw_files, &["intel_icd"]) {
            return Some(found);
        }
    }
    if probe.has_legacy_intel != 0 {
        if let Some(found) = find_matching_icd(&hw_files, &["intel_hasvk_icd", "intel_icd"]) {
            return Some(found);
        }
    }
    if probe.has_soc_vulkan != 0 || target_is_aarch64 {
        if let Some(found) = find_matching_icd(
            &hw_files,
            &[
                "freedreno_icd",
                "turnip",
                "asahi_icd",
                "honeykrisp",
                "panvk_icd",
                "broadcom_icd",
                "v3d_icd",
                "powervr",
            ],
        ) {
            return Some(found);
        }
    }

    // Universal fallback: any discovered non-software native ICD (excluding Mesa legacy/nvk mismatch
    // only when proprietary GPU is absent — prevents falling back to CPU Lavapipe on new vendors).
    if let Some((_, path)) = hw_files.first() {
        return Some(path.to_string_lossy().into_owned());
    }

    if probe.has_virtual_gpu != 0 {
        let vm_files: Vec<(String, PathBuf)> = collect_icd_files(dirs, target_is_aarch64)
            .into_iter()
            .filter(|(name, _)| !is_software_icd_name(name) && is_virtual_icd_name(name))
            .collect();
        if let Some((_, path)) = vm_files.first() {
            return Some(path.to_string_lossy().into_owned());
        }
    }

    None
}

pub fn select_universal_egl_vendor_from_dirs(dirs: &[&str], prefer_nvidia: bool) -> Option<String> {
    let mut manifests = Vec::new();
    for dir in dirs {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        let mut dir_files: Vec<(String, PathBuf)> = entries
            .flatten()
            .filter_map(|entry| {
                let p = entry.path();
                if !p.is_file() {
                    return None;
                }
                let name = entry.file_name().to_string_lossy().into_owned();
                if !name.ends_with(".json") {
                    return None;
                }
                Some((name, p))
            })
            .collect();
        dir_files.sort_by(|a, b| a.0.cmp(&b.0));
        manifests.extend(dir_files);
    }

    if prefer_nvidia {
        if let Some((_, p)) = manifests
            .iter()
            .find(|(n, _)| n.to_ascii_lowercase().contains("nvidia"))
        {
            return Some(p.to_string_lossy().into_owned());
        }
    }

    if let Some((_, p)) = manifests
        .iter()
        .find(|(n, _)| n.to_ascii_lowercase().contains("mesa"))
    {
        return Some(p.to_string_lossy().into_owned());
    }

    if !prefer_nvidia {
        if let Some((_, p)) = manifests
            .iter()
            .find(|(n, _)| !n.to_ascii_lowercase().contains("nvidia"))
        {
            return Some(p.to_string_lossy().into_owned());
        }
    }

    manifests
        .first()
        .map(|(_, p)| p.to_string_lossy().into_owned())
}

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

fn read_drm_driver_name(card_path: &Path) -> Option<String> {
    let driver_link = fs::read_link(card_path.join("device/driver")).ok()?;
    driver_link
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
}

pub fn probe_host_gpu_from_sysfs(drm_root: &Path, icd_dirs: &[&str]) -> MocktailHostGpuProbe {
    let mut probe = MocktailHostGpuProbe {
        total_ram_mb: probe_total_ram_mb(),
        nvidia_driver_major: probe_nvidia_driver_major(),
        ..Default::default()
    };

    let hw_icds: Vec<(String, PathBuf)> = collect_icd_files(icd_dirs, host_is_aarch64())
        .into_iter()
        .filter(|(name, _)| !is_software_icd_name(name) && !is_virtual_icd_name(name))
        .collect();
    if !hw_icds.is_empty() {
        probe.has_hw_vulkan_icd = 1;
    }
    let has_nouveau_icd = hw_icds.iter().any(|(n, _)| {
        let lower = n.to_ascii_lowercase();
        lower.contains("nouveau") || lower.contains("nvk")
    });

    let Ok(entries) = fs::read_dir(drm_root) else {
        return probe;
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("card") || name.contains('-') {
            continue;
        }
        if !name[4..].bytes().all(|b| b.is_ascii_digit()) || name.len() <= 4 {
            continue;
        }

        let card_path = entry.path();
        let driver = read_drm_driver_name(&card_path)
            .map(|d| d.to_ascii_lowercase())
            .unwrap_or_default();
        let vendor_id = read_trimmed(&card_path.join("device/vendor"))
            .and_then(|s| parse_pci_hex_str(&s))
            .unwrap_or(0);
        let device_id = read_trimmed(&card_path.join("device/device"))
            .and_then(|s| parse_pci_hex_str(&s))
            .unwrap_or(0);

        match driver.as_str() {
            "xe" => {
                probe.has_modern_intel = 1;
                if is_discrete_intel_device_id(device_id) {
                    probe.has_discrete_gpu = 1;
                } else {
                    probe.has_integrated_gpu = 1;
                }
            }
            "i915" => {
                if is_legacy_intel_device_id(device_id) {
                    probe.has_legacy_intel = 1;
                } else {
                    probe.has_modern_intel = 1;
                }
                if is_discrete_intel_device_id(device_id) {
                    probe.has_discrete_gpu = 1;
                } else {
                    probe.has_integrated_gpu = 1;
                }
            }
            "nvidia" => {
                let legacy_driver =
                    probe.nvidia_driver_major > 0 && probe.nvidia_driver_major <= 470;
                if legacy_driver || is_legacy_nvidia_device_id(device_id) {
                    probe.has_legacy_nvidia = 1;
                } else {
                    probe.has_modern_nvidia = 1;
                }
                probe.has_discrete_gpu = 1;
            }
            "nouveau" | "nova" => {
                if has_nouveau_icd && is_turing_or_newer_nvidia_device_id(device_id) {
                    probe.has_modern_nvidia = 1;
                } else {
                    probe.has_legacy_nvidia = 1;
                }
                probe.has_discrete_gpu = 1;
            }
            "amdgpu" => {
                probe.has_amd = 1;
                let vram_bytes = read_trimmed(&card_path.join("device/mem_info_vram_total"))
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);
                // Dedicated RDNA/GCN cards generally expose > 2 GiB VRAM, whereas
                // integrated APUs commonly reserve 512 MiB - 2 GiB BIOS carveout.
                if vram_bytes >= 3 * 1024 * 1024 * 1024 {
                    probe.has_discrete_gpu = 1;
                } else if vram_bytes > 0 {
                    probe.has_integrated_gpu = 1;
                } else {
                    probe.has_discrete_gpu = 1;
                }
            }
            "radeon" => {
                probe.has_amd_legacy_radeon = 1;
                probe.has_discrete_gpu = 1;
            }
            "msm" | "asahi" | "panthor" | "v3d" | "powervr" | "pvr" => {
                probe.has_soc_vulkan = 1;
                probe.has_integrated_gpu = 1;
            }
            "panfrost" | "lima" | "etnaviv" | "vc4" | "tegra-drm" | "tegradrm"
            | "exynos-drm" | "rockchip-drm" | "sun4i-drm" | "meson" => {
                probe.has_soc_gles_only = 1;
                probe.has_integrated_gpu = 1;
            }
            "virtio-pci" | "virtio_gpu" | "vmwgfx" | "qxl" | "bochs-drm" | "vboxvideo"
            | "hyperv_drm" => {
                probe.has_virtual_gpu = 1;
            }
            _ => {
                // PCI fallback when `driver` symlink is absent (e.g. restricted sandbox)
                match vendor_id {
                    0x8086 => {
                        if is_legacy_intel_device_id(device_id) {
                            probe.has_legacy_intel = 1;
                        } else {
                            probe.has_modern_intel = 1;
                        }
                        if is_discrete_intel_device_id(device_id) {
                            probe.has_discrete_gpu = 1;
                        } else {
                            probe.has_integrated_gpu = 1;
                        }
                    }
                    0x10de => {
                        if is_legacy_nvidia_device_id(device_id) {
                            probe.has_legacy_nvidia = 1;
                        } else {
                            probe.has_modern_nvidia = 1;
                        }
                        probe.has_discrete_gpu = 1;
                    }
                    0x1002 => {
                        probe.has_amd = 1;
                        probe.has_discrete_gpu = 1;
                    }
                    0x15ad | 0x1af4 | 0x1234 | 0x80ee => {
                        probe.has_virtual_gpu = 1;
                    }
                    _ => {}
                }
            }
        }
    }

    probe
}

#[no_mangle]
pub extern "C" fn mocktail_rust_graphics_probe_host_caps(
    out_probe: *mut MocktailHostGpuProbe,
) -> i32 {
    if out_probe.is_null() {
        return -1;
    }
    let probed = probe_host_gpu_from_sysfs(Path::new("/sys/class/drm"), DEFAULT_ICD_DIRS);
    unsafe {
        *out_probe = probed;
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_graphics_nvidia_supports_wayland_explicit_sync() -> i32 {
    if let Ok(override_val) = env::var("MOCKTAIL_NVIDIA_WAYLAND_VK") {
        let trimmed = override_val.trim();
        if trimmed == "0" || trimmed.eq_ignore_ascii_case("false") {
            return 0;
        }
        if trimmed == "1" || trimmed.eq_ignore_ascii_case("true") {
            return 1;
        }
    }
    // NVIDIA 555+ added linux-drm-syncobj-v1 explicit sync on Wayland Vulkan WSI.
    // 560+ made it production-ready across modern KWin/Mutter/wlroots compositors.
    let maj = probe_nvidia_driver_major();
    if maj >= 560 {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_graphics_select_universal_icd_manifest(
    dirs_nl: *const c_char,
    probe: *const MocktailHostGpuProbe,
    target_is_aarch64: i32,
    out_buf: *mut c_char,
    out_cap: usize,
) -> i32 {
    let Some(dirs_str) = cstr_to_opt_str(dirs_nl) else {
        return -1;
    };
    let probe_val = if probe.is_null() {
        MocktailHostGpuProbe::default()
    } else {
        unsafe { *probe }
    };
    let dirs: Vec<&str> = dirs_str.lines().filter(|l| !l.is_empty()).collect();
    match select_universal_icd_from_dirs(&dirs, &probe_val, target_is_aarch64 != 0) {
        Some(selected) => write_cstr_buf(&selected, out_buf, out_cap),
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_graphics_select_universal_egl_manifest(
    dirs_nl: *const c_char,
    prefer_nvidia: i32,
    out_buf: *mut c_char,
    out_cap: usize,
) -> i32 {
    let Some(dirs_str) = cstr_to_opt_str(dirs_nl) else {
        return -1;
    };
    let dirs: Vec<&str> = dirs_str.lines().filter(|l| !l.is_empty()).collect();
    match select_universal_egl_vendor_from_dirs(&dirs, prefer_nvidia != 0) {
        Some(selected) => write_cstr_buf(&selected, out_buf, out_cap),
        None => -1,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_graphics_default_quality(
    probe: *const MocktailHostGpuProbe,
) -> *const c_char {
    if probe.is_null() {
        return ptr::null();
    }
    let p = unsafe { *probe };
    let has_legacy = p.has_legacy_intel != 0
        || p.has_legacy_nvidia != 0
        || p.has_amd_legacy_radeon != 0;
    let is_gles_soc_only = p.has_soc_gles_only != 0 && p.has_discrete_gpu == 0;
    let low_ram = p.total_ram_mb > 0 && p.total_ram_mb <= 4096;
    let mid_ram_igpu = p.has_discrete_gpu == 0
        && p.total_ram_mb > 4096
        && p.total_ram_mb <= 8192;

    if has_legacy || is_gles_soc_only || low_ram {
        b"1\0".as_ptr().cast()
    } else if mid_ram_igpu {
        b"2\0".as_ptr().cast()
    } else {
        ptr::null()
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_graphics_needs_mesa_etc2_driconf(
    manifests: *const c_char,
) -> i32 {
    let Some(list) = cstr_to_opt_str(manifests) else {
        return 0;
    };
    let entries: Vec<&str> = list
        .split(':')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    if entries.len() != 1 {
        return 0;
    }
    let single = entries[0].to_ascii_lowercase();
    let base = Path::new(&single)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(&single);
    if base.contains("radeon_icd.") || base.contains("nouveau_icd.") || base.contains("nvk_icd.") {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::os::unix::fs::symlink;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = env::temp_dir().join(format!(
            "mocktail_graphics_launch_{label}_{}_{}",
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_nvidia_driver_version_parsing() {
        let proc_content = "NVRM version: NVIDIA UNIX x86_64 Kernel Module  570.124.04  Tue Feb 25 04:01:28 UTC 2025\nGCC version:  gcc version 14.2.1";
        assert_eq!(parse_nvidia_driver_major_str(proc_content), 570);
        assert_eq!(parse_nvidia_driver_major_str("470.256.02\n"), 470);
        assert_eq!(parse_nvidia_driver_major_str("unknown"), 0);
    }

    #[test]
    fn test_universal_icd_selection_filters_software_and_prefers_matching_gpu() {
        let root = make_temp_dir("icd_filter");
        let icd_dir = root.join("icd.d");
        fs::create_dir_all(&icd_dir).unwrap();
        fs::write(icd_dir.join("lvp_icd.x86_64.json"), "{}").unwrap();
        fs::write(icd_dir.join("radeon_icd.x86_64.json"), "{}").unwrap();
        fs::write(icd_dir.join("radeon_icd.i686.json"), "{}").unwrap();
        fs::write(icd_dir.join("freedreno_icd.aarch64.json"), "{}").unwrap();

        let dir_str = icd_dir.to_string_lossy().into_owned();

        // AMD desktop on x86_64 picks radeon_icd.x86_64.json, ignores lvp & i686 & aarch64
        let amd_probe = MocktailHostGpuProbe {
            has_amd: 1,
            has_discrete_gpu: 1,
            ..Default::default()
        };
        let selected = select_universal_icd_from_dirs(&[&dir_str], &amd_probe, false).unwrap();
        assert!(selected.ends_with("radeon_icd.x86_64.json"));

        // Qualcomm SoC on aarch64 picks freedreno_icd.aarch64.json
        let arm_probe = MocktailHostGpuProbe {
            has_soc_vulkan: 1,
            has_integrated_gpu: 1,
            ..Default::default()
        };
        let arm_selected = select_universal_icd_from_dirs(&[&dir_str], &arm_probe, true).unwrap();
        assert!(arm_selected.ends_with("freedreno_icd.aarch64.json"));

        // Software-only ICD dir returns None instead of accidentally selecting Lavapipe!
        let sw_dir = root.join("sw_icd.d");
        fs::create_dir_all(&sw_dir).unwrap();
        fs::write(sw_dir.join("lvp_icd.x86_64.json"), "{}").unwrap();
        let sw_str = sw_dir.to_string_lossy().into_owned();
        assert!(select_universal_icd_from_dirs(&[&sw_str], &amd_probe, false).is_none());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_universal_drm_sysfs_probe_handles_pci_and_soc() {
        let root = make_temp_dir("drm_probe");
        let drm = root.join("drm");
        let drivers = root.join("drivers");
        let icd = root.join("icd");
        fs::create_dir_all(&drm).unwrap();
        fs::create_dir_all(drivers.join("panthor")).unwrap();
        fs::create_dir_all(drivers.join("amdgpu")).unwrap();
        fs::create_dir_all(&icd).unwrap();
        fs::write(icd.join("panvk_icd.aarch64.json"), "{}").unwrap();
        fs::write(icd.join("radeon_icd.x86_64.json"), "{}").unwrap();

        // Card 0: ARM Mali Valhall (panthor, platform device with NO PCI vendor/device!)
        let card0_dev = drm.join("card0/device");
        fs::create_dir_all(&card0_dev).unwrap();
        symlink(drivers.join("panthor"), card0_dev.join("driver")).unwrap();

        // Card 1: AMD dGPU (8 GiB VRAM)
        let card1_dev = drm.join("card1/device");
        fs::create_dir_all(&card1_dev).unwrap();
        symlink(drivers.join("amdgpu"), card1_dev.join("driver")).unwrap();
        fs::write(card1_dev.join("mem_info_vram_total"), "8589934592\n").unwrap();

        let icd_str = icd.to_string_lossy().into_owned();
        let probe = probe_host_gpu_from_sysfs(&drm, &[&icd_str]);
        assert_eq!(probe.has_soc_vulkan, 1);
        assert_eq!(probe.has_integrated_gpu, 1);
        assert_eq!(probe.has_amd, 1);
        assert_eq!(probe.has_discrete_gpu, 1);
        assert_eq!(probe.has_hw_vulkan_icd, 1);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_default_graphics_quality_scaling() {
        let legacy = MocktailHostGpuProbe {
            has_legacy_intel: 1,
            total_ram_mb: 16384,
            ..Default::default()
        };
        let q1 = unsafe { CStr::from_ptr(mocktail_rust_graphics_default_quality(&legacy)) }
            .to_str()
            .unwrap();
        assert_eq!(q1, "1");

        let igpu_8g = MocktailHostGpuProbe {
            has_modern_intel: 1,
            has_integrated_gpu: 1,
            has_discrete_gpu: 0,
            total_ram_mb: 7373,
            ..Default::default()
        };
        let q2 = unsafe { CStr::from_ptr(mocktail_rust_graphics_default_quality(&igpu_8g)) }
            .to_str()
            .unwrap();
        assert_eq!(q2, "2");

        let intel_dgpu_16g = MocktailHostGpuProbe {
            has_modern_intel: 1,
            has_discrete_gpu: 1,
            total_ram_mb: 16384,
            ..Default::default()
        };
        assert!(mocktail_rust_graphics_default_quality(&intel_dgpu_16g).is_null());
    }

    #[test]
    fn test_needs_mesa_etc2_driconf() {
        let radeon = CString::new("/usr/share/vulkan/icd.d/radeon_icd.x86_64.json").unwrap();
        let nvk = CString::new("/usr/share/vulkan/icd.d/nouveau_icd.x86_64.json").unwrap();
        let mixed = CString::new("/test/radeon_icd.json:/test/intel_icd.json").unwrap();
        let intel = CString::new("/test/intel_icd.json").unwrap();
        let nv = CString::new("/test/nvidia_icd.json").unwrap();
        assert_eq!(mocktail_rust_graphics_needs_mesa_etc2_driconf(radeon.as_ptr()), 1);
        assert_eq!(mocktail_rust_graphics_needs_mesa_etc2_driconf(nvk.as_ptr()), 1);
        assert_eq!(mocktail_rust_graphics_needs_mesa_etc2_driconf(mixed.as_ptr()), 0);
        assert_eq!(mocktail_rust_graphics_needs_mesa_etc2_driconf(intel.as_ptr()), 0);
        assert_eq!(mocktail_rust_graphics_needs_mesa_etc2_driconf(nv.as_ptr()), 0);
    }
}
