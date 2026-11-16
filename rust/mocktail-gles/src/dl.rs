//! Dynamic library discovery for host EGL/GLESv2 libraries and Mocktail runtime hooks.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

pub const RTLD_LAZY: c_int = 1;
pub const RTLD_NOW: c_int = 2;
pub const RTLD_NOLOAD: c_int = 4;
pub const RTLD_LOCAL: c_int = 0;
pub const RTLD_GLOBAL: c_int = 0x100;
pub const RTLD_DEFAULT: *mut c_void = std::ptr::null_mut();

#[repr(C)]
struct DlInfo {
    dli_fname: *const c_char,
    dli_fbase: *mut c_void,
    dli_sname: *const c_char,
    dli_saddr: *mut c_void,
}

extern "C" {
    fn dlopen(filename: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
    fn dladdr(addr: *const c_void, info: *mut DlInfo) -> c_int;
}

extern "C" fn self_sentinel() {}

fn own_library_path() -> Option<String> {
    let mut info = DlInfo {
        dli_fname: std::ptr::null(),
        dli_fbase: std::ptr::null_mut(),
        dli_sname: std::ptr::null(),
        dli_saddr: std::ptr::null_mut(),
    };
    let rc = unsafe { dladdr(self_sentinel as *const c_void, &mut info) };
    if rc == 0 || info.dli_fname.is_null() {
        return None;
    }
    let path = unsafe { CStr::from_ptr(info.dli_fname) }
        .to_string_lossy()
        .into_owned();
    Some(path)
}

fn symbol_library_path(addr: *const c_void) -> Option<String> {
    if addr.is_null() {
        return None;
    }
    let mut info = DlInfo {
        dli_fname: std::ptr::null(),
        dli_fbase: std::ptr::null_mut(),
        dli_sname: std::ptr::null(),
        dli_saddr: std::ptr::null_mut(),
    };
    let rc = unsafe { dladdr(addr, &mut info) };
    if rc == 0 || info.dli_fname.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr(info.dli_fname) }
            .to_string_lossy()
            .into_owned(),
    )
}

fn is_stub_soname(path: &str) -> bool {
    let file = path.rsplit('/').next().unwrap_or(path);
    file == "libGLESv2.so" || file == "libEGL.so"
}

fn open_verified_library(candidates: &[String], probe_sym: &[u8]) -> usize {
    let own = own_library_path();
    let probe_cstr = CStr::from_bytes_with_nul(probe_sym).expect("nul-terminated symbol");
    for candidate in candidates {
        if candidate.is_empty() {
            continue;
        }
        let Ok(c_path) = CString::new(candidate.as_str()) else {
            continue;
        };
        let handle = unsafe { dlopen(c_path.as_ptr(), RTLD_LAZY | RTLD_LOCAL) };
        if handle.is_null() {
            continue;
        }
        let sym = unsafe { dlsym(handle, probe_cstr.as_ptr()) };
        if sym.is_null() {
            unsafe { dlclose(handle) };
            continue;
        }
        if let Some(resolved_path) = symbol_library_path(sym) {
            if own.as_deref() == Some(resolved_path.as_str()) || is_stub_soname(&resolved_path) {
                unsafe { dlclose(handle) };
                continue;
            }
        }
        return handle as usize;
    }
    0
}

pub fn host_gles_handle() -> *mut c_void {
    static HANDLE: OnceLock<usize> = OnceLock::new();
    let raw = *HANDLE.get_or_init(|| {
        let mut candidates = Vec::new();
        if let Ok(explicit) = std::env::var("MOCKTAIL_GLES_LIBRARY") {
            let trimmed = explicit.trim().to_string();
            if !trimmed.is_empty() {
                candidates.push(trimmed);
            }
        }
        for fallback in [
            "/usr/lib/libGLESv2.so.2",
            "/usr/lib64/libGLESv2.so.2",
            "/usr/lib/x86_64-linux-gnu/libGLESv2.so.2",
            "/usr/lib/aarch64-linux-gnu/libGLESv2.so.2",
            "libGLESv2.so.2",
        ] {
            candidates.push(fallback.to_string());
        }
        open_verified_library(&candidates, b"glGetError\0")
    });
    raw as *mut c_void
}

pub fn host_egl_handle() -> *mut c_void {
    static HANDLE: OnceLock<usize> = OnceLock::new();
    let raw = *HANDLE.get_or_init(|| {
        let mut candidates = Vec::new();
        if let Ok(explicit) = std::env::var("MOCKTAIL_EGL_LIBRARY") {
            let trimmed = explicit.trim().to_string();
            if !trimmed.is_empty() {
                candidates.push(trimmed);
            }
        }
        for fallback in [
            "/usr/lib/libEGL.so.1",
            "/usr/lib64/libEGL.so.1",
            "/usr/lib/x86_64-linux-gnu/libEGL.so.1",
            "/usr/lib/aarch64-linux-gnu/libEGL.so.1",
            "libEGL.so.1",
        ] {
            candidates.push(fallback.to_string());
        }
        open_verified_library(&candidates, b"eglGetError\0")
    });
    raw as *mut c_void
}

/// Finds our companion `libGLESv2.so` adapter when loaded by Mocktail or linked into tests.
pub fn adapter_gles_handle() -> *mut c_void {
    static HANDLE: AtomicUsize = AtomicUsize::new(0);
    let cached = HANDLE.load(Ordering::Acquire);
    if cached != 0 {
        return cached as *mut c_void;
    }

    // Prefer already-loaded `libGLESv2.so` (sibling of libEGL.so when both live in runtime dir).
    let mut try_paths = Vec::new();
    if let Some(own) = own_library_path() {
        if let Some((dir, _)) = own.rsplit_once('/') {
            try_paths.push(format!("{dir}/libGLESv2.so"));
        }
    }
    try_paths.push("libGLESv2.so".to_string());

    for candidate in try_paths {
        let Ok(c_path) = CString::new(candidate.as_str()) else {
            continue;
        };
        let handle = unsafe { dlopen(c_path.as_ptr(), RTLD_LAZY | RTLD_NOLOAD) };
        if !handle.is_null() {
            let marker = unsafe { dlsym(handle, b"mocktail_gles_lookup_proc\0".as_ptr().cast()) };
            if !marker.is_null() {
                HANDLE.store(handle as usize, Ordering::Release);
                return handle;
            }
            unsafe { dlclose(handle) };
        }
    }
    std::ptr::null_mut()
}

pub unsafe fn dlsym_default(name: &[u8]) -> *mut c_void {
    let Ok(sym) = CStr::from_bytes_with_nul(name) else {
        return std::ptr::null_mut();
    };
    unsafe { dlsym(RTLD_DEFAULT, sym.as_ptr()) }
}

pub unsafe fn dlsym_cstr(handle: *mut c_void, name: *const c_char) -> *mut c_void {
    if name.is_null() {
        return std::ptr::null_mut();
    }
    unsafe { dlsym(handle, name) }
}

pub fn env_flag_enabled(name: &str) -> bool {
    match std::env::var(name) {
        Ok(val) => {
            let trimmed = val.trim();
            !trimmed.is_empty() && trimmed != "0" && !trimmed.eq_ignore_ascii_case("false")
        }
        Err(_) => false,
    }
}

pub fn env_flag_enabled_default_true(name: &str) -> bool {
    match std::env::var(name) {
        Ok(val) => {
            let trimmed = val.trim();
            trimmed != "0" && !trimmed.eq_ignore_ascii_case("false")
        }
        Err(_) => true,
    }
}
