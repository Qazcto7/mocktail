//! Pure-Rust EGL 1.5 runtime bridging Bionic libEGL.so exports to host SDL/GLVND EGL.

use std::cell::Cell;
use std::collections::HashSet;
use std::ffi::{c_char, c_void, CStr, CString};
use std::sync::{Mutex, OnceLock};

use crate::dl::{
    adapter_gles_handle, dlsym_cstr, dlsym_default, env_flag_enabled, host_egl_handle,
};

pub type EGLBoolean = u32;
pub type EGLint = i32;
pub type EGLenum = u32;
pub type EGLDisplay = *mut c_void;
pub type EGLConfig = *mut c_void;
pub type EGLContext = *mut c_void;
pub type EGLSurface = *mut c_void;
pub type EGLNativeDisplayType = *mut c_void;
pub type EGLNativeWindowType = *mut c_void;

pub const EGL_FALSE: EGLBoolean = 0;
pub const EGL_TRUE: EGLBoolean = 1;
pub const EGL_NO_DISPLAY: EGLDisplay = std::ptr::null_mut();
pub const EGL_NO_CONTEXT: EGLContext = std::ptr::null_mut();
pub const EGL_NO_SURFACE: EGLSurface = std::ptr::null_mut();

pub const EGL_SUCCESS: EGLint = 0x3000;
pub const EGL_NOT_INITIALIZED: EGLint = 0x3001;
pub const EGL_BAD_ACCESS: EGLint = 0x3002;
pub const EGL_BAD_ALLOC: EGLint = 0x3003;
pub const EGL_BAD_ATTRIBUTE: EGLint = 0x3004;
pub const EGL_BAD_CONFIG: EGLint = 0x3005;
pub const EGL_BAD_CONTEXT: EGLint = 0x3006;
pub const EGL_BAD_CURRENT_SURFACE: EGLint = 0x3007;
pub const EGL_BAD_DISPLAY: EGLint = 0x3008;
pub const EGL_BAD_MATCH: EGLint = 0x3009;
pub const EGL_BAD_NATIVE_WINDOW: EGLint = 0x300B;
pub const EGL_BAD_PARAMETER: EGLint = 0x300C;
pub const EGL_BAD_SURFACE: EGLint = 0x300D;

pub const EGL_BUFFER_SIZE: EGLint = 0x3020;
pub const EGL_ALPHA_SIZE: EGLint = 0x3021;
pub const EGL_BLUE_SIZE: EGLint = 0x3022;
pub const EGL_GREEN_SIZE: EGLint = 0x3023;
pub const EGL_RED_SIZE: EGLint = 0x3024;
pub const EGL_DEPTH_SIZE: EGLint = 0x3025;
pub const EGL_STENCIL_SIZE: EGLint = 0x3026;
pub const EGL_CONFIG_CAVEAT: EGLint = 0x3027;
pub const EGL_CONFIG_ID: EGLint = 0x3028;
pub const EGL_LEVEL: EGLint = 0x3029;
pub const EGL_MAX_PBUFFER_HEIGHT: EGLint = 0x302A;
pub const EGL_MAX_PBUFFER_PIXELS: EGLint = 0x302B;
pub const EGL_MAX_PBUFFER_WIDTH: EGLint = 0x302C;
pub const EGL_NATIVE_RENDERABLE: EGLint = 0x302D;
pub const EGL_NATIVE_VISUAL_ID: EGLint = 0x302E;
pub const EGL_NATIVE_VISUAL_TYPE: EGLint = 0x302F;
pub const EGL_SAMPLES: EGLint = 0x3031;
pub const EGL_SAMPLE_BUFFERS: EGLint = 0x3032;
pub const EGL_SURFACE_TYPE: EGLint = 0x3033;
pub const EGL_TRANSPARENT_TYPE: EGLint = 0x3034;
pub const EGL_NONE: EGLint = 0x3038;
pub const EGL_MIN_SWAP_INTERVAL: EGLint = 0x303B;
pub const EGL_MAX_SWAP_INTERVAL: EGLint = 0x303C;
pub const EGL_RENDERABLE_TYPE: EGLint = 0x3040;
pub const EGL_CONFORMANT: EGLint = 0x3042;

pub const EGL_VENDOR: EGLint = 0x3053;
pub const EGL_VERSION: EGLint = 0x3054;
pub const EGL_EXTENSIONS: EGLint = 0x3055;
pub const EGL_HEIGHT: EGLint = 0x3056;
pub const EGL_WIDTH: EGLint = 0x3057;
pub const EGL_LARGEST_PBUFFER: EGLint = 0x3058;
pub const EGL_DRAW: EGLint = 0x3059;
pub const EGL_READ: EGLint = 0x305A;
pub const EGL_RENDER_BUFFER: EGLint = 0x3086;
pub const EGL_BACK_BUFFER: EGLint = 0x3084;
pub const EGL_CLIENT_APIS: EGLint = 0x308D;
pub const EGL_CONTEXT_CLIENT_VERSION: EGLint = 0x3098;
pub const EGL_CONTEXT_MINOR_VERSION: EGLint = 0x30FB;
pub const EGL_OPENGL_ES_API: EGLenum = 0x30A0;
pub const EGL_PBUFFER_BIT: EGLint = 0x0001;
pub const EGL_WINDOW_BIT: EGLint = 0x0004;
pub const EGL_OPENGL_ES2_BIT: EGLint = 0x0004;
pub const EGL_OPENGL_ES3_BIT_KHR: EGLint = 0x0040;

const MOCK_DISPLAY: usize = 0x1001;
const MOCK_CONFIG: usize = 0x1002;
const MOCK_WINDOW_SURFACE: usize = 0x1003;
const MOCK_SURFACE_BASE: usize = 0x2000;
const MOCK_CONTEXT_BASE: usize = 0x4000;

thread_local! {
    static TLS_LAST_ERROR: Cell<EGLint> = const { Cell::new(EGL_SUCCESS) };
    static TLS_CURRENT_DISPLAY: Cell<usize> = const { Cell::new(0) };
    static TLS_CURRENT_DRAW: Cell<usize> = const { Cell::new(0) };
    static TLS_CURRENT_READ: Cell<usize> = const { Cell::new(0) };
    static TLS_CURRENT_CONTEXT: Cell<usize> = const { Cell::new(0) };
    static TLS_BOUND_API: Cell<EGLenum> = const { Cell::new(EGL_OPENGL_ES_API) };
}

#[derive(Default)]
struct EglRegistry {
    next_mock_handle: usize,
    primary_context_claimed: bool,
    primary_surface_claimed: bool,
    mock_contexts: HashSet<usize>,
    mock_surfaces: HashSet<usize>,
    host_contexts: HashSet<usize>,
    host_pbuffers: HashSet<usize>,
}

static REGISTRY: OnceLock<Mutex<EglRegistry>> = OnceLock::new();

fn registry() -> &'static Mutex<EglRegistry> {
    REGISTRY.get_or_init(|| {
        Mutex::new(EglRegistry {
            next_mock_handle: 1,
            ..Default::default()
        })
    })
}

fn set_error(err: EGLint) {
    TLS_LAST_ERROR.with(|c| c.set(err));
}

fn test_stubs_enabled() -> bool {
    env_flag_enabled("MOCKTAIL_ENABLE_TEST_GRAPHICS_STUBS")
}

fn trace_enabled() -> bool {
    env_flag_enabled("MOCKTAIL_EGL_TRACE")
}

type FnPtrGetter = unsafe extern "C" fn() -> *mut c_void;
type FnWindowSwap = unsafe extern "C" fn() -> bool;
type FnWindowSwapInterval = unsafe extern "C" fn(i32) -> bool;
type FnWindowMakeCurrent = unsafe extern "C" fn() -> bool;
type FnWindowReleaseCurrent = unsafe extern "C" fn() -> bool;
type FnWindowDim = unsafe extern "C" fn() -> i32;
type FnGlProcAddress = unsafe extern "C" fn(*const c_char) -> *mut c_void;
type FnGlesNotifyMakeCurrent = unsafe extern "C" fn(usize);
type FnGlesNotifyContextDestroy = unsafe extern "C" fn(usize);

type HostEglCreateContext =
    unsafe extern "C" fn(EGLDisplay, EGLConfig, EGLContext, *const EGLint) -> EGLContext;
type HostEglDestroyContext = unsafe extern "C" fn(EGLDisplay, EGLContext) -> EGLBoolean;
type HostEglCreatePbufferSurface =
    unsafe extern "C" fn(EGLDisplay, EGLConfig, *const EGLint) -> EGLSurface;
type HostEglDestroySurface = unsafe extern "C" fn(EGLDisplay, EGLSurface) -> EGLBoolean;
type HostEglMakeCurrent =
    unsafe extern "C" fn(EGLDisplay, EGLSurface, EGLSurface, EGLContext) -> EGLBoolean;
type HostEglGetConfigAttrib =
    unsafe extern "C" fn(EGLDisplay, EGLConfig, EGLint, *mut EGLint) -> EGLBoolean;
type HostEglChooseConfig =
    unsafe extern "C" fn(EGLDisplay, *const EGLint, *mut EGLConfig, EGLint, *mut EGLint) -> EGLBoolean;
type HostEglQuerySurface =
    unsafe extern "C" fn(EGLDisplay, EGLSurface, EGLint, *mut EGLint) -> EGLBoolean;
type HostEglQueryString = unsafe extern "C" fn(EGLDisplay, EGLint) -> *const c_char;
type HostEglGetProcAddress = unsafe extern "C" fn(*const c_char) -> *mut c_void;
type HostEglGetError = unsafe extern "C" fn() -> EGLint;

unsafe fn query_host_handle(sym: &[u8]) -> *mut c_void {
    let fptr = unsafe { dlsym_default(sym) };
    if fptr.is_null() {
        return std::ptr::null_mut();
    }
    let func: FnPtrGetter = unsafe { std::mem::transmute(fptr) };
    unsafe { func() }
}

fn real_display() -> EGLDisplay {
    unsafe { query_host_handle(b"mocktail_egl_display\0") }
}

fn real_surface() -> EGLSurface {
    unsafe { query_host_handle(b"mocktail_egl_surface\0") }
}

fn real_context() -> EGLContext {
    unsafe { query_host_handle(b"mocktail_egl_context\0") }
}

fn real_config() -> EGLConfig {
    unsafe { query_host_handle(b"mocktail_egl_config\0") }
}

fn host_egl_sym<T: Copy>(name: &[u8]) -> Option<T> {
    let handle = host_egl_handle();
    if handle.is_null() {
        return None;
    }
    let sym = unsafe { dlsym_cstr(handle, name.as_ptr().cast()) };
    if sym.is_null() {
        return None;
    }
    Some(unsafe { std::mem::transmute_copy(&sym) })
}

fn active_display() -> EGLDisplay {
    let dpy = real_display();
    if !dpy.is_null() {
        return dpy;
    }
    if test_stubs_enabled() {
        return MOCK_DISPLAY as EGLDisplay;
    }
    EGL_NO_DISPLAY
}

fn notify_gles_make_current(ctx: EGLContext) {
    let gles = adapter_gles_handle();
    if gles.is_null() {
        return;
    }
    let sym = unsafe { dlsym_cstr(gles, b"mocktail_gles_on_make_current\0".as_ptr().cast()) };
    if !sym.is_null() {
        let cb: FnGlesNotifyMakeCurrent = unsafe { std::mem::transmute(sym) };
        unsafe { cb(ctx as usize) };
    }
}

fn notify_gles_context_destroy(ctx: EGLContext) {
    let gles = adapter_gles_handle();
    if gles.is_null() {
        return;
    }
    let sym = unsafe { dlsym_cstr(gles, b"mocktail_gles_on_context_destroy\0".as_ptr().cast()) };
    if !sym.is_null() {
        let cb: FnGlesNotifyContextDestroy = unsafe { std::mem::transmute(sym) };
        unsafe { cb(ctx as usize) };
    }
}

/// Evaluates our synthetic fallback config attributes (aligned with ES 3.x + swap interval bounds).
pub fn fallback_config_attrib(attribute: EGLint) -> Option<EGLint> {
    match attribute {
        EGL_BUFFER_SIZE => Some(32),
        EGL_ALPHA_SIZE => Some(8),
        EGL_BLUE_SIZE => Some(8),
        EGL_GREEN_SIZE => Some(8),
        EGL_RED_SIZE => Some(8),
        EGL_DEPTH_SIZE => Some(24),
        EGL_STENCIL_SIZE => Some(8),
        EGL_CONFIG_CAVEAT => Some(EGL_NONE),
        EGL_CONFIG_ID => Some(1),
        EGL_LEVEL => Some(0),
        EGL_MAX_PBUFFER_HEIGHT => Some(4096),
        EGL_MAX_PBUFFER_PIXELS => Some(4096 * 4096),
        EGL_MAX_PBUFFER_WIDTH => Some(4096),
        EGL_NATIVE_RENDERABLE => Some(1),
        EGL_NATIVE_VISUAL_ID => Some(1),
        EGL_NATIVE_VISUAL_TYPE => Some(0),
        EGL_SAMPLES => Some(0),
        EGL_SAMPLE_BUFFERS => Some(0),
        EGL_SURFACE_TYPE => Some(EGL_PBUFFER_BIT | EGL_WINDOW_BIT),
        EGL_TRANSPARENT_TYPE => Some(EGL_NONE),
        EGL_MIN_SWAP_INTERVAL => Some(0),
        EGL_MAX_SWAP_INTERVAL => Some(4),
        EGL_RENDERABLE_TYPE => Some(EGL_OPENGL_ES2_BIT | EGL_OPENGL_ES3_BIT_KHR),
        EGL_CONFORMANT => Some(EGL_OPENGL_ES2_BIT | EGL_OPENGL_ES3_BIT_KHR),
        _ => None,
    }
}

fn sanitize_context_attribs(attrib_list: *const EGLint) -> Vec<EGLint> {
    let mut major = 3;
    let mut minor: Option<EGLint> = None;
    if !attrib_list.is_null() {
        let mut idx = 0isize;
        while idx < 64 {
            let key = unsafe { *attrib_list.offset(idx) };
            if key == EGL_NONE {
                break;
            }
            let val = unsafe { *attrib_list.offset(idx + 1) };
            match key {
                EGL_CONTEXT_CLIENT_VERSION => {
                    if val >= 2 {
                        major = val;
                    }
                }
                EGL_CONTEXT_MINOR_VERSION => {
                    if val >= 0 {
                        minor = Some(val);
                    }
                }
                _ => {}
            }
            idx += 2;
        }
    }
    let mut out = vec![EGL_CONTEXT_CLIENT_VERSION, major];
    if let Some(m) = minor {
        out.push(EGL_CONTEXT_MINOR_VERSION);
        out.push(m);
    }
    out.push(EGL_NONE);
    out
}

fn sanitize_pbuffer_attribs(attrib_list: *const EGLint) -> [EGLint; 5] {
    let mut width: EGLint = 1;
    let mut height: EGLint = 1;
    if !attrib_list.is_null() {
        let mut idx = 0isize;
        while idx < 64 {
            let key = unsafe { *attrib_list.offset(idx) };
            if key == EGL_NONE {
                break;
            }
            let val = unsafe { *attrib_list.offset(idx + 1) };
            match key {
                EGL_WIDTH if val > 0 => width = val,
                EGL_HEIGHT if val > 0 => height = val,
                _ => {}
            }
            idx += 2;
        }
    }
    [EGL_WIDTH, width, EGL_HEIGHT, height, EGL_NONE]
}

fn strip_duplicate_ext_suffix(name: &str) -> Option<String> {
    for suffix in ["EXT", "KHR", "OES", "NV", "ARB"] {
        let doubled = format!("{suffix}{suffix}");
        if let Some(prefix) = name.strip_suffix(&doubled) {
            return Some(format!("{prefix}{suffix}"));
        }
    }
    None
}

fn resolve_egl_self_proc(name: &str) -> *mut c_void {
    match name {
        "eglBindAPI" => mocktail_rust_egl_bind_api as *mut c_void,
        "eglChooseConfig" => mocktail_rust_egl_choose_config as *mut c_void,
        "eglCreateContext" => mocktail_rust_egl_create_context as *mut c_void,
        "eglCreatePbufferSurface" => mocktail_rust_egl_create_pbuffer_surface as *mut c_void,
        "eglCreateWindowSurface" => mocktail_rust_egl_create_window_surface as *mut c_void,
        "eglDestroyContext" => mocktail_rust_egl_destroy_context as *mut c_void,
        "eglDestroySurface" => mocktail_rust_egl_destroy_surface as *mut c_void,
        "eglGetConfigAttrib" => mocktail_rust_egl_get_config_attrib as *mut c_void,
        "eglGetCurrentContext" => mocktail_rust_egl_get_current_context as *mut c_void,
        "eglGetCurrentDisplay" => mocktail_rust_egl_get_current_display as *mut c_void,
        "eglGetCurrentSurface" => mocktail_rust_egl_get_current_surface as *mut c_void,
        "eglGetDisplay" => mocktail_rust_egl_get_display as *mut c_void,
        "eglGetError" => mocktail_rust_egl_get_error as *mut c_void,
        "eglGetProcAddress" => mocktail_rust_egl_get_proc_address as *mut c_void,
        "eglInitialize" => mocktail_rust_egl_initialize as *mut c_void,
        "eglMakeCurrent" => mocktail_rust_egl_make_current as *mut c_void,
        "eglQueryString" => mocktail_rust_egl_query_string as *mut c_void,
        "eglQuerySurface" => mocktail_rust_egl_query_surface as *mut c_void,
        "eglSwapBuffers" => mocktail_rust_egl_swap_buffers as *mut c_void,
        "eglSwapInterval" => mocktail_rust_egl_swap_interval as *mut c_void,
        "eglTerminate" => mocktail_rust_egl_terminate as *mut c_void,
        _ => std::ptr::null_mut(),
    }
}

fn host_lookup_proc_cstr(c_name: *const c_char) -> *mut c_void {
    if let Some(proc_fn) = unsafe {
        let sym = dlsym_default(b"mocktail_gl_proc_address\0");
        if sym.is_null() {
            None
        } else {
            let func: FnGlProcAddress = std::mem::transmute(sym);
            Some(func)
        }
    } {
        let resolved = unsafe { proc_fn(c_name) };
        if !resolved.is_null() {
            return resolved;
        }
    }
    if let Some(host_get_proc) = host_egl_sym::<HostEglGetProcAddress>(b"eglGetProcAddress\0") {
        let resolved = unsafe { host_get_proc(c_name) };
        if !resolved.is_null() {
            return resolved;
        }
    }
    std::ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn mocktail_rust_egl_get_error() -> EGLint {
    let err = TLS_LAST_ERROR.with(|c| c.replace(EGL_SUCCESS));
    if err != EGL_SUCCESS {
        return err;
    }
    if real_display().is_null() {
        return EGL_SUCCESS;
    }
    if let Some(host_err) = host_egl_sym::<HostEglGetError>(b"eglGetError\0") {
        return unsafe { host_err() };
    }
    EGL_SUCCESS
}

#[no_mangle]
pub extern "C" fn mocktail_rust_egl_get_display(_display_id: EGLNativeDisplayType) -> EGLDisplay {
    let dpy = active_display();
    if dpy.is_null() {
        set_error(EGL_NOT_INITIALIZED);
        return EGL_NO_DISPLAY;
    }
    set_error(EGL_SUCCESS);
    dpy
}

#[no_mangle]
pub extern "C" fn mocktail_rust_egl_initialize(
    display: EGLDisplay,
    major: *mut EGLint,
    minor: *mut EGLint,
) -> EGLBoolean {
    let expected = active_display();
    if expected.is_null() {
        set_error(EGL_NOT_INITIALIZED);
        return EGL_FALSE;
    }
    if display.is_null() || display != expected {
        set_error(EGL_BAD_DISPLAY);
        return EGL_FALSE;
    }
    if !major.is_null() {
        unsafe { *major = 1 };
    }
    if !minor.is_null() {
        unsafe { *minor = 5 };
    }
    set_error(EGL_SUCCESS);
    EGL_TRUE
}

#[no_mangle]
pub extern "C" fn mocktail_rust_egl_terminate(display: EGLDisplay) -> EGLBoolean {
    let expected = active_display();
    if expected.is_null() || display != expected {
        set_error(EGL_BAD_DISPLAY);
        return EGL_FALSE;
    }
    let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    reg.primary_context_claimed = false;
    reg.primary_surface_claimed = false;
    reg.mock_contexts.clear();
    reg.mock_surfaces.clear();
    set_error(EGL_SUCCESS);
    EGL_TRUE
}

#[no_mangle]
pub extern "C" fn mocktail_rust_egl_bind_api(api: EGLenum) -> EGLBoolean {
    if api == EGL_OPENGL_ES_API {
        TLS_BOUND_API.with(|c| c.set(api));
        set_error(EGL_SUCCESS);
        return EGL_TRUE;
    }
    set_error(EGL_BAD_PARAMETER);
    EGL_FALSE
}

#[no_mangle]
pub extern "C" fn mocktail_rust_egl_query_string(
    display: EGLDisplay,
    name: EGLint,
) -> *const c_char {
    if display.is_null() && name == EGL_EXTENSIONS {
        return b"EGL_KHR_create_context EGL_KHR_surfaceless_context EGL_KHR_get_all_proc_addresses\0"
            .as_ptr()
            .cast();
    }
    let expected = active_display();
    if expected.is_null() {
        set_error(EGL_NOT_INITIALIZED);
        return std::ptr::null();
    }
    if display != expected {
        set_error(EGL_BAD_DISPLAY);
        return std::ptr::null();
    }
    if !real_display().is_null() {
        if let Some(host_query) = host_egl_sym::<HostEglQueryString>(b"eglQueryString\0") {
            let ptr = unsafe { host_query(display, name) };
            if !ptr.is_null() {
                set_error(EGL_SUCCESS);
                return ptr;
            }
        }
    }
    set_error(EGL_SUCCESS);
    match name {
        EGL_VENDOR => b"Mocktail\0".as_ptr().cast(),
        EGL_VERSION => b"1.5\0".as_ptr().cast(),
        EGL_CLIENT_APIS => b"OpenGL_ES\0".as_ptr().cast(),
        EGL_EXTENSIONS => b"EGL_KHR_create_context EGL_KHR_surfaceless_context EGL_KHR_get_all_proc_addresses\0"
            .as_ptr()
            .cast(),
        _ => {
            set_error(EGL_BAD_PARAMETER);
            std::ptr::null()
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_egl_choose_config(
    display: EGLDisplay,
    _attrib_list: *const EGLint,
    configs: *mut EGLConfig,
    config_size: EGLint,
    num_config: *mut EGLint,
) -> EGLBoolean {
    let expected = active_display();
    if expected.is_null() {
        set_error(EGL_NOT_INITIALIZED);
        return EGL_FALSE;
    }
    if display != expected {
        set_error(EGL_BAD_DISPLAY);
        return EGL_FALSE;
    }
    if num_config.is_null() {
        set_error(EGL_BAD_PARAMETER);
        return EGL_FALSE;
    }
    let mut cfg = real_config();
    if cfg.is_null() && test_stubs_enabled() {
        cfg = MOCK_CONFIG as EGLConfig;
    }
    if cfg.is_null() {
        set_error(EGL_NOT_INITIALIZED);
        return EGL_FALSE;
    }
    if !configs.is_null() && config_size > 0 {
        unsafe { *configs = cfg };
    }
    unsafe { *num_config = 1 };
    set_error(EGL_SUCCESS);
    EGL_TRUE
}

#[no_mangle]
pub extern "C" fn mocktail_rust_egl_get_config_attrib(
    display: EGLDisplay,
    config: EGLConfig,
    attribute: EGLint,
    value: *mut EGLint,
) -> EGLBoolean {
    let expected = active_display();
    if expected.is_null() {
        set_error(EGL_NOT_INITIALIZED);
        return EGL_FALSE;
    }
    if display != expected {
        set_error(EGL_BAD_DISPLAY);
        return EGL_FALSE;
    }
    if value.is_null() {
        set_error(EGL_BAD_PARAMETER);
        return EGL_FALSE;
    }
    if !real_display().is_null() && !config.is_null() {
        if let Some(host_attrib) = host_egl_sym::<HostEglGetConfigAttrib>(b"eglGetConfigAttrib\0") {
            let mut host_val: EGLint = 0;
            if unsafe { host_attrib(display, config, attribute, &mut host_val) } == EGL_TRUE {
                // Ensure OpenGL ES 3 renderable bit is preserved when ES2 is supported.
                if (attribute == EGL_RENDERABLE_TYPE || attribute == EGL_CONFORMANT)
                    && (host_val & EGL_OPENGL_ES2_BIT) != 0
                {
                    host_val |= EGL_OPENGL_ES3_BIT_KHR;
                }
                unsafe { *value = host_val };
                set_error(EGL_SUCCESS);
                return EGL_TRUE;
            }
        }
    }
    if let Some(v) = fallback_config_attrib(attribute) {
        unsafe { *value = v };
        set_error(EGL_SUCCESS);
        return EGL_TRUE;
    }
    set_error(EGL_BAD_ATTRIBUTE);
    EGL_FALSE
}

#[no_mangle]
pub extern "C" fn mocktail_rust_egl_create_window_surface(
    display: EGLDisplay,
    _config: EGLConfig,
    win: EGLNativeWindowType,
    _attrib_list: *const EGLint,
) -> EGLSurface {
    let expected = active_display();
    if expected.is_null() {
        set_error(EGL_NOT_INITIALIZED);
        return EGL_NO_SURFACE;
    }
    if display != expected {
        set_error(EGL_BAD_DISPLAY);
        return EGL_NO_SURFACE;
    }
    if win.is_null() && !test_stubs_enabled() {
        set_error(EGL_BAD_NATIVE_WINDOW);
        return EGL_NO_SURFACE;
    }
    let real_surf = real_surface();
    if !real_surf.is_null() {
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        reg.primary_surface_claimed = true;
        set_error(EGL_SUCCESS);
        return real_surf;
    }
    if test_stubs_enabled() {
        set_error(EGL_SUCCESS);
        return MOCK_WINDOW_SURFACE as EGLSurface;
    }
    set_error(EGL_NOT_INITIALIZED);
    EGL_NO_SURFACE
}

#[no_mangle]
pub extern "C" fn mocktail_rust_egl_create_pbuffer_surface(
    display: EGLDisplay,
    config: EGLConfig,
    attrib_list: *const EGLint,
) -> EGLSurface {
    let expected = active_display();
    if expected.is_null() {
        set_error(EGL_NOT_INITIALIZED);
        return EGL_NO_SURFACE;
    }
    if display != expected {
        set_error(EGL_BAD_DISPLAY);
        return EGL_NO_SURFACE;
    }
    if !real_display().is_null() {
        let pb_attrs = sanitize_pbuffer_attribs(attrib_list);
        if let Some(host_pb) =
            host_egl_sym::<HostEglCreatePbufferSurface>(b"eglCreatePbufferSurface\0")
        {
            let cfg = if !config.is_null() { config } else { real_config() };
            let mut surf = unsafe { host_pb(display, cfg, pb_attrs.as_ptr()) };
            if surf.is_null() {
                // Retry with an explicit pbuffer-capable config on the same display.
                if let Some(host_choose) =
                    host_egl_sym::<HostEglChooseConfig>(b"eglChooseConfig\0")
                {
                    let cfg_req = [
                        EGL_SURFACE_TYPE,
                        EGL_PBUFFER_BIT,
                        EGL_RENDERABLE_TYPE,
                        EGL_OPENGL_ES2_BIT,
                        EGL_NONE,
                    ];
                    let mut pbuf_cfg: EGLConfig = std::ptr::null_mut();
                    let mut count: EGLint = 0;
                    if unsafe {
                        host_choose(display, cfg_req.as_ptr(), &mut pbuf_cfg, 1, &mut count)
                    } == EGL_TRUE
                        && count > 0
                        && !pbuf_cfg.is_null()
                    {
                        surf = unsafe { host_pb(display, pbuf_cfg, pb_attrs.as_ptr()) };
                    }
                }
            }
            if !surf.is_null() {
                let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
                reg.host_pbuffers.insert(surf as usize);
                set_error(EGL_SUCCESS);
                return surf;
            }
            set_error(EGL_BAD_ALLOC);
            return EGL_NO_SURFACE;
        }
        set_error(EGL_NOT_INITIALIZED);
        return EGL_NO_SURFACE;
    }
    if test_stubs_enabled() {
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        let id = MOCK_SURFACE_BASE + reg.next_mock_handle;
        reg.next_mock_handle += 1;
        reg.mock_surfaces.insert(id);
        set_error(EGL_SUCCESS);
        return id as EGLSurface;
    }
    set_error(EGL_NOT_INITIALIZED);
    EGL_NO_SURFACE
}

#[no_mangle]
pub extern "C" fn mocktail_rust_egl_destroy_surface(
    display: EGLDisplay,
    surface: EGLSurface,
) -> EGLBoolean {
    let expected = active_display();
    if expected.is_null() || display != expected {
        set_error(EGL_BAD_DISPLAY);
        return EGL_FALSE;
    }
    if surface.is_null() {
        set_error(EGL_BAD_SURFACE);
        return EGL_FALSE;
    }
    if surface == real_surface() {
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        reg.primary_surface_claimed = false;
        set_error(EGL_SUCCESS);
        return EGL_TRUE;
    }
    let key = surface as usize;
    let is_host_pb = {
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        if reg.host_pbuffers.remove(&key) {
            true
        } else {
            reg.mock_surfaces.remove(&key);
            false
        }
    };
    if is_host_pb {
        if let Some(host_destroy) = host_egl_sym::<HostEglDestroySurface>(b"eglDestroySurface\0") {
            let ok = unsafe { host_destroy(display, surface) };
            set_error(if ok == EGL_TRUE {
                EGL_SUCCESS
            } else {
                EGL_BAD_SURFACE
            });
            return ok;
        }
    }
    set_error(EGL_SUCCESS);
    EGL_TRUE
}

#[no_mangle]
pub extern "C" fn mocktail_rust_egl_create_context(
    display: EGLDisplay,
    config: EGLConfig,
    share_context: EGLContext,
    attrib_list: *const EGLint,
) -> EGLContext {
    let expected = active_display();
    if expected.is_null() {
        set_error(EGL_NOT_INITIALIZED);
        return EGL_NO_CONTEXT;
    }
    if display != expected {
        set_error(EGL_BAD_DISPLAY);
        return EGL_NO_CONTEXT;
    }
    let primary = real_context();
    if !primary.is_null() {
        if share_context.is_null() {
            let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
            if !reg.primary_context_claimed {
                reg.primary_context_claimed = true;
                set_error(EGL_SUCCESS);
                return primary;
            }
        }
        // Auxiliary or shared worker thread context: create a real host EGL context.
        let attrs = sanitize_context_attribs(attrib_list);
        if let Some(host_create) = host_egl_sym::<HostEglCreateContext>(b"eglCreateContext\0") {
            let cfg = if !config.is_null() { config } else { real_config() };
            let mut created = unsafe { host_create(display, cfg, share_context, attrs.as_ptr()) };
            if created.is_null() {
                // Retry with ES 2 fallback attribute list in case driver rejects minor version.
                let fallback_attrs = [EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE];
                created = unsafe { host_create(display, cfg, share_context, fallback_attrs.as_ptr()) };
            }
            if !created.is_null() {
                let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
                reg.host_contexts.insert(created as usize);
                if trace_enabled() {
                    eprintln!(
                        "  [egl] created host context={created:?} share={share_context:?}"
                    );
                }
                set_error(EGL_SUCCESS);
                return created;
            }
            set_error(EGL_BAD_MATCH);
            return EGL_NO_CONTEXT;
        }
        set_error(EGL_NOT_INITIALIZED);
        return EGL_NO_CONTEXT;
    }
    if test_stubs_enabled() {
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        let id = MOCK_CONTEXT_BASE + reg.next_mock_handle;
        reg.next_mock_handle += 1;
        reg.mock_contexts.insert(id);
        set_error(EGL_SUCCESS);
        return id as EGLContext;
    }
    set_error(EGL_NOT_INITIALIZED);
    EGL_NO_CONTEXT
}

#[no_mangle]
pub extern "C" fn mocktail_rust_egl_destroy_context(
    display: EGLDisplay,
    context: EGLContext,
) -> EGLBoolean {
    let expected = active_display();
    if expected.is_null() || display != expected {
        set_error(EGL_BAD_DISPLAY);
        return EGL_FALSE;
    }
    if context.is_null() {
        set_error(EGL_BAD_CONTEXT);
        return EGL_FALSE;
    }
    notify_gles_context_destroy(context);

    if TLS_CURRENT_CONTEXT.with(|c| c.get()) == context as usize {
        TLS_CURRENT_CONTEXT.with(|c| c.set(0));
        TLS_CURRENT_DRAW.with(|c| c.set(0));
        TLS_CURRENT_READ.with(|c| c.set(0));
    }

    if context == real_context() {
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        reg.primary_context_claimed = false;
        set_error(EGL_SUCCESS);
        return EGL_TRUE;
    }
    let key = context as usize;
    let is_host_ctx = {
        let mut reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        if reg.host_contexts.remove(&key) {
            true
        } else {
            reg.mock_contexts.remove(&key);
            false
        }
    };
    if is_host_ctx {
        if let Some(host_destroy) = host_egl_sym::<HostEglDestroyContext>(b"eglDestroyContext\0") {
            let ok = unsafe { host_destroy(display, context) };
            set_error(if ok == EGL_TRUE {
                EGL_SUCCESS
            } else {
                EGL_BAD_CONTEXT
            });
            return ok;
        }
    }
    set_error(EGL_SUCCESS);
    EGL_TRUE
}

fn make_current_release(expected: EGLDisplay, prev_ctx: usize, primary_ctx: EGLContext) -> EGLBoolean {
    let mut ok = true;
    if prev_ctx == primary_ctx as usize && !primary_ctx.is_null() {
        let sym = unsafe { dlsym_default(b"mocktail_window_release_current\0") };
        if !sym.is_null() {
            let release: FnWindowReleaseCurrent = unsafe { std::mem::transmute(sym) };
            ok = unsafe { release() };
        }
    } else if !real_display().is_null() {
        if let Some(host_mc) = host_egl_sym::<HostEglMakeCurrent>(b"eglMakeCurrent\0") {
            ok = unsafe { host_mc(expected, EGL_NO_SURFACE, EGL_NO_SURFACE, EGL_NO_CONTEXT) }
                == EGL_TRUE;
        }
    }
    if !ok {
        set_error(EGL_BAD_ACCESS);
        return EGL_FALSE;
    }
    TLS_CURRENT_DISPLAY.with(|c| c.set(0));
    TLS_CURRENT_DRAW.with(|c| c.set(0));
    TLS_CURRENT_READ.with(|c| c.set(0));
    TLS_CURRENT_CONTEXT.with(|c| c.set(0));
    notify_gles_make_current(EGL_NO_CONTEXT);
    set_error(EGL_SUCCESS);
    EGL_TRUE
}

#[no_mangle]
pub extern "C" fn mocktail_rust_egl_make_current(
    display: EGLDisplay,
    draw: EGLSurface,
    read: EGLSurface,
    context: EGLContext,
) -> EGLBoolean {
    let expected = active_display();
    if expected.is_null() {
        set_error(EGL_NOT_INITIALIZED);
        return EGL_FALSE;
    }
    if display != expected {
        set_error(EGL_BAD_DISPLAY);
        return EGL_FALSE;
    }

    let prev_ctx = TLS_CURRENT_CONTEXT.with(|c| c.get());
    let primary_ctx = real_context();
    let primary_surf = real_surface();

    if draw.is_null() && read.is_null() && context.is_null() {
        return make_current_release(expected, prev_ctx, primary_ctx);
    }

    if !primary_ctx.is_null() {
        if context == primary_ctx && (draw == primary_surf || read == primary_surf) {
            let sym = unsafe { dlsym_default(b"mocktail_window_make_current\0") };
            let ok = if sym.is_null() {
                false
            } else {
                let mc: FnWindowMakeCurrent = unsafe { std::mem::transmute(sym) };
                unsafe { mc() }
            };
            if !ok {
                set_error(EGL_BAD_ACCESS);
                return EGL_FALSE;
            }
        } else {
            // Host-owned shared/pbuffer context or surfaceless makeCurrent.
            let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
            let known_ctx = reg.host_contexts.contains(&(context as usize))
                || context == primary_ctx;
            drop(reg);
            if !known_ctx {
                set_error(EGL_BAD_CONTEXT);
                return EGL_FALSE;
            }
            let Some(host_mc) = host_egl_sym::<HostEglMakeCurrent>(b"eglMakeCurrent\0") else {
                set_error(EGL_NOT_INITIALIZED);
                return EGL_FALSE;
            };
            let ok = unsafe { host_mc(display, draw, read, context) };
            if ok != EGL_TRUE {
                set_error(EGL_BAD_ACCESS);
                return EGL_FALSE;
            }
        }
        TLS_CURRENT_DISPLAY.with(|c| c.set(display as usize));
        TLS_CURRENT_DRAW.with(|c| c.set(draw as usize));
        TLS_CURRENT_READ.with(|c| c.set(read as usize));
        TLS_CURRENT_CONTEXT.with(|c| c.set(context as usize));
        notify_gles_make_current(context);
        set_error(EGL_SUCCESS);
        return EGL_TRUE;
    }

    if test_stubs_enabled() {
        let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
        let valid_ctx = reg.mock_contexts.contains(&(context as usize));
        let valid_draw = draw as usize == MOCK_WINDOW_SURFACE
            || reg.mock_surfaces.contains(&(draw as usize));
        let valid_read = read as usize == MOCK_WINDOW_SURFACE
            || reg.mock_surfaces.contains(&(read as usize));
        drop(reg);
        if !valid_ctx {
            set_error(EGL_BAD_CONTEXT);
            return EGL_FALSE;
        }
        if !valid_draw || !valid_read {
            set_error(EGL_BAD_SURFACE);
            return EGL_FALSE;
        }
        TLS_CURRENT_DISPLAY.with(|c| c.set(display as usize));
        TLS_CURRENT_DRAW.with(|c| c.set(draw as usize));
        TLS_CURRENT_READ.with(|c| c.set(read as usize));
        TLS_CURRENT_CONTEXT.with(|c| c.set(context as usize));
        notify_gles_make_current(context);
        set_error(EGL_SUCCESS);
        return EGL_TRUE;
    }

    set_error(EGL_NOT_INITIALIZED);
    EGL_FALSE
}

#[no_mangle]
pub extern "C" fn mocktail_rust_egl_get_current_context() -> EGLContext {
    let tls = TLS_CURRENT_CONTEXT.with(|c| c.get());
    if tls != 0 {
        return tls as EGLContext;
    }
    EGL_NO_CONTEXT
}

#[no_mangle]
pub extern "C" fn mocktail_rust_egl_get_current_display() -> EGLDisplay {
    let ctx = TLS_CURRENT_CONTEXT.with(|c| c.get());
    if ctx == 0 {
        return EGL_NO_DISPLAY;
    }
    let dpy = TLS_CURRENT_DISPLAY.with(|c| c.get());
    if dpy != 0 {
        return dpy as EGLDisplay;
    }
    active_display()
}

#[no_mangle]
pub extern "C" fn mocktail_rust_egl_get_current_surface(readdraw: EGLint) -> EGLSurface {
    if TLS_CURRENT_CONTEXT.with(|c| c.get()) == 0 {
        return EGL_NO_SURFACE;
    }
    match readdraw {
        EGL_DRAW => TLS_CURRENT_DRAW.with(|c| c.get()) as EGLSurface,
        EGL_READ => TLS_CURRENT_READ.with(|c| c.get()) as EGLSurface,
        _ => {
            set_error(EGL_BAD_PARAMETER);
            EGL_NO_SURFACE
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_egl_query_surface(
    display: EGLDisplay,
    surface: EGLSurface,
    attribute: EGLint,
    value: *mut EGLint,
) -> EGLBoolean {
    let expected = active_display();
    if expected.is_null() {
        set_error(EGL_NOT_INITIALIZED);
        return EGL_FALSE;
    }
    if display != expected {
        set_error(EGL_BAD_DISPLAY);
        return EGL_FALSE;
    }
    if surface.is_null() || value.is_null() {
        set_error(EGL_BAD_PARAMETER);
        return EGL_FALSE;
    }
    let reg = registry().lock().unwrap_or_else(|e| e.into_inner());
    let is_host_pb = reg.host_pbuffers.contains(&(surface as usize));
    drop(reg);

    if is_host_pb {
        if let Some(host_qs) = host_egl_sym::<HostEglQuerySurface>(b"eglQuerySurface\0") {
            let ok = unsafe { host_qs(display, surface, attribute, value) };
            set_error(if ok == EGL_TRUE {
                EGL_SUCCESS
            } else {
                EGL_BAD_ATTRIBUTE
            });
            return ok;
        }
    }

    match attribute {
        EGL_WIDTH => {
            let mut w = 1280;
            let sym = unsafe { dlsym_default(b"mocktail_window_width\0") };
            if !sym.is_null() {
                let func: FnWindowDim = unsafe { std::mem::transmute(sym) };
                w = unsafe { func() }.max(1);
            }
            unsafe { *value = w };
            set_error(EGL_SUCCESS);
            EGL_TRUE
        }
        EGL_HEIGHT => {
            let mut h = 720;
            let sym = unsafe { dlsym_default(b"mocktail_window_height\0") };
            if !sym.is_null() {
                let func: FnWindowDim = unsafe { std::mem::transmute(sym) };
                h = unsafe { func() }.max(1);
            }
            unsafe { *value = h };
            set_error(EGL_SUCCESS);
            EGL_TRUE
        }
        EGL_CONFIG_ID => {
            unsafe { *value = 1 };
            set_error(EGL_SUCCESS);
            EGL_TRUE
        }
        EGL_RENDER_BUFFER => {
            unsafe { *value = EGL_BACK_BUFFER };
            set_error(EGL_SUCCESS);
            EGL_TRUE
        }
        EGL_LARGEST_PBUFFER => {
            unsafe { *value = 0 };
            set_error(EGL_SUCCESS);
            EGL_TRUE
        }
        _ => {
            if !real_surface().is_null() && surface == real_surface() {
                if let Some(host_qs) = host_egl_sym::<HostEglQuerySurface>(b"eglQuerySurface\0") {
                    if unsafe { host_qs(display, surface, attribute, value) } == EGL_TRUE {
                        set_error(EGL_SUCCESS);
                        return EGL_TRUE;
                    }
                }
            }
            set_error(EGL_BAD_ATTRIBUTE);
            EGL_FALSE
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_egl_swap_buffers(
    display: EGLDisplay,
    surface: EGLSurface,
) -> EGLBoolean {
    let expected = active_display();
    if expected.is_null() {
        set_error(EGL_NOT_INITIALIZED);
        return EGL_FALSE;
    }
    if display != expected || surface.is_null() {
        set_error(EGL_BAD_SURFACE);
        return EGL_FALSE;
    }
    if !real_display().is_null() {
        let sym = unsafe { dlsym_default(b"mocktail_window_swap_buffers\0") };
        if sym.is_null() {
            set_error(EGL_BAD_ACCESS);
            return EGL_FALSE;
        }
        let swap: FnWindowSwap = unsafe { std::mem::transmute(sym) };
        let ok = unsafe { swap() };
        set_error(if ok { EGL_SUCCESS } else { EGL_BAD_ACCESS });
        return if ok { EGL_TRUE } else { EGL_FALSE };
    }
    if test_stubs_enabled() {
        set_error(EGL_SUCCESS);
        return EGL_TRUE;
    }
    set_error(EGL_NOT_INITIALIZED);
    EGL_FALSE
}

#[no_mangle]
pub extern "C" fn mocktail_rust_egl_swap_interval(
    display: EGLDisplay,
    interval: EGLint,
) -> EGLBoolean {
    let expected = active_display();
    if expected.is_null() || display != expected {
        set_error(EGL_BAD_DISPLAY);
        return EGL_FALSE;
    }
    if !real_display().is_null() {
        let sym = unsafe { dlsym_default(b"mocktail_window_set_swap_interval\0") };
        if !sym.is_null() {
            let set_iv: FnWindowSwapInterval = unsafe { std::mem::transmute(sym) };
            let ok = unsafe { set_iv(interval) };
            set_error(if ok { EGL_SUCCESS } else { EGL_BAD_ACCESS });
            return if ok { EGL_TRUE } else { EGL_FALSE };
        }
    }
    if test_stubs_enabled() {
        set_error(EGL_SUCCESS);
        return EGL_TRUE;
    }
    set_error(EGL_NOT_INITIALIZED);
    EGL_FALSE
}

#[no_mangle]
pub extern "C" fn mocktail_rust_egl_get_proc_address(procname: *const c_char) -> *mut c_void {
    if procname.is_null() {
        return std::ptr::null_mut();
    }
    let Ok(name) = unsafe { CStr::from_ptr(procname) }.to_str() else {
        return std::ptr::null_mut();
    };
    if name.is_empty() {
        return std::ptr::null_mut();
    }

    if name.starts_with("egl") {
        let self_egl = resolve_egl_self_proc(name);
        if !self_egl.is_null() {
            return self_egl;
        }
    }

    // First ask our companion libGLESv2.so interceptor/stub registry.
    let gles = adapter_gles_handle();
    if !gles.is_null() {
        let lookup_sym =
            unsafe { dlsym_cstr(gles, b"mocktail_gles_lookup_proc\0".as_ptr().cast()) };
        if !lookup_sym.is_null() {
            let lookup: FnGlProcAddress = unsafe { std::mem::transmute(lookup_sym) };
            let ptr = unsafe { lookup(procname) };
            if !ptr.is_null() {
                return ptr;
            }
        }
        let direct = unsafe { dlsym_cstr(gles, procname) };
        if !direct.is_null() {
            return direct;
        }
    }

    // Fallback directly to SDL/host EGL proc resolution.
    let raw = host_lookup_proc_cstr(procname);
    if !raw.is_null() {
        return raw;
    }

    // Fallback for known Roblox duplicate extension suffix strings (e.g. *EXTEXT / *KHRKHR).
    if let Some(fixed) = strip_duplicate_ext_suffix(name) {
        if let Ok(c_fixed) = CString::new(fixed) {
            if !gles.is_null() {
                let lookup_sym =
                    unsafe { dlsym_cstr(gles, b"mocktail_gles_lookup_proc\0".as_ptr().cast()) };
                if !lookup_sym.is_null() {
                    let lookup: FnGlProcAddress = unsafe { std::mem::transmute(lookup_sym) };
                    let ptr = unsafe { lookup(c_fixed.as_ptr()) };
                    if !ptr.is_null() {
                        return ptr;
                    }
                }
            }
            let fixed_ptr = host_lookup_proc_cstr(c_fixed.as_ptr());
            if !fixed_ptr.is_null() {
                return fixed_ptr;
            }
        }
    }

    std::ptr::null_mut()
}
