//! Isolated graphics readiness canary launcher and log/evidence validator.

use std::ffi::{c_char, c_void, CStr, CString};
use std::fs;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::unix_ipc::{
    create_unique_temp_dir, cstrings_as_mut_ptrs, current_pid, errno_message, last_errno,
    lookup_process_env_bytes, move_fd_above_stdio, path_from_ffi, path_to_cstr, posix_spawn_raw,
    push_env_kv, read_all_fd, slice_from_ffi, terminate_and_reap, validate_executable_regular_file,
    OwnedFd, SpawnFileActions, TempDirError,
};
use crate::{copy_error, copy_to_c_buffer};

pub const K_CANARY_BACKEND_DIRECT_VULKAN: i32 = 0;
pub const K_CANARY_BACKEND_OPENGL_ES: i32 = 1;
pub const K_CANARY_BACKEND_SYSTEM_EGL: i32 = 2;
pub const K_CANARY_BACKEND_ANGLE_VULKAN: i32 = 3;
pub const K_CANARY_BACKEND_ANGLE_SWIFTSHADER: i32 = 4;

const K_MAX_CANARY_LOG_BYTES: usize = 64 * 1024 * 1024;
const K_VULKAN_OVERRIDES_JSON: &[u8] =
    br#"{"FStringGraphicsVulkanShaderMTDenyPattern":"4318:.*"}"#;

const K_INHERITED_ENV_NAMES: &[&[u8]] = &[
    b"DISPLAY",
    b"WAYLAND_DISPLAY",
    b"XDG_RUNTIME_DIR",
    b"XDG_SESSION_TYPE",
    b"SDL_VIDEO_DRIVER",
    b"SDL_VIDEODRIVER",
    b"MOCKTAIL_FORCE_WAYLAND",
    b"MOCKTAIL_FORCE_X11",
    b"MOCKTAIL_ANGLE_FORCE_X11",
    b"MOCKTAIL_PREFER_WAYLAND",
    b"DBUS_SESSION_BUS_ADDRESS",
    b"PULSE_SERVER",
    b"PIPEWIRE_REMOTE",
    b"XAUTHORITY",
    b"LANG",
    b"LANGUAGE",
    b"TZ",
    b"USER",
    b"LOGNAME",
    b"VK_DRIVER_FILES",
    b"VK_ICD_FILENAMES",
    b"vk_require_etc2",
    b"MESA_LOADER_DRIVER_OVERRIDE",
    b"LIBGL_ALWAYS_SOFTWARE",
    b"LIBGL_DRIVERS_PATH",
    b"GALLIUM_DRIVER",
    b"__EGL_VENDOR_LIBRARY_FILENAMES",
    b"DRI_PRIME",
    b"__NV_PRIME_RENDER_OFFLOAD",
    b"__VK_LAYER_NV_optimus",
    b"__GLX_VENDOR_LIBRARY_NAME",
    b"LD_LIBRARY_PATH",
    b"MOCKTAIL_RUNTIME_LIBRARY_DIR",
    b"MOCKTAIL_EGL_LIBRARY",
    b"MOCKTAIL_GLES_LIBRARY",
    b"MOCKTAIL_ANGLE_LIB_DIR",
    b"GDK_PIXBUF_MODULE_FILE",
    b"XDG_DATA_DIRS",
    b"GSETTINGS_SCHEMA_DIR",
    b"GIO_EXTRA_MODULES",
    b"GTK_PATH",
    b"http_proxy",
    b"https_proxy",
    b"all_proxy",
    b"no_proxy",
    b"NO_PROXY",
];

const K_STATIC_CANARY_ENV: &[(&[u8], &[u8])] = &[
    (b"PATH", b"/usr/bin:/bin"),
    (b"MOCKTAIL_SKIP_UPDATE_CHECK", b"1"),
    (b"MOCKTAIL_ISOLATED_CANARY", b"1"),
    (b"MOCKTAIL_ALLOW_NO_COOKIE_LUA_APP", b"1"),
    (b"MOCKTAIL_SKIP_FIRST_LAUNCH_LOGIN", b"1"),
    (b"MOCKTAIL_VALIDATE_ROBLOX_COOKIE", b"0"),
    (b"MOCKTAIL_IGNORE_WINDOW_CLOSE", b"1"),
    (b"MOCKTAIL_DISABLE_SUPPORT_BUNDLE", b"1"),
    (b"MOCKTAIL_SKIP_LIBROBLOX_CTORS", b"0"),
    (b"MOCKTAIL_HOST_JNI_SINGLETON_SEED", b"0"),
    (b"MOCKTAIL_ENGINE_TRACE", b"1"),
    (b"MOCKTAIL_WINDOW_TRACE", b"1"),
    (b"MOCKTAIL_EGL_TRACE", b"1"),
    (b"MOCKTAIL_REQUIRE_REAL_GRAPHICS", b"1"),
    (b"MOCKTAIL_AUTO_EXIT_AFTER_PRESENT_MS", b"5000"),
    (b"MOCKTAIL_STARTUP_THREAD_TIMEOUT_MS", b"120000"),
];

pub type MocktailRustCanaryStrReceiver =
    Option<unsafe extern "C" fn(ctx: *mut c_void, data: *const c_char, len: usize)>;

pub type MocktailRustCanaryResultCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        exit_code: i32,
        teardown_crash: bool,
        log_path: *const c_char,
        log_path_len: usize,
        error: *const c_char,
        error_len: usize,
    ),
>;

#[repr(C)]
pub struct MocktailRustCanaryOptions {
    pub runtime_binary: *const c_char,
    pub runtime_binary_len: usize,
    pub payload_directory: *const c_char,
    pub payload_directory_len: usize,
    pub compatibility_manifest: *const c_char,
    pub compatibility_manifest_len: usize,
    pub host_abi_profile: *const c_char,
    pub host_abi_profile_len: usize,
    pub cache_root: *const c_char,
    pub cache_root_len: usize,
    pub state_root: *const c_char,
    pub state_root_len: usize,
    pub graphics_backend: i32,
    pub timeout_seconds: i32,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct CanaryRunOutput {
    pub exit_code: i32,
    pub teardown_crash: bool,
    pub log_path: String,
    pub error: String,
}

pub(crate) fn canary_backend_name_cstr(backend: i32) -> &'static CStr {
    match backend {
        K_CANARY_BACKEND_OPENGL_ES => c"opengl",
        K_CANARY_BACKEND_SYSTEM_EGL => c"system",
        K_CANARY_BACKEND_ANGLE_VULKAN => c"angle-vulkan",
        K_CANARY_BACKEND_ANGLE_SWIFTSHADER => c"angle-swiftshader",
        _ => c"direct-vulkan",
    }
}

pub(crate) fn canary_backend_name_str(backend: i32) -> &'static str {
    canary_backend_name_cstr(backend)
        .to_str()
        .unwrap_or("direct-vulkan")
}

pub(crate) fn canary_backend_parse_str(name: &str) -> Option<i32> {
    match name {
        "" | "vulkan" | "native-vulkan" | "direct-vulkan" => Some(K_CANARY_BACKEND_DIRECT_VULKAN),
        "gles" | "opengl" => Some(K_CANARY_BACKEND_OPENGL_ES),
        "auto" | "system" => Some(K_CANARY_BACKEND_SYSTEM_EGL),
        "angle-vulkan" => Some(K_CANARY_BACKEND_ANGLE_VULKAN),
        "angle-swiftshader" => Some(K_CANARY_BACKEND_ANGLE_SWIFTSHADER),
        _ => None,
    }
}

fn has_positive_number_after(text: &str, marker: &str) -> bool {
    let mut pos = 0usize;
    while let Some(found) = text[pos..].find(marker) {
        let start = pos + found + marker.len();
        let digits: String = text[start..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect();
        if let Ok(num) = digits.parse::<u64>() {
            if num > 0 {
                return true;
            }
        }
        pos = start;
    }
    false
}

pub(crate) fn validate_canary_audio_log_str(
    log: &str,
    require_clean_shutdown: bool,
) -> Result<(), (i32, &'static str)> {
    if log.is_empty() {
        return Ok(());
    }

    let opensl = has_positive_number_after(
        log,
        "[mocktail][audio] OpenSL playback activity: submitted_buffers=",
    );
    let fmod = has_positive_number_after(
        log,
        "[mocktail][audio] fmod_java first_submission submitted_buffers=",
    );

    if log.contains("[mocktail][audio] fmod_java init_failed")
        || log.contains("[mocktail][audio] fmod_java write_failed")
        || log.contains("[mocktail][audio] fmod_java close_failed")
    {
        return Err((-1, "graphics canary observed an FMOD audio failure"));
    }
    if opensl
        && (!has_positive_number_after(
            log,
            "[mocktail][audio] OpenSL playback evidence: consumed_buffers=",
        ) || (require_clean_shutdown
            && (!log.contains("[mocktail][audio] OpenSL player shutdown: submitted=")
                || !log.contains("clean=true"))))
    {
        return Err((
            -2,
            "graphics canary submitted OpenSL audio without clean consumption",
        ));
    }
    if fmod
        && (!has_positive_number_after(log, "consumed_buffers=")
            || (require_clean_shutdown
                && (!log.contains("[mocktail][audio] fmod_java shutdown submitted_buffers=")
                    || !log.contains("pending_buffers=0"))))
    {
        return Err((
            -3,
            "graphics canary submitted FMOD audio without clean consumption",
        ));
    }

    Ok(())
}

fn validate_present_evidence(backend: i32, log: &str) -> Result<(), String> {
    const REQUIRED_MARKERS: &[&str] = &[
        "[compat] legacy binary patches: disabled",
        "[compat] signal-recovery handler disabled",
        "[compat] native allocator retained; host allocator bridges disabled",
    ];
    for marker in REQUIRED_MARKERS {
        if !log.contains(marker) {
            return Err(format!("graphics readiness marker is missing: {marker}"));
        }
    }

    if backend == K_CANARY_BACKEND_DIRECT_VULKAN {
        if !log.contains("[window] first Roblox Vulkan frame presented") {
            return Err(
                "Vulkan readiness marker is missing: [window] first Roblox Vulkan frame presented"
                    .to_string(),
            );
        }
        if !has_positive_number_after(log, "[window] vkQueuePresentKHR #") {
            return Err("Vulkan readiness marker is missing: real queue present".to_string());
        }
    } else {
        for marker in [
            "[window] EGL context and surface initialized via SDL3",
            "[window] OpenGL ES context version=3.",
            "[window] first Roblox frame presented",
        ] {
            if !log.contains(marker) {
                return Err(format!("OpenGL readiness marker is missing: {marker}"));
            }
        }
        if !has_positive_number_after(log, "[window] SwapBuffers #") {
            return Err("OpenGL readiness marker is missing: real EGL swap".to_string());
        }
    }

    if log.contains("[FATAL]")
        || log.contains("Segmentation fault")
        || log.contains("core dumped")
    {
        return Err("graphics readiness log contains a fatal process failure".to_string());
    }

    Ok(())
}

pub(crate) fn validate_readiness_log_str(backend: i32, log: &str) -> Result<(), String> {
    validate_present_evidence(backend, log)?;
    const STOPPED_MARKER: &str = "[main] Roblox lifecycle shutdown: Stopped";
    if !log.contains(STOPPED_MARKER) {
        return Err(format!(
            "graphics readiness marker is missing: {STOPPED_MARKER}"
        ));
    }
    if backend == K_CANARY_BACKEND_DIRECT_VULKAN
        && !log.contains("[vulkan] SDL WSI adapter shut down")
    {
        return Err(
            "Vulkan readiness marker is missing: [vulkan] SDL WSI adapter shut down".to_string(),
        );
    }
    validate_canary_audio_log_str(log, true).map_err(|(_, msg)| msg.to_string())
}

pub(crate) fn validate_teardown_crash_log_str(backend: i32, log: &str) -> Result<(), String> {
    validate_present_evidence(backend, log)?;
    for marker in [
        "[window] automatic exit requested",
        "[main] window closed, shutting down",
    ] {
        if !log.contains(marker) {
            return Err(format!("graphics readiness marker is missing: {marker}"));
        }
    }
    validate_canary_audio_log_str(log, false).map_err(|(_, msg)| msg.to_string())
}

struct TempDirCleanup(Option<PathBuf>);

impl Drop for TempDirCleanup {
    fn drop(&mut self) {
        if let Some(dir) = self.0.take() {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

fn read_canary_log(path: &Path) -> Result<String, &'static str> {
    let Some(cpath) = path_to_cstr(path) else {
        return Err("canary readiness log is unavailable");
    };
    let Some(fd) = OwnedFd::from_raw(unsafe {
        libc::open(
            cpath.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    }) else {
        return Err("canary readiness log is unavailable");
    };

    let mut st = MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(fd.as_raw(), st.as_mut_ptr()) } != 0 {
        return Err("canary readiness log is invalid or excessive");
    }
    let st = unsafe { st.assume_init() };
    if (st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || st.st_size < 0
        || st.st_size as usize > K_MAX_CANARY_LOG_BYTES
    {
        return Err("canary readiness log is invalid or excessive");
    }

    let Ok(bytes) = read_all_fd(fd.as_raw(), st.st_size as usize) else {
        return Err("cannot read canary readiness log");
    };
    if bytes.len() > K_MAX_CANARY_LOG_BYTES {
        return Err("canary readiness log is invalid or excessive");
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn monotonic_nanos() -> i128 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as i128) * 1_000_000_000 + (ts.tv_nsec as i128)
}

#[derive(Clone)]
pub(crate) struct CanaryRunConfig {
    pub runtime_binary: PathBuf,
    pub payload_directory: PathBuf,
    pub compatibility_manifest: PathBuf,
    pub host_abi_profile: PathBuf,
    pub cache_root: PathBuf,
    pub state_root: PathBuf,
    pub graphics_backend: i32,
    pub timeout_seconds: i32,
}

fn build_canary_environment(config: &CanaryRunConfig, isolated: &Path) -> Result<Vec<CString>, ()> {
    let mut entries = Vec::with_capacity(72);
    for &name in K_INHERITED_ENV_NAMES {
        if let Some(value) = lookup_process_env_bytes(name) {
            push_env_kv(&mut entries, name, &value)?;
        }
    }

    let isolated_home = isolated.join("home");
    let isolated_data = isolated.join("data");
    let isolated_cache = isolated.join("cache");
    let isolated_state = isolated.join("state");
    let isolated_config = isolated.join("config");
    let roblox_lib = config.payload_directory.join("libroblox.so");
    let asset_root = config.payload_directory.join("assets");
    let asset_path = config.payload_directory.join("assets/content");

    for (name, path) in [
        (&b"HOME"[..], isolated_home.as_path()),
        (&b"XDG_DATA_HOME"[..], isolated_data.as_path()),
        (&b"XDG_CACHE_HOME"[..], isolated_cache.as_path()),
        (&b"XDG_STATE_HOME"[..], isolated_state.as_path()),
        (&b"XDG_CONFIG_HOME"[..], isolated_config.as_path()),
        (&b"MOCKTAIL_DATA_ROOT"[..], isolated_data.as_path()),
        (&b"MOCKTAIL_CACHE_ROOT"[..], isolated_cache.as_path()),
        (&b"MOCKTAIL_STATE_ROOT"[..], isolated_state.as_path()),
        (&b"MOCKTAIL_CONFIG_ROOT"[..], isolated_config.as_path()),
        (&b"ROBLOX_LIB_PATH"[..], roblox_lib.as_path()),
        (&b"MOCKTAIL_ASSET_ROOT"[..], asset_root.as_path()),
        (&b"MOCKTAIL_ASSET_PATH"[..], asset_path.as_path()),
        (
            &b"MOCKTAIL_COMPATIBILITY_MANIFEST"[..],
            config.compatibility_manifest.as_path(),
        ),
    ] {
        push_env_kv(&mut entries, name, path.as_os_str().as_bytes())?;
    }

    if !config.host_abi_profile.as_os_str().is_empty() {
        push_env_kv(
            &mut entries,
            b"MOCKTAIL_HOST_ABI_PROFILE_FILE",
            config.host_abi_profile.as_os_str().as_bytes(),
        )?;
        push_env_kv(&mut entries, b"MOCKTAIL_HOST_ABI_CANARY", b"1")?;
        push_env_kv(&mut entries, b"MOCKTAIL_ALLOW_CANDIDATE_HOST_ABI", b"1")?;
    }

    for &(name, value) in K_STATIC_CANARY_ENV {
        push_env_kv(&mut entries, name, value)?;
    }

    if config.graphics_backend == K_CANARY_BACKEND_DIRECT_VULKAN {
        push_env_kv(&mut entries, b"MOCKTAIL_GRAPHICS_BACKEND", b"direct-vulkan")?;
        push_env_kv(&mut entries, b"MOCKTAIL_PRELOAD_VULKAN_SHIM", b"1")?;
        push_env_kv(
            &mut entries,
            b"MOCKTAIL_CLIENT_SETTINGS_OVERRIDES_JSON",
            K_VULKAN_OVERRIDES_JSON,
        )?;
    } else {
        push_env_kv(
            &mut entries,
            b"MOCKTAIL_GRAPHICS_BACKEND",
            canary_backend_name_str(config.graphics_backend).as_bytes(),
        )?;
        push_env_kv(&mut entries, b"MOCKTAIL_PRELOAD_VULKAN_SHIM", b"0")?;
        push_env_kv(&mut entries, b"MOCKTAIL_SOFTWARE_WINDOW_FALLBACK", b"0")?;
        push_env_kv(
            &mut entries,
            b"MOCKTAIL_CLIENT_SETTINGS_OVERRIDES_JSON",
            b"{}",
        )?;
        if config.graphics_backend == K_CANARY_BACKEND_OPENGL_ES {
            push_env_kv(&mut entries, b"MOCKTAIL_DISABLE_AUTO_ANGLE_FALLBACK", b"1")?;
        }
    }

    Ok(entries)
}

pub(crate) fn run_readiness_canary(config: &CanaryRunConfig) -> CanaryRunOutput {
    let mut output = CanaryRunOutput::default();
    if config.timeout_seconds < 1 || config.timeout_seconds > 600 {
        output.error = "canary timeout must be between 1 and 600 seconds".to_string();
        return output;
    }
    if !validate_executable_regular_file(&config.runtime_binary) {
        output.error = "canary runtime is not an executable regular file".to_string();
        return output;
    }

    let isolated = match create_unique_temp_dir(&config.cache_root, ".native-update-canary") {
        Ok(dir) => dir,
        Err(TempDirError::CreateParent) => {
            output.error = "cannot create canary parent directory".to_string();
            return output;
        }
        Err(TempDirError::CreateTemp) => {
            output.error = "cannot create isolated canary directory".to_string();
            return output;
        }
    };
    let cleanup = TempDirCleanup(Some(isolated.clone()));

    for child in ["home", "data", "cache", "state", "config"] {
        if fs::create_dir_all(isolated.join(child)).is_err() {
            output.error = "cannot create isolated canary roots".to_string();
            return output;
        }
    }

    let log_directory = config.state_root.join("logs/update-canary");
    let _ = fs::create_dir_all(&log_directory);
    let backend_name = canary_backend_name_str(config.graphics_backend);
    let log_path = log_directory.join(format!(
        "{backend_name}-{}-{}.log",
        current_pid(),
        monotonic_nanos()
    ));
    output.log_path = log_path.to_string_lossy().into_owned();

    let Some(log_cpath) = path_to_cstr(&log_path) else {
        output.error = "cannot create canary readiness log".to_string();
        return output;
    };
    let open_flags =
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW;
    let Some(raw_log_fd) =
        OwnedFd::from_raw(unsafe { libc::open(log_cpath.as_ptr(), open_flags, 0o600 as libc::c_uint) })
    else {
        output.error = "cannot create canary readiness log".to_string();
        return output;
    };
    let Some(log_fd) = move_fd_above_stdio(raw_log_fd) else {
        output.error = "cannot create canary readiness log".to_string();
        return output;
    };

    let Ok(env_entries) = build_canary_environment(config, &isolated) else {
        output.error = "cannot configure canary runtime environment".to_string();
        return output;
    };
    let env_ptrs = cstrings_as_mut_ptrs(&env_entries);

    let Some(runtime_cstr) = path_to_cstr(&config.runtime_binary) else {
        output.error = "canary runtime is not an executable regular file".to_string();
        return output;
    };
    let probation_candidate = !config.host_abi_profile.as_os_str().is_empty();
    let mut arg_storage = vec![
        runtime_cstr.clone(),
        CString::new("--windowed").unwrap(),
    ];
    if probation_candidate {
        arg_storage.push(CString::new("--allow-unverified-build").unwrap());
    }
    let arg_ptrs = cstrings_as_mut_ptrs(&arg_storage);

    let spawn_result = (|| -> Result<libc::pid_t, i32> {
        let mut actions = SpawnFileActions::new()?;
        actions.add_dup2(log_fd.as_raw(), libc::STDOUT_FILENO)?;
        actions.add_dup2(log_fd.as_raw(), libc::STDERR_FILENO)?;
        actions.add_close(log_fd.as_raw())?;
        unsafe { posix_spawn_raw(&runtime_cstr, Some(&actions), &arg_ptrs, &env_ptrs) }
    })();
    drop(log_fd);

    let child = match spawn_result {
        Ok(pid) => pid,
        Err(err) => {
            output.error = errno_message("cannot start graphics canary", err);
            return output;
        }
    };

    let deadline = Instant::now() + Duration::from_secs(config.timeout_seconds as u64);
    let mut status: libc::c_int = 0;
    loop {
        let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if waited == child {
            break;
        }
        if waited < 0 && last_errno() != libc::EINTR {
            output.error = "cannot wait for graphics canary".to_string();
            break;
        }
        if Instant::now() >= deadline {
            let _ = terminate_and_reap(child, Duration::from_secs(5));
            output.error = "graphics canary timed out".to_string();
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(cleanup);
    if !output.error.is_empty() {
        return output;
    }

    output.exit_code = if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else if libc::WIFSIGNALED(status) {
        128 + libc::WTERMSIG(status)
    } else {
        128
    };

    let (log, log_error) = match read_canary_log(&log_path) {
        Ok(contents) => (contents, None),
        Err(err) => (String::new(), Some(err)),
    };
    let driver_teardown_crash = (libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGSEGV)
        || (libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 128);

    if output.exit_code != 0 {
        output.error = format!("graphics canary exited with status {}", output.exit_code);
        if driver_teardown_crash
            && log_error.is_none()
            && validate_teardown_crash_log_str(config.graphics_backend, &log).is_ok()
        {
            eprintln!(
                "  [update] graphics canary exited with status {} during teardown after proving readiness",
                output.exit_code
            );
            output.error.clear();
            output.teardown_crash = true;
        }
        return output;
    }

    if let Some(err) = log_error {
        output.error = err.to_string();
        return output;
    }
    if let Err(err) = validate_readiness_log_str(config.graphics_backend, &log) {
        output.error = err;
    }
    output
}

fn deliver_str(receiver: MocktailRustCanaryStrReceiver, ctx: *mut c_void, value: &str) {
    if let Some(cb) = receiver {
        unsafe {
            cb(ctx, value.as_ptr().cast::<c_char>(), value.len());
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_canary_backend_parse(
    name: *const c_char,
    out_backend: *mut i32,
) -> i32 {
    let s = if !name.is_null() {
        unsafe { CStr::from_ptr(name) }.to_str().unwrap_or("")
    } else {
        ""
    };
    let Some(val) = canary_backend_parse_str(s) else {
        return -1;
    };
    if !out_backend.is_null() {
        unsafe { *out_backend = val };
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_canary_backend_name(
    backend: i32,
    out_buf: *mut c_char,
    out_cap: usize,
) -> i32 {
    copy_to_c_buffer(canary_backend_name_str(backend), out_buf, out_cap);
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_canary_backend_name_cstr(backend: i32) -> *const c_char {
    canary_backend_name_cstr(backend).as_ptr()
}

#[no_mangle]
pub extern "C" fn mocktail_rust_validate_canary_audio_log(
    log_text: *const c_char,
    log_len: usize,
    require_clean_shutdown: i32,
    err_buf: *mut c_char,
    err_cap: usize,
) -> i32 {
    if log_text.is_null() || log_len == 0 {
        return 0;
    }
    let slice = unsafe { slice_from_ffi(log_text, log_len) };
    let log = String::from_utf8_lossy(slice);
    match validate_canary_audio_log_str(&log, require_clean_shutdown != 0) {
        Ok(()) => 0,
        Err((code, msg)) => {
            copy_error(err_buf, err_cap, msg);
            code
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_validate_readiness_log(
    backend: i32,
    log_text: *const c_char,
    log_len: usize,
    on_error: MocktailRustCanaryStrReceiver,
    ctx: *mut c_void,
) -> i32 {
    let slice = slice_from_ffi(log_text, log_len);
    let log = String::from_utf8_lossy(slice);
    match validate_readiness_log_str(backend, &log) {
        Ok(()) => 0,
        Err(err) => {
            deliver_str(on_error, ctx, &err);
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_validate_teardown_crash_log(
    backend: i32,
    log_text: *const c_char,
    log_len: usize,
    on_error: MocktailRustCanaryStrReceiver,
    ctx: *mut c_void,
) -> i32 {
    let slice = slice_from_ffi(log_text, log_len);
    let log = String::from_utf8_lossy(slice);
    match validate_teardown_crash_log_str(backend, &log) {
        Ok(()) => 0,
        Err(err) => {
            deliver_str(on_error, ctx, &err);
            -1
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_run_readiness_canary(
    options: *const MocktailRustCanaryOptions,
    on_result: MocktailRustCanaryResultCallback,
    ctx: *mut c_void,
) {
    let output = if let Some(opts) = options.as_ref() {
        let config_opt = (|| -> Option<CanaryRunConfig> {
            Some(CanaryRunConfig {
                runtime_binary: path_from_ffi(opts.runtime_binary, opts.runtime_binary_len)?,
                payload_directory: path_from_ffi(
                    opts.payload_directory,
                    opts.payload_directory_len,
                )?,
                compatibility_manifest: path_from_ffi(
                    opts.compatibility_manifest,
                    opts.compatibility_manifest_len,
                )?,
                host_abi_profile: path_from_ffi(opts.host_abi_profile, opts.host_abi_profile_len)?,
                cache_root: path_from_ffi(opts.cache_root, opts.cache_root_len)?,
                state_root: path_from_ffi(opts.state_root, opts.state_root_len)?,
                graphics_backend: opts.graphics_backend,
                timeout_seconds: opts.timeout_seconds,
            })
        })();
        match config_opt {
            Some(config) => run_readiness_canary(&config),
            None => CanaryRunOutput {
                error: "invalid readiness canary path arguments".to_string(),
                ..CanaryRunOutput::default()
            },
        }
    } else {
        CanaryRunOutput {
            error: "missing readiness canary options".to_string(),
            ..CanaryRunOutput::default()
        }
    };

    if let Some(cb) = on_result {
        cb(
            ctx,
            output.exit_code,
            output.teardown_crash,
            output.log_path.as_ptr().cast::<c_char>(),
            output.log_path.len(),
            output.error.as_ptr().cast::<c_char>(),
            output.error.len(),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unix_ipc::TEST_ENV_LOCK;
    use std::os::unix::fs::PermissionsExt;

    fn write_executable(path: &Path, script: &str) {
        fs::write(path, script).unwrap();
        let mut perms = fs::metadata(path).unwrap().permissions();
        perms.set_mode(0o700);
        fs::set_permissions(path, perms).unwrap();
    }

    #[test]
    fn validates_vulkan_and_opengl_logs_strictly() {
        let vk_ok = "[compat] legacy binary patches: disabled\n\
                     [compat] signal-recovery handler disabled\n\
                     [compat] native allocator retained; host allocator bridges disabled\n\
                     [window] first Roblox Vulkan frame presented\n\
                     [window] vkQueuePresentKHR #12 window=0x1\n\
                     [vulkan] SDL WSI adapter shut down\n\
                     [main] Roblox lifecycle shutdown: Stopped\n";
        assert!(validate_readiness_log_str(K_CANARY_BACKEND_DIRECT_VULKAN, vk_ok).is_ok());

        let vk_zero_queue = vk_ok.replace("#12", "#0");
        assert!(validate_readiness_log_str(K_CANARY_BACKEND_DIRECT_VULKAN, &vk_zero_queue)
            .unwrap_err()
            .contains("real queue present"));

        let gl_ok = "[compat] legacy binary patches: disabled\n\
                     [compat] signal-recovery handler disabled\n\
                     [compat] native allocator retained; host allocator bridges disabled\n\
                     [window] EGL context and surface initialized via SDL3\n\
                     [window] OpenGL ES context version=3.2\n\
                     [window] SwapBuffers #2 window=0x1\n\
                     [window] first Roblox frame presented\n\
                     [main] Roblox lifecycle shutdown: Stopped\n";
        assert!(validate_readiness_log_str(K_CANARY_BACKEND_OPENGL_ES, gl_ok).is_ok());
        assert!(validate_readiness_log_str(
            K_CANARY_BACKEND_OPENGL_ES,
            &gl_ok.replace("version=3.2", "version=2.0")
        )
        .unwrap_err()
        .contains("version=3."));
    }

    #[test]
    fn runs_canary_isolates_env_and_recovers_teardown_crash() {
        let _guard = TEST_ENV_LOCK.lock().unwrap();
        let temp = create_unique_temp_dir(Path::new("/tmp"), "mocktail_canary_rs_test").unwrap();
        let _cleanup = TempDirCleanup(Some(temp.clone()));
        let runtime = temp.join("runtime");
        write_executable(
            &runtime,
            "#!/bin/sh\n\
             printf 'stale=%s\\netc2=%s\\n' \"$MOCKTAIL_TEST_STALE\" \"$vk_require_etc2\"\n\
             printf '%s\\n' \\\n\
               '[compat] legacy binary patches: disabled' \\\n\
               '[compat] signal-recovery handler disabled' \\\n\
               '[compat] native allocator retained; host allocator bridges disabled' \\\n\
               '[window] first Roblox Vulkan frame presented' \\\n\
               '[window] vkQueuePresentKHR #3 window=0x1' \\\n\
               '[window] automatic exit requested 5000 ms' \\\n\
               '[main] window closed, shutting down'\n\
             kill -SEGV $$\n",
        );

        let stale_k = CString::new("MOCKTAIL_TEST_STALE").unwrap();
        let stale_v = CString::new("/stale/path").unwrap();
        let etc_k = CString::new("vk_require_etc2").unwrap();
        let etc_v = CString::new("true").unwrap();
        unsafe {
            libc::setenv(stale_k.as_ptr(), stale_v.as_ptr(), 1);
            libc::setenv(etc_k.as_ptr(), etc_v.as_ptr(), 1);
        }

        let out = run_readiness_canary(&CanaryRunConfig {
            runtime_binary: runtime,
            payload_directory: temp.join("payload"),
            compatibility_manifest: temp.join("compat.json"),
            host_abi_profile: PathBuf::new(),
            cache_root: temp.join("cache"),
            state_root: temp.join("state"),
            graphics_backend: K_CANARY_BACKEND_DIRECT_VULKAN,
            timeout_seconds: 5,
        });

        unsafe {
            libc::unsetenv(stale_k.as_ptr());
            libc::unsetenv(etc_k.as_ptr());
        }

        assert!(out.error.is_empty(), "unexpected error: {}", out.error);
        assert!(out.teardown_crash);
        assert_eq!(out.exit_code, 128 + libc::SIGSEGV);
        let log_contents = fs::read_to_string(&out.log_path).unwrap();
        assert!(log_contents.contains("stale=\n"));
        assert!(log_contents.contains("etc2=true\n"));
    }

    #[test]
    fn reaps_timed_out_canary_process() {
        let temp = create_unique_temp_dir(Path::new("/tmp"), "mocktail_canary_timeout_rs").unwrap();
        let _cleanup = TempDirCleanup(Some(temp.clone()));
        let runtime = temp.join("runtime");
        write_executable(&runtime, "#!/bin/sh\nsleep 10\n");

        let out = run_readiness_canary(&CanaryRunConfig {
            runtime_binary: runtime,
            payload_directory: temp.join("payload"),
            compatibility_manifest: temp.join("compat.json"),
            host_abi_profile: PathBuf::new(),
            cache_root: temp.join("cache"),
            state_root: temp.join("state"),
            graphics_backend: K_CANARY_BACKEND_DIRECT_VULKAN,
            timeout_seconds: 1,
        });

        assert_eq!(out.error, "graphics canary timed out");
    }
}
