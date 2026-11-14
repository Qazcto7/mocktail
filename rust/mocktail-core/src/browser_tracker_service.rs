//! Roblox BrowserTracker initialization, cookie reconciliation, and locked
//! atomic storage persistence.

use std::ffi::{c_char, c_void, CString, OsString};
use std::io::ErrorKind;
use std::mem::MaybeUninit;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use zeroize::Zeroizing;

use crate::runtime_policies::{
    parse_browser_tracker_init_response_str, parse_json_object_str,
    read_stored_browser_tracker_id_str, set_stored_browser_tracker_id_str,
};
use crate::unix_ipc::{
    current_euid, current_pid, find_existing_directory_ancestor, flock_fd, fsync_directory_chain,
    is_non_group_other_writable_dir, is_opened_file_at, is_safe_destination_at, last_errno,
    lexical_absolute, lstat_cstr, path_from_ffi, path_to_cstr, unlink_opened_file_at, write_all_fd,
    OwnedFd,
};
use crate::{
    extract_browser_id_from_tracker, extract_cookie_value_str, extract_tracker_from_headers_str,
    generate_browser_tracker_id_string,
};

pub const K_BROWSER_TRACKER_STATUS_EXISTING: i32 = 0;
pub const K_BROWSER_TRACKER_STATUS_CREATED: i32 = 1;

const K_INITIALIZE_URL_PREFIX: &str =
    "https://apis.roblox.com/browser-tracker-api/device/initialize?suggestedBrowserTrackerId=";
const K_INITIALIZE_HEADERS: &str = "Accept: application/json\nContent-Type: application/json";
const K_INITIALIZE_BODY: &str = "{}";
const K_INITIALIZE_MAX_BODY_BYTES: usize = 4096;

const K_MAXIMUM_STORAGE_BYTES: u64 = 4 * 1024 * 1024;
const K_MAXIMUM_COOKIE_BYTES: u64 = 64 * 1024;
const K_TRACKER_COOKIE_NAME: &str = "RBXEventTrackerV2";

static TEMP_SERIAL: AtomicU64 = AtomicU64::new(0);

pub type MocktailRustBrowserTrackerHttpResponseReceiver = Option<
    unsafe extern "C" fn(
        receiver_ctx: *mut c_void,
        body_ptr: *const c_char,
        body_len: usize,
        headers_ptr: *const c_char,
        headers_len: usize,
    ),
>;

pub type MocktailRustBrowserTrackerHttpPostCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        url_ptr: *const c_char,
        url_len: usize,
        headers_ptr: *const c_char,
        headers_len: usize,
        body_ptr: *const c_char,
        body_len: usize,
        maximum_body_bytes: usize,
        out_transport_ok: *mut bool,
        out_status_code: *mut i64,
        receiver_ctx: *mut c_void,
        receiver_cb: MocktailRustBrowserTrackerHttpResponseReceiver,
    ),
>;

pub type MocktailRustBrowserTrackerResultCallback = Option<
    unsafe extern "C" fn(
        ctx: *mut c_void,
        status: i32,
        http_status: i64,
        id_ptr: *const c_char,
        id_len: usize,
        err_ptr: *const c_char,
        err_len: usize,
    ),
>;

#[derive(Debug, Default)]
pub(crate) struct HttpPostOutput {
    pub transport_ok: bool,
    pub status_code: i64,
    pub body: String,
    pub headers: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct TrackerInitResult {
    pub status: i32,
    pub browser_tracker_id: String,
    pub http_status: i64,
    pub error: String,
}

impl Default for TrackerInitResult {
    fn default() -> Self {
        Self {
            status: K_BROWSER_TRACKER_STATUS_EXISTING,
            browser_tracker_id: String::new(),
            http_status: 0,
            error: String::new(),
        }
    }
}

fn read_storage(path: &Path) -> Result<String, &'static str> {
    match std::fs::metadata(path) {
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok("{}".to_owned()),
        Err(err) if err.raw_os_error() == Some(libc::ENOTDIR) => return Ok("{}".to_owned()),
        Err(_) => return Err("appStorage is unavailable"),
        Ok(meta) => {
            if !meta.is_file() || meta.len() > K_MAXIMUM_STORAGE_BYTES {
                return Err("appStorage is unavailable or exceeds the size limit");
            }
        }
    }
    let Ok(raw) = std::fs::read_to_string(path) else {
        return Err("appStorage is not a valid JSON object");
    };
    if parse_json_object_str(&raw, false).is_none() {
        return Err("appStorage is not a valid JSON object");
    }
    Ok(raw)
}

fn read_small_file(path: &Path) -> Result<Zeroizing<String>, &'static str> {
    match std::fs::metadata(path) {
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return Ok(Zeroizing::new(String::new()));
        }
        Err(err) if err.raw_os_error() == Some(libc::ENOTDIR) => {
            return Ok(Zeroizing::new(String::new()));
        }
        Err(_) => return Err("cookie file is unavailable"),
        Ok(meta) => {
            if !meta.is_file() || meta.len() > K_MAXIMUM_COOKIE_BYTES {
                return Err("cookie file is unavailable or exceeds the size limit");
            }
        }
    }
    let Ok(file) = std::fs::File::open(path) else {
        return Err("cookie file could not be opened");
    };
    use std::io::Read;
    let mut raw_bytes = Zeroizing::new(Vec::new());
    let mut reader = file;
    if reader.read_to_end(&mut raw_bytes).is_err() {
        return Err("cookie file could not be read");
    }
    let text = String::from_utf8(std::mem::take(&mut *raw_bytes))
        .map_err(|_| "cookie file could not be read")?;
    Ok(Zeroizing::new(text))
}

fn cstring_from_os_bytes(bytes: &[u8]) -> Option<CString> {
    CString::new(bytes).ok()
}

fn open_app_storage_lock(app_storage_file: &Path) -> Result<OwnedFd, &'static str> {
    let resolved = lexical_absolute(app_storage_file).ok_or("cannot lock appStorage")?;
    if resolved.as_os_str().is_empty() {
        return Err("cannot lock appStorage");
    }
    let mut lock_os = OsString::from(resolved.as_os_str());
    lock_os.push(".lock");
    let lock_path = PathBuf::from(lock_os);

    let lock_parent = lock_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let existing_ancestor =
        find_existing_directory_ancestor(&lock_parent).ok_or("cannot lock appStorage")?;
    let lock_parent_existed = existing_ancestor == lock_parent;

    if std::fs::create_dir_all(&lock_parent).is_err() {
        return Err("cannot lock appStorage");
    }
    let parent_c = path_to_cstr(&lock_parent).ok_or("cannot lock appStorage")?;
    let parent_st = lstat_cstr(&parent_c).map_err(|_| "cannot lock appStorage")?;
    let euid = current_euid();
    if !is_non_group_other_writable_dir(&parent_st, euid) {
        return Err("cannot lock appStorage");
    }

    let lock_c = path_to_cstr(&lock_path).ok_or("cannot lock appStorage")?;
    let raw_lock = unsafe {
        libc::open(
            lock_c.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600 as libc::mode_t,
        )
    };
    let Some(lock_fd) = OwnedFd::from_raw(raw_lock) else {
        return Err("cannot lock appStorage");
    };

    let mut lock_st = MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(lock_fd.as_raw(), lock_st.as_mut_ptr()) } != 0 {
        return Err("cannot lock appStorage");
    }
    let lock_st = unsafe { lock_st.assume_init() };
    if (lock_st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || lock_st.st_uid != euid
        || lock_st.st_nlink != 1
        || (lock_st.st_mode & (libc::S_IRWXG | libc::S_IRWXO)) != 0
        || !flock_fd(lock_fd.as_raw(), libc::LOCK_EX)
        || (!lock_parent_existed && !fsync_directory_chain(&lock_parent, &existing_ancestor))
    {
        return Err("cannot lock appStorage");
    }

    Ok(lock_fd)
}

fn open_cookie_writer_lock(cookie_file: &Path) -> Option<OwnedFd> {
    let resolved = lexical_absolute(cookie_file)?;
    if resolved.as_os_str().is_empty() {
        return None;
    }
    let parent = resolved.parent()?;
    if parent.as_os_str().is_empty() {
        return None;
    }
    let parent_c = path_to_cstr(parent)?;
    let parent_st = lstat_cstr(&parent_c).ok()?;
    let euid = current_euid();
    if !is_non_group_other_writable_dir(&parent_st, euid) {
        return None;
    }

    let dir_raw = unsafe {
        libc::open(
            parent_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    let dir_fd = OwnedFd::from_raw(dir_raw)?;
    let mut opened_parent_st = MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(dir_fd.as_raw(), opened_parent_st.as_mut_ptr()) } != 0 {
        return None;
    }
    let opened_parent_st = unsafe { opened_parent_st.assume_init() };
    if opened_parent_st.st_dev != parent_st.st_dev
        || opened_parent_st.st_ino != parent_st.st_ino
        || !is_non_group_other_writable_dir(&opened_parent_st, euid)
    {
        return None;
    }

    let filename = resolved.file_name()?.as_bytes();
    if filename.is_empty() || filename == b"." || filename == b".." {
        return None;
    }
    let mut lock_name_bytes = Vec::with_capacity(1 + filename.len() + 21);
    lock_name_bytes.push(b'.');
    lock_name_bytes.extend_from_slice(filename);
    lock_name_bytes.extend_from_slice(b".mocktail-writer.lock");
    let lock_name_c = cstring_from_os_bytes(&lock_name_bytes)?;

    let lock_raw = unsafe {
        libc::openat(
            dir_fd.as_raw(),
            lock_name_c.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            (libc::S_IRUSR | libc::S_IWUSR) as libc::mode_t,
        )
    };
    drop(dir_fd);
    let lock_fd = OwnedFd::from_raw(lock_raw)?;

    let mut lock_st = MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(lock_fd.as_raw(), lock_st.as_mut_ptr()) } != 0 {
        return None;
    }
    let lock_st = unsafe { lock_st.assume_init() };
    if (lock_st.st_mode & libc::S_IFMT) != libc::S_IFREG
        || lock_st.st_uid != euid
        || lock_st.st_nlink != 1
        || (lock_st.st_mode & (libc::S_IRWXG | libc::S_IRWXO)) != 0
        || !flock_fd(lock_fd.as_raw(), libc::LOCK_EX | libc::LOCK_NB)
    {
        return None;
    }

    Some(lock_fd)
}

fn atomic_write_contents(
    path: &Path,
    contents: &[u8],
    directory_error: &'static str,
    replacement_error: &'static str,
) -> Result<(), &'static str> {
    let resolved = lexical_absolute(path).ok_or(directory_error)?;
    if resolved.as_os_str().is_empty() {
        return Err(directory_error);
    }
    let parent = resolved.parent().ok_or(directory_error)?.to_path_buf();
    let existing_ancestor = find_existing_directory_ancestor(&parent).ok_or(directory_error)?;
    let parent_existed = existing_ancestor == parent;

    if std::fs::create_dir_all(&parent).is_err() {
        return Err(directory_error);
    }
    let parent_c = path_to_cstr(&parent).ok_or(directory_error)?;
    let parent_st = lstat_cstr(&parent_c).map_err(|_| directory_error)?;
    let euid = current_euid();
    if !is_non_group_other_writable_dir(&parent_st, euid) {
        return Err(directory_error);
    }

    let dir_raw = unsafe {
        libc::open(
            parent_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    let dir_fd = OwnedFd::from_raw(dir_raw).ok_or(directory_error)?;
    let mut opened_parent_st = MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::fstat(dir_fd.as_raw(), opened_parent_st.as_mut_ptr()) } != 0 {
        return Err(directory_error);
    }
    let opened_parent_st = unsafe { opened_parent_st.assume_init() };
    if opened_parent_st.st_dev != parent_st.st_dev
        || opened_parent_st.st_ino != parent_st.st_ino
        || !is_non_group_other_writable_dir(&opened_parent_st, euid)
    {
        return Err(directory_error);
    }

    let filename = resolved
        .file_name()
        .map(OsStrExt::as_bytes)
        .unwrap_or(&[]);
    if filename.is_empty() || filename == b"." || filename == b".." {
        return Err(replacement_error);
    }
    let filename_c = cstring_from_os_bytes(filename).ok_or(replacement_error)?;
    if !is_safe_destination_at(dir_fd.as_raw(), &filename_c, euid) {
        return Err(replacement_error);
    }

    let pid = current_pid();
    let mut temporary_c = None;
    let mut tmp_fd = None;
    for _attempt in 0..16 {
        let seq = TEMP_SERIAL.fetch_add(1, Ordering::Relaxed);
        let mut temp_bytes = Vec::with_capacity(1 + filename.len() + 40);
        temp_bytes.push(b'.');
        temp_bytes.extend_from_slice(filename);
        temp_bytes.extend_from_slice(format!(".mocktail.tmp-{pid}-{seq}").as_bytes());
        let Some(cand_c) = cstring_from_os_bytes(&temp_bytes) else {
            return Err(replacement_error);
        };
        let raw = unsafe {
            libc::openat(
                dir_fd.as_raw(),
                cand_c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                (libc::S_IRUSR | libc::S_IWUSR) as libc::mode_t,
            )
        };
        if raw >= 0 {
            temporary_c = Some(cand_c);
            tmp_fd = OwnedFd::from_raw(raw);
            break;
        }
        if last_errno() != libc::EEXIST {
            break;
        }
    }

    let (Some(temporary_c), Some(tmp_fd)) = (temporary_c, tmp_fd) else {
        return Err(replacement_error);
    };

    let mut temp_st = MaybeUninit::<libc::stat>::zeroed();
    let written = unsafe { libc::fstat(tmp_fd.as_raw(), temp_st.as_mut_ptr()) } == 0
        && {
            let temp_st = unsafe { temp_st.assume_init() };
            (temp_st.st_mode & libc::S_IFMT) == libc::S_IFREG
                && temp_st.st_uid == euid
                && temp_st.st_nlink == 1
        }
        && unsafe { libc::fchmod(tmp_fd.as_raw(), (libc::S_IRUSR | libc::S_IWUSR) as libc::mode_t) }
            == 0
        && write_all_fd(tmp_fd.as_raw(), contents)
        && unsafe { libc::fsync(tmp_fd.as_raw()) } == 0;

    let linked = written
        && is_safe_destination_at(dir_fd.as_raw(), &filename_c, euid)
        && is_opened_file_at(dir_fd.as_raw(), &temporary_c, tmp_fd.as_raw(), euid)
        && unsafe {
            libc::renameat(
                dir_fd.as_raw(),
                temporary_c.as_ptr(),
                dir_fd.as_raw(),
                filename_c.as_ptr(),
            )
        } == 0;

    if !linked {
        unlink_opened_file_at(dir_fd.as_raw(), &temporary_c, tmp_fd.as_raw(), euid);
    }
    let synchronized = linked && unsafe { libc::fsync(dir_fd.as_raw()) } == 0;
    drop(tmp_fd);
    drop(dir_fd);

    if synchronized && !parent_existed {
        let first_created_parent = parent
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        if !fsync_directory_chain(first_created_parent, &existing_ancestor) {
            return Err(replacement_error);
        }
    }

    if synchronized {
        Ok(())
    } else {
        Err(replacement_error)
    }
}

fn atomic_write_app_storage(path: &Path, storage_json: &str) -> Result<(), &'static str> {
    atomic_write_contents(
        path,
        storage_json.as_bytes(),
        "cannot create appStorage directory",
        "cannot atomically replace appStorage",
    )
}

fn atomic_write_cookie_text(path: &Path, contents: &str) -> Result<(), &'static str> {
    atomic_write_contents(
        path,
        contents.as_bytes(),
        "cannot create cookie directory",
        "cannot atomically replace cookie file",
    )
}

pub(crate) fn ensure_initialized_with<F>(
    app_storage_file: &Path,
    cookie_file: &Path,
    allow_cookie_update: bool,
    mut http_post: F,
) -> TrackerInitResult
where
    F: FnMut(&str, &str, &str, usize) -> HttpPostOutput,
{
    let mut result = TrackerInitResult::default();
    if app_storage_file.as_os_str().is_empty() || cookie_file.as_os_str().is_empty() {
        result.error = "BrowserTracker storage path is empty".to_owned();
        return result;
    }

    let _lock_fd = match open_app_storage_lock(app_storage_file) {
        Ok(fd) => fd,
        Err(msg) => {
            result.error = msg.to_owned();
            return result;
        }
    };

    let mut storage_json = match read_storage(app_storage_file) {
        Ok(s) => s,
        Err(msg) => {
            result.error = msg.to_owned();
            return result;
        }
    };

    let mut cookie_contents = match read_small_file(cookie_file) {
        Ok(s) => s,
        Err(msg) => {
            result.error = msg.to_owned();
            return result;
        }
    };

    let tracker_opt = extract_cookie_value_str(&cookie_contents, K_TRACKER_COOKIE_NAME);
    let mut authoritative_id = tracker_opt
        .and_then(extract_browser_id_from_tracker)
        .unwrap_or_default();
    if tracker_opt.is_some() && authoritative_id.is_empty() {
        result.error = "RBXEventTrackerV2 cookie has an invalid browserid".to_owned();
        return result;
    }

    let stored_id = match read_stored_browser_tracker_id_str(&storage_json) {
        Ok(opt) => opt.unwrap_or_default(),
        Err(()) => {
            result.error = "appStorage BrowserTrackerId is invalid".to_owned();
            return result;
        }
    };

    if !authoritative_id.is_empty() {
        result.browser_tracker_id = authoritative_id.clone();
        if stored_id == authoritative_id {
            return result;
        }
        if let Some(updated) = set_stored_browser_tracker_id_str(&storage_json, &authoritative_id) {
            storage_json = updated;
            match atomic_write_app_storage(app_storage_file, &storage_json) {
                Ok(()) => result.status = K_BROWSER_TRACKER_STATUS_CREATED,
                Err(msg) => result.error = msg.to_owned(),
            }
        }
        return result;
    }

    if !allow_cookie_update {
        result.error = "external cookie file has no RBXEventTrackerV2 browser identity".to_owned();
        return result;
    }

    let suggested = generate_browser_tracker_id_string();
    let request_url = format!("{K_INITIALIZE_URL_PREFIX}{suggested}");
    let response = http_post(
        &request_url,
        K_INITIALIZE_HEADERS,
        K_INITIALIZE_BODY,
        K_INITIALIZE_MAX_BODY_BYTES,
    );
    result.http_status = response.status_code;
    if !response.transport_ok {
        result.error = "BrowserTracker initialization transport failed".to_owned();
        return result;
    }
    if response.status_code != 200 {
        result.error = "BrowserTracker initialization was rejected".to_owned();
        return result;
    }

    let body_id = parse_browser_tracker_init_response_str(&response.body).unwrap_or_default();
    let response_tracker = extract_tracker_from_headers_str(&response.headers)
        .unwrap_or("")
        .to_owned();
    authoritative_id = extract_browser_id_from_tracker(&response_tracker).unwrap_or_default();
    if body_id.is_empty() || authoritative_id.is_empty() || body_id != authoritative_id {
        result.error = "BrowserTracker response does not contain a valid numeric ID".to_owned();
        return result;
    }

    let expected_cookie_contents = Zeroizing::new((*cookie_contents).clone());
    if !cookie_contents.is_empty()
        && !cookie_contents.ends_with('\n')
        && !cookie_contents.ends_with(';')
    {
        cookie_contents.push(';');
    }
    cookie_contents.push_str("RBXEventTrackerV2=");
    cookie_contents.push_str(&response_tracker);
    cookie_contents.push('\n');

    let Some(cookie_writer_lock) = open_cookie_writer_lock(cookie_file) else {
        result.error = "cannot lock cookie file for BrowserTracker update".to_owned();
        return result;
    };

    match read_small_file(cookie_file) {
        Ok(current_cookie_contents) if *current_cookie_contents == *expected_cookie_contents => {
            if let Err(msg) = atomic_write_cookie_text(cookie_file, &cookie_contents) {
                result.error = msg.to_owned();
            } else if let Some(updated) =
                set_stored_browser_tracker_id_str(&storage_json, &authoritative_id)
            {
                storage_json = updated;
            }
        }
        _ => {
            result.error = "cookie file changed during BrowserTracker update".to_owned();
        }
    }
    drop(cookie_writer_lock);

    if result.error.is_empty() {
        match atomic_write_app_storage(app_storage_file, &storage_json) {
            Ok(()) => {
                result.status = K_BROWSER_TRACKER_STATUS_CREATED;
                result.browser_tracker_id = authoritative_id;
            }
            Err(msg) => result.error = msg.to_owned(),
        }
    }

    result
}

unsafe extern "C" fn capture_http_response(
    receiver_ctx: *mut c_void,
    body_ptr: *const c_char,
    body_len: usize,
    headers_ptr: *const c_char,
    headers_len: usize,
) {
    if receiver_ctx.is_null() {
        return;
    }
    let out = &mut *(receiver_ctx as *mut HttpPostOutput);
    if !body_ptr.is_null() && body_len > 0 {
        let bytes = std::slice::from_raw_parts(body_ptr.cast::<u8>(), body_len);
        out.body = String::from_utf8_lossy(bytes).into_owned();
    }
    if !headers_ptr.is_null() && headers_len > 0 {
        let bytes = std::slice::from_raw_parts(headers_ptr.cast::<u8>(), headers_len);
        out.headers = String::from_utf8_lossy(bytes).into_owned();
    }
}

#[no_mangle]
pub unsafe extern "C" fn mocktail_rust_browser_tracker_ensure_initialized(
    app_storage_ptr: *const c_char,
    app_storage_len: usize,
    cookie_file_ptr: *const c_char,
    cookie_file_len: usize,
    allow_cookie_update: bool,
    http_post_cb: MocktailRustBrowserTrackerHttpPostCallback,
    on_result: MocktailRustBrowserTrackerResultCallback,
    ctx: *mut c_void,
) -> i32 {
    let app_storage_path = path_from_ffi(app_storage_ptr, app_storage_len).unwrap_or_default();
    let cookie_file_path = path_from_ffi(cookie_file_ptr, cookie_file_len).unwrap_or_default();

    let result = ensure_initialized_with(
        &app_storage_path,
        &cookie_file_path,
        allow_cookie_update,
        |url, headers, body, max_body_bytes| {
            let mut out = HttpPostOutput::default();
            let Some(cb) = http_post_cb else {
                return out;
            };
            let mut transport_ok = false;
            let mut status_code: i64 = 0;
            cb(
                ctx,
                url.as_ptr().cast::<c_char>(),
                url.len(),
                headers.as_ptr().cast::<c_char>(),
                headers.len(),
                body.as_ptr().cast::<c_char>(),
                body.len(),
                max_body_bytes,
                &mut transport_ok,
                &mut status_code,
                (&mut out as *mut HttpPostOutput).cast::<c_void>(),
                Some(capture_http_response),
            );
            out.transport_ok = transport_ok;
            out.status_code = status_code;
            out
        },
    );

    let ok = result.error.is_empty();
    if let Some(cb) = on_result {
        cb(
            ctx,
            result.status,
            result.http_status,
            result.browser_tracker_id.as_ptr().cast::<c_char>(),
            result.browser_tracker_id.len(),
            result.error.as_ptr().cast::<c_char>(),
            result.error.len(),
        );
    }

    if ok {
        0
    } else {
        -1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let seq = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "mocktail-rust-browser-tracker-{label}-{}-{seq}",
                current_pid()
            ));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn reuses_existing_valid_identity_without_http() {
        let dir = TempDir::new("existing");
        let storage = dir.path.join("appData/LocalStorage/appStorage.json");
        let cookies = dir.path.join("roblox.cookie");
        fs::create_dir_all(storage.parent().unwrap()).unwrap();
        fs::write(&storage, r#"{"BrowserTrackerId":"123456","keep":true}"#).unwrap();
        fs::write(
            &cookies,
            ".ROBLOSECURITY=secret; RBXEventTrackerV2=CreateDate=1&rbxid=2&browserid=123456",
        )
        .unwrap();

        let mut called = 0;
        let res = ensure_initialized_with(&storage, &cookies, true, |_, _, _, _| {
            called += 1;
            HttpPostOutput::default()
        });
        assert_eq!(res.error, "");
        assert_eq!(res.status, K_BROWSER_TRACKER_STATUS_EXISTING);
        assert_eq!(res.browser_tracker_id, "123456");
        assert_eq!(called, 0);
    }

    #[test]
    fn initializes_atomically_and_reconciles_cookie_refresh_race() {
        let dir = TempDir::new("init");
        let storage = dir.path.join("appData/LocalStorage/appStorage.json");
        let cookies = dir.path.join("roblox.cookie");
        fs::create_dir_all(storage.parent().unwrap()).unwrap();
        fs::write(&storage, r#"{"keep":"value"}"#).unwrap();
        fs::write(&cookies, ".ROBLOSECURITY=secret").unwrap();

        let res = ensure_initialized_with(&storage, &cookies, true, |url, _, body, max_bytes| {
            assert!(url.contains("suggestedBrowserTrackerId="));
            assert_eq!(body, "{}");
            assert_eq!(max_bytes, 4096);
            HttpPostOutput {
                transport_ok: true,
                status_code: 200,
                body: r#"{"browserTrackerId":987654321}"#.to_owned(),
                headers:
                    "Set-Cookie: RBXEventTrackerV2=CreateDate=1&rbxid=2&browserid=987654321; Path=/"
                        .to_owned(),
            }
        });
        assert_eq!(res.error, "");
        assert_eq!(res.status, K_BROWSER_TRACKER_STATUS_CREATED);
        assert_eq!(res.browser_tracker_id, "987654321");

        let saved: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&storage).unwrap()).unwrap();
        assert_eq!(saved["keep"], "value");
        assert_eq!(saved["BrowserTrackerId"], "987654321");
        assert!(fs::read_to_string(&cookies)
            .unwrap()
            .contains("browserid=987654321"));

        // Now verify cookie modification during POST aborts without clobbering.
        let dir2 = TempDir::new("race");
        let storage2 = dir2.path.join("appData/LocalStorage/appStorage.json");
        let cookies2 = dir2.path.join("roblox.cookie");
        fs::write(&cookies2, ".ROBLOSECURITY=old").unwrap();
        let res2 = ensure_initialized_with(&storage2, &cookies2, true, |_, _, _, _| {
            fs::write(&cookies2, ".ROBLOSECURITY=refreshed").unwrap();
            HttpPostOutput {
                transport_ok: true,
                status_code: 200,
                body: r#"{"browserTrackerId":987654321}"#.to_owned(),
                headers:
                    "Set-Cookie: RBXEventTrackerV2=CreateDate=1&rbxid=2&browserid=987654321; Path=/"
                        .to_owned(),
            }
        });
        assert_eq!(
            res2.error,
            "cookie file changed during BrowserTracker update"
        );
        assert_eq!(fs::read_to_string(&cookies2).unwrap(), ".ROBLOSECURITY=refreshed");
        assert!(!storage2.exists());
    }

    #[test]
    fn rejects_hardlinked_destination_and_lock() {
        let dir = TempDir::new("hardlink");
        let storage = dir.path.join("appData/LocalStorage/appStorage.json");
        let cookies = dir.path.join("roblox.cookie");
        fs::create_dir_all(storage.parent().unwrap()).unwrap();

        let protected = dir.path.join("protected-storage");
        fs::write(&protected, r#"{"BrowserTrackerId":"111"}"#).unwrap();
        fs::set_permissions(&protected, fs::Permissions::from_mode(0o400)).unwrap();
        fs::hard_link(&protected, &storage).unwrap();
        fs::write(
            &cookies,
            "RBXEventTrackerV2=CreateDate=1&rbxid=2&browserid=222",
        )
        .unwrap();

        let res = ensure_initialized_with(&storage, &cookies, true, |_, _, _, _| {
            panic!("http post should not run")
        });
        assert_eq!(res.error, "cannot atomically replace appStorage");
        assert_eq!(
            fs::read_to_string(&protected).unwrap(),
            r#"{"BrowserTrackerId":"111"}"#
        );

        let _ = fs::remove_file(&storage);
        let lock_path = PathBuf::from(format!("{}.lock", storage.display()));
        let _ = fs::remove_file(&lock_path);
        fs::write(&storage, r#"{"BrowserTrackerId":"222"}"#).unwrap();
        fs::hard_link(&cookies, &lock_path).unwrap();
        let res_lock = ensure_initialized_with(&storage, &cookies, false, |_, _, _, _| {
            panic!("http post should not run")
        });
        assert_eq!(res_lock.error, "cannot lock appStorage");
    }
}
