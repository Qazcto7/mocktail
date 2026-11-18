use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::path::Path;
use std::slice;
use crate::*;

// ============================================================================
// 22. YAML Runtime Configuration Parser
// ============================================================================

fn flatten_yaml_node(
    prefix: &str,
    node: &serde_yaml::Value,
    depth: usize,
    max_depth: usize,
    map: &mut std::collections::HashMap<String, String>,
) -> Result<(), String> {
    match node {
        serde_yaml::Value::Mapping(m) => {
            if depth > max_depth {
                return Err(format!("{} must be a scalar", prefix));
            }
            let mut keys_seen = std::collections::HashSet::new();
            for (k, v) in m {
                let key_str = match k.as_str() {
                    Some(s) if !s.is_empty() => s,
                    _ => return Err(format!("{} contains a non-scalar or empty key", prefix)),
                };
                if !keys_seen.insert(key_str.to_string()) {
                    return Err(format!("{} contains duplicate key: {}", prefix, key_str));
                }
                let new_path = if prefix.is_empty() {
                    key_str.to_string()
                } else {
                    format!("{}.{}", prefix, key_str)
                };
                match v {
                    serde_yaml::Value::Mapping(_) => {
                        if depth >= max_depth {
                            return Err(format!("{} must be a scalar", new_path));
                        }
                        flatten_yaml_node(&new_path, v, depth + 1, max_depth, map)?;
                    }
                    serde_yaml::Value::String(s) => {
                        map.insert(new_path, s.clone());
                    }
                    serde_yaml::Value::Number(n) => {
                        map.insert(new_path, n.to_string());
                    }
                    serde_yaml::Value::Bool(b) => {
                        map.insert(new_path, if *b { "true".to_string() } else { "false".to_string() });
                    }
                    serde_yaml::Value::Null => {
                        map.insert(new_path, String::new());
                    }
                    _ => return Err(format!("{} must be a scalar", new_path)),
                }
            }
            Ok(())
        }
        _ => Err(format!("{} must be a mapping", prefix)),
    }
}

fn parse_yaml_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

pub(crate) fn build_runtime_config_yaml_env_map(
    slice: &[u8],
) -> Result<serde_json::Map<String, serde_json::Value>, (c_int, String)> {
    if slice.len() > 1024 * 1024 {
        return Err((-2, "runtime configuration file exceeds maximum allowed size".to_string()));
    }
    let parsed_val: serde_yaml::Value = serde_yaml::from_slice(slice)
        .map_err(|e| (-3, format!("runtime configuration contains invalid YAML: {}", e)))?;
    let root_map = parsed_val
        .as_mapping()
        .ok_or_else(|| (-4, "root must be a mapping".to_string()))?;

    let mut values = std::collections::HashMap::new();
    for (k, v) in root_map {
        let key_str = k
            .as_str()
            .ok_or_else(|| (-5, "root contains non-scalar key".to_string()))?;
        if key_str == "device" {
            if let Some(s) = v.as_str() {
                values.insert("device".to_string(), s.to_string());
            } else if v.is_mapping() {
                values.insert("device.__mapping".to_string(), "1".to_string());
                flatten_yaml_node("device", v, 1, 1, &mut values).map_err(|e| (-6, e))?;
            } else {
                return Err((-7, "device must be a preset scalar or detailed mapping".to_string()));
            }
        } else if [
            "runtime", "appearance", "auth", "graphics", "performance",
            "audio", "window", "input", "compatibility", "network",
        ]
        .contains(&key_str)
        {
            flatten_yaml_node(key_str, v, 1, 1, &mut values).map_err(|e| (-8, e))?;
        } else if key_str == "integrations" {
            flatten_yaml_node("integrations", v, 1, 3, &mut values).map_err(|e| (-9, e))?;
        } else if key_str == "version" {
            if let Some(s) = v.as_str() {
                values.insert("version".to_string(), s.to_string());
            } else if let Some(n) = v.as_i64() {
                values.insert("version".to_string(), n.to_string());
            }
        }
    }

    const SUPPORTED: &[&str] = &[
        "version", "device", "device.__mapping", "device.type", "device.platform",
        "device.name", "device.manufacturer", "device.model", "device.brand",
        "device.code", "device.sku", "device.soc_model", "device.touch",
        "device.mouse", "device.keyboard", "runtime.headless", "auth.use_libsecret",
        "runtime.roblox_library", "appearance.theme", "graphics.backend",
        "graphics.frame_rate_limit", "graphics.vsync", "graphics.present_mode",
        "performance.multithreaded_rendering", "performance.physics_worker_mode",
        "performance.memory_limit_mb", "performance.gamemode", "audio.output_device",
        "audio.input_device", "window.width", "window.height", "window.title",
        "window.high_dpi", "input.touch_enabled", "compatibility.desktop_playability",
        "network.use_system_proxy", "network.proxy_host", "network.proxy_port",
        "network.proxy_scheme", "network.proxy_username", "network.proxy_password",
        "network.ca_bundle", "integrations.fleasion.enabled", "integrations.fleasion.proxy_mode",
        "integrations.fleasion.proxy_port", "integrations.fleasion.ca_certificate",
        "integrations.discord_rpc.enabled", "integrations.discord_rpc.show_place_name",
        "integrations.discord_rpc.show_elapsed_time", "integrations.discord_rpc.application_id",
        "integrations.discord_rpc.join.enabled", "integrations.discord_rpc.join.public_servers_only",
        "integrations.discord_rpc.join.button_label", "integrations.discord_rpc.text.browsing",
        "integrations.discord_rpc.text.joining", "integrations.discord_rpc.text.playing",
        "integrations.discord_rpc.text.state", "integrations.discord_rpc.text.unknown_place",
        "integrations.micup_rpc.enabled", "integrations.micup_rpc.token",
        "integrations.micup_rpc.token_file", "integrations.micup_rpc.gateway_url",
        "integrations.micup_rpc.status", "integrations.micup_rpc.activity_mode",
        "integrations.micup_rpc.show_place_name", "integrations.micup_rpc.show_elapsed_time",
        "integrations.micup_rpc.text.browsing", "integrations.micup_rpc.text.joining",
        "integrations.micup_rpc.text.playing", "integrations.micup_rpc.text.unknown_place",
    ];

    for (k, _) in &values {
        if !SUPPORTED.contains(&k.as_str()) {
            return Err((-10, format!("unknown runtime configuration key: {}", k)));
        }
    }

    if let Some(v) = values.get("version") {
        if v != "1" {
            return Err((-11, format!("unsupported runtime configuration version: {}", v)));
        }
    }

    let mut env = serde_json::Map::new();

    let scalar_device = values.get("device").cloned();
    let detailed_device = values.contains_key("device.__mapping");
    let detailed_type = values.get("device.type").cloned();
    if detailed_device && detailed_type.is_none() {
        return Err((-12, "device.type is required for detailed device configuration".to_string()));
    }
    let selected_device = scalar_device.or(detailed_type);
    if let Some(ref dev) = selected_device {
        const VALID_DEVS: &[&str] = &[
            "pc", "mobile", "console", "pc-windows-11", "mobile-pixel-7", "console-ps5",
        ];
        if !VALID_DEVS.contains(&dev.as_str()) {
            return Err((-13, "device must be pc, mobile, console, pc-windows-11, mobile-pixel-7, or console-ps5".to_string()));
        }
        if values.contains_key("input.touch_enabled") || values.contains_key("compatibility.desktop_playability") {
            return Err((-14, "device cannot be combined with input.touch_enabled or compatibility.desktop_playability".to_string()));
        }
        env.insert("MOCKTAIL_DEVICE_PROFILE".to_string(), serde_json::json!(dev));
    }

    if detailed_device {
        let string_fields = [
            ("device.platform", "MOCKTAIL_DEVICE_PLATFORM_NAME", 128),
            ("device.name", "MOCKTAIL_DEVICE_NAME", 128),
            ("device.manufacturer", "MOCKTAIL_DEVICE_MANUFACTURER", 128),
            ("device.model", "MOCKTAIL_DEVICE_MODEL", 128),
            ("device.brand", "MOCKTAIL_DEVICE_BRAND", 64),
            ("device.code", "MOCKTAIL_DEVICE_CODE", 64),
            ("device.sku", "MOCKTAIL_DEVICE_SKU", 64),
            ("device.soc_model", "MOCKTAIL_DEVICE_SOC_MODEL", 128),
        ];
        for (yaml_key, env_key, max_len) in string_fields {
            if let Some(val) = values.get(yaml_key) {
                if val.is_empty() || val.len() > max_len || val.bytes().any(|b| b < 0x20 || b == 0x7F) {
                    return Err((-15, format!("{} must be non-empty, bounded, and contain no control bytes", yaml_key)));
                }
                env.insert(env_key.to_string(), serde_json::json!(val));
            }
        }
        for (yaml_key, env_key) in [
            ("device.touch", "MOCKTAIL_TOUCH_MODE"),
            ("device.mouse", "MOCKTAIL_MOUSE_MODE"),
            ("device.keyboard", "MOCKTAIL_KEYBOARD_MODE"),
        ] {
            if let Some(val) = values.get(yaml_key) {
                let parsed = match parse_yaml_bool(val) {
                    Some(true) => "on",
                    Some(false) => "off",
                    None => return Err((-16, format!("{} must be true or false", yaml_key))),
                };
                env.insert(env_key.to_string(), serde_json::json!(parsed));
            }
        }
    }

    if let Some(h) = values.get("runtime.headless") {
        match parse_yaml_bool(h) {
            Some(true) => { env.insert("MOCKTAIL_HEADLESS".to_string(), serde_json::json!("1")); }
            Some(false) => { env.insert("MOCKTAIL_HEADLESS".to_string(), serde_json::json!("0")); }
            None => return Err((-17, "runtime.headless must be true or false".to_string())),
        }
    }
    if let Some(lib) = values.get("runtime.roblox_library") {
        if lib.is_empty() {
            return Err((-18, "runtime.roblox_library must not be empty".to_string()));
        }
        env.insert("ROBLOX_LIB_PATH".to_string(), serde_json::json!(lib));
    }

    if let Some(theme) = values.get("appearance.theme") {
        if !["roblox", "system", "light", "dark"].contains(&theme.as_str()) {
            return Err((-19, "appearance.theme must be roblox, system, light, or dark".to_string()));
        }
        env.insert("MOCKTAIL_THEME".to_string(), serde_json::json!(theme));
    }

    if let Some(backend) = values.get("graphics.backend") {
        if !["direct-vulkan", "vulkan", "native-vulkan", "opengl", "gles", "system", "angle-vulkan", "angle-swiftshader", "auto"].contains(&backend.as_str()) {
            return Err((-20, format!("graphics.backend is not supported: {}", backend)));
        }
        let mapped_backend = if backend == "vulkan" || backend == "native-vulkan" {
            "direct-vulkan"
        } else if backend == "gles" {
            "opengl"
        } else {
            backend.as_str()
        };
        env.insert("MOCKTAIL_GRAPHICS_BACKEND".to_string(), serde_json::json!(mapped_backend));
    }
    if let Some(fps) = values.get("graphics.frame_rate_limit") {
        let mut mode = 0i32;
        let mut fps_val = 0i32;
        let c_fps = std::ffi::CString::new(fps.as_str()).unwrap_or_default();
        mocktail_rust_frame_rate_parse(c_fps.as_ptr(), &mut mode, &mut fps_val);
        if mode == 4 {
            return Err((-21, format!("graphics.frame_rate_limit is not supported: {}", fps)));
        }
        env.insert("MOCKTAIL_FRAME_RATE_LIMIT".to_string(), serde_json::json!(fps));
    }
    if let Some(vsync) = values.get("graphics.vsync") {
        if !["auto", "on", "off"].contains(&vsync.as_str()) {
            return Err((-21, "graphics.vsync must be auto, on, or off".to_string()));
        }
        env.insert("MOCKTAIL_VSYNC".to_string(), serde_json::json!(vsync));
    }
    if let Some(pm) = values.get("graphics.present_mode") {
        if !["auto", "fifo", "mailbox", "immediate"].contains(&pm.as_str()) {
            return Err((-22, "graphics.present_mode must be auto, fifo, mailbox, or immediate".to_string()));
        }
        env.insert("MOCKTAIL_PRESENT_MODE".to_string(), serde_json::json!(pm));
    }

    if let Some(mr) = values.get("performance.multithreaded_rendering") {
        match parse_yaml_bool(mr) {
            Some(true) => { env.insert("MOCKTAIL_MULTITHREADED_RENDERING".to_string(), serde_json::json!("1")); }
            Some(false) => { env.insert("MOCKTAIL_MULTITHREADED_RENDERING".to_string(), serde_json::json!("0")); }
            None => return Err((-23, "performance.multithreaded_rendering must be true or false".to_string())),
        }
    }
    if let Some(pwm) = values.get("performance.physics_worker_mode") {
        if !["auto", "latency", "throughput"].contains(&pwm.as_str()) {
            return Err((-24, "performance.physics_worker_mode must be auto, latency, or throughput".to_string()));
        }
        env.insert("MOCKTAIL_PHYSICS_WORKER_MODE".to_string(), serde_json::json!(pwm));
    }
    if let Some(mem) = values.get("performance.memory_limit_mb") {
        let n: u64 = mem
            .parse()
            .map_err(|_| (-25, "performance.memory_limit_mb must be a non-negative integer".to_string()))?;
        env.insert("MOCKTAIL_MEMORY_LIMIT_MB".to_string(), serde_json::json!(n.to_string()));
    }
    if let Some(gm) = values.get("performance.gamemode") {
        if !["auto", "on", "off"].contains(&gm.as_str()) {
            return Err((-26, "performance.gamemode must be auto, on, or off".to_string()));
        }
        env.insert("MOCKTAIL_GAMEMODE".to_string(), serde_json::json!(gm));
    }

    if let Some(out_dev) = values.get("audio.output_device") {
        if out_dev.is_empty() || out_dev.len() > 512 || out_dev.bytes().any(|b| b < 0x20 || b == 0x7F) {
            return Err((-27, "audio.output_device must be non-empty, bounded, and contain no control bytes".to_string()));
        }
        env.insert("MOCKTAIL_AUDIO_OUTPUT_DEVICE".to_string(), serde_json::json!(out_dev));
    }
    if let Some(in_dev) = values.get("audio.input_device") {
        if in_dev.is_empty() || in_dev.len() > 512 || in_dev.bytes().any(|b| b < 0x20 || b == 0x7F) {
            return Err((-28, "audio.input_device must be non-empty, bounded, and contain no control bytes".to_string()));
        }
        env.insert("MOCKTAIL_AUDIO_INPUT_DEVICE".to_string(), serde_json::json!(in_dev));
    }

    if let Some(w) = values.get("window.width") {
        let n: u32 = w
            .parse()
            .ok()
            .filter(|v| *v > 0)
            .ok_or_else(|| (-29, "window.width must be a positive integer".to_string()))?;
        env.insert("MOCKTAIL_WIN_WIDTH".to_string(), serde_json::json!(n.to_string()));
    }
    if let Some(h) = values.get("window.height") {
        let n: u32 = h
            .parse()
            .ok()
            .filter(|v| *v > 0)
            .ok_or_else(|| (-30, "window.height must be a positive integer".to_string()))?;
        env.insert("MOCKTAIL_WIN_HEIGHT".to_string(), serde_json::json!(n.to_string()));
    }
    if let Some(title) = values.get("window.title") {
        if title.is_empty() {
            return Err((-31, "window.title must not be empty".to_string()));
        }
        env.insert("MOCKTAIL_WIN_TITLE".to_string(), serde_json::json!(title));
    }
    if let Some(hdpi) = values.get("window.high_dpi") {
        match parse_yaml_bool(hdpi) {
            Some(true) => { env.insert("MOCKTAIL_WIN_HIGH_DPI".to_string(), serde_json::json!("1")); }
            Some(false) => { env.insert("MOCKTAIL_WIN_HIGH_DPI".to_string(), serde_json::json!("0")); }
            None => return Err((-32, "window.high_dpi must be true or false".to_string())),
        }
    }

    if let Some(touch) = values.get("input.touch_enabled") {
        match parse_yaml_bool(touch) {
            Some(true) => { env.insert("MOCKTAIL_TOUCH_MODE".to_string(), serde_json::json!("on")); }
            Some(false) => { env.insert("MOCKTAIL_TOUCH_MODE".to_string(), serde_json::json!("off")); }
            None => return Err((-33, "input.touch_enabled must be true or false".to_string())),
        }
    }

    if let Some(dp) = values.get("compatibility.desktop_playability") {
        match parse_yaml_bool(dp) {
            Some(true) => { env.insert("MOCKTAIL_DESKTOP_PLAYABILITY".to_string(), serde_json::json!("1")); }
            Some(false) => { env.insert("MOCKTAIL_DESKTOP_PLAYABILITY".to_string(), serde_json::json!("0")); }
            None => return Err((-34, "compatibility.desktop_playability must be true or false".to_string())),
        }
    }

    if let Some(sys_prox) = values.get("network.use_system_proxy") {
        match parse_yaml_bool(sys_prox) {
            Some(true) => { env.insert("MOCKTAIL_USE_SYSTEM_PROXY".to_string(), serde_json::json!("1")); }
            Some(false) => { env.insert("MOCKTAIL_USE_SYSTEM_PROXY".to_string(), serde_json::json!("0")); }
            None => return Err((-35, "network.use_system_proxy must be true or false".to_string())),
        }
    }
    let proxy_host = values.get("network.proxy_host");
    let proxy_port = values.get("network.proxy_port");
    let proxy_scheme = values.get("network.proxy_scheme");
    let proxy_username = values.get("network.proxy_username");
    let proxy_password = values.get("network.proxy_password");
    if proxy_host.is_some() != proxy_port.is_some()
        || (proxy_scheme.is_some() && proxy_host.is_none())
        || (proxy_username.is_some() && proxy_host.is_none())
        || (proxy_password.is_some() && proxy_host.is_none())
    {
        return Err((-36, "network.proxy_host and network.proxy_port must be configured together".to_string()));
    }
    if let Some(host) = proxy_host {
        let port_str = proxy_port.unwrap();
        let port_num = port_str.parse::<u32>().unwrap_or(0);
        if host.contains("://") || host.contains('/') || port_num == 0 || port_num > 65535 {
            return Err((-38, "network proxy must use a valid host without a scheme, a port from 1 to 65535, an HTTP or SOCKS5 scheme, and valid credentials".to_string()));
        }
        if let Some(scheme) = proxy_scheme {
            if !["http", "https", "socks5"].contains(&scheme.as_str()) {
                return Err((-39, "network proxy must use a valid host without a scheme, a port from 1 to 65535, an HTTP or SOCKS5 scheme, and valid credentials".to_string()));
            }
        }
        env.insert("MOCKTAIL_HTTP_PROXY_HOST".to_string(), serde_json::json!(host));
        env.insert("MOCKTAIL_HTTP_PROXY_PORT".to_string(), serde_json::json!(port_str));
        env.insert(
            "MOCKTAIL_HTTP_PROXY_SCHEME".to_string(),
            serde_json::json!(proxy_scheme.map(|s| s.as_str()).unwrap_or("http")),
        );
        if let Some(u) = proxy_username {
            env.insert("MOCKTAIL_HTTP_PROXY_USERNAME".to_string(), serde_json::json!(u));
        }
        if let Some(p) = proxy_password {
            env.insert("MOCKTAIL_HTTP_PROXY_PASSWORD".to_string(), serde_json::json!(p));
        }
    }
    if let Some(ca) = values.get("network.ca_bundle") {
        if ca.is_empty() || !ca.starts_with('/') {
            return Err((-37, "network.ca_bundle must be an absolute file path".to_string()));
        }
        env.insert("MOCKTAIL_CA_BUNDLE".to_string(), serde_json::json!(ca));
    }

    if let Some(sec) = values.get("auth.use_libsecret") {
        match parse_yaml_bool(sec) {
            Some(true) => { env.insert("MOCKTAIL_USE_LIBSECRET".to_string(), serde_json::json!("1")); }
            Some(false) => { env.insert("MOCKTAIL_USE_LIBSECRET".to_string(), serde_json::json!("0")); }
            None => return Err((-38, "auth.use_libsecret must be true or false".to_string())),
        }
    }

    if let Some(fl) = values.get("integrations.fleasion.enabled") {
        match parse_yaml_bool(fl) {
            Some(true) => { env.insert("MOCKTAIL_FLEASION_ENABLED".to_string(), serde_json::json!("1")); }
            Some(false) => { env.insert("MOCKTAIL_FLEASION_ENABLED".to_string(), serde_json::json!("0")); }
            None => return Err((-39, "integrations.fleasion.enabled must be true or false".to_string())),
        }
    }
    if let Some(pm) = values.get("integrations.fleasion.proxy_mode") {
        env.insert("MOCKTAIL_FLEASION_PROXY_MODE".to_string(), serde_json::json!(pm));
    }
    if let Some(port) = values.get("integrations.fleasion.proxy_port") {
        env.insert("MOCKTAIL_FLEASION_PROXY_PORT".to_string(), serde_json::json!(port));
    }
    if let Some(ca) = values.get("integrations.fleasion.ca_certificate") {
        env.insert("MOCKTAIL_FLEASION_CA_CERTIFICATE".to_string(), serde_json::json!(ca));
    }

    let bool_discord_fields = [
        ("integrations.discord_rpc.enabled", "MOCKTAIL_DISCORD_RPC_ENABLED"),
        ("integrations.discord_rpc.show_place_name", "MOCKTAIL_DISCORD_RPC_SHOW_PLACE_NAME"),
        ("integrations.discord_rpc.show_elapsed_time", "MOCKTAIL_DISCORD_RPC_SHOW_ELAPSED_TIME"),
        ("integrations.discord_rpc.join.enabled", "MOCKTAIL_DISCORD_RPC_JOIN_ENABLED"),
        ("integrations.discord_rpc.join.public_servers_only", "MOCKTAIL_DISCORD_RPC_PUBLIC_SERVERS_ONLY"),
    ];
    for (k, env_k) in bool_discord_fields {
        if let Some(val) = values.get(k) {
            match parse_yaml_bool(val) {
                Some(true) => { env.insert(env_k.to_string(), serde_json::json!("1")); }
                Some(false) => { env.insert(env_k.to_string(), serde_json::json!("0")); }
                None => return Err((-40, format!("{} must be true or false", k))),
            }
        }
    }

    if let Some(app_id) = values.get("integrations.discord_rpc.application_id") {
        if app_id.len() < 17 || app_id.len() > 20 || !app_id.chars().all(|c| c.is_ascii_digit()) {
            return Err((-41, "integrations.discord_rpc.application_id must be a Discord snowflake".to_string()));
        }
        env.insert("MOCKTAIL_DISCORD_APPLICATION_ID".to_string(), serde_json::json!(app_id));
    }

    let string_discord_fields = [
        ("integrations.discord_rpc.join.button_label", "MOCKTAIL_DISCORD_RPC_JOIN_BUTTON_LABEL", 32),
        ("integrations.discord_rpc.text.browsing", "MOCKTAIL_DISCORD_RPC_TEXT_BROWSING", 128),
        ("integrations.discord_rpc.text.joining", "MOCKTAIL_DISCORD_RPC_TEXT_JOINING", 128),
        ("integrations.discord_rpc.text.playing", "MOCKTAIL_DISCORD_RPC_TEXT_PLAYING", 128),
        ("integrations.discord_rpc.text.state", "MOCKTAIL_DISCORD_RPC_TEXT_STATE", 128),
        ("integrations.discord_rpc.text.unknown_place", "MOCKTAIL_DISCORD_RPC_TEXT_UNKNOWN_PLACE", 128),
    ];
    for (yaml_key, env_key, max_len) in string_discord_fields {
        if let Some(val) = values.get(yaml_key) {
            if val.is_empty() || val.len() > max_len || val.bytes().any(|b| b < 0x20 || b == 0x7F) {
                return Err((-42, format!("{} must be non-empty, bounded, and contain no control bytes", yaml_key)));
            }
            env.insert(env_key.to_string(), serde_json::json!(val));
        }
    }

    let bool_micup_fields = [
        ("integrations.micup_rpc.enabled", "MOCKTAIL_MICUP_ENABLED"),
        ("integrations.micup_rpc.show_place_name", "MOCKTAIL_MICUP_SHOW_PLACE_NAME"),
        ("integrations.micup_rpc.show_elapsed_time", "MOCKTAIL_MICUP_SHOW_ELAPSED_TIME"),
    ];
    for (k, env_k) in bool_micup_fields {
        if let Some(val) = values.get(k) {
            match parse_yaml_bool(val) {
                Some(true) => { env.insert(env_k.to_string(), serde_json::json!("1")); }
                Some(false) => { env.insert(env_k.to_string(), serde_json::json!("0")); }
                None => return Err((-43, format!("{} must be true or false", k))),
            }
        }
    }

    if let Some(tok) = values.get("integrations.micup_rpc.token") {
        if !crate::micup_rpc::is_valid_micup_token(tok) {
            return Err((-44, "integrations.micup_rpc.token must be 1..=256 visible bytes with no control characters".to_string()));
        }
        env.insert("MOCKTAIL_MICUP_TOKEN".to_string(), serde_json::json!(tok));
    }

    if let Some(tok_file) = values.get("integrations.micup_rpc.token_file") {
        if tok_file.is_empty() || tok_file.len() > 4096 || tok_file.bytes().any(|b| b < 0x20 || b == 0x7F) {
            return Err((-45, "integrations.micup_rpc.token_file must be a bounded path without control bytes".to_string()));
        }
        env.insert("MOCKTAIL_MICUP_TOKEN_FILE".to_string(), serde_json::json!(tok_file));
    }

    if let Some(gw) = values.get("integrations.micup_rpc.gateway_url") {
        if crate::micup_rpc::normalize_gateway_url(gw).is_none() {
            return Err((-46, "integrations.micup_rpc.gateway_url must be a valid wss:// URL (or loopback ws://)".to_string()));
        }
        env.insert("MOCKTAIL_MICUP_GATEWAY_URL".to_string(), serde_json::json!(gw));
    }

    if let Some(status) = values.get("integrations.micup_rpc.status") {
        if !crate::micup_rpc::is_valid_micup_status(status) {
            return Err((-47, "integrations.micup_rpc.status must be auto, online, idle, dnd, or invisible".to_string()));
        }
        env.insert("MOCKTAIL_MICUP_STATUS".to_string(), serde_json::json!(status));
    }

    if let Some(mode) = values.get("integrations.micup_rpc.activity_mode") {
        if !crate::micup_rpc::is_valid_micup_activity_mode(mode) {
            return Err((-48, "integrations.micup_rpc.activity_mode must be auto, manual, or catalog".to_string()));
        }
        env.insert("MOCKTAIL_MICUP_ACTIVITY_MODE".to_string(), serde_json::json!(mode));
    }

    let string_micup_fields = [
        ("integrations.micup_rpc.text.browsing", "MOCKTAIL_MICUP_TEXT_BROWSING", 128),
        ("integrations.micup_rpc.text.joining", "MOCKTAIL_MICUP_TEXT_JOINING", 128),
        ("integrations.micup_rpc.text.playing", "MOCKTAIL_MICUP_TEXT_PLAYING", 128),
        ("integrations.micup_rpc.text.unknown_place", "MOCKTAIL_MICUP_TEXT_UNKNOWN_PLACE", 128),
    ];
    for (yaml_key, env_key, max_len) in string_micup_fields {
        if let Some(val) = values.get(yaml_key) {
            if !crate::micup_rpc::is_valid_micup_text(val, max_len) {
                return Err((-49, format!("{} must be non-empty, bounded, and contain no control bytes", yaml_key)));
            }
            env.insert(env_key.to_string(), serde_json::json!(val));
        }
    }

    Ok(env)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_parse_runtime_config_yaml(
    yaml_bytes: *const u8,
    yaml_len: usize,
    out_env_json: *mut c_char,
    out_cap: usize,
    out_error: *mut c_char,
    error_cap: usize,
) -> c_int {
    let set_error = |msg: &str| {
        copy_error(out_error, error_cap, msg);
    };
    if yaml_bytes.is_null() || out_env_json.is_null() || out_cap == 0 {
        set_error("invalid argument");
        return -1;
    }
    let slice = unsafe { slice::from_raw_parts(yaml_bytes, yaml_len) };
    let env = match build_runtime_config_yaml_env_map(slice) {
        Ok(m) => m,
        Err((code, msg)) => {
            set_error(&msg);
            return code;
        }
    };

    let dumped = serde_json::Value::Object(env).to_string();
    if dumped.len() + 1 > out_cap {
        set_error("output buffer too small");
        return -43;
    }
    unsafe {
        std::ptr::copy_nonoverlapping(dumped.as_ptr() as *const c_char, out_env_json, dumped.len());
        *out_env_json.add(dumped.len()) = 0;
    }
    0
}

// ============================================================================
// 23. Startup Lifecycle State Machine
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MocktailRustStartupState {
    Created = 0,
    Configured = 1,
    JniRuntimeReady = 2,
    LibrariesLoaded = 3,
    JniOnLoadComplete = 4,
    EngineStarted = 5,
    DataModelLoading = 6,
    LuaAppReady = 7,
    Ready = 8,
    Failure = 9,
    Stopping = 10,
    Stopped = 11,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MocktailRustStartupEvidence {
    Configured = 0,
    JniRuntimeReady = 1,
    LibrariesLoaded = 2,
    JniOnLoadComplete = 3,
    EngineStarted = 4,
    DataModelLoading = 5,
    LuaAppReady = 6,
    RealFramePresented = 7,
    InputReady = 8,
    AudioReady = 9,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MocktailRustStartupRequirements {
    pub windowed: c_int,
    pub require_input_ready: c_int,
    pub require_audio_ready: c_int,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MocktailRustStartupSnapshot {
    pub state: MocktailRustStartupState,
    pub requirements: MocktailRustStartupRequirements,
    pub configured: c_int,
    pub jni_runtime_ready: c_int,
    pub libraries_loaded: c_int,
    pub jni_on_load_complete: c_int,
    pub engine_started: c_int,
    pub data_model_loading: c_int,
    pub lua_app_ready: c_int,
    pub real_frame_presented: c_int,
    pub input_ready: c_int,
    pub audio_ready: c_int,
    pub revision: u64,
}

pub struct MocktailRustStartupSm {
    requirements: MocktailRustStartupRequirements,
    state: MocktailRustStartupState,
    evidence_bits: u32,
    revision: u64,
    failure_reason: String,
}

#[inline]
fn evidence_bit(ev: MocktailRustStartupEvidence) -> u32 {
    1u32 << (ev as u32)
}

fn expected_evidence_for_state(state: MocktailRustStartupState) -> Option<MocktailRustStartupEvidence> {
    match state {
        MocktailRustStartupState::Created => Some(MocktailRustStartupEvidence::Configured),
        MocktailRustStartupState::Configured => Some(MocktailRustStartupEvidence::JniRuntimeReady),
        MocktailRustStartupState::JniRuntimeReady => Some(MocktailRustStartupEvidence::LibrariesLoaded),
        MocktailRustStartupState::LibrariesLoaded => Some(MocktailRustStartupEvidence::JniOnLoadComplete),
        MocktailRustStartupState::JniOnLoadComplete => Some(MocktailRustStartupEvidence::EngineStarted),
        MocktailRustStartupState::EngineStarted => Some(MocktailRustStartupEvidence::DataModelLoading),
        MocktailRustStartupState::DataModelLoading => Some(MocktailRustStartupEvidence::LuaAppReady),
        _ => None,
    }
}

fn startup_state_name(state: MocktailRustStartupState) -> &'static str {
    match state {
        MocktailRustStartupState::Created => "Created",
        MocktailRustStartupState::Configured => "Configured",
        MocktailRustStartupState::JniRuntimeReady => "JniRuntimeReady",
        MocktailRustStartupState::LibrariesLoaded => "LibrariesLoaded",
        MocktailRustStartupState::JniOnLoadComplete => "JniOnLoadComplete",
        MocktailRustStartupState::EngineStarted => "EngineStarted",
        MocktailRustStartupState::DataModelLoading => "DataModelLoading",
        MocktailRustStartupState::LuaAppReady => "LuaAppReady",
        MocktailRustStartupState::Ready => "Ready",
        MocktailRustStartupState::Failure => "Failure",
        MocktailRustStartupState::Stopping => "Stopping",
        MocktailRustStartupState::Stopped => "Stopped",
    }
}

fn startup_evidence_name(ev_val: c_int) -> &'static str {
    match ev_val {
        0 => "Configured",
        1 => "JniRuntimeReady",
        2 => "LibrariesLoaded",
        3 => "JniOnLoadComplete",
        4 => "EngineStarted",
        5 => "DataModelLoading",
        6 => "LuaAppReady",
        7 => "RealFramePresented",
        8 => "InputReady",
        9 => "AudioReady",
        _ => "Unknown",
    }
}

fn expected_evidence_name_for_state(state: MocktailRustStartupState) -> &'static str {
    match state {
        MocktailRustStartupState::Created => "Configured",
        MocktailRustStartupState::Configured => "JniRuntimeReady",
        MocktailRustStartupState::JniRuntimeReady => "LibrariesLoaded",
        MocktailRustStartupState::LibrariesLoaded => "JniOnLoadComplete",
        MocktailRustStartupState::JniOnLoadComplete => "EngineStarted",
        MocktailRustStartupState::EngineStarted => "DataModelLoading",
        MocktailRustStartupState::DataModelLoading => "LuaAppReady",
        _ => "no further evidence",
    }
}

fn state_for_core_evidence(evidence: MocktailRustStartupEvidence) -> MocktailRustStartupState {
    match evidence {
        MocktailRustStartupEvidence::Configured => MocktailRustStartupState::Configured,
        MocktailRustStartupEvidence::JniRuntimeReady => MocktailRustStartupState::JniRuntimeReady,
        MocktailRustStartupEvidence::LibrariesLoaded => MocktailRustStartupState::LibrariesLoaded,
        MocktailRustStartupEvidence::JniOnLoadComplete => MocktailRustStartupState::JniOnLoadComplete,
        MocktailRustStartupEvidence::EngineStarted => MocktailRustStartupState::EngineStarted,
        MocktailRustStartupEvidence::DataModelLoading => MocktailRustStartupState::DataModelLoading,
        MocktailRustStartupEvidence::LuaAppReady => MocktailRustStartupState::LuaAppReady,
        _ => MocktailRustStartupState::Failure,
    }
}

impl MocktailRustStartupSm {
    fn has_evidence(&self, ev: MocktailRustStartupEvidence) -> bool {
        (self.evidence_bits & evidence_bit(ev)) != 0
    }

    fn evaluate_ready(&mut self) {
        if !self.has_evidence(MocktailRustStartupEvidence::LuaAppReady) {
            return;
        }
        if self.requirements.windowed != 0 && !self.has_evidence(MocktailRustStartupEvidence::RealFramePresented) {
            self.state = MocktailRustStartupState::LuaAppReady;
            return;
        }
        if self.requirements.require_input_ready != 0 && !self.has_evidence(MocktailRustStartupEvidence::InputReady) {
            self.state = MocktailRustStartupState::LuaAppReady;
            return;
        }
        if self.requirements.require_audio_ready != 0 && !self.has_evidence(MocktailRustStartupEvidence::AudioReady) {
            self.state = MocktailRustStartupState::LuaAppReady;
            return;
        }
        self.state = MocktailRustStartupState::Ready;
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_startup_sm_create(
    req: MocktailRustStartupRequirements,
) -> *mut MocktailRustStartupSm {
    let sm = Box::new(MocktailRustStartupSm {
        requirements: req,
        state: MocktailRustStartupState::Created,
        evidence_bits: 0,
        revision: 0,
        failure_reason: String::new(),
    });
    Box::into_raw(sm)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_startup_sm_destroy(sm: *mut MocktailRustStartupSm) {
    if !sm.is_null() {
        unsafe { drop(Box::from_raw(sm)); }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_startup_sm_record_evidence(
    sm_ptr: *mut MocktailRustStartupSm,
    evidence_val: c_int,
    out_state: *mut MocktailRustStartupState,
    out_status: *mut c_int,
    out_msg: *mut c_char,
    msg_cap: usize,
) -> c_int {
    let set_msg = |msg: &str| {
        if !out_msg.is_null() && msg_cap > 0 {
            let len = std::cmp::min(msg.len(), msg_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_msg, len);
                *out_msg.add(len) = 0;
            }
        }
    };
    if sm_ptr.is_null() {
        return -1;
    }
    let sm = unsafe { &mut *sm_ptr };
    let ev = match evidence_val {
        0 => MocktailRustStartupEvidence::Configured,
        1 => MocktailRustStartupEvidence::JniRuntimeReady,
        2 => MocktailRustStartupEvidence::LibrariesLoaded,
        3 => MocktailRustStartupEvidence::JniOnLoadComplete,
        4 => MocktailRustStartupEvidence::EngineStarted,
        5 => MocktailRustStartupEvidence::DataModelLoading,
        6 => MocktailRustStartupEvidence::LuaAppReady,
        7 => MocktailRustStartupEvidence::RealFramePresented,
        8 => MocktailRustStartupEvidence::InputReady,
        9 => MocktailRustStartupEvidence::AudioReady,
        _ => {
            let expected = expected_evidence_name_for_state(sm.state);
            sm.failure_reason = format!(
                "invalid startup evidence order in state {}: expected {}, received Unknown",
                startup_state_name(sm.state),
                expected
            );
            sm.state = MocktailRustStartupState::Failure;
            sm.revision += 1;
            set_msg(&sm.failure_reason);
            unsafe {
                if !out_state.is_null() { *out_state = sm.state; }
                if !out_status.is_null() { *out_status = 2; /* Rejected */ }
            }
            return 0;
        }
    };

    if sm.has_evidence(ev) {
        unsafe {
            if !out_state.is_null() { *out_state = sm.state; }
            if !out_status.is_null() { *out_status = 1; /* Duplicate */ }
        }
        let msg = format!("duplicate startup evidence: {}", startup_evidence_name(evidence_val));
        set_msg(&msg);
        return 0;
    }

    if sm.state == MocktailRustStartupState::Failure
        || sm.state == MocktailRustStartupState::Stopping
        || sm.state == MocktailRustStartupState::Stopped
    {
        let msg = format!("startup evidence rejected in state {}", startup_state_name(sm.state));
        unsafe {
            if !out_state.is_null() { *out_state = sm.state; }
            if !out_status.is_null() { *out_status = 2; /* Rejected */ }
        }
        set_msg(&msg);
        return 0;
    }

    let is_core = (evidence_val >= 0) && (evidence_val <= 6);
    if is_core {
        let expected_ev = expected_evidence_for_state(sm.state);
        if expected_ev != Some(ev) {
            let expected_str = expected_evidence_name_for_state(sm.state);
            sm.failure_reason = format!(
                "invalid startup evidence order in state {}: expected {}, received {}",
                startup_state_name(sm.state),
                expected_str,
                startup_evidence_name(evidence_val)
            );
            sm.state = MocktailRustStartupState::Failure;
            sm.revision += 1;
            set_msg(&sm.failure_reason);
            unsafe {
                if !out_state.is_null() { *out_state = sm.state; }
                if !out_status.is_null() { *out_status = 2; /* Rejected */ }
            }
            return 0;
        }
        sm.evidence_bits |= evidence_bit(ev);
        sm.state = state_for_core_evidence(ev);
        sm.revision += 1;
        sm.evaluate_ready();
        let msg = format!("accepted startup evidence: {}", startup_evidence_name(evidence_val));
        set_msg(&msg);
        unsafe {
            if !out_state.is_null() { *out_state = sm.state; }
            if !out_status.is_null() { *out_status = 0; /* Applied */ }
        }
        return 0;
    } else {
        if !sm.has_evidence(MocktailRustStartupEvidence::Configured) {
            sm.failure_reason = format!(
                "invalid startup evidence order in state {}: expected Configured, received {}",
                startup_state_name(sm.state),
                startup_evidence_name(evidence_val)
            );
            sm.state = MocktailRustStartupState::Failure;
            sm.revision += 1;
            set_msg(&sm.failure_reason);
            unsafe {
                if !out_state.is_null() { *out_state = sm.state; }
                if !out_status.is_null() { *out_status = 2; /* Rejected */ }
            }
            return 0;
        }
        if ev == MocktailRustStartupEvidence::RealFramePresented && !sm.has_evidence(MocktailRustStartupEvidence::EngineStarted) {
            sm.failure_reason = format!(
                "invalid startup evidence order in state {}: expected EngineStarted, received {}",
                startup_state_name(sm.state),
                startup_evidence_name(evidence_val)
            );
            sm.state = MocktailRustStartupState::Failure;
            sm.revision += 1;
            set_msg(&sm.failure_reason);
            unsafe {
                if !out_state.is_null() { *out_state = sm.state; }
                if !out_status.is_null() { *out_status = 2; /* Rejected */ }
            }
            return 0;
        }
        sm.evidence_bits |= evidence_bit(ev);
        sm.revision += 1;
        sm.evaluate_ready();
        let msg = format!("accepted startup evidence: {}", startup_evidence_name(evidence_val));
        set_msg(&msg);
        unsafe {
            if !out_state.is_null() { *out_state = sm.state; }
            if !out_status.is_null() { *out_status = 0; /* Applied */ }
        }
        return 0;
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_startup_sm_fail(
    sm_ptr: *mut MocktailRustStartupSm,
    reason: *const c_char,
    out_state: *mut MocktailRustStartupState,
    out_status: *mut c_int,
    out_msg: *mut c_char,
    msg_cap: usize,
) -> c_int {
    let set_msg = |msg: &str| {
        if !out_msg.is_null() && msg_cap > 0 {
            let len = std::cmp::min(msg.len(), msg_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_msg, len);
                *out_msg.add(len) = 0;
            }
        }
    };
    if sm_ptr.is_null() {
        return -1;
    }
    let sm = unsafe { &mut *sm_ptr };
    if sm.state == MocktailRustStartupState::Failure {
        unsafe {
            if !out_state.is_null() { *out_state = sm.state; }
            if !out_status.is_null() { *out_status = 1; /* Duplicate */ }
        }
        set_msg(&sm.failure_reason);
        return 0;
    }
    if sm.state == MocktailRustStartupState::Stopped {
        unsafe {
            if !out_state.is_null() { *out_state = sm.state; }
            if !out_status.is_null() { *out_status = 2; /* Rejected */ }
        }
        set_msg("cannot fail an already stopped runtime");
        return 0;
    }
    let r_str = if reason.is_null() {
        "startup failed"
    } else {
        unsafe { CStr::from_ptr(reason) }.to_str().unwrap_or("startup failed")
    };
    sm.failure_reason = if r_str.is_empty() { "startup failed".to_string() } else { r_str.to_string() };
    sm.state = MocktailRustStartupState::Failure;
    sm.revision += 1;
    unsafe {
        if !out_state.is_null() { *out_state = sm.state; }
        if !out_status.is_null() { *out_status = 0; /* Applied */ }
    }
    set_msg(&sm.failure_reason);
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_startup_sm_begin_stopping(
    sm_ptr: *mut MocktailRustStartupSm,
    out_state: *mut MocktailRustStartupState,
    out_status: *mut c_int,
    out_msg: *mut c_char,
    msg_cap: usize,
) -> c_int {
    let set_msg = |msg: &str| {
        if !out_msg.is_null() && msg_cap > 0 {
            let len = std::cmp::min(msg.len(), msg_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_msg, len);
                *out_msg.add(len) = 0;
            }
        }
    };
    if sm_ptr.is_null() {
        return -1;
    }
    let sm = unsafe { &mut *sm_ptr };
    if sm.state == MocktailRustStartupState::Stopping || sm.state == MocktailRustStartupState::Stopped {
        unsafe {
            if !out_state.is_null() { *out_state = sm.state; }
            if !out_status.is_null() { *out_status = 1; /* Duplicate */ }
        }
        let msg = format!("runtime is already {}", startup_state_name(sm.state));
        set_msg(&msg);
        return 0;
    }
    sm.state = MocktailRustStartupState::Stopping;
    sm.revision += 1;
    unsafe {
        if !out_state.is_null() { *out_state = sm.state; }
        if !out_status.is_null() { *out_status = 0; /* Applied */ }
    }
    set_msg("runtime stopping");
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_startup_sm_mark_stopped(
    sm_ptr: *mut MocktailRustStartupSm,
    out_state: *mut MocktailRustStartupState,
    out_status: *mut c_int,
    out_msg: *mut c_char,
    msg_cap: usize,
) -> c_int {
    let set_msg = |msg: &str| {
        if !out_msg.is_null() && msg_cap > 0 {
            let len = std::cmp::min(msg.len(), msg_cap - 1);
            unsafe {
                std::ptr::copy_nonoverlapping(msg.as_ptr() as *const c_char, out_msg, len);
                *out_msg.add(len) = 0;
            }
        }
    };
    if sm_ptr.is_null() {
        return -1;
    }
    let sm = unsafe { &mut *sm_ptr };
    if sm.state == MocktailRustStartupState::Stopped {
        unsafe {
            if !out_state.is_null() { *out_state = sm.state; }
            if !out_status.is_null() { *out_status = 1; /* Duplicate */ }
        }
        set_msg("runtime is already Stopped");
        return 0;
    }
    if sm.state != MocktailRustStartupState::Stopping {
        sm.failure_reason = format!(
            "invalid lifecycle order: Stopped requires Stopping, was {}",
            startup_state_name(sm.state)
        );
        sm.state = MocktailRustStartupState::Failure;
        sm.revision += 1;
        unsafe {
            if !out_state.is_null() { *out_state = sm.state; }
            if !out_status.is_null() { *out_status = 2; /* Rejected */ }
        }
        set_msg(&sm.failure_reason);
        return 0;
    }
    sm.state = MocktailRustStartupState::Stopped;
    sm.revision += 1;
    unsafe {
        if !out_state.is_null() { *out_state = sm.state; }
        if !out_status.is_null() { *out_status = 0; /* Applied */ }
    }
    set_msg("runtime stopped");
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_startup_sm_snapshot(
    sm_ptr: *const MocktailRustStartupSm,
    out_snapshot: *mut MocktailRustStartupSnapshot,
    out_reason: *mut c_char,
    reason_cap: usize,
) -> c_int {
    if sm_ptr.is_null() || out_snapshot.is_null() {
        return -1;
    }
    let sm = unsafe { &*sm_ptr };
    unsafe {
        (*out_snapshot).state = sm.state;
        (*out_snapshot).requirements = sm.requirements;
        (*out_snapshot).configured = if sm.has_evidence(MocktailRustStartupEvidence::Configured) { 1 } else { 0 };
        (*out_snapshot).jni_runtime_ready = if sm.has_evidence(MocktailRustStartupEvidence::JniRuntimeReady) { 1 } else { 0 };
        (*out_snapshot).libraries_loaded = if sm.has_evidence(MocktailRustStartupEvidence::LibrariesLoaded) { 1 } else { 0 };
        (*out_snapshot).jni_on_load_complete = if sm.has_evidence(MocktailRustStartupEvidence::JniOnLoadComplete) { 1 } else { 0 };
        (*out_snapshot).engine_started = if sm.has_evidence(MocktailRustStartupEvidence::EngineStarted) { 1 } else { 0 };
        (*out_snapshot).data_model_loading = if sm.has_evidence(MocktailRustStartupEvidence::DataModelLoading) { 1 } else { 0 };
        (*out_snapshot).lua_app_ready = if sm.has_evidence(MocktailRustStartupEvidence::LuaAppReady) { 1 } else { 0 };
        (*out_snapshot).real_frame_presented = if sm.has_evidence(MocktailRustStartupEvidence::RealFramePresented) { 1 } else { 0 };
        (*out_snapshot).input_ready = if sm.has_evidence(MocktailRustStartupEvidence::InputReady) { 1 } else { 0 };
        (*out_snapshot).audio_ready = if sm.has_evidence(MocktailRustStartupEvidence::AudioReady) { 1 } else { 0 };
        (*out_snapshot).revision = sm.revision;
        if !out_reason.is_null() && reason_cap > 0 {
            let len = std::cmp::min(sm.failure_reason.len(), reason_cap - 1);
            std::ptr::copy_nonoverlapping(sm.failure_reason.as_ptr() as *const c_char, out_reason, len);
            *out_reason.add(len) = 0;
        }
    }
    0
}

// ============================================================================
// 24. Fleasion CA Certificate & Bundle Manager
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_fleasion_prepare_bundle(
    ca_pem_path: *const c_char,
    base_bundle_path: *const c_char,
    dest_bundle_path: *const c_char,
    out_error: *mut c_char,
    error_cap: usize,
) -> c_int {
    let set_error = |msg: &str| {
        copy_error(out_error, error_cap, msg);
    };
    if ca_pem_path.is_null() || base_bundle_path.is_null() || dest_bundle_path.is_null() {
        set_error("invalid argument");
        return -1;
    }
    let ca_path = match unsafe { CStr::from_ptr(ca_pem_path) }.to_str() {
        Ok(s) => Path::new(s),
        Err(_) => {
            set_error("invalid ca path encoding");
            return -2;
        }
    };
    let base_path = match unsafe { CStr::from_ptr(base_bundle_path) }.to_str() {
        Ok(s) => Path::new(s),
        Err(_) => {
            set_error("invalid base bundle path encoding");
            return -3;
        }
    };
    let dest_path = match unsafe { CStr::from_ptr(dest_bundle_path) }.to_str() {
        Ok(s) => Path::new(s),
        Err(_) => {
            set_error("invalid dest bundle path encoding");
            return -4;
        }
    };

    let ca_pem = match std::fs::read_to_string(ca_path) {
        Ok(s) => s,
        Err(_) => {
            set_error(&format!("cannot read Fleasion CA certificate at {}", ca_path.display()));
            return -5;
        }
    };
    if !ca_pem.contains("-----BEGIN CERTIFICATE-----") || !ca_pem.contains("-----END CERTIFICATE-----") {
        set_error("Fleasion CA must be a currently valid PEM CA certificate");
        return -6;
    }

    let base_pem = match std::fs::read_to_string(base_path) {
        Ok(s) => s,
        Err(_) => {
            set_error(&format!("cannot read base CA bundle for Fleasion: {}", base_path.display()));
            return -7;
        }
    };

    let mut out_bundle = String::new();
    let mut cursor = 0;
    let mut count = 0;
    while let Some(start) = base_pem[cursor..].find("-----BEGIN CERTIFICATE-----") {
        let abs_start = cursor + start;
        if let Some(end) = base_pem[abs_start..].find("-----END CERTIFICATE-----") {
            let abs_end = abs_start + end + "-----END CERTIFICATE-----".len();
            let cert_block = &base_pem[abs_start..abs_end];
            let cert_norm: String = cert_block.chars().filter(|c| !c.is_whitespace()).collect();
            let ca_norm: String = ca_pem.chars().filter(|c| !c.is_whitespace()).collect();
            if cert_norm != ca_norm {
                out_bundle.push_str(cert_block.trim());
                out_bundle.push('\n');
                count += 1;
            }
            cursor = abs_end;
        } else {
            break;
        }
    }
    if count == 0 {
        set_error("base bundle must contain PEM certificates");
        return -8;
    }

    out_bundle.push_str(ca_pem.trim());
    out_bundle.push('\n');

    if let Some(parent) = dest_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let tmp_path = format!("{}.tmp.{}", dest_path.display(), std::process::id());
    if std::fs::write(&tmp_path, out_bundle.as_bytes()).is_err() {
        set_error(&format!("cannot write generated Fleasion CA bundle: {}", dest_path.display()));
        return -9;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600));
    }
    if std::fs::rename(&tmp_path, dest_path).is_err() {
        let _ = std::fs::remove_file(&tmp_path);
        set_error(&format!("cannot write generated Fleasion CA bundle: {}", dest_path.display()));
        return -10;
    }
    0
}

// ============================================================================
// 25. APK Signing Block & Chunk Hash Verifier
// ============================================================================

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MocktailRustApkSigningBlockInfo {
    pub block_begin: u64,
    pub central_directory: u64,
    pub eocd: u64,
    pub v2_offset: u64,
    pub v2_len: u64,
    pub v3_offset: u64,
    pub v3_len: u64,
    pub v31_offset: u64,
    pub v31_len: u64,
}

#[inline]
pub(crate) fn read_u32_le(slice: &[u8]) -> u32 {
    u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]])
}

#[inline]
pub(crate) fn read_u64_le(slice: &[u8]) -> u64 {
    u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3],
        slice[4], slice[5], slice[6], slice[7],
    ])
}

pub(crate) fn find_apk_signing_block_internal(
    slice: &[u8],
) -> Result<MocktailRustApkSigningBlockInfo, (c_int, &'static str)> {
    let file_size = slice.len();
    if file_size < 32 {
        return Err((-1, "invalid argument"));
    }

    let min_search = if file_size > 65557 { file_size - 65557 } else { 0 };
    let mut eocd_pos = None;
    for pos in (min_search..=file_size - 22).rev() {
        if read_u32_le(&slice[pos..pos + 4]) == 0x06054b50 {
            let comment_len = u16::from_le_bytes([slice[pos + 20], slice[pos + 21]]) as usize;
            if pos + 22 + comment_len == file_size {
                eocd_pos = Some(pos);
                break;
            }
        }
    }
    let eocd = eocd_pos.ok_or((-2, "APK has no valid ZIP end record"))?;

    let cd_offset = read_u32_le(&slice[eocd + 16..eocd + 20]) as usize;
    if cd_offset < 32 || cd_offset > eocd {
        return Err((-3, "APK has no Signature Scheme v2/v3 block"));
    }
    if &slice[cd_offset - 16..cd_offset] != b"APK Sig Block 42" {
        return Err((-4, "APK has no Signature Scheme v2/v3 block"));
    }
    let footer_size = usize::try_from(read_u64_le(&slice[cd_offset - 24..cd_offset - 16]))
        .map_err(|_| (-5, "APK signing block size is invalid"))?;
    if footer_size < 24 || footer_size > cd_offset - 8 {
        return Err((-5, "APK signing block size is invalid"));
    }
    let total_size = footer_size + 8;
    let block_begin = cd_offset - total_size;
    let header_size = usize::try_from(read_u64_le(&slice[block_begin..block_begin + 8]))
        .map_err(|_| (-6, "APK signing block size headers disagree"))?;
    if header_size != footer_size {
        return Err((-6, "APK signing block size headers disagree"));
    }

    let mut info = MocktailRustApkSigningBlockInfo {
        block_begin: block_begin as u64,
        central_directory: cd_offset as u64,
        eocd: eocd as u64,
        v2_offset: 0,
        v2_len: 0,
        v3_offset: 0,
        v3_len: 0,
        v31_offset: 0,
        v31_len: 0,
    };

    let mut cursor = block_begin + 8;
    let pairs_end = cd_offset - 24;
    while cursor < pairs_end {
        if pairs_end - cursor < 12 {
            return Err((-7, "APK signing block pair is truncated"));
        }
        let pair_size = usize::try_from(read_u64_le(&slice[cursor..cursor + 8]))
            .map_err(|_| (-8, "APK signing block pair is malformed"))?;
        cursor += 8;
        if pair_size < 4 || pair_size > pairs_end - cursor {
            return Err((-8, "APK signing block pair is malformed"));
        }
        let id = read_u32_le(&slice[cursor..cursor + 4]);
        let val_offset = (cursor + 4) as u64;
        let val_len = (pair_size - 4) as u64;
        match id {
            0x7109871a => {
                info.v2_offset = val_offset;
                info.v2_len = val_len;
            }
            0xf05368c0 => {
                info.v3_offset = val_offset;
                info.v3_len = val_len;
            }
            0x1b93ad61 => {
                info.v31_offset = val_offset;
                info.v31_len = val_len;
            }
            _ => {}
        }
        cursor += pair_size;
    }

    Ok(info)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_find_apk_signing_block(
    file_bytes: *const u8,
    file_size: usize,
    out_info: *mut MocktailRustApkSigningBlockInfo,
    out_error: *mut c_char,
    error_cap: usize,
) -> c_int {
    let set_error = |msg: &str| {
        copy_error(out_error, error_cap, msg);
    };
    if file_bytes.is_null() || out_info.is_null() || file_size < 32 {
        set_error("invalid argument");
        return -1;
    }
    let slice = unsafe { slice::from_raw_parts(file_bytes, file_size) };
    match find_apk_signing_block_internal(slice) {
        Ok(info) => {
            unsafe {
                *out_info = info;
            }
            0
        }
        Err((code, msg)) => {
            set_error(msg);
            code
        }
    }
}

