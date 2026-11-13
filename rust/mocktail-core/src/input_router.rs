use std::ffi::CStr;
use std::os::raw::{c_char, c_void};

use crate::{
    copy_error, mocktail_rust_gamepad_button_to_android, mocktail_rust_gamepad_stick,
    mocktail_rust_gamepad_trigger, mocktail_rust_map_sdl_key_to_android,
    mocktail_rust_map_sdl_mouse_button, mocktail_rust_roblox_gamepad_type, MocktailRustKeyMapping,
};

const K_ANDROID_TOUCH_DOWN: i32 = 0;
const K_ANDROID_TOUCH_MOVE: i32 = 1;
const K_ANDROID_TOUCH_UP: i32 = 2;
const K_MAXIMUM_ANDROID_POINTERS: i32 = 32;

const K_ANDROID_AXES: [i32; 6] = [0, 1, 11, 14, 17, 18];
// SDL_GAMEPAD_BUTTON_SOUTH (0)..=RIGHT_STICK (8), LEFT_SHOULDER (9), RIGHT_SHOULDER (10),
// DPAD_UP (11)..=DPAD_RIGHT (14) matching SDL3/SDL_gamepad.h and roblox_gamepad_input.cc kButtons:
const K_SDL_GAMEPAD_BUTTON_SOUTH: u8 = 0;
const K_SDL_GAMEPAD_BUTTON_EAST: u8 = 1;
const K_SDL_GAMEPAD_BUTTON_WEST: u8 = 2;
const K_SDL_GAMEPAD_BUTTON_NORTH: u8 = 3;
const K_SDL_GAMEPAD_BUTTON_BACK: u8 = 4;
const K_SDL_GAMEPAD_BUTTON_START: u8 = 6;
const K_SDL_GAMEPAD_BUTTON_LEFT_STICK: u8 = 7;
const K_SDL_GAMEPAD_BUTTON_RIGHT_STICK: u8 = 8;
const K_SDL_GAMEPAD_BUTTON_LEFT_SHOULDER: u8 = 9;
const K_SDL_GAMEPAD_BUTTON_RIGHT_SHOULDER: u8 = 10;
const K_SDL_GAMEPAD_BUTTON_DPAD_UP: u8 = 11;
const K_SDL_GAMEPAD_BUTTON_DPAD_DOWN: u8 = 12;
const K_SDL_GAMEPAD_BUTTON_DPAD_LEFT: u8 = 13;
const K_SDL_GAMEPAD_BUTTON_DPAD_RIGHT: u8 = 14;

const K_BUTTONS: [u8; 14] = [
    K_SDL_GAMEPAD_BUTTON_SOUTH,
    K_SDL_GAMEPAD_BUTTON_EAST,
    K_SDL_GAMEPAD_BUTTON_WEST,
    K_SDL_GAMEPAD_BUTTON_NORTH,
    K_SDL_GAMEPAD_BUTTON_DPAD_UP,
    K_SDL_GAMEPAD_BUTTON_DPAD_DOWN,
    K_SDL_GAMEPAD_BUTTON_DPAD_LEFT,
    K_SDL_GAMEPAD_BUTTON_DPAD_RIGHT,
    K_SDL_GAMEPAD_BUTTON_RIGHT_SHOULDER,
    K_SDL_GAMEPAD_BUTTON_LEFT_SHOULDER,
    K_SDL_GAMEPAD_BUTTON_LEFT_STICK,
    K_SDL_GAMEPAD_BUTTON_RIGHT_STICK,
    K_SDL_GAMEPAD_BUTTON_BACK,
    K_SDL_GAMEPAD_BUTTON_START,
];

pub const DISPATCH_STATE_DISPATCHED: i32 = 0;
pub const DISPATCH_STATE_STATE_UPDATED: i32 = 1;
pub const DISPATCH_STATE_IGNORED_INACTIVE: i32 = 2;
pub const DISPATCH_STATE_IGNORED_UNFOCUSED: i32 = 3;
pub const DISPATCH_STATE_IGNORED_UNSUPPORTED: i32 = 4;
pub const DISPATCH_STATE_REJECTED_INVALID: i32 = 5;
pub const DISPATCH_STATE_NATIVE_ERROR: i32 = 6;

pub const EVENT_KIND_NONE: i32 = 0;
pub const EVENT_KIND_MOUSE_MOTION: i32 = 1;
pub const EVENT_KIND_MOUSE_BUTTON: i32 = 2;
pub const EVENT_KIND_MOUSE_WHEEL: i32 = 3;
pub const EVENT_KIND_TOUCH: i32 = 4;
pub const EVENT_KIND_KEYBOARD: i32 = 5;
pub const EVENT_KIND_TEXT: i32 = 6;
pub const EVENT_KIND_FOCUS: i32 = 7;
pub const EVENT_KIND_VIEWPORT: i32 = 8;
pub const EVENT_KIND_GAMEPAD_CONNECTION: i32 = 9;
pub const EVENT_KIND_GAMEPAD_BUTTON: i32 = 10;
pub const EVENT_KIND_GAMEPAD_AXIS: i32 = 11;

pub const ERR_NONE: i32 = 0;
pub const ERR_INVALID_ARGUMENT: i32 = 1;
pub const ERR_UNSUPPORTED: i32 = 2;
pub const ERR_FAILED_PRECONDITION: i32 = 3;
pub const ERR_UNAVAILABLE: i32 = 4;
pub const ERR_NATIVE_CALLBACK: i32 = 5;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MocktailRustInputViewport {
    pub logical_width: i32,
    pub logical_height: i32,
    pub pixel_width: i32,
    pub pixel_height: i32,
    pub density_scale: f32,
}

impl MocktailRustInputViewport {
    fn valid(&self) -> bool {
        self.logical_width > 0
            && self.logical_height > 0
            && self.pixel_width > 0
            && self.pixel_height > 0
            && self.density_scale.is_finite()
            && self.density_scale > 0.0
    }

    fn guest_width(&self) -> f32 {
        if self.valid() {
            self.pixel_width as f32 / self.density_scale
        } else {
            0.0
        }
    }

    fn guest_height(&self) -> f32 {
        if self.valid() {
            self.pixel_height as f32 / self.density_scale
        } else {
            0.0
        }
    }

    fn rounded_guest_width(&self) -> i32 {
        if self.valid() {
            (self.guest_width() as f64).round() as i32
        } else {
            0
        }
    }

    fn rounded_guest_height(&self) -> i32 {
        if self.valid() {
            (self.guest_height() as f64).round() as i32
        } else {
            0
        }
    }

    fn host_logical_to_guest_x(&self, coord: f32) -> f32 {
        if self.valid() {
            coord * (self.pixel_width as f32) / (self.logical_width as f32) / self.density_scale
        } else {
            coord
        }
    }

    fn host_logical_to_guest_y(&self, coord: f32) -> f32 {
        if self.valid() {
            coord * (self.pixel_height as f32) / (self.logical_height as f32) / self.density_scale
        } else {
            coord
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MocktailRustInputSnapshot {
    pub active: i32,
    pub focused: i32,
    pub viewport: MocktailRustInputViewport,
    pub mouse_events: u64,
    pub touch_events: u64,
    pub keyboard_events: u64,
    pub ignored_text_events: u64,
    pub text_events: u64,
    pub native_errors: u64,
    pub active_mouse_buttons: u32,
    pub active_touches: u32,
    pub active_keys: u32,
    pub gamepad_events: u64,
    pub detected_gamepads: u32,
    pub connected_gamepads: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MocktailRustInputDispatchResult {
    pub state: i32,
    pub kind: i32,
    pub status_code: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MocktailRustInputCallbacks {
    pub has_mouse_move: i32,
    pub has_mouse_button: i32,
    pub has_mouse_wheel: i32,
    pub has_touch: i32,
    pub has_key: i32,
    pub has_gamepad: i32,
    pub mouse_move: Option<unsafe extern "C" fn(ctx: *mut c_void, x: f32, y: f32, dx: f32, dy: f32) -> i32>,
    pub mouse_button: Option<unsafe extern "C" fn(ctx: *mut c_void, x: f32, y: f32, pressed: i32, button: i32) -> i32>,
    pub mouse_wheel: Option<unsafe extern "C" fn(ctx: *mut c_void, x: f32, y: f32, delta_y: f32) -> i32>,
    pub touch: Option<unsafe extern "C" fn(ctx: *mut c_void, pointer_id: i32, x: f32, y: f32, action: i32, w: i32, h: i32) -> i32>,
    pub key: Option<unsafe extern "C" fn(ctx: *mut c_void, pressed: i32, scan_code: i32, key_code: i32, repeat: i32) -> i32>,
    pub end_text_focus: Option<unsafe extern "C" fn(ctx: *mut c_void) -> i32>,
    pub gamepad_supported_key: Option<unsafe extern "C" fn(ctx: *mut c_void, device_id: i32, key: i32, supported: i32, gp_type: i32) -> i32>,
    pub gamepad_supported_motion: Option<unsafe extern "C" fn(ctx: *mut c_void, device_id: i32, axis: i32, direction: i32, supported: i32, gp_type: i32) -> i32>,
    pub gamepad_connect: Option<unsafe extern "C" fn(ctx: *mut c_void, device_id: i32, gp_type: i32) -> i32>,
    pub gamepad_disconnect: Option<unsafe extern "C" fn(ctx: *mut c_void, device_id: i32) -> i32>,
    pub gamepad_button: Option<unsafe extern "C" fn(ctx: *mut c_void, device_id: i32, key: i32, pressed: i32) -> i32>,
    pub gamepad_axis: Option<unsafe extern "C" fn(ctx: *mut c_void, device_id: i32, axis: i32, x: f32, y: f32, z: f32) -> i32>,
}

struct ActiveTouch {
    touch_id: i64,
    finger_id: i64,
    pointer_id: i32,
    x: f32,
    y: f32,
}

struct ActiveKey {
    sdl_scancode: u32,
    scan_code: i32,
    key_code: i32,
}

struct ActiveGamepad {
    instance_id: i64,
    device_id: i32,
    family: i32,
    buttons_mask: u32,
    axes_mask: u32,
    connected: bool,
    pressed_buttons: u32,
    raw_axes: [i16; 6],
    sent_axes: [f32; 6],
}

pub struct MocktailRustInputRouterState {
    active: bool,
    focused: bool,
    viewport: MocktailRustInputViewport,
    mouse_events: u64,
    touch_events: u64,
    keyboard_events: u64,
    ignored_text_events: u64,
    text_events: u64,
    native_errors: u64,
    gamepad_events: u64,
    connected_gamepads: u32,
    active_mouse_buttons: Vec<i32>,
    active_touches: Vec<ActiveTouch>,
    active_keys: Vec<ActiveKey>,
    gamepads: Vec<ActiveGamepad>,
    mouse_x: f32,
    mouse_y: f32,
}

#[inline]
fn has_bit(mask: u32, index: u8) -> bool {
    index < 32 && (mask & (1u32 << index)) != 0
}

#[inline]
fn clamp_finite(v: f32, hi: f32) -> f32 {
    if !v.is_finite() {
        return v;
    }
    let upper = if hi.is_finite() && hi > 0.0 { hi } else { 0.0 };
    v.clamp(0.0, upper)
}

#[inline]
fn stick_vector(raw_x: i16, raw_y: i16) -> [f32; 2] {
    let mut ox = 0.0f32;
    let mut oy = 0.0f32;
    mocktail_rust_gamepad_stick(raw_x, raw_y, &mut ox, &mut oy);
    [ox, oy]
}

fn keep_first_err(current_ok: &mut bool, call_rc: i32) {
    if call_rc != 0 && *current_ok {
        *current_ok = false;
    }
}

impl MocktailRustInputRouterState {
    fn new() -> Self {
        Self {
            active: false,
            focused: false,
            viewport: MocktailRustInputViewport::default(),
            mouse_events: 0,
            touch_events: 0,
            keyboard_events: 0,
            ignored_text_events: 0,
            text_events: 0,
            native_errors: 0,
            gamepad_events: 0,
            connected_gamepads: 0,
            active_mouse_buttons: Vec::new(),
            active_touches: Vec::new(),
            active_keys: Vec::new(),
            gamepads: Vec::new(),
            mouse_x: 0.0,
            mouse_y: 0.0,
        }
    }

    fn snapshot(&self) -> MocktailRustInputSnapshot {
        MocktailRustInputSnapshot {
            active: i32::from(self.active),
            focused: i32::from(self.focused),
            viewport: self.viewport,
            mouse_events: self.mouse_events,
            touch_events: self.touch_events,
            keyboard_events: self.keyboard_events,
            ignored_text_events: self.ignored_text_events,
            text_events: self.text_events,
            native_errors: self.native_errors,
            active_mouse_buttons: self.active_mouse_buttons.len() as u32,
            active_touches: self.active_touches.len() as u32,
            active_keys: self.active_keys.len() as u32,
            gamepad_events: self.gamepad_events,
            detected_gamepads: self.gamepads.len() as u32,
            connected_gamepads: self.connected_gamepads,
        }
    }

    fn allocate_pointer_id(&self) -> i32 {
        for candidate in 0..K_MAXIMUM_ANDROID_POINTERS {
            if !self.active_touches.iter().any(|t| t.pointer_id == candidate) {
                return candidate;
            }
        }
        -1
    }

    fn native_result(&mut self, call_ok: bool, kind: i32) -> MocktailRustInputDispatchResult {
        if !call_ok {
            self.native_errors += 1;
            return MocktailRustInputDispatchResult {
                state: DISPATCH_STATE_NATIVE_ERROR,
                kind,
                status_code: ERR_NATIVE_CALLBACK,
            };
        }
        match kind {
            EVENT_KIND_MOUSE_MOTION | EVENT_KIND_MOUSE_BUTTON | EVENT_KIND_MOUSE_WHEEL => {
                self.mouse_events += 1;
            }
            EVENT_KIND_TOUCH => {
                self.touch_events += 1;
            }
            EVENT_KIND_KEYBOARD => {
                self.keyboard_events += 1;
            }
            EVENT_KIND_GAMEPAD_BUTTON | EVENT_KIND_GAMEPAD_AXIS => {
                self.gamepad_events += 1;
            }
            _ => {}
        }
        MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_DISPATCHED,
            kind,
            status_code: ERR_NONE,
        }
    }

    fn configure_gamepad(
        gp: &ActiveGamepad,
        available: bool,
        cb: &MocktailRustInputCallbacks,
        cb_ctx: *mut c_void,
    ) -> bool {
        let gp_type = if available {
            mocktail_rust_roblox_gamepad_type(gp.family)
        } else {
            0
        };
        let mut all_ok = true;
        if let Some(supported_key) = cb.gamepad_supported_key {
            for &button in &K_BUTTONS {
                let android_key = mocktail_rust_gamepad_button_to_android(button);
                let supported = i32::from(available && has_bit(gp.buttons_mask, button));
                let rc = unsafe { supported_key(cb_ctx, gp.device_id, android_key, supported, gp_type) };
                keep_first_err(&mut all_ok, rc);
            }
        }
        if let Some(supported_motion) = cb.gamepad_supported_motion {
            for (axis_idx, &android_axis) in K_ANDROID_AXES.iter().enumerate() {
                let supported = i32::from(available && has_bit(gp.axes_mask, axis_idx as u8));
                let rc = unsafe { supported_motion(cb_ctx, gp.device_id, android_axis, -1, supported, gp_type) };
                keep_first_err(&mut all_ok, rc);
            }
            for &axis in &[22i32, 23, 15, 16] {
                let rc = unsafe { supported_motion(cb_ctx, gp.device_id, axis, -1, 0, gp_type) };
                keep_first_err(&mut all_ok, rc);
                if axis == 15 || axis == 16 {
                    let rc2 = unsafe { supported_motion(cb_ctx, gp.device_id, axis, 1, 0, gp_type) };
                    keep_first_err(&mut all_ok, rc2);
                }
            }
        }
        all_ok
    }

    fn connect_gamepad(
        gp: &mut ActiveGamepad,
        connected_count: &mut u32,
        cb: &MocktailRustInputCallbacks,
        cb_ctx: *mut c_void,
    ) -> bool {
        if gp.connected {
            return true;
        }
        let mut ok = Self::configure_gamepad(gp, true, cb, cb_ctx);
        let gp_type = mocktail_rust_roblox_gamepad_type(gp.family);
        if ok {
            if let Some(connect_fn) = cb.gamepad_connect {
                ok = unsafe { connect_fn(cb_ctx, gp.device_id, gp_type) } == 0;
            }
        }
        if !ok {
            let _ = Self::configure_gamepad(gp, false, cb, cb_ctx);
            if let Some(disc_fn) = cb.gamepad_disconnect {
                let _ = unsafe { disc_fn(cb_ctx, gp.device_id) };
            }
            return false;
        }
        gp.connected = true;
        *connected_count += 1;
        eprintln!(
            "  [gamepad] connected to Roblox: device={} type={}",
            gp.device_id, gp_type
        );
        true
    }

    fn dispatch_gamepad_axes(
        gp: &mut ActiveGamepad,
        connected_count: &mut u32,
        axis: u8,
        cb: &MocktailRustInputCallbacks,
        cb_ctx: *mut c_void,
    ) -> (bool, bool) {
        let first = if axis < 4 { axis & !1u8 } else { axis };
        let count = if axis < 4 { 2u8 } else { 1u8 };
        let stick = if axis < 4 {
            stick_vector(gp.raw_axes[first as usize], gp.raw_axes[first as usize + 1])
        } else {
            [mocktail_rust_gamepad_trigger(gp.raw_axes[axis as usize]), 0.0]
        };
        if gp.sent_axes[first as usize] == stick[0]
            && (count == 1 || gp.sent_axes[first as usize + 1] == stick[1])
        {
            return (true, false);
        }
        if !Self::connect_gamepad(gp, connected_count, cb, cb_ctx) {
            return (false, false);
        }
        let mut dispatched = false;
        if let Some(axis_fn) = cb.gamepad_axis {
            for index in first..(first + count) {
                if !has_bit(gp.axes_mask, index) {
                    continue;
                }
                let x = if count == 2 { stick[0] } else { 0.0 };
                let y = if count == 2 { stick[1] } else { 0.0 };
                let z = if count == 1 { stick[0] } else { 0.0 };
                if unsafe { axis_fn(cb_ctx, gp.device_id, K_ANDROID_AXES[index as usize], x, y, z) } != 0 {
                    return (false, dispatched);
                }
                dispatched = true;
            }
        }
        gp.sent_axes[first as usize] = stick[0];
        if count == 2 {
            gp.sent_axes[first as usize + 1] = stick[1];
        }
        (true, dispatched)
    }

    fn release_gamepad_inputs(
        gp: &mut ActiveGamepad,
        gamepad_events: &mut u64,
        connected_count: &mut u32,
        cb: &MocktailRustInputCallbacks,
        cb_ctx: *mut c_void,
    ) -> bool {
        let mut all_ok = true;
        if gp.connected {
            if let Some(button_fn) = cb.gamepad_button {
                for &button in &K_BUTTONS {
                    if has_bit(gp.pressed_buttons, button) {
                        let key = mocktail_rust_gamepad_button_to_android(button);
                        let rc = unsafe { button_fn(cb_ctx, gp.device_id, key, 0) };
                        if rc == 0 {
                            *gamepad_events += 1;
                        }
                        keep_first_err(&mut all_ok, rc);
                    }
                }
            }
            gp.raw_axes = [0; 6];
            for &axis in &[0u8, 2, 4, 5] {
                let (ok, dispatched) = Self::dispatch_gamepad_axes(gp, connected_count, axis, cb, cb_ctx);
                if ok && dispatched {
                    *gamepad_events += 1;
                }
                if !ok && all_ok {
                    all_ok = false;
                }
            }
        }
        gp.pressed_buttons = 0;
        gp.raw_axes = [0; 6];
        gp.sent_axes = [0.0; 6];
        all_ok
    }

    fn disconnect_gamepad(
        gp: &mut ActiveGamepad,
        gamepad_events: &mut u64,
        connected_count: &mut u32,
        cb: &MocktailRustInputCallbacks,
        cb_ctx: *mut c_void,
    ) -> bool {
        let mut all_ok = Self::release_gamepad_inputs(gp, gamepad_events, connected_count, cb, cb_ctx);
        if gp.connected {
            if !Self::configure_gamepad(gp, false, cb, cb_ctx) && all_ok {
                all_ok = false;
            }
            if let Some(disc_fn) = cb.gamepad_disconnect {
                let rc = unsafe { disc_fn(cb_ctx, gp.device_id) };
                keep_first_err(&mut all_ok, rc);
            }
            gp.connected = false;
            *connected_count = connected_count.saturating_sub(1);
            eprintln!("  [gamepad] disconnected from Roblox: device={}", gp.device_id);
        }
        all_ok
    }

    fn release_pressed_inputs(
        &mut self,
        cb: &MocktailRustInputCallbacks,
        cb_ctx: *mut c_void,
    ) -> bool {
        let mut all_ok = true;
        for gp in &mut self.gamepads {
            let ok = Self::release_gamepad_inputs(
                gp,
                &mut self.gamepad_events,
                &mut self.connected_gamepads,
                cb,
                cb_ctx,
            );
            if !ok && all_ok {
                all_ok = false;
            }
        }
        if let Some(mouse_button_fn) = cb.mouse_button {
            for &button in &self.active_mouse_buttons {
                let rc = unsafe { mouse_button_fn(cb_ctx, self.mouse_x, self.mouse_y, 0, button) };
                if rc == 0 {
                    self.mouse_events += 1;
                }
                keep_first_err(&mut all_ok, rc);
            }
        }
        self.active_mouse_buttons.clear();

        if let Some(touch_fn) = cb.touch {
            let gw = self.viewport.rounded_guest_width();
            let gh = self.viewport.rounded_guest_height();
            for t in &self.active_touches {
                let rc = unsafe { touch_fn(cb_ctx, t.pointer_id, t.x, t.y, K_ANDROID_TOUCH_UP, gw, gh) };
                if rc == 0 {
                    self.touch_events += 1;
                }
                keep_first_err(&mut all_ok, rc);
            }
        }
        self.active_touches.clear();

        if let Some(key_fn) = cb.key {
            for k in &self.active_keys {
                let rc = unsafe { key_fn(cb_ctx, 0, k.scan_code, k.key_code, 0) };
                if rc == 0 {
                    self.keyboard_events += 1;
                }
                keep_first_err(&mut all_ok, rc);
            }
        }
        self.active_keys.clear();
        all_ok
    }

    fn disconnect_gamepads(
        &mut self,
        cb: &MocktailRustInputCallbacks,
        cb_ctx: *mut c_void,
    ) -> bool {
        let mut all_ok = true;
        for gp in &mut self.gamepads {
            let ok = Self::disconnect_gamepad(
                gp,
                &mut self.gamepad_events,
                &mut self.connected_gamepads,
                cb,
                cb_ctx,
            );
            if !ok && all_ok {
                all_ok = false;
            }
        }
        self.gamepads.clear();
        all_ok
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_router_new() -> *mut MocktailRustInputRouterState {
    Box::into_raw(Box::new(MocktailRustInputRouterState::new()))
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_router_free(state: *mut MocktailRustInputRouterState) {
    if !state.is_null() {
        unsafe {
            drop(Box::from_raw(state));
        }
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_router_snapshot(
    state: *const MocktailRustInputRouterState,
    out_snapshot: *mut MocktailRustInputSnapshot,
) {
    if state.is_null() || out_snapshot.is_null() {
        return;
    }
    unsafe {
        *out_snapshot = (*state).snapshot();
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_router_is_active(
    state: *const MocktailRustInputRouterState,
) -> i32 {
    if state.is_null() {
        return 0;
    }
    i32::from(unsafe { (*state).active })
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_router_activate(
    state: *mut MocktailRustInputRouterState,
    viewport: MocktailRustInputViewport,
    initially_focused: i32,
    err_buf: *mut c_char,
    err_cap: usize,
) -> i32 {
    if state.is_null() {
        copy_error(err_buf, err_cap, "input router state is null");
        return ERR_INVALID_ARGUMENT;
    }
    let st = unsafe { &mut *state };
    if st.active {
        copy_error(err_buf, err_cap, "Roblox input router is already active");
        return ERR_FAILED_PRECONDITION;
    }
    if !viewport.valid() {
        copy_error(err_buf, err_cap, "input viewport dimensions must be positive");
        return ERR_INVALID_ARGUMENT;
    }
    *st = MocktailRustInputRouterState::new();
    st.active = true;
    st.focused = initially_focused != 0;
    st.viewport = viewport;
    ERR_NONE
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_router_deactivate(
    state: *mut MocktailRustInputRouterState,
    cb: *const MocktailRustInputCallbacks,
    cb_ctx: *mut c_void,
) -> i32 {
    if state.is_null() {
        return ERR_NONE;
    }
    let st = unsafe { &mut *state };
    if !st.active {
        return ERR_NONE;
    }
    let empty_cb = MocktailRustInputCallbacks::default();
    let callbacks = if cb.is_null() { &empty_cb } else { unsafe { &*cb } };
    let mut all_ok = st.release_pressed_inputs(callbacks, cb_ctx);
    if !st.disconnect_gamepads(callbacks, cb_ctx) && all_ok {
        all_ok = false;
    }
    if let Some(end_text) = callbacks.end_text_focus {
        let rc = unsafe { end_text(cb_ctx) };
        if rc != 0 && all_ok {
            all_ok = false;
        }
    }
    st.active = false;
    st.focused = false;
    st.active_mouse_buttons.clear();
    st.active_touches.clear();
    st.active_keys.clear();
    if all_ok {
        ERR_NONE
    } else {
        ERR_NATIVE_CALLBACK
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_router_prepare_routed_event(
    state: *mut MocktailRustInputRouterState,
) -> i32 {
    if state.is_null() {
        return 0;
    }
    let st = unsafe { &mut *state };
    if !st.active {
        return 0;
    }
    if !st.focused {
        st.focused = true;
    }
    1
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_router_record_text_result(
    state: *mut MocktailRustInputRouterState,
    handled: i32,
    dispatched: i32,
    failed: i32,
) -> MocktailRustInputDispatchResult {
    if state.is_null() {
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_INACTIVE,
            kind: EVENT_KIND_TEXT,
            status_code: ERR_NONE,
        };
    }
    let st = unsafe { &mut *state };
    if handled == 0 {
        st.ignored_text_events += 1;
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_UNSUPPORTED,
            kind: EVENT_KIND_TEXT,
            status_code: ERR_UNSUPPORTED,
        };
    }
    if failed != 0 {
        st.native_errors += 1;
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_NATIVE_ERROR,
            kind: EVENT_KIND_TEXT,
            status_code: ERR_NATIVE_CALLBACK,
        };
    }
    if dispatched != 0 {
        st.text_events += 1;
    }
    MocktailRustInputDispatchResult {
        state: if dispatched != 0 {
            DISPATCH_STATE_DISPATCHED
        } else {
            DISPATCH_STATE_STATE_UPDATED
        },
        kind: EVENT_KIND_TEXT,
        status_code: ERR_NONE,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_router_handle_viewport(
    state: *mut MocktailRustInputRouterState,
    viewport: MocktailRustInputViewport,
    err_buf: *mut c_char,
    err_cap: usize,
) -> MocktailRustInputDispatchResult {
    if state.is_null() || unsafe { !(*state).active } {
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_INACTIVE,
            kind: EVENT_KIND_NONE,
            status_code: ERR_NONE,
        };
    }
    if !viewport.valid() {
        copy_error(err_buf, err_cap, "resized input viewport is invalid");
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_REJECTED_INVALID,
            kind: EVENT_KIND_VIEWPORT,
            status_code: ERR_INVALID_ARGUMENT,
        };
    }
    unsafe {
        (*state).viewport = viewport;
    }
    MocktailRustInputDispatchResult {
        state: DISPATCH_STATE_STATE_UPDATED,
        kind: EVENT_KIND_VIEWPORT,
        status_code: ERR_NONE,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_router_handle_focus(
    state: *mut MocktailRustInputRouterState,
    focused: i32,
    cb: *const MocktailRustInputCallbacks,
    cb_ctx: *mut c_void,
) -> MocktailRustInputDispatchResult {
    if state.is_null() || unsafe { !(*state).active } {
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_INACTIVE,
            kind: EVENT_KIND_NONE,
            status_code: ERR_NONE,
        };
    }
    let st = unsafe { &mut *state };
    let want_focused = focused != 0;
    if !want_focused && st.focused {
        let empty_cb = MocktailRustInputCallbacks::default();
        let callbacks = if cb.is_null() { &empty_cb } else { unsafe { &*cb } };
        let mut all_ok = st.release_pressed_inputs(callbacks, cb_ctx);
        if let Some(end_text) = callbacks.end_text_focus {
            let rc = unsafe { end_text(cb_ctx) };
            if rc != 0 && all_ok {
                all_ok = false;
            }
        }
        st.focused = false;
        if !all_ok {
            st.native_errors += 1;
            return MocktailRustInputDispatchResult {
                state: DISPATCH_STATE_NATIVE_ERROR,
                kind: EVENT_KIND_FOCUS,
                status_code: ERR_NATIVE_CALLBACK,
            };
        }
    } else {
        st.focused = want_focused;
    }
    MocktailRustInputDispatchResult {
        state: DISPATCH_STATE_STATE_UPDATED,
        kind: EVENT_KIND_FOCUS,
        status_code: ERR_NONE,
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_router_handle_mouse_motion(
    state: *mut MocktailRustInputRouterState,
    x: f32,
    y: f32,
    delta_x: f32,
    delta_y: f32,
    relative_mode: i32,
    cb: *const MocktailRustInputCallbacks,
    cb_ctx: *mut c_void,
    err_buf: *mut c_char,
    err_cap: usize,
) -> MocktailRustInputDispatchResult {
    if mocktail_rust_input_router_prepare_routed_event(state) == 0 {
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_INACTIVE,
            kind: EVENT_KIND_NONE,
            status_code: ERR_NONE,
        };
    }
    let empty_cb = MocktailRustInputCallbacks::default();
    let callbacks = if cb.is_null() { &empty_cb } else { unsafe { &*cb } };
    let Some(mouse_move_cb) = callbacks.mouse_move.filter(|_| callbacks.has_mouse_move != 0) else {
        copy_error(err_buf, err_cap, "native mouse motion is unavailable");
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_UNSUPPORTED,
            kind: EVENT_KIND_MOUSE_MOTION,
            status_code: ERR_UNSUPPORTED,
        };
    };
    let st = unsafe { &mut *state };
    let dx = st.viewport.host_logical_to_guest_x(delta_x);
    let dy = st.viewport.host_logical_to_guest_y(delta_y);
    let rel = relative_mode != 0;
    if rel {
        st.mouse_x += dx;
        st.mouse_y += dy;
    } else {
        st.mouse_x = st.viewport.host_logical_to_guest_x(x);
        st.mouse_y = st.viewport.host_logical_to_guest_y(y);
    }
    let max_x = (st.viewport.guest_width() - 1.0).max(0.0);
    let max_y = (st.viewport.guest_height() - 1.0).max(0.0);
    let out_x = if rel { st.mouse_x } else { clamp_finite(st.mouse_x, max_x) };
    let out_y = if rel { st.mouse_y } else { clamp_finite(st.mouse_y, max_y) };
    let rc = unsafe { mouse_move_cb(cb_ctx, out_x, out_y, dx, dy) };
    st.native_result(rc == 0, EVENT_KIND_MOUSE_MOTION)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_router_handle_mouse_button(
    state: *mut MocktailRustInputRouterState,
    pressed: i32,
    sdl_button: u8,
    x: f32,
    y: f32,
    relative_mode: i32,
    cb: *const MocktailRustInputCallbacks,
    cb_ctx: *mut c_void,
    err_buf: *mut c_char,
    err_cap: usize,
) -> MocktailRustInputDispatchResult {
    if mocktail_rust_input_router_prepare_routed_event(state) == 0 {
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_INACTIVE,
            kind: EVENT_KIND_NONE,
            status_code: ERR_NONE,
        };
    }
    let empty_cb = MocktailRustInputCallbacks::default();
    let callbacks = if cb.is_null() { &empty_cb } else { unsafe { &*cb } };
    let Some(mouse_button_cb) = callbacks
        .mouse_button
        .filter(|_| callbacks.has_mouse_button != 0)
    else {
        copy_error(err_buf, err_cap, "native mouse buttons are unavailable");
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_UNSUPPORTED,
            kind: EVENT_KIND_MOUSE_BUTTON,
            status_code: ERR_UNSUPPORTED,
        };
    };
    let roblox_button = mocktail_rust_map_sdl_mouse_button(sdl_button);
    if roblox_button < 0 {
        copy_error(err_buf, err_cap, "SDL mouse button has no Roblox mapping");
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_UNSUPPORTED,
            kind: EVENT_KIND_MOUSE_BUTTON,
            status_code: ERR_UNSUPPORTED,
        };
    }
    let st = unsafe { &mut *state };
    if relative_mode == 0 {
        st.mouse_x = st.viewport.host_logical_to_guest_x(x);
        st.mouse_y = st.viewport.host_logical_to_guest_y(y);
    }
    let max_x = (st.viewport.guest_width() - 1.0).max(0.0);
    let max_y = (st.viewport.guest_height() - 1.0).max(0.0);
    let clamped_x = clamp_finite(st.mouse_x, max_x);
    let clamped_y = clamp_finite(st.mouse_y, max_y);
    let is_pressed = pressed != 0;
    let rc = unsafe { mouse_button_cb(cb_ctx, clamped_x, clamped_y, pressed, roblox_button) };
    if rc == 0 {
        let pos = st.active_mouse_buttons.iter().position(|&b| b == roblox_button);
        if is_pressed && pos.is_none() {
            st.active_mouse_buttons.push(roblox_button);
        } else if !is_pressed {
            if let Some(idx) = pos {
                st.active_mouse_buttons.remove(idx);
            }
        }
    }
    st.native_result(rc == 0, EVENT_KIND_MOUSE_BUTTON)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_router_handle_mouse_wheel(
    state: *mut MocktailRustInputRouterState,
    delta_y: f32,
    mouse_x: f32,
    mouse_y: f32,
    relative_mode: i32,
    cb: *const MocktailRustInputCallbacks,
    cb_ctx: *mut c_void,
    err_buf: *mut c_char,
    err_cap: usize,
) -> MocktailRustInputDispatchResult {
    if mocktail_rust_input_router_prepare_routed_event(state) == 0 {
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_INACTIVE,
            kind: EVENT_KIND_NONE,
            status_code: ERR_NONE,
        };
    }
    let empty_cb = MocktailRustInputCallbacks::default();
    let callbacks = if cb.is_null() { &empty_cb } else { unsafe { &*cb } };
    let Some(mouse_wheel_cb) = callbacks
        .mouse_wheel
        .filter(|_| callbacks.has_mouse_wheel != 0 && delta_y != 0.0)
    else {
        copy_error(err_buf, err_cap, "vertical native mouse wheel is unavailable");
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_UNSUPPORTED,
            kind: EVENT_KIND_MOUSE_WHEEL,
            status_code: ERR_UNSUPPORTED,
        };
    };
    let st = unsafe { &mut *state };
    if relative_mode == 0 {
        st.mouse_x = st.viewport.host_logical_to_guest_x(mouse_x.max(0.0));
        st.mouse_y = st.viewport.host_logical_to_guest_y(mouse_y.max(0.0));
    }
    let rc = unsafe {
        mouse_wheel_cb(cb_ctx, st.mouse_x.max(0.0), st.mouse_y.max(0.0), delta_y)
    };
    st.native_result(rc == 0, EVENT_KIND_MOUSE_WHEEL)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_router_handle_touch(
    state: *mut MocktailRustInputRouterState,
    action_kind: i32, // 0=kDown, 1=kMove, 2=kUp, 3=kCancelled
    touch_id: i64,
    finger_id: i64,
    norm_x: f32,
    norm_y: f32,
    cb: *const MocktailRustInputCallbacks,
    cb_ctx: *mut c_void,
    err_buf: *mut c_char,
    err_cap: usize,
) -> MocktailRustInputDispatchResult {
    if mocktail_rust_input_router_prepare_routed_event(state) == 0 {
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_INACTIVE,
            kind: EVENT_KIND_NONE,
            status_code: ERR_NONE,
        };
    }
    let empty_cb = MocktailRustInputCallbacks::default();
    let callbacks = if cb.is_null() { &empty_cb } else { unsafe { &*cb } };
    let Some(touch_cb) = callbacks.touch.filter(|_| callbacks.has_touch != 0) else {
        copy_error(err_buf, err_cap, "native touch input is unavailable");
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_UNSUPPORTED,
            kind: EVENT_KIND_TOUCH,
            status_code: ERR_UNSUPPORTED,
        };
    };
    let st = unsafe { &mut *state };
    let gw = st.viewport.rounded_guest_width();
    let gh = st.viewport.rounded_guest_height();
    let x = clamp_finite(norm_x, 1.0) * (gw as f32);
    let y = clamp_finite(norm_y, 1.0) * (gh as f32);

    let active_idx = st
        .active_touches
        .iter()
        .position(|t| t.touch_id == touch_id && t.finger_id == finger_id);

    let (android_action, pointer_id) = if action_kind == 0 {
        if active_idx.is_some() {
            copy_error(err_buf, err_cap, "duplicate touch down was rejected");
            return MocktailRustInputDispatchResult {
                state: DISPATCH_STATE_REJECTED_INVALID,
                kind: EVENT_KIND_TOUCH,
                status_code: ERR_INVALID_ARGUMENT,
            };
        }
        let pid = st.allocate_pointer_id();
        if pid < 0 {
            copy_error(err_buf, err_cap, "Android pointer limit was reached");
            return MocktailRustInputDispatchResult {
                state: DISPATCH_STATE_REJECTED_INVALID,
                kind: EVENT_KIND_TOUCH,
                status_code: ERR_INVALID_ARGUMENT,
            };
        }
        (K_ANDROID_TOUCH_DOWN, pid)
    } else {
        let idx = match active_idx {
            Some(i) => i,
            None => {
                copy_error(err_buf, err_cap, "touch event has no active pointer");
                return MocktailRustInputDispatchResult {
                    state: DISPATCH_STATE_REJECTED_INVALID,
                    kind: EVENT_KIND_TOUCH,
                    status_code: ERR_INVALID_ARGUMENT,
                };
            }
        };
        let act = if action_kind == 1 {
            K_ANDROID_TOUCH_MOVE
        } else {
            K_ANDROID_TOUCH_UP
        };
        (act, st.active_touches[idx].pointer_id)
    };

    let rc = unsafe { touch_cb(cb_ctx, pointer_id, x, y, android_action, gw, gh) };
    if action_kind == 0 && rc == 0 {
        st.active_touches.push(ActiveTouch {
            touch_id,
            finger_id,
            pointer_id,
            x,
            y,
        });
    } else if let Some(idx) = active_idx {
        if action_kind == 1 {
            if rc == 0 {
                st.active_touches[idx].x = x;
                st.active_touches[idx].y = y;
            }
        } else {
            st.active_touches.remove(idx);
        }
    }
    st.native_result(rc == 0, EVENT_KIND_TOUCH)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_router_handle_key(
    state: *mut MocktailRustInputRouterState,
    pressed: i32,
    repeat: i32,
    scancode: u32,
    keycode: u32,
    cb: *const MocktailRustInputCallbacks,
    cb_ctx: *mut c_void,
    err_buf: *mut c_char,
    err_cap: usize,
) -> MocktailRustInputDispatchResult {
    if mocktail_rust_input_router_prepare_routed_event(state) == 0 {
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_INACTIVE,
            kind: EVENT_KIND_NONE,
            status_code: ERR_NONE,
        };
    }
    let empty_cb = MocktailRustInputCallbacks::default();
    let callbacks = if cb.is_null() { &empty_cb } else { unsafe { &*cb } };
    let Some(key_cb) = callbacks.key.filter(|_| callbacks.has_key != 0) else {
        copy_error(err_buf, err_cap, "native hardware keyboard is unavailable");
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_UNSUPPORTED,
            kind: EVENT_KIND_KEYBOARD,
            status_code: ERR_UNSUPPORTED,
        };
    };
    let mut mapping = MocktailRustKeyMapping {
        scan_code: 0,
        key_code: 0,
    };
    if mocktail_rust_map_sdl_key_to_android(scancode, keycode, &mut mapping) != 1
        || mapping.scan_code <= 0
        || mapping.key_code <= 0
    {
        copy_error(err_buf, err_cap, "SDL key has no Android mapping");
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_UNSUPPORTED,
            kind: EVENT_KIND_KEYBOARD,
            status_code: ERR_UNSUPPORTED,
        };
    }
    let st = unsafe { &mut *state };
    let rc = unsafe { key_cb(cb_ctx, pressed, mapping.scan_code, mapping.key_code, repeat) };
    if rc == 0 {
        let pos = st.active_keys.iter().position(|k| k.sdl_scancode == scancode);
        if pressed != 0 && pos.is_none() {
            st.active_keys.push(ActiveKey {
                sdl_scancode: scancode,
                scan_code: mapping.scan_code,
                key_code: mapping.key_code,
            });
        } else if pressed == 0 {
            if let Some(idx) = pos {
                st.active_keys.remove(idx);
            }
        }
    }
    st.native_result(rc == 0, EVENT_KIND_KEYBOARD)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_router_handle_gamepad_connection(
    state: *mut MocktailRustInputRouterState,
    instance_id: i64,
    connected: i32,
    remapped: i32,
    family: i32,
    name: *const c_char,
    buttons_mask: u32,
    axes_mask: u32,
    cb: *const MocktailRustInputCallbacks,
    cb_ctx: *mut c_void,
    err_buf: *mut c_char,
    err_cap: usize,
) -> MocktailRustInputDispatchResult {
    if state.is_null() || unsafe { !(*state).active } {
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_INACTIVE,
            kind: EVENT_KIND_NONE,
            status_code: ERR_NONE,
        };
    }
    let empty_cb = MocktailRustInputCallbacks::default();
    let callbacks = if cb.is_null() { &empty_cb } else { unsafe { &*cb } };
    if callbacks.has_gamepad == 0 {
        copy_error(err_buf, err_cap, "Roblox gamepad export table is incomplete");
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_UNSUPPORTED,
            kind: EVENT_KIND_GAMEPAD_CONNECTION,
            status_code: ERR_UNSUPPORTED,
        };
    }
    if instance_id <= 0 {
        copy_error(err_buf, err_cap, "invalid gamepad ID");
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_REJECTED_INVALID,
            kind: EVENT_KIND_GAMEPAD_CONNECTION,
            status_code: ERR_INVALID_ARGUMENT,
        };
    }
    let st = unsafe { &mut *state };
    let mut disconnect_ok = true;
    if let Some(idx) = st.gamepads.iter().position(|g| g.instance_id == instance_id) {
        if connected != 0 && remapped == 0 {
            return MocktailRustInputDispatchResult {
                state: DISPATCH_STATE_STATE_UPDATED,
                kind: EVENT_KIND_GAMEPAD_CONNECTION,
                status_code: ERR_NONE,
            };
        }
        disconnect_ok = MocktailRustInputRouterState::disconnect_gamepad(
            &mut st.gamepads[idx],
            &mut st.gamepad_events,
            &mut st.connected_gamepads,
            callbacks,
            cb_ctx,
        );
        st.gamepads.remove(idx);
    }

    if connected != 0 {
        let mut device_id = 1i32;
        while st.gamepads.iter().any(|g| g.device_id == device_id) {
            if device_id == i32::MAX {
                copy_error(err_buf, err_cap, "Roblox gamepad device IDs exhausted");
                return MocktailRustInputDispatchResult {
                    state: DISPATCH_STATE_REJECTED_INVALID,
                    kind: EVENT_KIND_GAMEPAD_CONNECTION,
                    status_code: ERR_UNAVAILABLE,
                };
            }
            device_id += 1;
        }
        st.gamepads.push(ActiveGamepad {
            instance_id,
            device_id,
            family,
            buttons_mask,
            axes_mask,
            connected: false,
            pressed_buttons: 0,
            raw_axes: [0; 6],
            sent_axes: [0.0; 6],
        });
        let name_str = if name.is_null() {
            ""
        } else {
            unsafe { CStr::from_ptr(name) }.to_str().unwrap_or("")
        };
        let gp_type = mocktail_rust_roblox_gamepad_type(family);
        let mut trunc_end = name_str.len().min(160);
        while trunc_end > 0 && !name_str.is_char_boundary(trunc_end) {
            trunc_end -= 1;
        }
        eprintln!(
            "  [gamepad] detected SDL device {}: {} (type={}); ready for input",
            instance_id,
            &name_str[..trunc_end],
            gp_type
        );
    }

    if disconnect_ok {
        MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_STATE_UPDATED,
            kind: EVENT_KIND_GAMEPAD_CONNECTION,
            status_code: ERR_NONE,
        }
    } else {
        st.native_result(false, EVENT_KIND_GAMEPAD_CONNECTION)
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_router_handle_gamepad_button(
    state: *mut MocktailRustInputRouterState,
    instance_id: i64,
    button: u8,
    pressed: i32,
    cb: *const MocktailRustInputCallbacks,
    cb_ctx: *mut c_void,
    err_buf: *mut c_char,
    err_cap: usize,
) -> MocktailRustInputDispatchResult {
    if state.is_null() || unsafe { !(*state).active } {
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_INACTIVE,
            kind: EVENT_KIND_NONE,
            status_code: ERR_NONE,
        };
    }
    let st = unsafe { &mut *state };
    let empty_cb = MocktailRustInputCallbacks::default();
    let callbacks = if cb.is_null() { &empty_cb } else { unsafe { &*cb } };
    let found_idx = st.gamepads.iter().position(|g| g.instance_id == instance_id);
    let Some(gp_button_cb) = callbacks
        .gamepad_button
        .filter(|_| callbacks.has_gamepad != 0)
    else {
        copy_error(err_buf, err_cap, "gamepad is not available");
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_UNSUPPORTED,
            kind: EVENT_KIND_GAMEPAD_BUTTON,
            status_code: ERR_UNSUPPORTED,
        };
    };
    let Some(idx) = found_idx else {
        copy_error(err_buf, err_cap, "gamepad is not available");
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_UNSUPPORTED,
            kind: EVENT_KIND_GAMEPAD_BUTTON,
            status_code: ERR_UNSUPPORTED,
        };
    };
    if !st.focused {
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_UNFOCUSED,
            kind: EVENT_KIND_GAMEPAD_BUTTON,
            status_code: ERR_NONE,
        };
    }
    let key = mocktail_rust_gamepad_button_to_android(button);
    if key < 0 || !has_bit(st.gamepads[idx].buttons_mask, button) {
        copy_error(err_buf, err_cap, "gamepad button is not supported");
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_UNSUPPORTED,
            kind: EVENT_KIND_GAMEPAD_BUTTON,
            status_code: ERR_UNSUPPORTED,
        };
    }
    let is_pressed = pressed != 0;
    if has_bit(st.gamepads[idx].pressed_buttons, button) == is_pressed {
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_STATE_UPDATED,
            kind: EVENT_KIND_GAMEPAD_BUTTON,
            status_code: ERR_NONE,
        };
    }
    let mut ok = MocktailRustInputRouterState::connect_gamepad(
        &mut st.gamepads[idx],
        &mut st.connected_gamepads,
        callbacks,
        cb_ctx,
    );
    if ok {
        let dev_id = st.gamepads[idx].device_id;
        ok = unsafe { gp_button_cb(cb_ctx, dev_id, key, pressed) } == 0;
    }
    if ok {
        if let Some(mask) = 1u32.checked_shl(u32::from(button)) {
            if is_pressed {
                st.gamepads[idx].pressed_buttons |= mask;
            } else {
                st.gamepads[idx].pressed_buttons &= !mask;
            }
        }
    }
    st.native_result(ok, EVENT_KIND_GAMEPAD_BUTTON)
}

#[no_mangle]
pub extern "C" fn mocktail_rust_input_router_handle_gamepad_axis(
    state: *mut MocktailRustInputRouterState,
    instance_id: i64,
    axis: u8,
    value: i16,
    cb: *const MocktailRustInputCallbacks,
    cb_ctx: *mut c_void,
    err_buf: *mut c_char,
    err_cap: usize,
) -> MocktailRustInputDispatchResult {
    if state.is_null() || unsafe { !(*state).active } {
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_INACTIVE,
            kind: EVENT_KIND_NONE,
            status_code: ERR_NONE,
        };
    }
    let st = unsafe { &mut *state };
    let empty_cb = MocktailRustInputCallbacks::default();
    let callbacks = if cb.is_null() { &empty_cb } else { unsafe { &*cb } };
    let found_idx = st.gamepads.iter().position(|g| g.instance_id == instance_id);
    if callbacks.has_gamepad == 0 || callbacks.gamepad_axis.is_none() {
        copy_error(err_buf, err_cap, "gamepad is not available");
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_UNSUPPORTED,
            kind: EVENT_KIND_GAMEPAD_AXIS,
            status_code: ERR_UNSUPPORTED,
        };
    }
    let Some(idx) = found_idx else {
        copy_error(err_buf, err_cap, "gamepad is not available");
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_UNSUPPORTED,
            kind: EVENT_KIND_GAMEPAD_AXIS,
            status_code: ERR_UNSUPPORTED,
        };
    };
    if !st.focused {
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_UNFOCUSED,
            kind: EVENT_KIND_GAMEPAD_AXIS,
            status_code: ERR_NONE,
        };
    }
    if (axis as usize) >= K_ANDROID_AXES.len() || !has_bit(st.gamepads[idx].axes_mask, axis) {
        copy_error(err_buf, err_cap, "gamepad axis is not supported");
        return MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_IGNORED_UNSUPPORTED,
            kind: EVENT_KIND_GAMEPAD_AXIS,
            status_code: ERR_UNSUPPORTED,
        };
    }
    st.gamepads[idx].raw_axes[axis as usize] = value;
    let (ok, dispatched) = MocktailRustInputRouterState::dispatch_gamepad_axes(
        &mut st.gamepads[idx],
        &mut st.connected_gamepads,
        axis,
        callbacks,
        cb_ctx,
    );
    if ok && !dispatched {
        MocktailRustInputDispatchResult {
            state: DISPATCH_STATE_STATE_UPDATED,
            kind: EVENT_KIND_GAMEPAD_AXIS,
            status_code: ERR_NONE,
        }
    } else {
        st.native_result(ok, EVENT_KIND_GAMEPAD_AXIS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct TestSink {
        log: Vec<String>,
        fail_next_connect: bool,
    }

    unsafe extern "C" fn on_mouse_move(ctx: *mut c_void, x: f32, y: f32, dx: f32, dy: f32) -> i32 {
        let s = &mut *(ctx as *mut TestSink);
        s.log.push(format!("mm:{x:.1},{y:.1},{dx:.1},{dy:.1}"));
        0
    }
    unsafe extern "C" fn on_mouse_button(ctx: *mut c_void, x: f32, y: f32, pressed: i32, btn: i32) -> i32 {
        let s = &mut *(ctx as *mut TestSink);
        s.log.push(format!("mb:{x:.1},{y:.1},{pressed},{btn}"));
        0
    }
    unsafe extern "C" fn on_touch(ctx: *mut c_void, pid: i32, x: f32, y: f32, act: i32, w: i32, h: i32) -> i32 {
        let s = &mut *(ctx as *mut TestSink);
        s.log.push(format!("touch:{pid},{x:.0},{y:.0},{act},{w}x{h}"));
        0
    }
    unsafe extern "C" fn on_gp_sup_key(_: *mut c_void, _: i32, _: i32, _: i32, _: i32) -> i32 { 0 }
    unsafe extern "C" fn on_gp_sup_motion(_: *mut c_void, _: i32, _: i32, _: i32, _: i32, _: i32) -> i32 { 0 }
    unsafe extern "C" fn on_gp_connect(ctx: *mut c_void, dev: i32, gp_type: i32) -> i32 {
        let s = &mut *(ctx as *mut TestSink);
        s.log.push(format!("gp_conn:{dev},{gp_type}"));
        if s.fail_next_connect {
            s.fail_next_connect = false;
            return -1;
        }
        0
    }
    unsafe extern "C" fn on_gp_disconnect(ctx: *mut c_void, dev: i32) -> i32 {
        let s = &mut *(ctx as *mut TestSink);
        s.log.push(format!("gp_disc:{dev}"));
        0
    }
    unsafe extern "C" fn on_gp_button(ctx: *mut c_void, dev: i32, key: i32, pressed: i32) -> i32 {
        let s = &mut *(ctx as *mut TestSink);
        s.log.push(format!("gp_btn:{dev},{key},{pressed}"));
        0
    }
    unsafe extern "C" fn on_gp_axis(ctx: *mut c_void, dev: i32, ax: i32, x: f32, y: f32, z: f32) -> i32 {
        let s = &mut *(ctx as *mut TestSink);
        s.log.push(format!("gp_ax:{dev},{ax},{x:.2},{y:.2},{z:.2}"));
        0
    }

    fn test_callbacks() -> MocktailRustInputCallbacks {
        MocktailRustInputCallbacks {
            has_mouse_move: 1,
            has_mouse_button: 1,
            has_mouse_wheel: 1,
            has_touch: 1,
            has_key: 1,
            has_gamepad: 1,
            mouse_move: Some(on_mouse_move),
            mouse_button: Some(on_mouse_button),
            mouse_wheel: None,
            touch: Some(on_touch),
            key: None,
            end_text_focus: None,
            gamepad_supported_key: Some(on_gp_sup_key),
            gamepad_supported_motion: Some(on_gp_sup_motion),
            gamepad_connect: Some(on_gp_connect),
            gamepad_disconnect: Some(on_gp_disconnect),
            gamepad_button: Some(on_gp_button),
            gamepad_axis: Some(on_gp_axis),
        }
    }

    #[test]
    fn mouse_touch_focus_loss_and_gamepad_lifecycle() {
        let st = mocktail_rust_input_router_new();
        let mut sink = TestSink::default();
        let cb = test_callbacks();
        let sink_ptr = &mut sink as *mut _ as *mut c_void;
        let mut err = [0i8; 256];

        let vp = MocktailRustInputViewport {
            logical_width: 1280,
            logical_height: 720,
            pixel_width: 1280,
            pixel_height: 720,
            density_scale: 1.0,
        };
        assert_eq!(mocktail_rust_input_router_activate(st, vp, 1, err.as_mut_ptr(), err.len()), ERR_NONE);

        // Touch down allocates pointer 0, focus loss sends touch up + mouse button up.
        let r_mb = mocktail_rust_input_router_handle_mouse_button(st, 1, 1, 100.0, 200.0, 0, &cb, sink_ptr, err.as_mut_ptr(), err.len());
        assert_eq!(r_mb.state, DISPATCH_STATE_DISPATCHED);
        let r_td = mocktail_rust_input_router_handle_touch(st, 0, 1, 5, 0.5, 0.5, &cb, sink_ptr, err.as_mut_ptr(), err.len());
        assert_eq!(r_td.state, DISPATCH_STATE_DISPATCHED);

        // Failed gamepad connect rolls back cleanly without incrementing connected_gamepads.
        let r_gc = mocktail_rust_input_router_handle_gamepad_connection(
            st, 42, 1, 0, 1, std::ptr::null(), (1 << 15) - 1, (1 << 6) - 1,
            &cb, sink_ptr, err.as_mut_ptr(), err.len(),
        );
        assert_eq!(r_gc.state, DISPATCH_STATE_STATE_UPDATED);

        sink.fail_next_connect = true;
        let r_gb_fail = mocktail_rust_input_router_handle_gamepad_button(
            st, 42, K_SDL_GAMEPAD_BUTTON_SOUTH, 1, &cb, sink_ptr, err.as_mut_ptr(), err.len(),
        );
        assert_eq!(r_gb_fail.state, DISPATCH_STATE_NATIVE_ERROR);
        let mut snap = MocktailRustInputSnapshot::default();
        mocktail_rust_input_router_snapshot(st, &mut snap);
        assert_eq!(snap.connected_gamepads, 0);
        assert_eq!(snap.native_errors, 1);

        // Retry succeeds!
        let r_gb_ok = mocktail_rust_input_router_handle_gamepad_button(
            st, 42, K_SDL_GAMEPAD_BUTTON_SOUTH, 1, &cb, sink_ptr, err.as_mut_ptr(), err.len(),
        );
        assert_eq!(r_gb_ok.state, DISPATCH_STATE_DISPATCHED);
        mocktail_rust_input_router_snapshot(st, &mut snap);
        assert_eq!(snap.connected_gamepads, 1);

        // Focus loss releases gamepad button, mouse button, and touch pointer.
        let r_fl = mocktail_rust_input_router_handle_focus(st, 0, &cb, sink_ptr);
        assert_eq!(r_fl.state, DISPATCH_STATE_STATE_UPDATED);
        mocktail_rust_input_router_snapshot(st, &mut snap);
        assert_eq!(snap.focused, 0);
        assert_eq!(snap.active_mouse_buttons, 0);
        assert_eq!(snap.active_touches, 0);
        assert!(sink.log.iter().any(|l| l == "gp_btn:1,96,0"));
        assert!(sink.log.iter().any(|l| l.starts_with("touch:0,")));

        assert_eq!(mocktail_rust_input_router_deactivate(st, &cb, sink_ptr), ERR_NONE);
        assert!(sink.log.iter().any(|l| l == "gp_disc:1"));
        mocktail_rust_input_router_free(st);
    }

    #[test]
    fn test_missing_callbacks_and_oob_button_do_not_panic() {
        let st = mocktail_rust_input_router_new();
        let mut err = [0i8; 256];
        let vp = MocktailRustInputViewport {
            logical_width: 800,
            logical_height: 600,
            pixel_width: 800,
            pixel_height: 600,
            density_scale: 1.0,
        };
        assert_eq!(mocktail_rust_input_router_activate(st, vp, 1, err.as_mut_ptr(), err.len()), ERR_NONE);

        let r_mm = mocktail_rust_input_router_handle_mouse_motion(
            st, 10.0, 20.0, 1.0, 2.0, 0, std::ptr::null(), std::ptr::null_mut(), err.as_mut_ptr(), err.len(),
        );
        assert_eq!(r_mm.state, DISPATCH_STATE_IGNORED_UNSUPPORTED);

        let partial_cb = MocktailRustInputCallbacks {
            has_gamepad: 1,
            gamepad_button: Some(on_gp_button),
            ..MocktailRustInputCallbacks::default()
        };
        let r_gc = mocktail_rust_input_router_handle_gamepad_connection(
            st, 7, 1, 0, 1, std::ptr::null(), u32::MAX, 0,
            &partial_cb, std::ptr::null_mut(), err.as_mut_ptr(), err.len(),
        );
        assert_eq!(r_gc.state, DISPATCH_STATE_STATE_UPDATED);

        let r_oob = mocktail_rust_input_router_handle_gamepad_button(
            st, 7, 250, 1, &partial_cb, std::ptr::null_mut(), err.as_mut_ptr(), err.len(),
        );
        assert_eq!(r_oob.state, DISPATCH_STATE_IGNORED_UNSUPPORTED);

        mocktail_rust_input_router_free(st);
    }
}
