//! Pure-Rust GLES 3.x interceptor, per-context state cache, lifecycle telemetry,
//! and test stub runtime backing `libGLESv2.so`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::OnceLock;

use crate::dl::{
    dlsym_cstr, dlsym_default, env_flag_enabled, env_flag_enabled_default_true,
    host_egl_handle, host_gles_handle,
};

pub type GLenum = u32;
pub type GLboolean = u8;
pub type GLbitfield = u32;
pub type GLint = i32;
pub type GLsizei = i32;
pub type GLuint = u32;
pub type GLfloat = f32;
pub type GLchar = c_char;
pub type GLintptr = isize;
pub type GLsizeiptr = isize;
pub type GLuint64 = u64;
pub type GLsync = *mut c_void;

pub const GL_NO_ERROR: GLenum = 0;
pub const GL_INVALID_VALUE: GLenum = 0x0501;
pub const GL_INVALID_OPERATION: GLenum = 0x0502;
pub const GL_OUT_OF_MEMORY: GLenum = 0x0505;

pub const GL_VENDOR: GLenum = 0x1F00;
pub const GL_RENDERER: GLenum = 0x1F01;
pub const GL_VERSION: GLenum = 0x1F02;
pub const GL_EXTENSIONS: GLenum = 0x1F03;
pub const GL_SHADING_LANGUAGE_VERSION: GLenum = 0x8B8C;

pub const GL_MAX_TEXTURE_SIZE: GLenum = 0x0D33;
pub const GL_MAX_VIEWPORT_DIMS: GLenum = 0x0D3A;
pub const GL_VIEWPORT: GLenum = 0x0BA2;
pub const GL_SCISSOR_BOX: GLenum = 0x0C10;
pub const GL_UNPACK_ALIGNMENT: GLenum = 0x0CF5;
pub const GL_PACK_ALIGNMENT: GLenum = 0x0D05;
pub const GL_MAX_COMBINED_TEXTURE_IMAGE_UNITS: GLenum = 0x8B4D;
pub const GL_NUM_COMPRESSED_TEXTURE_FORMATS: GLenum = 0x86A2;
pub const GL_COMPRESSED_TEXTURE_FORMATS: GLenum = 0x86A3;
pub const GL_NUM_EXTENSIONS: GLenum = 0x821D;
pub const GL_MAX_COLOR_ATTACHMENTS: GLenum = 0x8CDF;

pub const GL_FRAMEBUFFER: GLenum = 0x8D40;
pub const GL_READ_FRAMEBUFFER: GLenum = 0x8CA8;
pub const GL_DRAW_FRAMEBUFFER: GLenum = 0x8CA9;
pub const GL_RENDERBUFFER: GLenum = 0x8D41;
pub const GL_FRAMEBUFFER_COMPLETE: GLenum = 0x8CD5;
pub const GL_FRAMEBUFFER_UNSUPPORTED: GLenum = 0x8CDD;

pub const GL_COMPILE_STATUS: GLenum = 0x8B81;
pub const GL_LINK_STATUS: GLenum = 0x8B82;
pub const GL_VALIDATE_STATUS: GLenum = 0x8B83;
pub const GL_INFO_LOG_LENGTH: GLenum = 0x8B84;
pub const GL_ACTIVE_UNIFORMS: GLenum = 0x8B86;
pub const GL_ACTIVE_UNIFORM_MAX_LENGTH: GLenum = 0x8B87;
pub const GL_ACTIVE_ATTRIBUTES: GLenum = 0x8B89;
pub const GL_ACTIVE_ATTRIBUTE_MAX_LENGTH: GLenum = 0x8B8A;
pub const GL_FLOAT_MAT4: GLenum = 0x8B5C;

pub const GL_ARRAY_BUFFER: GLenum = 0x8892;
pub const GL_ELEMENT_ARRAY_BUFFER: GLenum = 0x8893;
pub const GL_PIXEL_PACK_BUFFER: GLenum = 0x88EB;
pub const GL_PIXEL_UNPACK_BUFFER: GLenum = 0x88EC;
pub const GL_UNIFORM_BUFFER: GLenum = 0x8A11;
pub const GL_TRANSFORM_FEEDBACK_BUFFER: GLenum = 0x8C8E;
pub const GL_COPY_READ_BUFFER: GLenum = 0x8F36;
pub const GL_COPY_WRITE_BUFFER: GLenum = 0x8F37;
pub const GL_SHADER_STORAGE_BUFFER: GLenum = 0x90D2;

pub const GL_TEXTURE0: GLenum = 0x84C0;
pub const GL_TEXTURE_2D: GLenum = 0x0DE1;
pub const GL_TEXTURE_CUBE_MAP: GLenum = 0x8513;
pub const GL_TEXTURE_3D: GLenum = 0x806F;
pub const GL_TEXTURE_2D_ARRAY: GLenum = 0x8C1A;
pub const GL_TEXTURE_EXTERNAL_OES: GLenum = 0x8D65;

const CAP_BLEND: u32 = 1 << 0;
const CAP_CULL_FACE: u32 = 1 << 1;
const CAP_DEPTH_TEST: u32 = 1 << 2;
const CAP_SCISSOR_TEST: u32 = 1 << 3;
const CAP_STENCIL_TEST: u32 = 1 << 4;
const CAP_DITHER: u32 = 1 << 5;
const CAP_POLYGON_OFFSET_FILL: u32 = 1 << 6;
const CAP_SAMPLE_ALPHA_TO_COVERAGE: u32 = 1 << 7;
const CAP_SAMPLE_COVERAGE: u32 = 1 << 8;

const MAX_TEX_UNITS: usize = 32;
const MAX_CACHED_UBO_SLOTS: usize = 16;
const MAX_CACHED_SSBO_SLOTS: usize = 4;
const MAX_CACHED_VERTEX_ATTRIBS: usize = 16;
const MAX_CACHED_UNIFORM1I_SLOTS: usize = 64;
const MAX_CACHED_TEX_PARAM_SLOTS: usize = 64;
const MAX_CACHED_UNIFORM_LOC_ENTRIES: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VertexAttribPointerState {
    pub buffer: GLuint,
    pub size: GLint,
    pub typ: GLenum,
    pub normalized: bool,
    pub stride: GLsizei,
    pub pointer: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CachedUniform1i {
    program: GLuint,
    location: GLint,
    value: GLint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CachedTexParam {
    target: GLenum,
    texture: GLuint,
    pname: GLenum,
    value: GLint,
}

fn is_cacheable_tex_param_i(pname: GLenum) -> bool {
    matches!(
        pname,
        0x2800 // GL_TEXTURE_MAG_FILTER
        | 0x2801 // GL_TEXTURE_MIN_FILTER
        | 0x2802 // GL_TEXTURE_WRAP_S
        | 0x2803 // GL_TEXTURE_WRAP_T
        | 0x8072 // GL_TEXTURE_WRAP_R
        | 0x813C // GL_TEXTURE_BASE_LEVEL
        | 0x813D // GL_TEXTURE_MAX_LEVEL
        | 0x884C // GL_TEXTURE_COMPARE_MODE
        | 0x884D // GL_TEXTURE_COMPARE_FUNC
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexedBufferBinding {
    Base(GLuint),
    Range {
        buffer: GLuint,
        offset: GLintptr,
        size: GLsizeiptr,
    },
}

impl IndexedBufferBinding {
    fn buffer_id(self) -> GLuint {
        match self {
            IndexedBufferBinding::Base(buffer) => buffer,
            IndexedBufferBinding::Range { buffer, .. } => buffer,
        }
    }
}

fn cap_bit(cap: GLenum) -> Option<u32> {
    match cap {
        0x0BE2 => Some(CAP_BLEND),
        0x0B44 => Some(CAP_CULL_FACE),
        0x0B71 => Some(CAP_DEPTH_TEST),
        0x0C11 => Some(CAP_SCISSOR_TEST),
        0x0B90 => Some(CAP_STENCIL_TEST),
        0x0BD0 => Some(CAP_DITHER),
        0x8037 => Some(CAP_POLYGON_OFFSET_FILL),
        0x809E => Some(CAP_SAMPLE_ALPHA_TO_COVERAGE),
        0x80A0 => Some(CAP_SAMPLE_COVERAGE),
        _ => None,
    }
}

/// Pure per-context GLES state cache.
/// All slots start `None` so unknown driver defaults are never falsely assumed.
#[derive(Debug, Clone)]
pub struct GlStateCache {
    pub program: Option<GLuint>,
    pub vao: Option<GLuint>,
    pub active_texture: Option<usize>,
    pub tex_2d: [Option<GLuint>; MAX_TEX_UNITS],
    pub tex_cube: [Option<GLuint>; MAX_TEX_UNITS],
    pub tex_3d: [Option<GLuint>; MAX_TEX_UNITS],
    pub tex_array: [Option<GLuint>; MAX_TEX_UNITS],
    pub array_buffer: Option<GLuint>,
    pub element_array_buffer: Option<GLuint>,
    pub uniform_buffer: Option<GLuint>,
    pub pixel_pack_buffer: Option<GLuint>,
    pub pixel_unpack_buffer: Option<GLuint>,
    pub copy_read_buffer: Option<GLuint>,
    pub copy_write_buffer: Option<GLuint>,
    pub ssbo: Option<GLuint>,
    pub ubo_indexed: [Option<IndexedBufferBinding>; MAX_CACHED_UBO_SLOTS],
    pub ssbo_indexed: [Option<IndexedBufferBinding>; MAX_CACHED_SSBO_SLOTS],
    pub draw_fbo: Option<GLuint>,
    pub read_fbo: Option<GLuint>,
    pub renderbuffer: Option<GLuint>,
    pub viewport: Option<[GLint; 4]>,
    pub scissor: Option<[GLint; 4]>,
    pub clear_color_bits: Option<[u32; 4]>,
    pub clear_depth_bits: Option<u32>,
    pub clear_stencil: Option<GLint>,
    pub polygon_offset_bits: Option<(u32, u32)>,
    pub depth_mask: Option<bool>,
    pub depth_func: Option<GLenum>,
    pub color_mask: Option<[bool; 4]>,
    pub blend_func: Option<(GLenum, GLenum, GLenum, GLenum)>,
    pub cull_face: Option<GLenum>,
    pub front_face: Option<GLenum>,
    pub stencil_func: Option<(GLenum, GLint, GLuint)>,
    pub stencil_mask: Option<GLuint>,
    pub stencil_op: Option<(GLenum, GLenum, GLenum)>,
    pub unpack_alignment: Option<GLint>,
    pub pack_alignment: Option<GLint>,
    pub attrib_known: u16,
    pub attrib_enabled: u16,
    pub attrib_ptrs: [Option<VertexAttribPointerState>; MAX_CACHED_VERTEX_ATTRIBS],
    pub attrib_divisors: [Option<GLuint>; MAX_CACHED_VERTEX_ATTRIBS],
    pub cap_known: u32,
    pub cap_enabled: u32,
    uniform1i_slots: [Option<CachedUniform1i>; MAX_CACHED_UNIFORM1I_SLOTS],
    uniform1i_cursor: usize,
    tex_param_slots: [Option<CachedTexParam>; MAX_CACHED_TEX_PARAM_SLOTS],
    tex_param_cursor: usize,
    uniform_locs: HashMap<GLuint, HashMap<String, GLint>>,
    uniform_loc_entries: usize,
}

impl Default for GlStateCache {
    fn default() -> Self {
        Self {
            program: None,
            vao: None,
            active_texture: None,
            tex_2d: [None; MAX_TEX_UNITS],
            tex_cube: [None; MAX_TEX_UNITS],
            tex_3d: [None; MAX_TEX_UNITS],
            tex_array: [None; MAX_TEX_UNITS],
            array_buffer: None,
            element_array_buffer: None,
            uniform_buffer: None,
            pixel_pack_buffer: None,
            pixel_unpack_buffer: None,
            copy_read_buffer: None,
            copy_write_buffer: None,
            ssbo: None,
            ubo_indexed: [None; MAX_CACHED_UBO_SLOTS],
            ssbo_indexed: [None; MAX_CACHED_SSBO_SLOTS],
            draw_fbo: None,
            read_fbo: None,
            renderbuffer: None,
            viewport: None,
            scissor: None,
            clear_color_bits: None,
            clear_depth_bits: None,
            clear_stencil: None,
            polygon_offset_bits: None,
            depth_mask: None,
            depth_func: None,
            color_mask: None,
            blend_func: None,
            cull_face: None,
            front_face: None,
            stencil_func: None,
            stencil_mask: None,
            stencil_op: None,
            unpack_alignment: None,
            pack_alignment: None,
            attrib_known: 0,
            attrib_enabled: 0,
            attrib_ptrs: [None; MAX_CACHED_VERTEX_ATTRIBS],
            attrib_divisors: [None; MAX_CACHED_VERTEX_ATTRIBS],
            cap_known: 0,
            cap_enabled: 0,
            uniform1i_slots: [None; MAX_CACHED_UNIFORM1I_SLOTS],
            uniform1i_cursor: 0,
            tex_param_slots: [None; MAX_CACHED_TEX_PARAM_SLOTS],
            tex_param_cursor: 0,
            uniform_locs: HashMap::new(),
            uniform_loc_entries: 0,
        }
    }
}

impl GlStateCache {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn should_use_program(&mut self, program: GLuint) -> bool {
        if self.program == Some(program) {
            return false;
        }
        self.program = Some(program);
        true
    }

    pub fn should_bind_vao(&mut self, vao: GLuint) -> bool {
        if self.vao == Some(vao) {
            return false;
        }
        self.vao = Some(vao);
        // GL_ELEMENT_ARRAY_BUFFER binding and vertex attrib layout are container-local per VAO.
        self.element_array_buffer = None;
        self.attrib_known = 0;
        self.attrib_enabled = 0;
        self.attrib_ptrs = [None; MAX_CACHED_VERTEX_ATTRIBS];
        self.attrib_divisors = [None; MAX_CACHED_VERTEX_ATTRIBS];
        true
    }

    pub fn should_set_vertex_attrib_enabled(&mut self, index: GLuint, enable: bool) -> bool {
        let idx = index as usize;
        if idx >= MAX_CACHED_VERTEX_ATTRIBS {
            return true;
        }
        let bit = 1u16 << idx;
        if (self.attrib_known & bit) != 0 && ((self.attrib_enabled & bit) != 0) == enable {
            return false;
        }
        self.attrib_known |= bit;
        if enable {
            self.attrib_enabled |= bit;
        } else {
            self.attrib_enabled &= !bit;
        }
        true
    }

    pub fn should_set_active_texture(&mut self, unit_enum: GLenum) -> bool {
        let Some(unit) = unit_enum.checked_sub(GL_TEXTURE0) else {
            return true;
        };
        let unit_idx = unit as usize;
        if unit_idx >= MAX_TEX_UNITS {
            return true;
        }
        if self.active_texture == Some(unit_idx) {
            return false;
        }
        self.active_texture = Some(unit_idx);
        true
    }

    pub fn should_bind_texture(&mut self, target: GLenum, texture: GLuint) -> bool {
        let Some(unit) = self.active_texture else {
            return true;
        };
        if unit >= MAX_TEX_UNITS {
            return true;
        }
        let slot = match target {
            GL_TEXTURE_2D => &mut self.tex_2d[unit],
            GL_TEXTURE_CUBE_MAP => &mut self.tex_cube[unit],
            GL_TEXTURE_3D => &mut self.tex_3d[unit],
            GL_TEXTURE_2D_ARRAY => &mut self.tex_array[unit],
            _ => return true,
        };
        if *slot == Some(texture) {
            return false;
        }
        *slot = Some(texture);
        true
    }

    pub fn should_bind_buffer(&mut self, target: GLenum, buffer: GLuint) -> bool {
        let slot = match target {
            GL_ARRAY_BUFFER => &mut self.array_buffer,
            GL_ELEMENT_ARRAY_BUFFER => &mut self.element_array_buffer,
            GL_UNIFORM_BUFFER => &mut self.uniform_buffer,
            GL_PIXEL_PACK_BUFFER => &mut self.pixel_pack_buffer,
            GL_PIXEL_UNPACK_BUFFER => &mut self.pixel_unpack_buffer,
            GL_COPY_READ_BUFFER => &mut self.copy_read_buffer,
            GL_COPY_WRITE_BUFFER => &mut self.copy_write_buffer,
            GL_SHADER_STORAGE_BUFFER => &mut self.ssbo,
            _ => return true,
        };
        if *slot == Some(buffer) {
            return false;
        }
        *slot = Some(buffer);
        true
    }

    pub fn on_bind_buffer_indexed(&mut self, target: GLenum) {
        match target {
            GL_UNIFORM_BUFFER => self.uniform_buffer = None,
            GL_SHADER_STORAGE_BUFFER => self.ssbo = None,
            _ => {}
        }
    }

    pub fn should_bind_buffer_indexed(
        &mut self,
        target: GLenum,
        index: GLuint,
        binding: IndexedBufferBinding,
    ) -> bool {
        let idx = index as usize;
        let buffer = binding.buffer_id();
        let (generic_slot, slot_ref): (&mut Option<GLuint>, Option<&mut Option<IndexedBufferBinding>>) =
            match target {
                GL_UNIFORM_BUFFER => (&mut self.uniform_buffer, self.ubo_indexed.get_mut(idx)),
                GL_SHADER_STORAGE_BUFFER => (&mut self.ssbo, self.ssbo_indexed.get_mut(idx)),
                _ => {
                    self.on_bind_buffer_indexed(target);
                    return true;
                }
            };
        let Some(indexed_slot) = slot_ref else {
            *generic_slot = None;
            return true;
        };
        if *indexed_slot == Some(binding) && *generic_slot == Some(buffer) {
            return false;
        }
        *indexed_slot = Some(binding);
        *generic_slot = Some(buffer);
        true
    }

    pub fn on_buffer_data(&mut self, target: GLenum) {
        let generic = match target {
            GL_ARRAY_BUFFER => self.array_buffer,
            GL_ELEMENT_ARRAY_BUFFER => self.element_array_buffer,
            GL_UNIFORM_BUFFER => self.uniform_buffer,
            GL_PIXEL_PACK_BUFFER => self.pixel_pack_buffer,
            GL_PIXEL_UNPACK_BUFFER => self.pixel_unpack_buffer,
            GL_COPY_READ_BUFFER => self.copy_read_buffer,
            GL_COPY_WRITE_BUFFER => self.copy_write_buffer,
            GL_SHADER_STORAGE_BUFFER => self.ssbo,
            _ => None,
        };
        if let Some(buf_id) = generic {
            self.invalidate_indexed_buffer(buf_id);
        }
    }

    fn invalidate_indexed_buffer(&mut self, id: GLuint) {
        if id == 0 {
            return;
        }
        for slot in self.ubo_indexed.iter_mut() {
            if slot.map(IndexedBufferBinding::buffer_id) == Some(id) {
                *slot = None;
            }
        }
        for slot in self.ssbo_indexed.iter_mut() {
            if slot.map(IndexedBufferBinding::buffer_id) == Some(id) {
                *slot = None;
            }
        }
    }

    pub fn should_bind_framebuffer(&mut self, target: GLenum, fb: GLuint) -> bool {
        match target {
            GL_FRAMEBUFFER => {
                if self.draw_fbo == Some(fb) && self.read_fbo == Some(fb) {
                    return false;
                }
                self.draw_fbo = Some(fb);
                self.read_fbo = Some(fb);
                true
            }
            GL_DRAW_FRAMEBUFFER => {
                if self.draw_fbo == Some(fb) {
                    return false;
                }
                self.draw_fbo = Some(fb);
                true
            }
            GL_READ_FRAMEBUFFER => {
                if self.read_fbo == Some(fb) {
                    return false;
                }
                self.read_fbo = Some(fb);
                true
            }
            _ => true,
        }
    }

    pub fn should_bind_renderbuffer(&mut self, target: GLenum, rb: GLuint) -> bool {
        if target != GL_RENDERBUFFER {
            return true;
        }
        if self.renderbuffer == Some(rb) {
            return false;
        }
        self.renderbuffer = Some(rb);
        true
    }

    pub fn should_set_cap(&mut self, cap: GLenum, enable: bool) -> bool {
        let Some(bit) = cap_bit(cap) else {
            return true;
        };
        let known = (self.cap_known & bit) != 0;
        let cur = (self.cap_enabled & bit) != 0;
        if known && cur == enable {
            return false;
        }
        self.cap_known |= bit;
        if enable {
            self.cap_enabled |= bit;
        } else {
            self.cap_enabled &= !bit;
        }
        true
    }

    pub fn should_set_viewport(&mut self, x: GLint, y: GLint, w: GLsizei, h: GLsizei) -> bool {
        let next = [x, y, w, h];
        if self.viewport == Some(next) {
            return false;
        }
        self.viewport = Some(next);
        true
    }

    pub fn should_set_scissor(&mut self, x: GLint, y: GLint, w: GLsizei, h: GLsizei) -> bool {
        let next = [x, y, w, h];
        if self.scissor == Some(next) {
            return false;
        }
        self.scissor = Some(next);
        true
    }

    pub fn should_set_blend_func(&mut self, src: GLenum, dst: GLenum) -> bool {
        self.should_set_blend_func_separate(src, dst, src, dst)
    }

    pub fn should_set_blend_func_separate(
        &mut self,
        src_rgb: GLenum,
        dst_rgb: GLenum,
        src_alpha: GLenum,
        dst_alpha: GLenum,
    ) -> bool {
        let next = (src_rgb, dst_rgb, src_alpha, dst_alpha);
        if self.blend_func == Some(next) {
            return false;
        }
        self.blend_func = Some(next);
        true
    }

    pub fn should_set_depth_mask(&mut self, flag: GLboolean) -> bool {
        let b = flag != 0;
        if self.depth_mask == Some(b) {
            return false;
        }
        self.depth_mask = Some(b);
        true
    }

    pub fn should_set_depth_func(&mut self, func: GLenum) -> bool {
        if self.depth_func == Some(func) {
            return false;
        }
        self.depth_func = Some(func);
        true
    }

    pub fn should_set_color_mask(&mut self, r: GLboolean, g: GLboolean, b: GLboolean, a: GLboolean) -> bool {
        let next = [r != 0, g != 0, b != 0, a != 0];
        if self.color_mask == Some(next) {
            return false;
        }
        self.color_mask = Some(next);
        true
    }

    pub fn should_set_clear_color(&mut self, r: GLfloat, g: GLfloat, b: GLfloat, a: GLfloat) -> bool {
        let next = [r.to_bits(), g.to_bits(), b.to_bits(), a.to_bits()];
        if self.clear_color_bits == Some(next) {
            return false;
        }
        self.clear_color_bits = Some(next);
        true
    }

    pub fn should_set_clear_depthf(&mut self, depth: GLfloat) -> bool {
        let bits = depth.to_bits();
        if self.clear_depth_bits == Some(bits) {
            return false;
        }
        self.clear_depth_bits = Some(bits);
        true
    }

    pub fn should_set_clear_stencil(&mut self, s: GLint) -> bool {
        if self.clear_stencil == Some(s) {
            return false;
        }
        self.clear_stencil = Some(s);
        true
    }

    pub fn should_set_polygon_offset(&mut self, factor: GLfloat, units: GLfloat) -> bool {
        let next = (factor.to_bits(), units.to_bits());
        if self.polygon_offset_bits == Some(next) {
            return false;
        }
        self.polygon_offset_bits = Some(next);
        true
    }

    pub fn should_set_cull_face(&mut self, mode: GLenum) -> bool {
        if self.cull_face == Some(mode) {
            return false;
        }
        self.cull_face = Some(mode);
        true
    }

    pub fn should_set_front_face(&mut self, mode: GLenum) -> bool {
        if self.front_face == Some(mode) {
            return false;
        }
        self.front_face = Some(mode);
        true
    }

    pub fn should_set_stencil_func(&mut self, func: GLenum, r: GLint, mask: GLuint) -> bool {
        let next = (func, r, mask);
        if self.stencil_func == Some(next) {
            return false;
        }
        self.stencil_func = Some(next);
        true
    }

    pub fn should_set_stencil_mask(&mut self, mask: GLuint) -> bool {
        if self.stencil_mask == Some(mask) {
            return false;
        }
        self.stencil_mask = Some(mask);
        true
    }

    pub fn should_set_stencil_op(&mut self, sfail: GLenum, dpfail: GLenum, dppass: GLenum) -> bool {
        let next = (sfail, dpfail, dppass);
        if self.stencil_op == Some(next) {
            return false;
        }
        self.stencil_op = Some(next);
        true
    }

    pub fn should_set_pixel_storei(&mut self, pname: GLenum, param: GLint) -> bool {
        let slot = match pname {
            GL_UNPACK_ALIGNMENT => &mut self.unpack_alignment,
            GL_PACK_ALIGNMENT => &mut self.pack_alignment,
            _ => return true,
        };
        if *slot == Some(param) {
            return false;
        }
        *slot = Some(param);
        true
    }

    pub fn on_delete_textures(&mut self, ids: &[GLuint]) {
        for &id in ids {
            if id == 0 {
                continue;
            }
            for arr in [
                &mut self.tex_2d,
                &mut self.tex_cube,
                &mut self.tex_3d,
                &mut self.tex_array,
            ] {
                for slot in arr.iter_mut() {
                    if *slot == Some(id) {
                        *slot = None;
                    }
                }
            }
            for slot in self.tex_param_slots.iter_mut() {
                if let Some(entry) = *slot {
                    if entry.texture == id {
                        *slot = None;
                    }
                }
            }
        }
    }

    pub fn on_delete_buffers(&mut self, ids: &[GLuint]) {
        for &id in ids {
            if id == 0 {
                continue;
            }
            for slot in [
                &mut self.array_buffer,
                &mut self.element_array_buffer,
                &mut self.uniform_buffer,
                &mut self.pixel_pack_buffer,
                &mut self.pixel_unpack_buffer,
                &mut self.copy_read_buffer,
                &mut self.copy_write_buffer,
                &mut self.ssbo,
            ] {
                if *slot == Some(id) {
                    *slot = None;
                }
            }
            for slot in self.attrib_ptrs.iter_mut() {
                if let Some(ptr_state) = *slot {
                    if ptr_state.buffer == id {
                        *slot = None;
                    }
                }
            }
            self.invalidate_indexed_buffer(id);
        }
    }

    pub fn on_delete_framebuffers(&mut self, ids: &[GLuint]) {
        for &id in ids {
            if id == 0 {
                continue;
            }
            if self.draw_fbo == Some(id) {
                self.draw_fbo = None;
            }
            if self.read_fbo == Some(id) {
                self.read_fbo = None;
            }
        }
    }

    pub fn on_delete_renderbuffers(&mut self, ids: &[GLuint]) {
        for &id in ids {
            if id == 0 {
                continue;
            }
            if self.renderbuffer == Some(id) {
                self.renderbuffer = None;
            }
        }
    }

    pub fn on_delete_vaos(&mut self, ids: &[GLuint]) {
        for &id in ids {
            if id == 0 {
                continue;
            }
            if self.vao == Some(id) {
                self.vao = None;
                self.element_array_buffer = None;
                self.attrib_known = 0;
                self.attrib_enabled = 0;
                self.attrib_ptrs = [None; MAX_CACHED_VERTEX_ATTRIBS];
                self.attrib_divisors = [None; MAX_CACHED_VERTEX_ATTRIBS];
            }
        }
    }

    pub fn on_program_relinked(&mut self, id: GLuint) {
        if id == 0 {
            return;
        }
        for slot in self.uniform1i_slots.iter_mut() {
            if let Some(entry) = *slot {
                if entry.program == id {
                    *slot = None;
                }
            }
        }
        if let Some(removed) = self.uniform_locs.remove(&id) {
            self.uniform_loc_entries = self.uniform_loc_entries.saturating_sub(removed.len());
        }
    }

    pub fn on_delete_program(&mut self, id: GLuint) {
        if id != 0 {
            if self.program == Some(id) {
                self.program = None;
            }
            self.on_program_relinked(id);
        }
    }

    pub fn should_set_vertex_attrib_pointer(
        &mut self,
        index: GLuint,
        size: GLint,
        typ: GLenum,
        normalized: GLboolean,
        stride: GLsizei,
        pointer: usize,
    ) -> bool {
        let idx = index as usize;
        let Some(buffer) = self.array_buffer else {
            return true;
        };
        if self.vao.is_none() || idx >= MAX_CACHED_VERTEX_ATTRIBS {
            return true;
        }
        let next = VertexAttribPointerState {
            buffer,
            size,
            typ,
            normalized: normalized != 0,
            stride,
            pointer,
        };
        if self.attrib_ptrs[idx] == Some(next) {
            return false;
        }
        self.attrib_ptrs[idx] = Some(next);
        true
    }

    pub fn should_set_vertex_attrib_divisor(&mut self, index: GLuint, divisor: GLuint) -> bool {
        let idx = index as usize;
        if self.vao.is_none() || idx >= MAX_CACHED_VERTEX_ATTRIBS {
            return true;
        }
        if self.attrib_divisors[idx] == Some(divisor) {
            return false;
        }
        self.attrib_divisors[idx] = Some(divisor);
        true
    }

    pub fn should_set_uniform1i(&mut self, location: GLint, v0: GLint) -> bool {
        let Some(program) = self.program else {
            return true;
        };
        if program == 0 || location < 0 {
            return true;
        }
        for slot in self.uniform1i_slots.iter_mut() {
            if let Some(entry) = slot {
                if entry.program == program && entry.location == location {
                    if entry.value == v0 {
                        return false;
                    }
                    entry.value = v0;
                    return true;
                }
            }
        }
        self.uniform1i_slots[self.uniform1i_cursor] = Some(CachedUniform1i {
            program,
            location,
            value: v0,
        });
        self.uniform1i_cursor = (self.uniform1i_cursor + 1) % MAX_CACHED_UNIFORM1I_SLOTS;
        true
    }

    fn current_bound_texture(&self, target: GLenum) -> Option<GLuint> {
        let unit = self.active_texture?;
        if unit >= MAX_TEX_UNITS {
            return None;
        }
        match target {
            GL_TEXTURE_2D => self.tex_2d[unit],
            GL_TEXTURE_CUBE_MAP => self.tex_cube[unit],
            GL_TEXTURE_3D => self.tex_3d[unit],
            GL_TEXTURE_2D_ARRAY => self.tex_array[unit],
            _ => None,
        }
    }

    pub fn should_set_tex_parameteri(
        &mut self,
        target: GLenum,
        pname: GLenum,
        param: GLint,
    ) -> bool {
        if !is_cacheable_tex_param_i(pname) {
            return true;
        }
        let Some(texture) = self.current_bound_texture(target) else {
            return true;
        };
        if texture == 0 {
            return true;
        }
        for slot in self.tex_param_slots.iter_mut() {
            if let Some(entry) = slot {
                if entry.target == target && entry.texture == texture && entry.pname == pname {
                    if entry.value == param {
                        return false;
                    }
                    entry.value = param;
                    return true;
                }
            }
        }
        self.tex_param_slots[self.tex_param_cursor] = Some(CachedTexParam {
            target,
            texture,
            pname,
            value: param,
        });
        self.tex_param_cursor = (self.tex_param_cursor + 1) % MAX_CACHED_TEX_PARAM_SLOTS;
        true
    }

    pub fn invalidate_tex_param(&mut self, target: GLenum, pname: GLenum) {
        let Some(texture) = self.current_bound_texture(target) else {
            return;
        };
        if texture == 0 {
            return;
        }
        for slot in self.tex_param_slots.iter_mut() {
            if let Some(entry) = *slot {
                if entry.target == target && entry.texture == texture && entry.pname == pname {
                    *slot = None;
                }
            }
        }
    }

    pub fn lookup_uniform_location(&self, program: GLuint, name: &str) -> Option<GLint> {
        self.uniform_locs.get(&program)?.get(name).copied()
    }

    pub fn store_uniform_location(&mut self, program: GLuint, name: &str, loc: GLint) {
        if program == 0 || name.len() > 256 {
            return;
        }
        if self.uniform_loc_entries >= MAX_CACHED_UNIFORM_LOC_ENTRIES {
            self.uniform_locs.clear();
            self.uniform_loc_entries = 0;
        }
        let table = self.uniform_locs.entry(program).or_default();
        if !table.contains_key(name) {
            self.uniform_loc_entries += 1;
        }
        table.insert(name.to_owned(), loc);
    }

    pub fn trim_ephemeral_caches(&mut self) {
        if !self.uniform_locs.is_empty() {
            self.uniform_locs.clear();
            self.uniform_locs.shrink_to_fit();
            self.uniform_loc_entries = 0;
        }
    }
}

struct GlThreadState {
    ctx_id: usize,
    epoch: u64,
    cache: GlStateCache,
    last_stub_error: GLenum,
    stub_viewport: [GLint; 4],
}

impl Default for GlThreadState {
    fn default() -> Self {
        Self {
            ctx_id: 0,
            epoch: 0,
            cache: GlStateCache::default(),
            last_stub_error: GL_NO_ERROR,
            stub_viewport: [0, 0, 1280, 720],
        }
    }
}

static GLOBAL_INVALIDATE_EPOCH: AtomicU64 = AtomicU64::new(1);
static STUB_NEXT_OBJECT: AtomicUsize = AtomicUsize::new(1);
static DUMP_REGISTERED: AtomicBool = AtomicBool::new(false);
static PENDING_MEMORY_TRIM: AtomicBool = AtomicBool::new(false);
static TRIM_CALLBACK_REGISTERED: AtomicBool = AtomicBool::new(false);

pub struct GlStats {
    pub state_calls: AtomicU64,
    pub state_elided: AtomicU64,
    pub tex_live: AtomicUsize,
    pub buf_live: AtomicUsize,
    pub fbo_live: AtomicUsize,
    pub rbo_live: AtomicUsize,
    pub vao_live: AtomicUsize,
    pub shader_live: AtomicUsize,
    pub program_live: AtomicUsize,
    pub sync_live: AtomicUsize,
    pub oom_errors: AtomicU64,
    pub shader_trims: AtomicU64,
}

impl GlStats {
    const fn new() -> Self {
        Self {
            state_calls: AtomicU64::new(0),
            state_elided: AtomicU64::new(0),
            tex_live: AtomicUsize::new(0),
            buf_live: AtomicUsize::new(0),
            fbo_live: AtomicUsize::new(0),
            rbo_live: AtomicUsize::new(0),
            vao_live: AtomicUsize::new(0),
            shader_live: AtomicUsize::new(0),
            program_live: AtomicUsize::new(0),
            sync_live: AtomicUsize::new(0),
            oom_errors: AtomicU64::new(0),
            shader_trims: AtomicU64::new(0),
        }
    }
}

static STATS: GlStats = GlStats::new();

thread_local! {
    static TLS_GL: RefCell<GlThreadState> = RefCell::new(GlThreadState::default());
}

extern "C" {
    fn atexit(func: extern "C" fn()) -> i32;
}

extern "C" fn on_process_exit_dump_stats() {
    mocktail_gles_dump_stats();
}

fn stats_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    let enabled = *ENABLED.get_or_init(|| env_flag_enabled("MOCKTAIL_GLES_STATS"));
    if enabled && !DUMP_REGISTERED.swap(true, Ordering::AcqRel) {
        unsafe { atexit(on_process_exit_dump_stats) };
    }
    enabled
}

fn state_cache_enabled() -> bool {
    env_flag_enabled_default_true("MOCKTAIL_GLES_STATE_CACHE")
}

fn test_stubs_enabled() -> bool {
    env_flag_enabled("MOCKTAIL_ENABLE_TEST_GRAPHICS_STUBS")
}

fn host_context_active() -> bool {
    let fptr = unsafe { dlsym_default(b"mocktail_egl_context\0") };
    if !fptr.is_null() {
        let get_ctx: unsafe extern "C" fn() -> *mut c_void = unsafe { std::mem::transmute(fptr) };
        if !unsafe { get_ctx() }.is_null() {
            return true;
        }
    }
    TLS_GL.with(|cell| cell.borrow().ctx_id != 0)
        || env_flag_enabled("MOCKTAIL_GLES_ALLOW_UNBOUND_HOST")
}

fn host_active() -> bool {
    !test_stubs_enabled()
        && !env_flag_enabled("MOCKTAIL_GLES_FORCE_STUB")
        && host_context_active()
        && !host_gles_handle().is_null()
}

fn sync_tls_cache<R>(f: impl FnOnce(&mut GlStateCache) -> R) -> R {
    let epoch = GLOBAL_INVALIDATE_EPOCH.load(Ordering::Acquire);
    TLS_GL.with(|cell| {
        let mut st = cell.borrow_mut();
        if st.epoch != epoch {
            st.cache.reset();
            st.epoch = epoch;
        }
        f(&mut st.cache)
    })
}

fn with_cache_check(predicate: impl FnOnce(&mut GlStateCache) -> bool) -> bool {
    if !state_cache_enabled() {
        return true;
    }
    let track = stats_enabled();
    if track {
        STATS.state_calls.fetch_add(1, Ordering::Relaxed);
    }
    let execute = sync_tls_cache(predicate);
    if !execute && track {
        STATS.state_elided.fetch_add(1, Ordering::Relaxed);
    }
    execute
}

fn stub_require() -> bool {
    if test_stubs_enabled() {
        return true;
    }
    TLS_GL.with(|cell| {
        cell.borrow_mut().last_stub_error = GL_INVALID_OPERATION;
    });
    false
}

fn next_stub_object() -> GLuint {
    STUB_NEXT_OBJECT.fetch_add(1, Ordering::Relaxed) as GLuint
}

fn fill_stub_objects(n: GLsizei, objects: *mut GLuint) {
    if !stub_require() || n <= 0 || objects.is_null() {
        return;
    }
    for i in 0..n as isize {
        unsafe { *objects.offset(i) = next_stub_object() };
    }
}

fn copy_stub_string(src: &str, buf_size: GLsizei, length: *mut GLsizei, out: *mut GLchar) {
    if !length.is_null() {
        unsafe { *length = src.len() as GLsizei };
    }
    if out.is_null() || buf_size <= 0 {
        return;
    }
    let max_copy = (buf_size - 1).min(src.len() as GLsizei).max(0) as usize;
    unsafe {
        std::ptr::copy_nonoverlapping(src.as_ptr(), out.cast::<u8>(), max_copy);
        *out.add(max_copy) = 0;
    }
}

fn resolve_host_gl_sym(name: &[u8]) -> *mut c_void {
    let handle = host_gles_handle();
    if !handle.is_null() {
        let p = unsafe { dlsym_cstr(handle, name.as_ptr().cast()) };
        if !p.is_null() {
            return p;
        }
    }
    let sym = unsafe { dlsym_default(b"mocktail_gl_proc_address\0") };
    if !sym.is_null() {
        let func: unsafe extern "C" fn(*const c_char) -> *mut c_void =
            unsafe { std::mem::transmute(sym) };
        let p = unsafe { func(name.as_ptr().cast()) };
        if !p.is_null() {
            return p;
        }
    }
    let egl = host_egl_handle();
    if !egl.is_null() {
        let egl_gpa = unsafe { dlsym_cstr(egl, b"eglGetProcAddress\0".as_ptr().cast()) };
        if !egl_gpa.is_null() {
            let func: unsafe extern "C" fn(*const c_char) -> *mut c_void =
                unsafe { std::mem::transmute(egl_gpa) };
            let p = unsafe { func(name.as_ptr().cast()) };
            if !p.is_null() {
                return p;
            }
        }
    }
    std::ptr::null_mut()
}

macro_rules! host_gl {
    ($slot:ident, $sym:literal, $sig:ty) => {{
        static SLOT: AtomicUsize = AtomicUsize::new(0);
        let cached = SLOT.load(Ordering::Relaxed);
        let ptr = if cached != 0 {
            cached as *mut c_void
        } else {
            let found = resolve_host_gl_sym(concat!($sym, "\0").as_bytes());
            if !found.is_null() {
                SLOT.store(found as usize, Ordering::Relaxed);
            }
            found
        };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute::<*mut c_void, $sig>(ptr) })
        }
    }};
}

fn live_add(counter: &AtomicUsize, n: GLsizei) {
    if stats_enabled() && n > 0 {
        counter.fetch_add(n as usize, Ordering::Relaxed);
    }
}

fn atomic_saturating_sub(counter: &AtomicUsize, dec: usize) {
    let mut cur = counter.load(Ordering::Relaxed);
    loop {
        let next = cur.saturating_sub(dec);
        match counter.compare_exchange_weak(cur, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(actual) => cur = actual,
        }
    }
}

fn live_sub_ids(counter: &AtomicUsize, n: GLsizei, ids: *const GLuint) {
    if !stats_enabled() || n <= 0 || ids.is_null() {
        return;
    }
    let slice = unsafe { std::slice::from_raw_parts(ids, n as usize) };
    let non_zero = slice.iter().filter(|&&id| id != 0).count();
    if non_zero > 0 {
        atomic_saturating_sub(counter, non_zero);
    }
}

fn live_sub_one(counter: &AtomicUsize, id: GLuint) {
    if stats_enabled() && id != 0 {
        atomic_saturating_sub(counter, 1);
    }
}

// ============================================================================
// Runtime Bridge Hooks (EGL <-> GLESv2 and TextOverlay)
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_gles_request_trim(_android_trim_level: i32) {
    PENDING_MEMORY_TRIM.store(true, Ordering::Release);
}

#[no_mangle]
pub extern "C" fn mocktail_gles_on_frame_present() {
    if !PENDING_MEMORY_TRIM.swap(false, Ordering::AcqRel) {
        return;
    }
    sync_tls_cache(|c| c.trim_ephemeral_caches());
    if host_active() {
        if let Some(f) = host_gl!(FN, "glReleaseShaderCompiler", unsafe extern "C" fn()) {
            unsafe { f() };
        }
    }
    if stats_enabled() {
        STATS.shader_trims.fetch_add(1, Ordering::Relaxed);
    }
}

#[no_mangle]
pub extern "C" fn mocktail_gles_on_make_current(ctx: usize) {
    if ctx != 0 && !TRIM_CALLBACK_REGISTERED.swap(true, Ordering::AcqRel) {
        let reg = unsafe { dlsym_default(b"mocktail_rust_memory_register_trim_callback\0") };
        if !reg.is_null() {
            let register_fn: unsafe extern "C" fn(extern "C" fn(i32)) =
                unsafe { std::mem::transmute(reg) };
            unsafe { register_fn(mocktail_gles_request_trim) };
        }
    }
    TLS_GL.with(|cell| {
        let mut st = cell.borrow_mut();
        st.ctx_id = ctx;
        st.cache.reset();
        st.epoch = GLOBAL_INVALIDATE_EPOCH.load(Ordering::Acquire);
    });
}

#[no_mangle]
pub extern "C" fn mocktail_gles_on_context_destroy(ctx: usize) {
    TLS_GL.with(|cell| {
        let mut st = cell.borrow_mut();
        if st.ctx_id == ctx {
            st.ctx_id = 0;
            st.cache.reset();
        }
    });
}

#[no_mangle]
pub extern "C" fn mocktail_gles_invalidate_state_cache() {
    GLOBAL_INVALIDATE_EPOCH.fetch_add(1, Ordering::Release);
}

#[no_mangle]
pub extern "C" fn mocktail_gles_dump_stats() {
    if !stats_enabled() {
        return;
    }
    let calls = STATS.state_calls.load(Ordering::Relaxed);
    let elided = STATS.state_elided.load(Ordering::Relaxed);
    let pct = if calls > 0 {
        (elided as f64 * 100.0) / calls as f64
    } else {
        0.0
    };
    eprintln!(
        "  [gles] state_calls={} elided={} ({:.1}%) live(tex={} buf={} fbo={} rbo={} vao={} prog={} shader={} sync={}) oom={} shader_trims={}",
        calls,
        elided,
        pct,
        STATS.tex_live.load(Ordering::Relaxed),
        STATS.buf_live.load(Ordering::Relaxed),
        STATS.fbo_live.load(Ordering::Relaxed),
        STATS.rbo_live.load(Ordering::Relaxed),
        STATS.vao_live.load(Ordering::Relaxed),
        STATS.program_live.load(Ordering::Relaxed),
        STATS.shader_live.load(Ordering::Relaxed),
        STATS.sync_live.load(Ordering::Relaxed),
        STATS.oom_errors.load(Ordering::Relaxed),
        STATS.shader_trims.load(Ordering::Relaxed),
    );
}

#[no_mangle]
pub extern "C" fn mocktail_gles_lookup_proc(procname: *const c_char) -> *mut c_void {
    if procname.is_null() {
        return std::ptr::null_mut();
    }
    let Ok(name) = unsafe { CStr::from_ptr(procname) }.to_str() else {
        return std::ptr::null_mut();
    };
    match name {
        "glActiveTexture" => mocktail_rust_gl_active_texture as *mut c_void,
        "glAttachShader" => mocktail_rust_gl_attach_shader as *mut c_void,
        "glBindAttribLocation" => mocktail_rust_gl_bind_attrib_location as *mut c_void,
        "glBindBuffer" => mocktail_rust_gl_bind_buffer as *mut c_void,
        "glBindBufferBase" => mocktail_rust_gl_bind_buffer_base as *mut c_void,
        "glBindBufferRange" => mocktail_rust_gl_bind_buffer_range as *mut c_void,
        "glBindFramebuffer" => mocktail_rust_gl_bind_framebuffer as *mut c_void,
        "glBindRenderbuffer" => mocktail_rust_gl_bind_renderbuffer as *mut c_void,
        "glBindTexture" => mocktail_rust_gl_bind_texture as *mut c_void,
        "glBindVertexArray" | "glBindVertexArrayOES" => {
            mocktail_rust_gl_bind_vertex_array as *mut c_void
        }
        "glBlendFunc" => mocktail_rust_gl_blend_func as *mut c_void,
        "glBlendFuncSeparate" => mocktail_rust_gl_blend_func_separate as *mut c_void,
        "glBlitFramebuffer" => mocktail_rust_gl_blit_framebuffer as *mut c_void,
        "glBufferData" => mocktail_rust_gl_buffer_data as *mut c_void,
        "glBufferSubData" => mocktail_rust_gl_buffer_sub_data as *mut c_void,
        "glCheckFramebufferStatus" => mocktail_rust_gl_check_framebuffer_status as *mut c_void,
        "glClear" => mocktail_rust_gl_clear as *mut c_void,
        "glClearColor" => mocktail_rust_gl_clear_color as *mut c_void,
        "glClearDepthf" => mocktail_rust_gl_clear_depthf as *mut c_void,
        "glClearStencil" => mocktail_rust_gl_clear_stencil as *mut c_void,
        "glClientWaitSync" => mocktail_rust_gl_client_wait_sync as *mut c_void,
        "glColorMask" => mocktail_rust_gl_color_mask as *mut c_void,
        "glCompileShader" => mocktail_rust_gl_compile_shader as *mut c_void,
        "glCompressedTexImage2D" => mocktail_rust_gl_compressed_tex_image_2d as *mut c_void,
        "glCompressedTexSubImage2D" => mocktail_rust_gl_compressed_tex_sub_image_2d as *mut c_void,
        "glCopyTexSubImage2D" => mocktail_rust_gl_copy_tex_sub_image_2d as *mut c_void,
        "glCreateProgram" => mocktail_rust_gl_create_program as *mut c_void,
        "glCreateShader" => mocktail_rust_gl_create_shader as *mut c_void,
        "glCullFace" => mocktail_rust_gl_cull_face as *mut c_void,
        "glDeleteBuffers" => mocktail_rust_gl_delete_buffers as *mut c_void,
        "glDeleteFramebuffers" => mocktail_rust_gl_delete_framebuffers as *mut c_void,
        "glDeleteProgram" => mocktail_rust_gl_delete_program as *mut c_void,
        "glDeleteRenderbuffers" => mocktail_rust_gl_delete_renderbuffers as *mut c_void,
        "glDeleteShader" => mocktail_rust_gl_delete_shader as *mut c_void,
        "glDeleteSync" => mocktail_rust_gl_delete_sync as *mut c_void,
        "glDeleteTextures" => mocktail_rust_gl_delete_textures as *mut c_void,
        "glDeleteVertexArrays" | "glDeleteVertexArraysOES" => {
            mocktail_rust_gl_delete_vertex_arrays as *mut c_void
        }
        "glDepthFunc" => mocktail_rust_gl_depth_func as *mut c_void,
        "glDepthMask" => mocktail_rust_gl_depth_mask as *mut c_void,
        "glDisable" => mocktail_rust_gl_disable as *mut c_void,
        "glDisableVertexAttribArray" => {
            mocktail_rust_gl_disable_vertex_attrib_array as *mut c_void
        }
        "glDrawArrays" => mocktail_rust_gl_draw_arrays as *mut c_void,
        "glDrawArraysInstanced" => mocktail_rust_gl_draw_arrays_instanced as *mut c_void,
        "glDrawElements" => mocktail_rust_gl_draw_elements as *mut c_void,
        "glDrawElementsInstanced" => mocktail_rust_gl_draw_elements_instanced as *mut c_void,
        "glEnable" => mocktail_rust_gl_enable as *mut c_void,
        "glEnableVertexAttribArray" => mocktail_rust_gl_enable_vertex_attrib_array as *mut c_void,
        "glFenceSync" => mocktail_rust_gl_fence_sync as *mut c_void,
        "glFinish" => mocktail_rust_gl_finish as *mut c_void,
        "glFlush" => mocktail_rust_gl_flush as *mut c_void,
        "glFramebufferRenderbuffer" => mocktail_rust_gl_framebuffer_renderbuffer as *mut c_void,
        "glFramebufferTexture2D" => mocktail_rust_gl_framebuffer_texture_2d as *mut c_void,
        "glFrontFace" => mocktail_rust_gl_front_face as *mut c_void,
        "glGenBuffers" => mocktail_rust_gl_gen_buffers as *mut c_void,
        "glGenFramebuffers" => mocktail_rust_gl_gen_framebuffers as *mut c_void,
        "glGenRenderbuffers" => mocktail_rust_gl_gen_renderbuffers as *mut c_void,
        "glGenTextures" => mocktail_rust_gl_gen_textures as *mut c_void,
        "glGenVertexArrays" | "glGenVertexArraysOES" => {
            mocktail_rust_gl_gen_vertex_arrays as *mut c_void
        }
        "glGenerateMipmap" => mocktail_rust_gl_generate_mipmap as *mut c_void,
        "glGetActiveUniform" => mocktail_rust_gl_get_active_uniform as *mut c_void,
        "glGetError" => mocktail_rust_gl_get_error as *mut c_void,
        "glGetIntegerv" => mocktail_rust_gl_get_integerv as *mut c_void,
        "glGetProgramBinary" => mocktail_rust_gl_get_program_binary as *mut c_void,
        "glGetProgramInfoLog" => mocktail_rust_gl_get_program_info_log as *mut c_void,
        "glGetProgramiv" => mocktail_rust_gl_get_programiv as *mut c_void,
        "glGetShaderInfoLog" => mocktail_rust_gl_get_shader_info_log as *mut c_void,
        "glGetShaderiv" => mocktail_rust_gl_get_shaderiv as *mut c_void,
        "glGetString" => mocktail_rust_gl_get_string as *mut c_void,
        "glGetStringi" => mocktail_rust_gl_get_stringi as *mut c_void,
        "glGetUniformLocation" => mocktail_rust_gl_get_uniform_location as *mut c_void,
        "glInvalidateFramebuffer" => mocktail_rust_gl_invalidate_framebuffer as *mut c_void,
        "glIsEnabled" => mocktail_rust_gl_is_enabled as *mut c_void,
        "glLinkProgram" => mocktail_rust_gl_link_program as *mut c_void,
        "glObjectLabel" | "glObjectLabelKHR" | "glObjectLabelKHRKHR" => {
            mocktail_rust_gl_object_label as *mut c_void
        }
        "glPixelStorei" => mocktail_rust_gl_pixel_storei as *mut c_void,
        "glPolygonOffset" => mocktail_rust_gl_polygon_offset as *mut c_void,
        "glProgramBinary" => mocktail_rust_gl_program_binary as *mut c_void,
        "glReadPixels" => mocktail_rust_gl_read_pixels as *mut c_void,
        "glReleaseShaderCompiler" => mocktail_rust_gl_release_shader_compiler as *mut c_void,
        "glRenderbufferStorage" => mocktail_rust_gl_renderbuffer_storage as *mut c_void,
        "glScissor" => mocktail_rust_gl_scissor as *mut c_void,
        "glShaderSource" => mocktail_rust_gl_shader_source as *mut c_void,
        "glStencilFunc" => mocktail_rust_gl_stencil_func as *mut c_void,
        "glStencilFuncSeparate" => mocktail_rust_gl_stencil_func_separate as *mut c_void,
        "glStencilMask" => mocktail_rust_gl_stencil_mask as *mut c_void,
        "glStencilMaskSeparate" => mocktail_rust_gl_stencil_mask_separate as *mut c_void,
        "glStencilOp" => mocktail_rust_gl_stencil_op as *mut c_void,
        "glStencilOpSeparate" => mocktail_rust_gl_stencil_op_separate as *mut c_void,
        "glTexImage2D" => mocktail_rust_gl_tex_image_2d as *mut c_void,
        "glTexParameterf" => mocktail_rust_gl_tex_parameterf as *mut c_void,
        "glTexParameterfv" => mocktail_rust_gl_tex_parameterfv as *mut c_void,
        "glTexParameteri" => mocktail_rust_gl_tex_parameteri as *mut c_void,
        "glTexSubImage2D" => mocktail_rust_gl_tex_sub_image_2d as *mut c_void,
        "glUniform1i" => mocktail_rust_gl_uniform1i as *mut c_void,
        "glUseProgram" => mocktail_rust_gl_use_program as *mut c_void,
        "glVertexAttribDivisor" => mocktail_rust_gl_vertex_attrib_divisor as *mut c_void,
        "glVertexAttribPointer" => mocktail_rust_gl_vertex_attrib_pointer as *mut c_void,
        "glViewport" => mocktail_rust_gl_viewport as *mut c_void,
        _ => std::ptr::null_mut(),
    }
}

// ============================================================================
// GLES Entrypoint Implementations
// ============================================================================

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_get_string(name: GLenum) -> *const u8 {
    if host_active() {
        if let Some(f) = host_gl!(FN, "glGetString", unsafe extern "C" fn(GLenum) -> *const u8) {
            return unsafe { f(name) };
        }
    }
    if !stub_require() {
        return std::ptr::null();
    }
    match name {
        GL_VENDOR => b"Mocktail\0".as_ptr(),
        GL_RENDERER => b"Mocktail GLES Stub\0".as_ptr(),
        GL_VERSION => b"OpenGL ES 3.2 Mocktail Stub\0".as_ptr(),
        GL_SHADING_LANGUAGE_VERSION => b"OpenGL ES GLSL ES 3.20 Mocktail Stub\0".as_ptr(),
        GL_EXTENSIONS => {
            b"GL_OES_vertex_array_object GL_OES_texture_npot GL_EXT_color_buffer_float\0".as_ptr()
        }
        _ => b"\0".as_ptr(),
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_get_stringi(name: GLenum, index: GLuint) -> *const u8 {
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glGetStringi",
            unsafe extern "C" fn(GLenum, GLuint) -> *const u8
        ) {
            return unsafe { f(name, index) };
        }
    }
    if !stub_require() || name != GL_EXTENSIONS {
        return std::ptr::null();
    }
    match index {
        0 => b"GL_OES_vertex_array_object\0".as_ptr(),
        1 => b"GL_OES_texture_npot\0".as_ptr(),
        2 => b"GL_EXT_color_buffer_float\0".as_ptr(),
        _ => std::ptr::null(),
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_get_error() -> GLenum {
    if host_active() {
        if let Some(f) = host_gl!(FN, "glGetError", unsafe extern "C" fn() -> GLenum) {
            let err = unsafe { f() };
            if err != GL_NO_ERROR {
                if err == GL_OUT_OF_MEMORY && stats_enabled() {
                    STATS.oom_errors.fetch_add(1, Ordering::Relaxed);
                }
                if env_flag_enabled("MOCKTAIL_GLES_TRACE_ERRORS") {
                    eprintln!("  [gles] host glGetError() -> 0x{err:04x}");
                }
            }
            return err;
        }
    }
    TLS_GL.with(|cell| {
        let mut st = cell.borrow_mut();
        let err = st.last_stub_error;
        if test_stubs_enabled() {
            st.last_stub_error = GL_NO_ERROR;
        }
        err
    })
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_get_integerv(pname: GLenum, data: *mut GLint) {
    if data.is_null() {
        return;
    }
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glGetIntegerv",
            unsafe extern "C" fn(GLenum, *mut GLint)
        ) {
            unsafe { f(pname, data) };
            if pname == GL_MAX_TEXTURE_SIZE {
                if let Ok(raw) = std::env::var("MOCKTAIL_GLES_MAX_TEXTURE_SIZE") {
                    if let Ok(cap) = raw.trim().parse::<GLint>() {
                        if cap >= 256 && unsafe { *data } > cap {
                            unsafe { *data = cap };
                        }
                    }
                }
            }
            return;
        }
    }
    if !stub_require() {
        return;
    }
    match pname {
        GL_VIEWPORT | GL_SCISSOR_BOX => {
            let vp = TLS_GL.with(|c| c.borrow().stub_viewport);
            unsafe { std::ptr::copy_nonoverlapping(vp.as_ptr(), data, 4) };
        }
        GL_MAX_VIEWPORT_DIMS => unsafe {
            *data = 4096;
            *data.add(1) = 4096;
        },
        GL_MAX_TEXTURE_SIZE => unsafe { *data = 4096 },
        GL_MAX_COMBINED_TEXTURE_IMAGE_UNITS => unsafe { *data = 16 },
        GL_NUM_COMPRESSED_TEXTURE_FORMATS => unsafe { *data = 0 },
        GL_NUM_EXTENSIONS => unsafe { *data = 3 },
        GL_MAX_COLOR_ATTACHMENTS => unsafe { *data = 4 },
        GL_COMPRESSED_TEXTURE_FORMATS => {}
        _ => unsafe { *data = 0 },
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_gen_textures(n: GLsizei, textures: *mut GLuint) {
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glGenTextures",
            unsafe extern "C" fn(GLsizei, *mut GLuint)
        ) {
            unsafe { f(n, textures) };
            live_add(&STATS.tex_live, n);
            return;
        }
    }
    fill_stub_objects(n, textures);
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_gen_buffers(n: GLsizei, buffers: *mut GLuint) {
    if host_active() {
        if let Some(f) = host_gl!(FN, "glGenBuffers", unsafe extern "C" fn(GLsizei, *mut GLuint)) {
            unsafe { f(n, buffers) };
            live_add(&STATS.buf_live, n);
            return;
        }
    }
    fill_stub_objects(n, buffers);
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_gen_framebuffers(n: GLsizei, framebuffers: *mut GLuint) {
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glGenFramebuffers",
            unsafe extern "C" fn(GLsizei, *mut GLuint)
        ) {
            unsafe { f(n, framebuffers) };
            live_add(&STATS.fbo_live, n);
            return;
        }
    }
    fill_stub_objects(n, framebuffers);
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_gen_renderbuffers(n: GLsizei, renderbuffers: *mut GLuint) {
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glGenRenderbuffers",
            unsafe extern "C" fn(GLsizei, *mut GLuint)
        ) {
            unsafe { f(n, renderbuffers) };
            live_add(&STATS.rbo_live, n);
            return;
        }
    }
    fill_stub_objects(n, renderbuffers);
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_gen_vertex_arrays(n: GLsizei, arrays: *mut GLuint) {
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glGenVertexArrays",
            unsafe extern "C" fn(GLsizei, *mut GLuint)
        ) {
            unsafe { f(n, arrays) };
            live_add(&STATS.vao_live, n);
            return;
        }
    }
    fill_stub_objects(n, arrays);
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_create_shader(shader_type: GLenum) -> GLuint {
    if host_active() {
        if let Some(f) = host_gl!(FN, "glCreateShader", unsafe extern "C" fn(GLenum) -> GLuint) {
            let id = unsafe { f(shader_type) };
            if id != 0 {
                live_add(&STATS.shader_live, 1);
            }
            return id;
        }
    }
    if !stub_require() {
        return 0;
    }
    next_stub_object()
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_create_program() -> GLuint {
    if host_active() {
        if let Some(f) = host_gl!(FN, "glCreateProgram", unsafe extern "C" fn() -> GLuint) {
            let id = unsafe { f() };
            if id != 0 {
                live_add(&STATS.program_live, 1);
            }
            return id;
        }
    }
    if !stub_require() {
        return 0;
    }
    next_stub_object()
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_delete_textures(n: GLsizei, textures: *const GLuint) {
    if n > 0 && !textures.is_null() {
        let slice = unsafe { std::slice::from_raw_parts(textures, n as usize) };
        sync_tls_cache(|c| c.on_delete_textures(slice));
        live_sub_ids(&STATS.tex_live, n, textures);
    }
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glDeleteTextures",
            unsafe extern "C" fn(GLsizei, *const GLuint)
        ) {
            unsafe { f(n, textures) };
            return;
        }
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_delete_buffers(n: GLsizei, buffers: *const GLuint) {
    if n > 0 && !buffers.is_null() {
        let slice = unsafe { std::slice::from_raw_parts(buffers, n as usize) };
        sync_tls_cache(|c| c.on_delete_buffers(slice));
        live_sub_ids(&STATS.buf_live, n, buffers);
    }
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glDeleteBuffers",
            unsafe extern "C" fn(GLsizei, *const GLuint)
        ) {
            unsafe { f(n, buffers) };
            return;
        }
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_delete_framebuffers(n: GLsizei, framebuffers: *const GLuint) {
    if n > 0 && !framebuffers.is_null() {
        let slice = unsafe { std::slice::from_raw_parts(framebuffers, n as usize) };
        sync_tls_cache(|c| c.on_delete_framebuffers(slice));
        live_sub_ids(&STATS.fbo_live, n, framebuffers);
    }
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glDeleteFramebuffers",
            unsafe extern "C" fn(GLsizei, *const GLuint)
        ) {
            unsafe { f(n, framebuffers) };
            return;
        }
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_delete_renderbuffers(
    n: GLsizei,
    renderbuffers: *const GLuint,
) {
    if n > 0 && !renderbuffers.is_null() {
        let slice = unsafe { std::slice::from_raw_parts(renderbuffers, n as usize) };
        sync_tls_cache(|c| c.on_delete_renderbuffers(slice));
        live_sub_ids(&STATS.rbo_live, n, renderbuffers);
    }
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glDeleteRenderbuffers",
            unsafe extern "C" fn(GLsizei, *const GLuint)
        ) {
            unsafe { f(n, renderbuffers) };
            return;
        }
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_delete_vertex_arrays(n: GLsizei, arrays: *const GLuint) {
    if n > 0 && !arrays.is_null() {
        let slice = unsafe { std::slice::from_raw_parts(arrays, n as usize) };
        sync_tls_cache(|c| c.on_delete_vaos(slice));
        live_sub_ids(&STATS.vao_live, n, arrays);
    }
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glDeleteVertexArrays",
            unsafe extern "C" fn(GLsizei, *const GLuint)
        ) {
            unsafe { f(n, arrays) };
            return;
        }
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_delete_shader(shader: GLuint) {
    live_sub_one(&STATS.shader_live, shader);
    if host_active() {
        if let Some(f) = host_gl!(FN, "glDeleteShader", unsafe extern "C" fn(GLuint)) {
            unsafe { f(shader) };
            return;
        }
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_delete_program(program: GLuint) {
    sync_tls_cache(|c| c.on_delete_program(program));
    live_sub_one(&STATS.program_live, program);
    if host_active() {
        if let Some(f) = host_gl!(FN, "glDeleteProgram", unsafe extern "C" fn(GLuint)) {
            unsafe { f(program) };
            return;
        }
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_get_shaderiv(
    shader: GLuint,
    pname: GLenum,
    params: *mut GLint,
) {
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glGetShaderiv",
            unsafe extern "C" fn(GLuint, GLenum, *mut GLint)
        ) {
            unsafe { f(shader, pname, params) };
            return;
        }
    }
    if !stub_require() || params.is_null() {
        return;
    }
    unsafe {
        *params = match pname {
            GL_COMPILE_STATUS => 1,
            GL_INFO_LOG_LENGTH => 0,
            _ => 0,
        };
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_get_programiv(
    program: GLuint,
    pname: GLenum,
    params: *mut GLint,
) {
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glGetProgramiv",
            unsafe extern "C" fn(GLuint, GLenum, *mut GLint)
        ) {
            unsafe { f(program, pname, params) };
            return;
        }
    }
    if !stub_require() || params.is_null() {
        return;
    }
    unsafe {
        *params = match pname {
            GL_LINK_STATUS | GL_VALIDATE_STATUS | GL_ACTIVE_UNIFORMS | GL_ACTIVE_ATTRIBUTES => 1,
            GL_ACTIVE_UNIFORM_MAX_LENGTH | GL_ACTIVE_ATTRIBUTE_MAX_LENGTH => 16,
            GL_INFO_LOG_LENGTH => 0,
            _ => 0,
        };
    }
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_get_shader_info_log(
    shader: GLuint,
    buf_size: GLsizei,
    length: *mut GLsizei,
    info_log: *mut GLchar,
) {
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glGetShaderInfoLog",
            unsafe extern "C" fn(GLuint, GLsizei, *mut GLsizei, *mut GLchar)
        ) {
            unsafe { f(shader, buf_size, length, info_log) };
            return;
        }
    }
    if !stub_require() {
        return;
    }
    copy_stub_string("", buf_size, length, info_log);
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_get_program_info_log(
    program: GLuint,
    buf_size: GLsizei,
    length: *mut GLsizei,
    info_log: *mut GLchar,
) {
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glGetProgramInfoLog",
            unsafe extern "C" fn(GLuint, GLsizei, *mut GLsizei, *mut GLchar)
        ) {
            unsafe { f(program, buf_size, length, info_log) };
            return;
        }
    }
    if !stub_require() {
        return;
    }
    copy_stub_string("", buf_size, length, info_log);
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_get_active_uniform(
    program: GLuint,
    index: GLuint,
    buf_size: GLsizei,
    length: *mut GLsizei,
    size: *mut GLint,
    typ: *mut GLenum,
    name: *mut GLchar,
) {
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glGetActiveUniform",
            unsafe extern "C" fn(
                GLuint,
                GLuint,
                GLsizei,
                *mut GLsizei,
                *mut GLint,
                *mut GLenum,
                *mut GLchar
            )
        ) {
            unsafe { f(program, index, buf_size, length, size, typ, name) };
            return;
        }
    }
    if !stub_require() {
        return;
    }
    if !size.is_null() {
        unsafe { *size = 1 };
    }
    if !typ.is_null() {
        unsafe { *typ = GL_FLOAT_MAT4 };
    }
    copy_stub_string("u_stub", buf_size, length, name);
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_get_uniform_location(
    program: GLuint,
    name: *const GLchar,
) -> GLint {
    if host_active() {
        let name_str = if !name.is_null() && program != 0 && state_cache_enabled() {
            unsafe { CStr::from_ptr(name) }.to_str().ok()
        } else {
            None
        };
        if let Some(key) = name_str {
            let track = stats_enabled();
            if track {
                STATS.state_calls.fetch_add(1, Ordering::Relaxed);
            }
            if let Some(cached) = sync_tls_cache(|c| c.lookup_uniform_location(program, key)) {
                if track {
                    STATS.state_elided.fetch_add(1, Ordering::Relaxed);
                }
                return cached;
            }
        }
        if let Some(f) = host_gl!(
            FN,
            "glGetUniformLocation",
            unsafe extern "C" fn(GLuint, *const GLchar) -> GLint
        ) {
            let loc = unsafe { f(program, name) };
            if let Some(key) = name_str {
                sync_tls_cache(|c| c.store_uniform_location(program, key, loc));
            }
            return loc;
        }
    }
    if !stub_require() {
        return -1;
    }
    0
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_check_framebuffer_status(target: GLenum) -> GLenum {
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glCheckFramebufferStatus",
            unsafe extern "C" fn(GLenum) -> GLenum
        ) {
            return unsafe { f(target) };
        }
    }
    if !stub_require() {
        return GL_FRAMEBUFFER_UNSUPPORTED;
    }
    GL_FRAMEBUFFER_COMPLETE
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_is_enabled(cap: GLenum) -> GLboolean {
    if host_active() {
        if let Some(f) = host_gl!(FN, "glIsEnabled", unsafe extern "C" fn(GLenum) -> GLboolean) {
            return unsafe { f(cap) };
        }
    }
    let _ = stub_require();
    0
}

// State-cached GL calls
#[no_mangle]
pub extern "C" fn mocktail_rust_gl_use_program(program: GLuint) {
    if host_active() {
        if with_cache_check(|c| c.should_use_program(program)) {
            if let Some(f) = host_gl!(FN, "glUseProgram", unsafe extern "C" fn(GLuint)) {
                unsafe { f(program) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_bind_vertex_array(array: GLuint) {
    if host_active() {
        if with_cache_check(|c| c.should_bind_vao(array)) {
            if let Some(f) = host_gl!(FN, "glBindVertexArray", unsafe extern "C" fn(GLuint)) {
                unsafe { f(array) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_active_texture(texture: GLenum) {
    if host_active() {
        if with_cache_check(|c| c.should_set_active_texture(texture)) {
            if let Some(f) = host_gl!(FN, "glActiveTexture", unsafe extern "C" fn(GLenum)) {
                unsafe { f(texture) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_bind_texture(target: GLenum, texture: GLuint) {
    if host_active() {
        if with_cache_check(|c| c.should_bind_texture(target, texture)) {
            if let Some(f) = host_gl!(
                FN,
                "glBindTexture",
                unsafe extern "C" fn(GLenum, GLuint)
            ) {
                unsafe { f(target, texture) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_bind_buffer(target: GLenum, buffer: GLuint) {
    if host_active() {
        if with_cache_check(|c| c.should_bind_buffer(target, buffer)) {
            if let Some(f) = host_gl!(FN, "glBindBuffer", unsafe extern "C" fn(GLenum, GLuint)) {
                unsafe { f(target, buffer) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_bind_buffer_base(
    target: GLenum,
    index: GLuint,
    buffer: GLuint,
) {
    if host_active() {
        if with_cache_check(|c| {
            c.should_bind_buffer_indexed(target, index, IndexedBufferBinding::Base(buffer))
        }) {
            if let Some(f) = host_gl!(
                FN,
                "glBindBufferBase",
                unsafe extern "C" fn(GLenum, GLuint, GLuint)
            ) {
                unsafe { f(target, index, buffer) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_bind_buffer_range(
    target: GLenum,
    index: GLuint,
    buffer: GLuint,
    offset: GLintptr,
    size: GLsizeiptr,
) {
    if host_active() {
        if with_cache_check(|c| {
            c.should_bind_buffer_indexed(
                target,
                index,
                IndexedBufferBinding::Range {
                    buffer,
                    offset,
                    size,
                },
            )
        }) {
            if let Some(f) = host_gl!(
                FN,
                "glBindBufferRange",
                unsafe extern "C" fn(GLenum, GLuint, GLuint, GLintptr, GLsizeiptr)
            ) {
                unsafe { f(target, index, buffer, offset, size) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_buffer_data(
    target: GLenum,
    size: GLsizeiptr,
    data: *const c_void,
    usage: GLenum,
) {
    if host_active() {
        sync_tls_cache(|c| c.on_buffer_data(target));
        if let Some(f) = host_gl!(
            FN,
            "glBufferData",
            unsafe extern "C" fn(GLenum, GLsizeiptr, *const c_void, GLenum)
        ) {
            unsafe { f(target, size, data, usage) };
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_enable_vertex_attrib_array(index: GLuint) {
    if host_active() {
        if with_cache_check(|c| c.should_set_vertex_attrib_enabled(index, true)) {
            if let Some(f) =
                host_gl!(FN, "glEnableVertexAttribArray", unsafe extern "C" fn(GLuint))
            {
                unsafe { f(index) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_disable_vertex_attrib_array(index: GLuint) {
    if host_active() {
        if with_cache_check(|c| c.should_set_vertex_attrib_enabled(index, false)) {
            if let Some(f) =
                host_gl!(FN, "glDisableVertexAttribArray", unsafe extern "C" fn(GLuint))
            {
                unsafe { f(index) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_polygon_offset(factor: GLfloat, units: GLfloat) {
    if host_active() {
        if with_cache_check(|c| c.should_set_polygon_offset(factor, units)) {
            if let Some(f) =
                host_gl!(FN, "glPolygonOffset", unsafe extern "C" fn(GLfloat, GLfloat))
            {
                unsafe { f(factor, units) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_bind_framebuffer(target: GLenum, framebuffer: GLuint) {
    if host_active() {
        if with_cache_check(|c| c.should_bind_framebuffer(target, framebuffer)) {
            if let Some(f) = host_gl!(
                FN,
                "glBindFramebuffer",
                unsafe extern "C" fn(GLenum, GLuint)
            ) {
                unsafe { f(target, framebuffer) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_bind_renderbuffer(target: GLenum, renderbuffer: GLuint) {
    if host_active() {
        if with_cache_check(|c| c.should_bind_renderbuffer(target, renderbuffer)) {
            if let Some(f) = host_gl!(
                FN,
                "glBindRenderbuffer",
                unsafe extern "C" fn(GLenum, GLuint)
            ) {
                unsafe { f(target, renderbuffer) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_enable(cap: GLenum) {
    if host_active() {
        if with_cache_check(|c| c.should_set_cap(cap, true)) {
            if let Some(f) = host_gl!(FN, "glEnable", unsafe extern "C" fn(GLenum)) {
                unsafe { f(cap) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_disable(cap: GLenum) {
    if host_active() {
        if with_cache_check(|c| c.should_set_cap(cap, false)) {
            if let Some(f) = host_gl!(FN, "glDisable", unsafe extern "C" fn(GLenum)) {
                unsafe { f(cap) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_viewport(
    x: GLint,
    y: GLint,
    width: GLsizei,
    height: GLsizei,
) {
    if host_active() {
        if with_cache_check(|c| c.should_set_viewport(x, y, width, height)) {
            if let Some(f) = host_gl!(
                FN,
                "glViewport",
                unsafe extern "C" fn(GLint, GLint, GLsizei, GLsizei)
            ) {
                unsafe { f(x, y, width, height) };
            }
        }
        return;
    }
    if !stub_require() {
        return;
    }
    if width < 0 || height < 0 {
        TLS_GL.with(|c| c.borrow_mut().last_stub_error = GL_INVALID_VALUE);
        return;
    }
    TLS_GL.with(|c| c.borrow_mut().stub_viewport = [x, y, width, height]);
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_scissor(
    x: GLint,
    y: GLint,
    width: GLsizei,
    height: GLsizei,
) {
    if host_active() {
        if with_cache_check(|c| c.should_set_scissor(x, y, width, height)) {
            if let Some(f) = host_gl!(
                FN,
                "glScissor",
                unsafe extern "C" fn(GLint, GLint, GLsizei, GLsizei)
            ) {
                unsafe { f(x, y, width, height) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_blend_func(sfactor: GLenum, dfactor: GLenum) {
    if host_active() {
        if with_cache_check(|c| c.should_set_blend_func(sfactor, dfactor)) {
            if let Some(f) = host_gl!(FN, "glBlendFunc", unsafe extern "C" fn(GLenum, GLenum)) {
                unsafe { f(sfactor, dfactor) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_blend_func_separate(
    src_rgb: GLenum,
    dst_rgb: GLenum,
    src_alpha: GLenum,
    dst_alpha: GLenum,
) {
    if host_active() {
        if with_cache_check(|c| {
            c.should_set_blend_func_separate(src_rgb, dst_rgb, src_alpha, dst_alpha)
        }) {
            if let Some(f) = host_gl!(
                FN,
                "glBlendFuncSeparate",
                unsafe extern "C" fn(GLenum, GLenum, GLenum, GLenum)
            ) {
                unsafe { f(src_rgb, dst_rgb, src_alpha, dst_alpha) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_depth_mask(flag: GLboolean) {
    if host_active() {
        if with_cache_check(|c| c.should_set_depth_mask(flag)) {
            if let Some(f) = host_gl!(FN, "glDepthMask", unsafe extern "C" fn(GLboolean)) {
                unsafe { f(flag) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_depth_func(func: GLenum) {
    if host_active() {
        if with_cache_check(|c| c.should_set_depth_func(func)) {
            if let Some(f) = host_gl!(FN, "glDepthFunc", unsafe extern "C" fn(GLenum)) {
                unsafe { f(func) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_color_mask(
    red: GLboolean,
    green: GLboolean,
    blue: GLboolean,
    alpha: GLboolean,
) {
    if host_active() {
        if with_cache_check(|c| c.should_set_color_mask(red, green, blue, alpha)) {
            if let Some(f) = host_gl!(
                FN,
                "glColorMask",
                unsafe extern "C" fn(GLboolean, GLboolean, GLboolean, GLboolean)
            ) {
                unsafe { f(red, green, blue, alpha) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_clear_color(
    r: GLfloat,
    g: GLfloat,
    b: GLfloat,
    a: GLfloat,
) {
    if host_active() {
        if with_cache_check(|c| c.should_set_clear_color(r, g, b, a)) {
            if let Some(f) = host_gl!(
                FN,
                "glClearColor",
                unsafe extern "C" fn(GLfloat, GLfloat, GLfloat, GLfloat)
            ) {
                unsafe { f(r, g, b, a) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_clear_depthf(depth: GLfloat) {
    if host_active() {
        if with_cache_check(|c| c.should_set_clear_depthf(depth)) {
            if let Some(f) = host_gl!(FN, "glClearDepthf", unsafe extern "C" fn(GLfloat)) {
                unsafe { f(depth) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_clear_stencil(s: GLint) {
    if host_active() {
        if with_cache_check(|c| c.should_set_clear_stencil(s)) {
            if let Some(f) = host_gl!(FN, "glClearStencil", unsafe extern "C" fn(GLint)) {
                unsafe { f(s) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_cull_face(mode: GLenum) {
    if host_active() {
        if with_cache_check(|c| c.should_set_cull_face(mode)) {
            if let Some(f) = host_gl!(FN, "glCullFace", unsafe extern "C" fn(GLenum)) {
                unsafe { f(mode) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_front_face(mode: GLenum) {
    if host_active() {
        if with_cache_check(|c| c.should_set_front_face(mode)) {
            if let Some(f) = host_gl!(FN, "glFrontFace", unsafe extern "C" fn(GLenum)) {
                unsafe { f(mode) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_stencil_func(func: GLenum, ref_val: GLint, mask: GLuint) {
    if host_active() {
        if with_cache_check(|c| c.should_set_stencil_func(func, ref_val, mask)) {
            if let Some(f) = host_gl!(
                FN,
                "glStencilFunc",
                unsafe extern "C" fn(GLenum, GLint, GLuint)
            ) {
                unsafe { f(func, ref_val, mask) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_stencil_func_separate(
    face: GLenum,
    func: GLenum,
    ref_val: GLint,
    mask: GLuint,
) {
    if host_active() {
        sync_tls_cache(|c| c.stencil_func = None);
        if let Some(f) = host_gl!(
            FN,
            "glStencilFuncSeparate",
            unsafe extern "C" fn(GLenum, GLenum, GLint, GLuint)
        ) {
            unsafe { f(face, func, ref_val, mask) };
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_stencil_mask(mask: GLuint) {
    if host_active() {
        if with_cache_check(|c| c.should_set_stencil_mask(mask)) {
            if let Some(f) = host_gl!(FN, "glStencilMask", unsafe extern "C" fn(GLuint)) {
                unsafe { f(mask) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_stencil_mask_separate(face: GLenum, mask: GLuint) {
    if host_active() {
        sync_tls_cache(|c| c.stencil_mask = None);
        if let Some(f) = host_gl!(
            FN,
            "glStencilMaskSeparate",
            unsafe extern "C" fn(GLenum, GLuint)
        ) {
            unsafe { f(face, mask) };
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_stencil_op(
    fail: GLenum,
    zfail: GLenum,
    zpass: GLenum,
) {
    if host_active() {
        if with_cache_check(|c| c.should_set_stencil_op(fail, zfail, zpass)) {
            if let Some(f) = host_gl!(
                FN,
                "glStencilOp",
                unsafe extern "C" fn(GLenum, GLenum, GLenum)
            ) {
                unsafe { f(fail, zfail, zpass) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_stencil_op_separate(
    face: GLenum,
    sfail: GLenum,
    dpfail: GLenum,
    dppass: GLenum,
) {
    if host_active() {
        sync_tls_cache(|c| c.stencil_op = None);
        if let Some(f) = host_gl!(
            FN,
            "glStencilOpSeparate",
            unsafe extern "C" fn(GLenum, GLenum, GLenum, GLenum)
        ) {
            unsafe { f(face, sfail, dpfail, dppass) };
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_pixel_storei(pname: GLenum, param: GLint) {
    if host_active() {
        if with_cache_check(|c| c.should_set_pixel_storei(pname, param)) {
            if let Some(f) = host_gl!(FN, "glPixelStorei", unsafe extern "C" fn(GLenum, GLint)) {
                unsafe { f(pname, param) };
            }
        }
        return;
    }
    let _ = stub_require();
}

// Sync, invalidate, and extension guards
#[no_mangle]
pub extern "C" fn mocktail_rust_gl_fence_sync(condition: GLenum, flags: GLbitfield) -> GLsync {
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glFenceSync",
            unsafe extern "C" fn(GLenum, GLbitfield) -> GLsync
        ) {
            let sync = unsafe { f(condition, flags) };
            if !sync.is_null() {
                live_add(&STATS.sync_live, 1);
            }
            return sync;
        }
    }
    if !stub_require() {
        return std::ptr::null_mut();
    }
    next_stub_object() as usize as GLsync
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_delete_sync(sync: GLsync) {
    if !sync.is_null() && stats_enabled() {
        atomic_saturating_sub(&STATS.sync_live, 1);
    }
    if host_active() {
        if let Some(f) = host_gl!(FN, "glDeleteSync", unsafe extern "C" fn(GLsync)) {
            unsafe { f(sync) };
            return;
        }
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_client_wait_sync(
    sync: GLsync,
    flags: GLbitfield,
    timeout: GLuint64,
) -> GLenum {
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glClientWaitSync",
            unsafe extern "C" fn(GLsync, GLbitfield, GLuint64) -> GLenum
        ) {
            return unsafe { f(sync, flags, timeout) };
        }
    }
    if !stub_require() {
        return 0x911D; // GL_WAIT_FAILED
    }
    0x911A // GL_ALREADY_SIGNALED
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_invalidate_framebuffer(
    target: GLenum,
    num_attachments: GLsizei,
    attachments: *const GLenum,
) {
    if env_flag_enabled("MOCKTAIL_GLES_DISABLE_INVALIDATE") {
        return;
    }
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glInvalidateFramebuffer",
            unsafe extern "C" fn(GLenum, GLsizei, *const GLenum)
        ) {
            unsafe { f(target, num_attachments, attachments) };
            return;
        }
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_object_label(
    identifier: GLenum,
    name: GLuint,
    length: GLsizei,
    label: *const GLchar,
) {
    if host_active() {
        if !env_flag_enabled("MOCKTAIL_GLES_OBJECT_LABELS") {
            return;
        }
        if let Some(f) = host_gl!(
            FN,
            "glObjectLabel",
            unsafe extern "C" fn(GLenum, GLuint, GLsizei, *const GLchar)
        ) {
            unsafe { f(identifier, name, length, label) };
            return;
        }
        if let Some(f) = host_gl!(
            FN,
            "glObjectLabelKHR",
            unsafe extern "C" fn(GLenum, GLuint, GLsizei, *const GLchar)
        ) {
            unsafe { f(identifier, name, length, label) };
            return;
        }
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_draw_arrays(
    mode: GLenum,
    first: GLint,
    count: GLsizei,
) {
    if env_flag_enabled("MOCKTAIL_GLES_NOOP_DRAW_CALLS") {
        return;
    }
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glDrawArrays",
            unsafe extern "C" fn(GLenum, GLint, GLsizei)
        ) {
            unsafe { f(mode, first, count) };
            return;
        }
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_draw_elements(
    mode: GLenum,
    count: GLsizei,
    typ: GLenum,
    indices: *const c_void,
) {
    if env_flag_enabled("MOCKTAIL_GLES_NOOP_DRAW_CALLS") {
        return;
    }
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glDrawElements",
            unsafe extern "C" fn(GLenum, GLsizei, GLenum, *const c_void)
        ) {
            unsafe { f(mode, count, typ, indices) };
            return;
        }
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_draw_arrays_instanced(
    mode: GLenum,
    first: GLint,
    count: GLsizei,
    instancecount: GLsizei,
) {
    if env_flag_enabled("MOCKTAIL_GLES_NOOP_DRAW_CALLS") {
        return;
    }
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glDrawArraysInstanced",
            unsafe extern "C" fn(GLenum, GLint, GLsizei, GLsizei)
        ) {
            unsafe { f(mode, first, count, instancecount) };
            return;
        }
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_draw_elements_instanced(
    mode: GLenum,
    count: GLsizei,
    typ: GLenum,
    indices: *const c_void,
    instancecount: GLsizei,
) {
    if env_flag_enabled("MOCKTAIL_GLES_NOOP_DRAW_CALLS") {
        return;
    }
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glDrawElementsInstanced",
            unsafe extern "C" fn(GLenum, GLsizei, GLenum, *const c_void, GLsizei)
        ) {
            unsafe { f(mode, count, typ, indices, instancecount) };
            return;
        }
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_read_pixels(
    x: GLint,
    y: GLint,
    width: GLsizei,
    height: GLsizei,
    format: GLenum,
    typ: GLenum,
    pixels: *mut c_void,
) {
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glReadPixels",
            unsafe extern "C" fn(GLint, GLint, GLsizei, GLsizei, GLenum, GLenum, *mut c_void)
        ) {
            unsafe { f(x, y, width, height, format, typ, pixels) };
            return;
        }
    }
    if !stub_require() || pixels.is_null() || width <= 0 || height <= 0 {
        return;
    }
    let bytes = width as usize * height as usize * 4;
    unsafe { std::ptr::write_bytes(pixels.cast::<u8>(), 0, bytes) };
}

macro_rules! gl_passthrough {
    ($fn_name:ident, $gl_sym:literal, ($($arg:ident : $ty:ty),*)) => {
        #[no_mangle]
        pub extern "C" fn $fn_name($($arg: $ty),*) {
            if host_active() {
                if let Some(f) = host_gl!(FN, $gl_sym, unsafe extern "C" fn($($ty),*)) {
                    unsafe { f($($arg),*) };
                    return;
                }
            }
            let _ = stub_require();
        }
    };
}

gl_passthrough!(mocktail_rust_gl_attach_shader, "glAttachShader", (program: GLuint, shader: GLuint));
gl_passthrough!(mocktail_rust_gl_bind_attrib_location, "glBindAttribLocation", (program: GLuint, index: GLuint, name: *const GLchar));
gl_passthrough!(mocktail_rust_gl_blit_framebuffer, "glBlitFramebuffer", (sx0: GLint, sy0: GLint, sx1: GLint, sy1: GLint, dx0: GLint, dy0: GLint, dx1: GLint, dy1: GLint, mask: GLbitfield, filter: GLenum));
gl_passthrough!(mocktail_rust_gl_buffer_sub_data, "glBufferSubData", (target: GLenum, offset: GLintptr, size: GLsizeiptr, data: *const c_void));
gl_passthrough!(mocktail_rust_gl_clear, "glClear", (mask: GLbitfield));
gl_passthrough!(mocktail_rust_gl_compile_shader, "glCompileShader", (shader: GLuint));
gl_passthrough!(mocktail_rust_gl_compressed_tex_image_2d, "glCompressedTexImage2D", (target: GLenum, level: GLint, internalformat: GLenum, width: GLsizei, height: GLsizei, border: GLint, image_size: GLsizei, data: *const c_void));
gl_passthrough!(mocktail_rust_gl_compressed_tex_sub_image_2d, "glCompressedTexSubImage2D", (target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, width: GLsizei, height: GLsizei, format: GLenum, image_size: GLsizei, data: *const c_void));
gl_passthrough!(mocktail_rust_gl_copy_tex_sub_image_2d, "glCopyTexSubImage2D", (target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, x: GLint, y: GLint, width: GLsizei, height: GLsizei));
gl_passthrough!(mocktail_rust_gl_finish, "glFinish", ());
gl_passthrough!(mocktail_rust_gl_flush, "glFlush", ());
gl_passthrough!(mocktail_rust_gl_framebuffer_renderbuffer, "glFramebufferRenderbuffer", (target: GLenum, attachment: GLenum, renderbuffertarget: GLenum, renderbuffer: GLuint));
gl_passthrough!(mocktail_rust_gl_framebuffer_texture_2d, "glFramebufferTexture2D", (target: GLenum, attachment: GLenum, textarget: GLenum, texture: GLuint, level: GLint));
gl_passthrough!(mocktail_rust_gl_generate_mipmap, "glGenerateMipmap", (target: GLenum));
gl_passthrough!(mocktail_rust_gl_get_program_binary, "glGetProgramBinary", (program: GLuint, buf_size: GLsizei, length: *mut GLsizei, binary_format: *mut GLenum, binary: *mut c_void));
#[no_mangle]
pub extern "C" fn mocktail_rust_gl_link_program(program: GLuint) {
    sync_tls_cache(|c| c.on_program_relinked(program));
    if host_active() {
        if let Some(f) = host_gl!(FN, "glLinkProgram", unsafe extern "C" fn(GLuint)) {
            unsafe { f(program) };
            return;
        }
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_program_binary(
    program: GLuint,
    binary_format: GLenum,
    binary: *const c_void,
    length: GLsizei,
) {
    sync_tls_cache(|c| c.on_program_relinked(program));
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glProgramBinary",
            unsafe extern "C" fn(GLuint, GLenum, *const c_void, GLsizei)
        ) {
            unsafe { f(program, binary_format, binary, length) };
            return;
        }
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_tex_parameterf(
    target: GLenum,
    pname: GLenum,
    param: GLfloat,
) {
    sync_tls_cache(|c| c.invalidate_tex_param(target, pname));
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glTexParameterf",
            unsafe extern "C" fn(GLenum, GLenum, GLfloat)
        ) {
            unsafe { f(target, pname, param) };
            return;
        }
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_tex_parameterfv(
    target: GLenum,
    pname: GLenum,
    params: *const GLfloat,
) {
    sync_tls_cache(|c| c.invalidate_tex_param(target, pname));
    if host_active() {
        if let Some(f) = host_gl!(
            FN,
            "glTexParameterfv",
            unsafe extern "C" fn(GLenum, GLenum, *const GLfloat)
        ) {
            unsafe { f(target, pname, params) };
            return;
        }
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_tex_parameteri(
    target: GLenum,
    pname: GLenum,
    param: GLint,
) {
    if host_active() {
        if with_cache_check(|c| c.should_set_tex_parameteri(target, pname, param)) {
            if let Some(f) = host_gl!(
                FN,
                "glTexParameteri",
                unsafe extern "C" fn(GLenum, GLenum, GLint)
            ) {
                unsafe { f(target, pname, param) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_uniform1i(location: GLint, v0: GLint) {
    if host_active() {
        if with_cache_check(|c| c.should_set_uniform1i(location, v0)) {
            if let Some(f) = host_gl!(FN, "glUniform1i", unsafe extern "C" fn(GLint, GLint)) {
                unsafe { f(location, v0) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_vertex_attrib_divisor(index: GLuint, divisor: GLuint) {
    if host_active() {
        if with_cache_check(|c| c.should_set_vertex_attrib_divisor(index, divisor)) {
            if let Some(f) = host_gl!(
                FN,
                "glVertexAttribDivisor",
                unsafe extern "C" fn(GLuint, GLuint)
            ) {
                unsafe { f(index, divisor) };
            }
        }
        return;
    }
    let _ = stub_require();
}

#[no_mangle]
pub extern "C" fn mocktail_rust_gl_vertex_attrib_pointer(
    index: GLuint,
    size: GLint,
    typ: GLenum,
    normalized: GLboolean,
    stride: GLsizei,
    pointer: *const c_void,
) {
    if host_active() {
        if with_cache_check(|c| {
            c.should_set_vertex_attrib_pointer(index, size, typ, normalized, stride, pointer as usize)
        }) {
            if let Some(f) = host_gl!(
                FN,
                "glVertexAttribPointer",
                unsafe extern "C" fn(GLuint, GLint, GLenum, GLboolean, GLsizei, *const c_void)
            ) {
                unsafe { f(index, size, typ, normalized, stride, pointer) };
            }
        }
        return;
    }
    let _ = stub_require();
}

gl_passthrough!(mocktail_rust_gl_release_shader_compiler, "glReleaseShaderCompiler", ());
gl_passthrough!(mocktail_rust_gl_renderbuffer_storage, "glRenderbufferStorage", (target: GLenum, internalformat: GLenum, width: GLsizei, height: GLsizei));
gl_passthrough!(mocktail_rust_gl_shader_source, "glShaderSource", (shader: GLuint, count: GLsizei, string: *const *const GLchar, length: *const GLint));
gl_passthrough!(mocktail_rust_gl_tex_image_2d, "glTexImage2D", (target: GLenum, level: GLint, internalformat: GLint, width: GLsizei, height: GLsizei, border: GLint, format: GLenum, typ: GLenum, pixels: *const c_void));
gl_passthrough!(mocktail_rust_gl_tex_sub_image_2d, "glTexSubImage2D", (target: GLenum, level: GLint, xoffset: GLint, yoffset: GLint, width: GLsizei, height: GLsizei, format: GLenum, typ: GLenum, pixels: *const c_void));
