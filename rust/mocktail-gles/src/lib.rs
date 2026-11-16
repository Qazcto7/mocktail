//! `mocktail-gles`: Pure-Rust EGL 1.5 & GLES 3.x adapter/interceptor runtime.

pub mod dl;
pub mod egl;
pub mod gles;

#[cfg(test)]
mod tests {
    use super::egl::{
        fallback_config_attrib, mocktail_rust_egl_choose_config, mocktail_rust_egl_create_context,
        mocktail_rust_egl_create_pbuffer_surface, mocktail_rust_egl_destroy_context,
        mocktail_rust_egl_destroy_surface, mocktail_rust_egl_get_config_attrib,
        mocktail_rust_egl_get_current_context, mocktail_rust_egl_get_current_surface,
        mocktail_rust_egl_get_display, mocktail_rust_egl_get_error,
        mocktail_rust_egl_get_proc_address, mocktail_rust_egl_initialize,
        mocktail_rust_egl_make_current, EGLConfig, EGL_CONFIG_CAVEAT, EGL_DRAW,
        EGL_MAX_SWAP_INTERVAL, EGL_MIN_SWAP_INTERVAL, EGL_NONE, EGL_OPENGL_ES2_BIT,
        EGL_OPENGL_ES3_BIT_KHR, EGL_PBUFFER_BIT, EGL_READ, EGL_RENDERABLE_TYPE, EGL_SUCCESS,
        EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
    };
    use super::gles::{
        mocktail_gles_lookup_proc, mocktail_rust_gl_get_error, mocktail_rust_gl_get_string,
        GlStateCache, IndexedBufferBinding, GL_ARRAY_BUFFER, GL_DRAW_FRAMEBUFFER,
        GL_ELEMENT_ARRAY_BUFFER, GL_FRAMEBUFFER, GL_READ_FRAMEBUFFER, GL_SHADER_STORAGE_BUFFER,
        GL_TEXTURE0, GL_TEXTURE_2D, GL_UNIFORM_BUFFER, GL_VERSION,
    };
    use std::ffi::CString;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn state_cache_elides_redundant_binds_and_respects_vao_ebo_rule() {
        let mut cache = GlStateCache::default();
        assert!(cache.should_use_program(42));
        assert!(!cache.should_use_program(42));
        assert!(cache.should_use_program(99));

        assert!(cache.should_bind_vao(1));
        assert!(cache.should_bind_buffer(GL_ELEMENT_ARRAY_BUFFER, 7));
        assert!(!cache.should_bind_buffer(GL_ELEMENT_ARRAY_BUFFER, 7));

        // Switching VAO invalidates cached element_array_buffer binding per GLES 3 spec.
        assert!(cache.should_bind_vao(2));
        assert!(cache.should_bind_buffer(GL_ELEMENT_ARRAY_BUFFER, 7));

        assert!(cache.should_bind_buffer(GL_ARRAY_BUFFER, 10));
        assert!(!cache.should_bind_buffer(GL_ARRAY_BUFFER, 10));
        cache.on_delete_buffers(&[10]);
        assert!(cache.should_bind_buffer(GL_ARRAY_BUFFER, 10));
    }

    #[test]
    fn state_cache_tracks_texture_units_fbos_and_indexed_buffers() {
        let mut cache = GlStateCache::default();
        assert!(cache.should_set_active_texture(GL_TEXTURE0));
        assert!(!cache.should_set_active_texture(GL_TEXTURE0));
        assert!(cache.should_bind_texture(GL_TEXTURE_2D, 11));
        assert!(!cache.should_bind_texture(GL_TEXTURE_2D, 11));

        assert!(cache.should_set_active_texture(GL_TEXTURE0 + 1));
        assert!(cache.should_bind_texture(GL_TEXTURE_2D, 11));
        cache.on_delete_textures(&[11]);
        assert!(cache.should_bind_texture(GL_TEXTURE_2D, 11));

        assert!(cache.should_bind_framebuffer(GL_FRAMEBUFFER, 5));
        assert!(!cache.should_bind_framebuffer(GL_DRAW_FRAMEBUFFER, 5));
        assert!(!cache.should_bind_framebuffer(GL_READ_FRAMEBUFFER, 5));
        assert!(cache.should_bind_framebuffer(GL_READ_FRAMEBUFFER, 0));
        assert!(cache.should_bind_framebuffer(GL_FRAMEBUFFER, 5));

        assert!(cache.should_bind_buffer(GL_UNIFORM_BUFFER, 3));
        cache.on_bind_buffer_indexed(GL_UNIFORM_BUFFER);
        assert!(cache.should_bind_buffer(GL_UNIFORM_BUFFER, 3));
    }

    #[test]
    fn config_attribs_include_swap_intervals_and_es3_bit() {
        assert_eq!(fallback_config_attrib(EGL_MIN_SWAP_INTERVAL), Some(0));
        assert_eq!(fallback_config_attrib(EGL_MAX_SWAP_INTERVAL), Some(4));
        assert_eq!(fallback_config_attrib(EGL_CONFIG_CAVEAT), Some(EGL_NONE));
        let renderable = fallback_config_attrib(EGL_RENDERABLE_TYPE).unwrap();
        assert_ne!(renderable & EGL_OPENGL_ES2_BIT, 0);
        assert_ne!(renderable & EGL_OPENGL_ES3_BIT_KHR, 0);
        let surf = fallback_config_attrib(EGL_SURFACE_TYPE).unwrap();
        assert_ne!(surf & EGL_PBUFFER_BIT, 0);
        assert_ne!(surf & EGL_WINDOW_BIT, 0);
    }

    #[test]
    fn egl_stub_read_draw_surfaces_and_proc_lookup_work() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("MOCKTAIL_ENABLE_TEST_GRAPHICS_STUBS", "1");

        let dpy = mocktail_rust_egl_get_display(std::ptr::null_mut());
        assert!(!dpy.is_null());
        let mut maj = 0;
        let mut min = 0;
        assert_eq!(mocktail_rust_egl_initialize(dpy, &mut maj, &mut min), 1);

        let mut cfg: EGLConfig = std::ptr::null_mut();
        let mut ncfg = 0;
        assert_eq!(
            mocktail_rust_egl_choose_config(dpy, std::ptr::null(), &mut cfg, 1, &mut ncfg),
            1
        );
        let mut min_iv = -1;
        assert_eq!(
            mocktail_rust_egl_get_config_attrib(dpy, cfg, EGL_MIN_SWAP_INTERVAL, &mut min_iv),
            1
        );
        assert_eq!(min_iv, 0);

        let ctx = mocktail_rust_egl_create_context(dpy, cfg, std::ptr::null_mut(), std::ptr::null());
        let pb1 = mocktail_rust_egl_create_pbuffer_surface(dpy, cfg, std::ptr::null());
        let pb2 = mocktail_rust_egl_create_pbuffer_surface(dpy, cfg, std::ptr::null());
        assert!(!ctx.is_null() && !pb1.is_null() && !pb2.is_null() && pb1 != pb2);

        assert_eq!(mocktail_rust_egl_make_current(dpy, pb1, pb2, ctx), 1);
        assert_eq!(mocktail_rust_egl_get_current_context(), ctx);
        assert_eq!(mocktail_rust_egl_get_current_surface(EGL_DRAW), pb1);
        assert_eq!(mocktail_rust_egl_get_current_surface(EGL_READ), pb2);
        assert_eq!(mocktail_rust_egl_get_error(), EGL_SUCCESS);

        assert!(!mocktail_rust_gl_get_string(GL_VERSION).is_null());
        assert_eq!(mocktail_rust_gl_get_error(), 0);

        let proc_name = CString::new("glFenceSync").unwrap();
        assert!(!mocktail_gles_lookup_proc(proc_name.as_ptr()).is_null());
        let egl_name = CString::new("eglGetConfigAttrib").unwrap();
        assert!(!mocktail_rust_egl_get_proc_address(egl_name.as_ptr()).is_null());

        assert_eq!(
            mocktail_rust_egl_make_current(
                dpy,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut()
            ),
            1
        );
        assert_eq!(mocktail_rust_egl_destroy_surface(dpy, pb1), 1);
        assert_eq!(mocktail_rust_egl_destroy_surface(dpy, pb2), 1);
        assert_eq!(mocktail_rust_egl_destroy_context(dpy, ctx), 1);
        std::env::remove_var("MOCKTAIL_ENABLE_TEST_GRAPHICS_STUBS");
    }

    #[test]
    fn state_cache_deduplicates_viewport_blend_caps_and_masks() {
        let mut cache = GlStateCache::default();
        assert!(cache.should_set_viewport(0, 0, 1280, 720));
        assert!(!cache.should_set_viewport(0, 0, 1280, 720));
        assert!(cache.should_set_viewport(0, 0, 1920, 1080));

        assert!(cache.should_set_scissor(10, 10, 100, 100));
        assert!(!cache.should_set_scissor(10, 10, 100, 100));

        assert!(cache.should_set_blend_func(0x0302, 0x0303));
        assert!(!cache.should_set_blend_func_separate(0x0302, 0x0303, 0x0302, 0x0303));
        assert!(cache.should_set_blend_func_separate(0x0302, 0x0303, 1, 0x0303));

        assert!(cache.should_set_cap(0x0BE2, true)); // GL_BLEND
        assert!(!cache.should_set_cap(0x0BE2, true));
        assert!(cache.should_set_cap(0x0BE2, false));

        assert!(cache.should_set_depth_mask(1));
        assert!(!cache.should_set_depth_mask(255)); // any non-zero GLboolean normalizes
        assert!(cache.should_set_depth_mask(0));

        assert!(cache.should_set_color_mask(1, 1, 1, 1));
        assert!(!cache.should_set_color_mask(2, 1, 1, 1));
        assert!(cache.should_set_color_mask(1, 0, 1, 1));
    }

    #[test]
    fn state_cache_phase2_tracks_attribs_indexed_buffers_and_polygon_offset() {
        let mut cache = GlStateCache::default();

        // Vertex attrib enable flags follow the currently bound VAO.
        assert!(cache.should_bind_vao(10));
        assert!(cache.should_set_vertex_attrib_enabled(0, true));
        assert!(!cache.should_set_vertex_attrib_enabled(0, true));
        assert!(cache.should_set_vertex_attrib_enabled(0, false));
        assert!(!cache.should_set_vertex_attrib_enabled(0, false));
        assert!(cache.should_set_vertex_attrib_enabled(16, true));
        assert!(cache.should_set_vertex_attrib_enabled(16, true));

        // Switching or deleting VAO invalidates per-VAO attrib bits.
        assert!(cache.should_bind_vao(11));
        assert!(cache.should_set_vertex_attrib_enabled(0, false));
        cache.on_delete_vaos(&[11]);
        assert!(cache.should_set_vertex_attrib_enabled(0, false));

        // Indexed buffer slots respect generic binding and Base vs Range variants.
        assert!(cache.should_bind_buffer_indexed(
            GL_UNIFORM_BUFFER,
            0,
            IndexedBufferBinding::Base(5)
        ));
        assert!(!cache.should_bind_buffer_indexed(
            GL_UNIFORM_BUFFER,
            0,
            IndexedBufferBinding::Base(5)
        ));
        assert!(!cache.should_bind_buffer(GL_UNIFORM_BUFFER, 5));
        // Intervening generic bind forces rebind because glBindBufferBase also sets generic binding.
        assert!(cache.should_bind_buffer(GL_UNIFORM_BUFFER, 9));
        assert!(cache.should_bind_buffer_indexed(
            GL_UNIFORM_BUFFER,
            0,
            IndexedBufferBinding::Base(5)
        ));
        // Range with different offset/size or vs Base never collides.
        assert!(cache.should_bind_buffer_indexed(
            GL_UNIFORM_BUFFER,
            0,
            IndexedBufferBinding::Range {
                buffer: 5,
                offset: 0,
                size: 128,
            }
        ));
        assert!(!cache.should_bind_buffer_indexed(
            GL_UNIFORM_BUFFER,
            0,
            IndexedBufferBinding::Range {
                buffer: 5,
                offset: 0,
                size: 128,
            }
        ));
        // glBufferData / glDeleteBuffers invalidate cached indexed slots for that buffer.
        cache.on_buffer_data(GL_UNIFORM_BUFFER);
        assert!(cache.should_bind_buffer_indexed(
            GL_UNIFORM_BUFFER,
            0,
            IndexedBufferBinding::Range {
                buffer: 5,
                offset: 0,
                size: 128,
            }
        ));
        cache.on_delete_buffers(&[5]);
        assert!(cache.should_bind_buffer_indexed(
            GL_UNIFORM_BUFFER,
            0,
            IndexedBufferBinding::Range {
                buffer: 5,
                offset: 0,
                size: 128,
            }
        ));
        // SSBO out-of-min-spec index passes through safely without polluting slot 0.
        assert!(cache.should_bind_buffer_indexed(
            GL_SHADER_STORAGE_BUFFER,
            4,
            IndexedBufferBinding::Base(7)
        ));
        assert!(cache.should_bind_buffer_indexed(
            GL_SHADER_STORAGE_BUFFER,
            4,
            IndexedBufferBinding::Base(7)
        ));

        // Polygon offset deduplication.
        assert!(cache.should_set_polygon_offset(1.0, 2.0));
        assert!(!cache.should_set_polygon_offset(1.0, 2.0));
        assert!(cache.should_set_polygon_offset(-1.0, 2.0));
    }

    #[test]
    fn state_cache_phase3_tracks_uniforms_vertex_attrib_layouts_tex_params_and_trim() {
        let mut cache = GlStateCache::default();

        // Program-scoped uniform1i deduplication and relink/delete invalidation.
        assert!(cache.should_set_uniform1i(0, 2)); // No active program yet -> bypass
        assert!(cache.should_use_program(17));
        assert!(cache.should_set_uniform1i(0, 2));
        assert!(!cache.should_set_uniform1i(0, 2));
        assert!(cache.should_set_uniform1i(0, 3));
        assert!(cache.should_set_uniform1i(-1, 0)); // Invalid location -> bypass
        cache.on_program_relinked(17);
        assert!(cache.should_set_uniform1i(0, 3));

        // Uniform location cache lifecycle & trim cleanup.
        assert_eq!(cache.lookup_uniform_location(17, "u_tex"), None);
        cache.store_uniform_location(17, "u_tex", 4);
        assert_eq!(cache.lookup_uniform_location(17, "u_tex"), Some(4));
        cache.on_program_relinked(17);
        assert_eq!(cache.lookup_uniform_location(17, "u_tex"), None);
        cache.store_uniform_location(17, "u_tex", 4);
        cache.trim_ephemeral_caches();
        assert_eq!(cache.lookup_uniform_location(17, "u_tex"), None);

        // VertexAttribPointer depends on bound VAO + ARRAY_BUFFER, and Divisor depends on VAO.
        assert!(cache.should_bind_vao(1));
        assert!(cache.should_bind_buffer(GL_ARRAY_BUFFER, 20));
        assert!(cache.should_set_vertex_attrib_pointer(0, 3, 0x1406, 0, 12, 0));
        assert!(!cache.should_set_vertex_attrib_pointer(0, 3, 0x1406, 0, 12, 0));
        assert!(cache.should_bind_buffer(GL_ARRAY_BUFFER, 21));
        assert!(cache.should_set_vertex_attrib_pointer(0, 3, 0x1406, 0, 12, 0));
        assert!(cache.should_set_vertex_attrib_divisor(0, 1));
        assert!(!cache.should_set_vertex_attrib_divisor(0, 1));
        cache.on_delete_buffers(&[21]);
        assert!(cache.should_bind_buffer(GL_ARRAY_BUFFER, 21));
        assert!(cache.should_set_vertex_attrib_pointer(0, 3, 0x1406, 0, 12, 0));
        assert!(cache.should_bind_vao(2));
        assert!(cache.should_set_vertex_attrib_pointer(0, 3, 0x1406, 0, 12, 0));
        assert!(cache.should_set_vertex_attrib_divisor(0, 1));

        // Per-texture TexParameteri deduplication and invalidation.
        assert!(cache.should_set_active_texture(GL_TEXTURE0));
        assert!(cache.should_bind_texture(GL_TEXTURE_2D, 30));
        assert!(cache.should_set_tex_parameteri(GL_TEXTURE_2D, 0x2801, 0x2601));
        assert!(!cache.should_set_tex_parameteri(GL_TEXTURE_2D, 0x2801, 0x2601));
        cache.invalidate_tex_param(GL_TEXTURE_2D, 0x2801);
        assert!(cache.should_set_tex_parameteri(GL_TEXTURE_2D, 0x2801, 0x2601));
        cache.on_delete_textures(&[30]);
        assert!(cache.should_bind_texture(GL_TEXTURE_2D, 30));
        assert!(cache.should_set_tex_parameteri(GL_TEXTURE_2D, 0x2801, 0x2601));
    }
}
