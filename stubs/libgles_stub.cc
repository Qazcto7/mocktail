// Thin C ABI trampoline exporting libGLESv2.so entry points.
// All state caching, host forwarding, lifecycle telemetry, and test stubs
// live in Rust (rust/mocktail-gles).

#include <cstdint>

extern "C" {

using GLenum = uint32_t;
using GLboolean = uint8_t;
using GLbitfield = uint32_t;
using GLint = int32_t;
using GLsizei = int32_t;
using GLuint = uint32_t;
using GLfloat = float;
using GLchar = char;
using GLintptr = intptr_t;
using GLsizeiptr = intptr_t;
using GLuint64 = uint64_t;
using GLsync = void*;

const uint8_t* mocktail_rust_gl_get_string(GLenum name);
const uint8_t* mocktail_rust_gl_get_stringi(GLenum name, GLuint index);
GLenum mocktail_rust_gl_get_error();
void mocktail_rust_gl_get_integerv(GLenum pname, GLint* data);
void mocktail_rust_gl_gen_textures(GLsizei n, GLuint* textures);
void mocktail_rust_gl_gen_buffers(GLsizei n, GLuint* buffers);
void mocktail_rust_gl_gen_framebuffers(GLsizei n, GLuint* framebuffers);
void mocktail_rust_gl_gen_renderbuffers(GLsizei n, GLuint* renderbuffers);
void mocktail_rust_gl_gen_vertex_arrays(GLsizei n, GLuint* arrays);
GLuint mocktail_rust_gl_create_shader(GLenum shader_type);
GLuint mocktail_rust_gl_create_program();
void mocktail_rust_gl_delete_textures(GLsizei n, const GLuint* textures);
void mocktail_rust_gl_delete_buffers(GLsizei n, const GLuint* buffers);
void mocktail_rust_gl_delete_framebuffers(GLsizei n, const GLuint* framebuffers);
void mocktail_rust_gl_delete_renderbuffers(GLsizei n,
                                           const GLuint* renderbuffers);
void mocktail_rust_gl_delete_vertex_arrays(GLsizei n, const GLuint* arrays);
void mocktail_rust_gl_delete_shader(GLuint shader);
void mocktail_rust_gl_delete_program(GLuint program);
void mocktail_rust_gl_get_shaderiv(GLuint shader, GLenum pname, GLint* params);
void mocktail_rust_gl_get_programiv(GLuint program, GLenum pname,
                                    GLint* params);
void mocktail_rust_gl_get_shader_info_log(GLuint shader, GLsizei buf_size,
                                          GLsizei* length, GLchar* info_log);
void mocktail_rust_gl_get_program_info_log(GLuint program, GLsizei buf_size,
                                           GLsizei* length, GLchar* info_log);
void mocktail_rust_gl_get_active_uniform(GLuint program, GLuint index,
                                         GLsizei buf_size, GLsizei* length,
                                         GLint* size, GLenum* type,
                                         GLchar* name);
GLint mocktail_rust_gl_get_uniform_location(GLuint program,
                                            const GLchar* name);
GLenum mocktail_rust_gl_check_framebuffer_status(GLenum target);
GLboolean mocktail_rust_gl_is_enabled(GLenum cap);
void mocktail_rust_gl_use_program(GLuint program);
void mocktail_rust_gl_bind_vertex_array(GLuint array);
void mocktail_rust_gl_active_texture(GLenum texture);
void mocktail_rust_gl_bind_texture(GLenum target, GLuint texture);
void mocktail_rust_gl_bind_buffer(GLenum target, GLuint buffer);
void mocktail_rust_gl_bind_buffer_base(GLenum target, GLuint index,
                                       GLuint buffer);
void mocktail_rust_gl_bind_buffer_range(GLenum target, GLuint index,
                                        GLuint buffer, GLintptr offset,
                                        GLsizeiptr size);
void mocktail_rust_gl_bind_framebuffer(GLenum target, GLuint framebuffer);
void mocktail_rust_gl_bind_renderbuffer(GLenum target, GLuint renderbuffer);
void mocktail_rust_gl_enable(GLenum cap);
void mocktail_rust_gl_disable(GLenum cap);
void mocktail_rust_gl_viewport(GLint x, GLint y, GLsizei width, GLsizei height);
void mocktail_rust_gl_scissor(GLint x, GLint y, GLsizei width, GLsizei height);
void mocktail_rust_gl_blend_func(GLenum sfactor, GLenum dfactor);
void mocktail_rust_gl_blend_func_separate(GLenum src_rgb, GLenum dst_rgb,
                                          GLenum src_alpha, GLenum dst_alpha);
void mocktail_rust_gl_depth_mask(GLboolean flag);
void mocktail_rust_gl_depth_func(GLenum func);
void mocktail_rust_gl_color_mask(GLboolean r, GLboolean g, GLboolean b,
                                 GLboolean a);
void mocktail_rust_gl_clear_color(GLfloat r, GLfloat g, GLfloat b, GLfloat a);
void mocktail_rust_gl_clear_depthf(GLfloat depth);
void mocktail_rust_gl_clear_stencil(GLint s);
void mocktail_rust_gl_cull_face(GLenum mode);
void mocktail_rust_gl_front_face(GLenum mode);
void mocktail_rust_gl_stencil_func(GLenum func, GLint ref, GLuint mask);
void mocktail_rust_gl_stencil_func_separate(GLenum face, GLenum func, GLint ref,
                                            GLuint mask);
void mocktail_rust_gl_stencil_mask(GLuint mask);
void mocktail_rust_gl_stencil_mask_separate(GLenum face, GLuint mask);
void mocktail_rust_gl_stencil_op(GLenum fail, GLenum zfail, GLenum zpass);
void mocktail_rust_gl_stencil_op_separate(GLenum face, GLenum sfail,
                                          GLenum dpfail, GLenum dppass);
void mocktail_rust_gl_pixel_storei(GLenum pname, GLint param);
GLsync mocktail_rust_gl_fence_sync(GLenum condition, GLbitfield flags);
void mocktail_rust_gl_delete_sync(GLsync sync);
GLenum mocktail_rust_gl_client_wait_sync(GLsync sync, GLbitfield flags,
                                         GLuint64 timeout);
void mocktail_rust_gl_invalidate_framebuffer(GLenum target,
                                             GLsizei num_attachments,
                                             const GLenum* attachments);
void mocktail_rust_gl_object_label(GLenum identifier, GLuint name,
                                   GLsizei length, const GLchar* label);
void mocktail_rust_gl_draw_arrays(GLenum mode, GLint first, GLsizei count);
void mocktail_rust_gl_draw_elements(GLenum mode, GLsizei count, GLenum type,
                                    const void* indices);
void mocktail_rust_gl_draw_arrays_instanced(GLenum mode, GLint first,
                                            GLsizei count,
                                            GLsizei instancecount);
void mocktail_rust_gl_draw_elements_instanced(GLenum mode, GLsizei count,
                                              GLenum type, const void* indices,
                                              GLsizei instancecount);
void mocktail_rust_gl_read_pixels(GLint x, GLint y, GLsizei width,
                                  GLsizei height, GLenum format, GLenum type,
                                  void* pixels);
void mocktail_rust_gl_attach_shader(GLuint program, GLuint shader);
void mocktail_rust_gl_bind_attrib_location(GLuint program, GLuint index,
                                           const GLchar* name);
void mocktail_rust_gl_blit_framebuffer(GLint sx0, GLint sy0, GLint sx1,
                                       GLint sy1, GLint dx0, GLint dy0,
                                       GLint dx1, GLint dy1, GLbitfield mask,
                                       GLenum filter);
void mocktail_rust_gl_buffer_data(GLenum target, GLsizeiptr size,
                                  const void* data, GLenum usage);
void mocktail_rust_gl_buffer_sub_data(GLenum target, GLintptr offset,
                                      GLsizeiptr size, const void* data);
void mocktail_rust_gl_clear(GLbitfield mask);
void mocktail_rust_gl_compile_shader(GLuint shader);
void mocktail_rust_gl_compressed_tex_image_2d(GLenum target, GLint level,
                                              GLenum internalformat,
                                              GLsizei width, GLsizei height,
                                              GLint border, GLsizei image_size,
                                              const void* data);
void mocktail_rust_gl_compressed_tex_sub_image_2d(
    GLenum target, GLint level, GLint xoffset, GLint yoffset, GLsizei width,
    GLsizei height, GLenum format, GLsizei image_size, const void* data);
void mocktail_rust_gl_copy_tex_sub_image_2d(GLenum target, GLint level,
                                            GLint xoffset, GLint yoffset,
                                            GLint x, GLint y, GLsizei width,
                                            GLsizei height);
void mocktail_rust_gl_disable_vertex_attrib_array(GLuint index);
void mocktail_rust_gl_enable_vertex_attrib_array(GLuint index);
void mocktail_rust_gl_finish();
void mocktail_rust_gl_flush();
void mocktail_rust_gl_framebuffer_renderbuffer(GLenum target, GLenum attachment,
                                              GLenum renderbuffertarget,
                                              GLuint renderbuffer);
void mocktail_rust_gl_framebuffer_texture_2d(GLenum target, GLenum attachment,
                                             GLenum textarget, GLuint texture,
                                             GLint level);
void mocktail_rust_gl_generate_mipmap(GLenum target);
void mocktail_rust_gl_get_program_binary(GLuint program, GLsizei buf_size,
                                         GLsizei* length, GLenum* binary_format,
                                         void* binary);
void mocktail_rust_gl_link_program(GLuint program);
void mocktail_rust_gl_polygon_offset(GLfloat factor, GLfloat units);
void mocktail_rust_gl_program_binary(GLuint program, GLenum binary_format,
                                     const void* binary, GLsizei length);
void mocktail_rust_gl_release_shader_compiler();
void mocktail_rust_gl_renderbuffer_storage(GLenum target, GLenum internalformat,
                                           GLsizei width, GLsizei height);
void mocktail_rust_gl_shader_source(GLuint shader, GLsizei count,
                                    const GLchar* const* string,
                                    const GLint* length);
void mocktail_rust_gl_tex_image_2d(GLenum target, GLint level,
                                   GLint internalformat, GLsizei width,
                                   GLsizei height, GLint border, GLenum format,
                                   GLenum type, const void* pixels);
void mocktail_rust_gl_tex_parameterf(GLenum target, GLenum pname,
                                     GLfloat param);
void mocktail_rust_gl_tex_parameterfv(GLenum target, GLenum pname,
                                      const GLfloat* params);
void mocktail_rust_gl_tex_parameteri(GLenum target, GLenum pname, GLint param);
void mocktail_rust_gl_tex_sub_image_2d(GLenum target, GLint level, GLint xoffset,
                                       GLint yoffset, GLsizei width,
                                       GLsizei height, GLenum format,
                                       GLenum type, const void* pixels);
void mocktail_rust_gl_uniform1i(GLint location, GLint v0);
void mocktail_rust_gl_vertex_attrib_divisor(GLuint index, GLuint divisor);
void mocktail_rust_gl_vertex_attrib_pointer(GLuint index, GLint size,
                                            GLenum type, GLboolean normalized,
                                            GLsizei stride,
                                            const void* pointer);

// Reference bridge helpers so they are retained in libGLESv2.so dynamic table.
void* mocktail_gles_lookup_proc(const char* procname);
void mocktail_gles_on_make_current(uintptr_t ctx);
void mocktail_gles_on_context_destroy(uintptr_t ctx);
void mocktail_gles_invalidate_state_cache();
void mocktail_gles_dump_stats();

// Public C GLES entry points
const uint8_t* glGetString(GLenum name) {
  return mocktail_rust_gl_get_string(name);
}
const uint8_t* glGetStringi(GLenum name, GLuint index) {
  return mocktail_rust_gl_get_stringi(name, index);
}
GLenum glGetError() { return mocktail_rust_gl_get_error(); }
void glGetIntegerv(GLenum pname, GLint* data) {
  mocktail_rust_gl_get_integerv(pname, data);
}
void glGenTextures(GLsizei n, GLuint* textures) {
  mocktail_rust_gl_gen_textures(n, textures);
}
void glGenBuffers(GLsizei n, GLuint* buffers) {
  mocktail_rust_gl_gen_buffers(n, buffers);
}
void glGenFramebuffers(GLsizei n, GLuint* framebuffers) {
  mocktail_rust_gl_gen_framebuffers(n, framebuffers);
}
void glGenRenderbuffers(GLsizei n, GLuint* renderbuffers) {
  mocktail_rust_gl_gen_renderbuffers(n, renderbuffers);
}
void glGenVertexArrays(GLsizei n, GLuint* arrays) {
  mocktail_rust_gl_gen_vertex_arrays(n, arrays);
}
GLuint glCreateShader(GLenum shader_type) {
  return mocktail_rust_gl_create_shader(shader_type);
}
GLuint glCreateProgram() { return mocktail_rust_gl_create_program(); }
void glDeleteTextures(GLsizei n, const GLuint* textures) {
  mocktail_rust_gl_delete_textures(n, textures);
}
void glDeleteBuffers(GLsizei n, const GLuint* buffers) {
  mocktail_rust_gl_delete_buffers(n, buffers);
}
void glDeleteFramebuffers(GLsizei n, const GLuint* framebuffers) {
  mocktail_rust_gl_delete_framebuffers(n, framebuffers);
}
void glDeleteRenderbuffers(GLsizei n, const GLuint* renderbuffers) {
  mocktail_rust_gl_delete_renderbuffers(n, renderbuffers);
}
void glDeleteVertexArrays(GLsizei n, const GLuint* arrays) {
  mocktail_rust_gl_delete_vertex_arrays(n, arrays);
}
void glDeleteShader(GLuint shader) { mocktail_rust_gl_delete_shader(shader); }
void glDeleteProgram(GLuint program) {
  mocktail_rust_gl_delete_program(program);
}
void glGetShaderiv(GLuint shader, GLenum pname, GLint* params) {
  mocktail_rust_gl_get_shaderiv(shader, pname, params);
}
void glGetProgramiv(GLuint program, GLenum pname, GLint* params) {
  mocktail_rust_gl_get_programiv(program, pname, params);
}
void glGetShaderInfoLog(GLuint shader, GLsizei buf_size, GLsizei* length,
                        GLchar* info_log) {
  mocktail_rust_gl_get_shader_info_log(shader, buf_size, length, info_log);
}
void glGetProgramInfoLog(GLuint program, GLsizei buf_size, GLsizei* length,
                         GLchar* info_log) {
  mocktail_rust_gl_get_program_info_log(program, buf_size, length, info_log);
}
void glGetActiveUniform(GLuint program, GLuint index, GLsizei buf_size,
                        GLsizei* length, GLint* size, GLenum* type,
                        GLchar* name) {
  mocktail_rust_gl_get_active_uniform(program, index, buf_size, length, size,
                                      type, name);
}
GLint glGetUniformLocation(GLuint program, const GLchar* name) {
  return mocktail_rust_gl_get_uniform_location(program, name);
}
GLenum glCheckFramebufferStatus(GLenum target) {
  return mocktail_rust_gl_check_framebuffer_status(target);
}
GLboolean glIsEnabled(GLenum cap) { return mocktail_rust_gl_is_enabled(cap); }
void glUseProgram(GLuint program) { mocktail_rust_gl_use_program(program); }
void glBindVertexArray(GLuint array) {
  mocktail_rust_gl_bind_vertex_array(array);
}
void glActiveTexture(GLenum texture) {
  mocktail_rust_gl_active_texture(texture);
}
void glBindTexture(GLenum target, GLuint texture) {
  mocktail_rust_gl_bind_texture(target, texture);
}
void glBindBuffer(GLenum target, GLuint buffer) {
  mocktail_rust_gl_bind_buffer(target, buffer);
}
void glBindBufferBase(GLenum target, GLuint index, GLuint buffer) {
  mocktail_rust_gl_bind_buffer_base(target, index, buffer);
}
void glBindBufferRange(GLenum target, GLuint index, GLuint buffer,
                       GLintptr offset, GLsizeiptr size) {
  mocktail_rust_gl_bind_buffer_range(target, index, buffer, offset, size);
}
void glBindFramebuffer(GLenum target, GLuint framebuffer) {
  mocktail_rust_gl_bind_framebuffer(target, framebuffer);
}
void glBindRenderbuffer(GLenum target, GLuint renderbuffer) {
  mocktail_rust_gl_bind_renderbuffer(target, renderbuffer);
}
void glEnable(GLenum cap) { mocktail_rust_gl_enable(cap); }
void glDisable(GLenum cap) { mocktail_rust_gl_disable(cap); }
void glViewport(GLint x, GLint y, GLsizei width, GLsizei height) {
  mocktail_rust_gl_viewport(x, y, width, height);
}
void glScissor(GLint x, GLint y, GLsizei width, GLsizei height) {
  mocktail_rust_gl_scissor(x, y, width, height);
}
void glBlendFunc(GLenum sfactor, GLenum dfactor) {
  mocktail_rust_gl_blend_func(sfactor, dfactor);
}
void glBlendFuncSeparate(GLenum src_rgb, GLenum dst_rgb, GLenum src_alpha,
                         GLenum dst_alpha) {
  mocktail_rust_gl_blend_func_separate(src_rgb, dst_rgb, src_alpha, dst_alpha);
}
void glDepthMask(GLboolean flag) { mocktail_rust_gl_depth_mask(flag); }
void glDepthFunc(GLenum func) { mocktail_rust_gl_depth_func(func); }
void glColorMask(GLboolean r, GLboolean g, GLboolean b, GLboolean a) {
  mocktail_rust_gl_color_mask(r, g, b, a);
}
void glClearColor(GLfloat r, GLfloat g, GLfloat b, GLfloat a) {
  mocktail_rust_gl_clear_color(r, g, b, a);
}
void glClearDepthf(GLfloat depth) { mocktail_rust_gl_clear_depthf(depth); }
void glClearStencil(GLint s) { mocktail_rust_gl_clear_stencil(s); }
void glCullFace(GLenum mode) { mocktail_rust_gl_cull_face(mode); }
void glFrontFace(GLenum mode) { mocktail_rust_gl_front_face(mode); }
void glStencilFunc(GLenum func, GLint ref, GLuint mask) {
  mocktail_rust_gl_stencil_func(func, ref, mask);
}
void glStencilFuncSeparate(GLenum face, GLenum func, GLint ref, GLuint mask) {
  mocktail_rust_gl_stencil_func_separate(face, func, ref, mask);
}
void glStencilMask(GLuint mask) { mocktail_rust_gl_stencil_mask(mask); }
void glStencilMaskSeparate(GLenum face, GLuint mask) {
  mocktail_rust_gl_stencil_mask_separate(face, mask);
}
void glStencilOp(GLenum fail, GLenum zfail, GLenum zpass) {
  mocktail_rust_gl_stencil_op(fail, zfail, zpass);
}
void glStencilOpSeparate(GLenum face, GLenum sfail, GLenum dpfail,
                         GLenum dppass) {
  mocktail_rust_gl_stencil_op_separate(face, sfail, dpfail, dppass);
}
void glPixelStorei(GLenum pname, GLint param) {
  mocktail_rust_gl_pixel_storei(pname, param);
}
GLsync glFenceSync(GLenum condition, GLbitfield flags) {
  return mocktail_rust_gl_fence_sync(condition, flags);
}
void glDeleteSync(GLsync sync) { mocktail_rust_gl_delete_sync(sync); }
GLenum glClientWaitSync(GLsync sync, GLbitfield flags, GLuint64 timeout) {
  return mocktail_rust_gl_client_wait_sync(sync, flags, timeout);
}
void glInvalidateFramebuffer(GLenum target, GLsizei num_attachments,
                             const GLenum* attachments) {
  mocktail_rust_gl_invalidate_framebuffer(target, num_attachments, attachments);
}
void glObjectLabel(GLenum identifier, GLuint name, GLsizei length,
                   const GLchar* label) {
  mocktail_rust_gl_object_label(identifier, name, length, label);
}
void glObjectLabelKHR(GLenum identifier, GLuint name, GLsizei length,
                      const GLchar* label) {
  mocktail_rust_gl_object_label(identifier, name, length, label);
}
void glDrawArrays(GLenum mode, GLint first, GLsizei count) {
  mocktail_rust_gl_draw_arrays(mode, first, count);
}
void glDrawElements(GLenum mode, GLsizei count, GLenum type,
                    const void* indices) {
  mocktail_rust_gl_draw_elements(mode, count, type, indices);
}
void glDrawArraysInstanced(GLenum mode, GLint first, GLsizei count,
                           GLsizei instancecount) {
  mocktail_rust_gl_draw_arrays_instanced(mode, first, count, instancecount);
}
void glDrawElementsInstanced(GLenum mode, GLsizei count, GLenum type,
                             const void* indices, GLsizei instancecount) {
  mocktail_rust_gl_draw_elements_instanced(mode, count, type, indices,
                                           instancecount);
}
void glReadPixels(GLint x, GLint y, GLsizei width, GLsizei height, GLenum format,
                  GLenum type, void* pixels) {
  mocktail_rust_gl_read_pixels(x, y, width, height, format, type, pixels);
}
void glAttachShader(GLuint program, GLuint shader) {
  mocktail_rust_gl_attach_shader(program, shader);
}
void glBindAttribLocation(GLuint program, GLuint index, const GLchar* name) {
  mocktail_rust_gl_bind_attrib_location(program, index, name);
}
void glBlitFramebuffer(GLint sx0, GLint sy0, GLint sx1, GLint sy1, GLint dx0,
                       GLint dy0, GLint dx1, GLint dy1, GLbitfield mask,
                       GLenum filter) {
  mocktail_rust_gl_blit_framebuffer(sx0, sy0, sx1, sy1, dx0, dy0, dx1, dy1,
                                    mask, filter);
}
void glBufferData(GLenum target, GLsizeiptr size, const void* data,
                  GLenum usage) {
  mocktail_rust_gl_buffer_data(target, size, data, usage);
}
void glBufferSubData(GLenum target, GLintptr offset, GLsizeiptr size,
                     const void* data) {
  mocktail_rust_gl_buffer_sub_data(target, offset, size, data);
}
void glClear(GLbitfield mask) { mocktail_rust_gl_clear(mask); }
void glCompileShader(GLuint shader) { mocktail_rust_gl_compile_shader(shader); }
void glCompressedTexImage2D(GLenum target, GLint level, GLenum internalformat,
                            GLsizei width, GLsizei height, GLint border,
                            GLsizei image_size, const void* data) {
  mocktail_rust_gl_compressed_tex_image_2d(target, level, internalformat, width,
                                           height, border, image_size, data);
}
void glCompressedTexSubImage2D(GLenum target, GLint level, GLint xoffset,
                               GLint yoffset, GLsizei width, GLsizei height,
                               GLenum format, GLsizei image_size,
                               const void* data) {
  mocktail_rust_gl_compressed_tex_sub_image_2d(
      target, level, xoffset, yoffset, width, height, format, image_size, data);
}
void glCopyTexSubImage2D(GLenum target, GLint level, GLint xoffset,
                         GLint yoffset, GLint x, GLint y, GLsizei width,
                         GLsizei height) {
  mocktail_rust_gl_copy_tex_sub_image_2d(target, level, xoffset, yoffset, x, y,
                                         width, height);
}
void glDisableVertexAttribArray(GLuint index) {
  mocktail_rust_gl_disable_vertex_attrib_array(index);
}
void glEnableVertexAttribArray(GLuint index) {
  mocktail_rust_gl_enable_vertex_attrib_array(index);
}
void glFinish() { mocktail_rust_gl_finish(); }
void glFlush() { mocktail_rust_gl_flush(); }
void glFramebufferRenderbuffer(GLenum target, GLenum attachment,
                               GLenum renderbuffertarget, GLuint renderbuffer) {
  mocktail_rust_gl_framebuffer_renderbuffer(target, attachment,
                                            renderbuffertarget, renderbuffer);
}
void glFramebufferTexture2D(GLenum target, GLenum attachment, GLenum textarget,
                            GLuint texture, GLint level) {
  mocktail_rust_gl_framebuffer_texture_2d(target, attachment, textarget,
                                          texture, level);
}
void glGenerateMipmap(GLenum target) {
  mocktail_rust_gl_generate_mipmap(target);
}
void glGetProgramBinary(GLuint program, GLsizei buf_size, GLsizei* length,
                        GLenum* binary_format, void* binary) {
  mocktail_rust_gl_get_program_binary(program, buf_size, length, binary_format,
                                      binary);
}
void glLinkProgram(GLuint program) { mocktail_rust_gl_link_program(program); }
void glPolygonOffset(GLfloat factor, GLfloat units) {
  mocktail_rust_gl_polygon_offset(factor, units);
}
void glProgramBinary(GLuint program, GLenum binary_format, const void* binary,
                     GLsizei length) {
  mocktail_rust_gl_program_binary(program, binary_format, binary, length);
}
void glReleaseShaderCompiler() { mocktail_rust_gl_release_shader_compiler(); }
void glRenderbufferStorage(GLenum target, GLenum internalformat, GLsizei width,
                           GLsizei height) {
  mocktail_rust_gl_renderbuffer_storage(target, internalformat, width, height);
}
void glShaderSource(GLuint shader, GLsizei count, const GLchar* const* string,
                    const GLint* length) {
  mocktail_rust_gl_shader_source(shader, count, string, length);
}
void glTexImage2D(GLenum target, GLint level, GLint internalformat,
                  GLsizei width, GLsizei height, GLint border, GLenum format,
                  GLenum type, const void* pixels) {
  mocktail_rust_gl_tex_image_2d(target, level, internalformat, width, height,
                                border, format, type, pixels);
}
void glTexParameterf(GLenum target, GLenum pname, GLfloat param) {
  mocktail_rust_gl_tex_parameterf(target, pname, param);
}
void glTexParameterfv(GLenum target, GLenum pname, const GLfloat* params) {
  mocktail_rust_gl_tex_parameterfv(target, pname, params);
}
void glTexParameteri(GLenum target, GLenum pname, GLint param) {
  mocktail_rust_gl_tex_parameteri(target, pname, param);
}
void glTexSubImage2D(GLenum target, GLint level, GLint xoffset, GLint yoffset,
                     GLsizei width, GLsizei height, GLenum format, GLenum type,
                     const void* pixels) {
  mocktail_rust_gl_tex_sub_image_2d(target, level, xoffset, yoffset, width,
                                    height, format, type, pixels);
}
void glUniform1i(GLint location, GLint v0) {
  mocktail_rust_gl_uniform1i(location, v0);
}
void glVertexAttribDivisor(GLuint index, GLuint divisor) {
  mocktail_rust_gl_vertex_attrib_divisor(index, divisor);
}
void glVertexAttribPointer(GLuint index, GLint size, GLenum type,
                           GLboolean normalized, GLsizei stride,
                           const void* pointer) {
  mocktail_rust_gl_vertex_attrib_pointer(index, size, type, normalized, stride,
                                         pointer);
}

// Keep bridge hooks referenced so `--gc-sections` and staticlib extraction
// preserve them cleanly under glesv2.ver.
static const void* kMocktailGlesBridgeKeepalive[] = {
    reinterpret_cast<const void*>(&mocktail_gles_lookup_proc),
    reinterpret_cast<const void*>(&mocktail_gles_on_make_current),
    reinterpret_cast<const void*>(&mocktail_gles_on_context_destroy),
    reinterpret_cast<const void*>(&mocktail_gles_invalidate_state_cache),
    reinterpret_cast<const void*>(&mocktail_gles_dump_stats),
};

const void* mocktail_gles_keepalive_anchor() {
  return kMocktailGlesBridgeKeepalive;
}

}  // extern "C"
