// Thin C ABI trampoline exporting the Bionic libEGL.so entry points.
// All EGL state, shared-context/pbuffer delegation, and proc routing live in
// Rust (rust/mocktail-gles).

#include <cstdint>

extern "C" {

using EGLBoolean = unsigned int;
using EGLint = int32_t;
using EGLenum = unsigned int;
using EGLDisplay = void*;
using EGLConfig = void*;
using EGLContext = void*;
using EGLSurface = void*;
using EGLNativeDisplayType = void*;
using EGLNativeWindowType = void*;

EGLint mocktail_rust_egl_get_error();
EGLDisplay mocktail_rust_egl_get_display(EGLNativeDisplayType display_id);
EGLBoolean mocktail_rust_egl_initialize(EGLDisplay display, EGLint* major,
                                        EGLint* minor);
EGLBoolean mocktail_rust_egl_terminate(EGLDisplay display);
EGLBoolean mocktail_rust_egl_bind_api(EGLenum api);
const char* mocktail_rust_egl_query_string(EGLDisplay display, EGLint name);
EGLBoolean mocktail_rust_egl_choose_config(EGLDisplay display,
                                           const EGLint* attrib_list,
                                           EGLConfig* configs,
                                           EGLint config_size,
                                           EGLint* num_config);
EGLBoolean mocktail_rust_egl_get_config_attrib(EGLDisplay display,
                                               EGLConfig config,
                                               EGLint attribute, EGLint* value);
EGLSurface mocktail_rust_egl_create_window_surface(EGLDisplay display,
                                                   EGLConfig config,
                                                   EGLNativeWindowType win,
                                                   const EGLint* attrib_list);
EGLSurface mocktail_rust_egl_create_pbuffer_surface(EGLDisplay display,
                                                    EGLConfig config,
                                                    const EGLint* attrib_list);
EGLBoolean mocktail_rust_egl_destroy_surface(EGLDisplay display,
                                             EGLSurface surface);
EGLContext mocktail_rust_egl_create_context(EGLDisplay display,
                                            EGLConfig config,
                                            EGLContext share_context,
                                            const EGLint* attrib_list);
EGLBoolean mocktail_rust_egl_destroy_context(EGLDisplay display,
                                             EGLContext context);
EGLBoolean mocktail_rust_egl_make_current(EGLDisplay display, EGLSurface draw,
                                          EGLSurface read, EGLContext context);
EGLContext mocktail_rust_egl_get_current_context();
EGLDisplay mocktail_rust_egl_get_current_display();
EGLSurface mocktail_rust_egl_get_current_surface(EGLint readdraw);
EGLBoolean mocktail_rust_egl_query_surface(EGLDisplay display, EGLSurface surface,
                                           EGLint attribute, EGLint* value);
EGLBoolean mocktail_rust_egl_swap_buffers(EGLDisplay display,
                                          EGLSurface surface);
EGLBoolean mocktail_rust_egl_swap_interval(EGLDisplay display, EGLint interval);
void* mocktail_rust_egl_get_proc_address(const char* procname);

EGLint eglGetError() { return mocktail_rust_egl_get_error(); }

EGLDisplay eglGetDisplay(EGLNativeDisplayType display_id) {
  return mocktail_rust_egl_get_display(display_id);
}

EGLBoolean eglInitialize(EGLDisplay display, EGLint* major, EGLint* minor) {
  return mocktail_rust_egl_initialize(display, major, minor);
}

EGLBoolean eglTerminate(EGLDisplay display) {
  return mocktail_rust_egl_terminate(display);
}

EGLBoolean eglBindAPI(EGLenum api) { return mocktail_rust_egl_bind_api(api); }

const char* eglQueryString(EGLDisplay display, EGLint name) {
  return mocktail_rust_egl_query_string(display, name);
}

EGLBoolean eglChooseConfig(EGLDisplay display, const EGLint* attrib_list,
                           EGLConfig* configs, EGLint config_size,
                           EGLint* num_config) {
  return mocktail_rust_egl_choose_config(display, attrib_list, configs,
                                         config_size, num_config);
}

EGLBoolean eglGetConfigAttrib(EGLDisplay display, EGLConfig config,
                              EGLint attribute, EGLint* value) {
  return mocktail_rust_egl_get_config_attrib(display, config, attribute, value);
}

EGLSurface eglCreateWindowSurface(EGLDisplay display, EGLConfig config,
                                  EGLNativeWindowType win,
                                  const EGLint* attrib_list) {
  return mocktail_rust_egl_create_window_surface(display, config, win,
                                                 attrib_list);
}

EGLSurface eglCreatePbufferSurface(EGLDisplay display, EGLConfig config,
                                   const EGLint* attrib_list) {
  return mocktail_rust_egl_create_pbuffer_surface(display, config, attrib_list);
}

EGLBoolean eglDestroySurface(EGLDisplay display, EGLSurface surface) {
  return mocktail_rust_egl_destroy_surface(display, surface);
}

EGLContext eglCreateContext(EGLDisplay display, EGLConfig config,
                            EGLContext share_context,
                            const EGLint* attrib_list) {
  return mocktail_rust_egl_create_context(display, config, share_context,
                                          attrib_list);
}

EGLBoolean eglDestroyContext(EGLDisplay display, EGLContext context) {
  return mocktail_rust_egl_destroy_context(display, context);
}

EGLBoolean eglMakeCurrent(EGLDisplay display, EGLSurface draw, EGLSurface read,
                          EGLContext context) {
  return mocktail_rust_egl_make_current(display, draw, read, context);
}

EGLContext eglGetCurrentContext() {
  return mocktail_rust_egl_get_current_context();
}

EGLDisplay eglGetCurrentDisplay() {
  return mocktail_rust_egl_get_current_display();
}

EGLSurface eglGetCurrentSurface(EGLint readdraw) {
  return mocktail_rust_egl_get_current_surface(readdraw);
}

EGLBoolean eglQuerySurface(EGLDisplay display, EGLSurface surface,
                           EGLint attribute, EGLint* value) {
  return mocktail_rust_egl_query_surface(display, surface, attribute, value);
}

EGLBoolean eglSwapBuffers(EGLDisplay display, EGLSurface surface) {
  return mocktail_rust_egl_swap_buffers(display, surface);
}

EGLBoolean eglSwapInterval(EGLDisplay display, EGLint interval) {
  return mocktail_rust_egl_swap_interval(display, interval);
}

void* eglGetProcAddress(const char* procname) {
  return mocktail_rust_egl_get_proc_address(procname);
}

}  // extern "C"
