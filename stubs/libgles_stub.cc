// Copyright 2026 Mocktail Project Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

// Fake object/status semantics are available only when
// MOCKTAIL_ENABLE_TEST_GRAPHICS_STUBS=1. Production must resolve every GLES
// symbol from a real ANGLE or system implementation.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

using GLbitfield = uint32_t;
using GLboolean = uint8_t;
using GLchar = char;
using GLenum = uint32_t;
using GLfloat = float;
using GLint = int32_t;
using GLsizei = int32_t;
using GLuint = uint32_t;
using GLsizeiptr = std::ptrdiff_t;
using GLintptr = std::ptrdiff_t;

namespace {

constexpr GLenum kGlNoError = 0;
constexpr GLenum kGlInvalidOperation = 0x0502;
constexpr GLenum kGlVendor = 0x1f00;
constexpr GLenum kGlRenderer = 0x1f01;
constexpr GLenum kGlVersion = 0x1f02;
constexpr GLenum kGlExtensions = 0x1f03;
constexpr GLenum kGlShadingLanguageVersion = 0x8b8c;
constexpr GLenum kGlFramebufferComplete = 0x8cd5;
constexpr GLenum kGlFramebufferUnsupported = 0x8cdd;
constexpr GLenum kGlCompileStatus = 0x8b81;
constexpr GLenum kGlLinkStatus = 0x8b82;
constexpr GLenum kGlInfoLogLength = 0x8b84;
constexpr GLenum kGlMaxTextureSize = 0x0d33;
constexpr GLenum kGlMaxTextureImageUnits = 0x8872;
constexpr GLenum kGlMaxVertexAttribs = 0x8869;
constexpr GLenum kGlMaxVaryingVectors = 0x8dfc;
constexpr GLenum kGlMaxVertexUniformVectors = 0x8dfb;
constexpr GLenum kGlMaxFragmentUniformVectors = 0x8dfd;
constexpr GLenum kGlViewport = 0x0ba2;

GLuint g_next_object = 1;
thread_local GLenum g_last_error = kGlNoError;
thread_local GLint g_viewport[4] = {0, 0, 1280, 720};

bool TestGraphicsStubsEnabled() {
  const char* value = std::getenv("MOCKTAIL_ENABLE_TEST_GRAPHICS_STUBS");
  return value != nullptr && std::strcmp(value, "1") == 0;
}

bool RequireTestGraphicsStub() {
  if (TestGraphicsStubsEnabled()) {
    return true;
  }
  g_last_error = kGlInvalidOperation;
  return false;
}

GLuint NextObject() {
  if (!RequireTestGraphicsStub()) {
    return 0;
  }
  return g_next_object++;
}

void FillObjects(GLsizei n, GLuint* objects) {
  if (objects == nullptr || n <= 0) {
    return;
  }
  if (!RequireTestGraphicsStub()) {
    std::memset(objects, 0, static_cast<size_t>(n) * sizeof(*objects));
    return;
  }
  for (GLsizei i = 0; i < n; ++i) {
    objects[i] = NextObject();
  }
}

void CopyString(const char* source, GLsizei buf_size, GLsizei* length,
                GLchar* info_log) {
  const GLsizei source_length =
      source == nullptr ? 0 : static_cast<GLsizei>(std::strlen(source));
  if (length != nullptr) {
    *length = source_length;
  }
  if (info_log == nullptr || buf_size <= 0) {
    return;
  }
  const GLsizei copy_length =
      source_length < buf_size - 1 ? source_length : buf_size - 1;
  if (copy_length > 0) {
    std::memcpy(info_log, source, static_cast<size_t>(copy_length));
  }
  info_log[copy_length] = '\0';
}

}  // namespace

extern "C" {

const uint8_t* glGetString(GLenum name) {
  if (!RequireTestGraphicsStub()) {
    return nullptr;
  }
  switch (name) {
    case kGlVendor:
      return reinterpret_cast<const uint8_t*>("Mocktail");
    case kGlRenderer:
      return reinterpret_cast<const uint8_t*>("Mocktail GLES shim");
    case kGlVersion:
      return reinterpret_cast<const uint8_t*>("OpenGL ES 3.0 Mocktail");
    case kGlShadingLanguageVersion:
      return reinterpret_cast<const uint8_t*>("OpenGL ES GLSL ES 3.00");
    case kGlExtensions:
      return reinterpret_cast<const uint8_t*>(
          "GL_OES_element_index_uint GL_OES_rgb8_rgba8 "
          "GL_EXT_texture_filter_anisotropic");
    default:
      return reinterpret_cast<const uint8_t*>("");
  }
}

GLenum glGetError() {
  GLenum error = g_last_error;
  g_last_error = kGlNoError;
  return error;
}

void glGetIntegerv(GLenum pname, GLint* data) {
  if (data == nullptr) {
    return;
  }
  if (!RequireTestGraphicsStub()) {
    *data = 0;
    return;
  }
  switch (pname) {
    case kGlMaxTextureSize:
      *data = 4096;
      break;
    case kGlMaxTextureImageUnits:
      *data = 16;
      break;
    case kGlMaxVertexAttribs:
      *data = 16;
      break;
    case kGlMaxVaryingVectors:
    case kGlMaxVertexUniformVectors:
    case kGlMaxFragmentUniformVectors:
      *data = 128;
      break;
    case kGlViewport:
      std::memcpy(data, g_viewport, sizeof(g_viewport));
      break;
    default:
      *data = 1;
      break;
  }
}

void glGenTextures(GLsizei n, GLuint* textures) { FillObjects(n, textures); }
void glGenBuffers(GLsizei n, GLuint* buffers) { FillObjects(n, buffers); }
void glGenFramebuffers(GLsizei n, GLuint* framebuffers) {
  FillObjects(n, framebuffers);
}
void glGenRenderbuffers(GLsizei n, GLuint* renderbuffers) {
  FillObjects(n, renderbuffers);
}

GLuint glCreateShader(GLenum /*type*/) { return NextObject(); }
GLuint glCreateProgram() { return NextObject(); }

void glGetShaderiv(GLuint /*shader*/, GLenum pname, GLint* params) {
  if (params == nullptr) {
    return;
  }
  if (!RequireTestGraphicsStub()) {
    *params = 0;
    return;
  }
  if (pname == kGlCompileStatus) {
    *params = 1;
  } else if (pname == kGlInfoLogLength) {
    *params = 1;
  } else {
    *params = 1;
  }
}

void glGetProgramiv(GLuint /*program*/, GLenum pname, GLint* params) {
  if (params == nullptr) {
    return;
  }
  if (!RequireTestGraphicsStub()) {
    *params = 0;
    return;
  }
  if (pname == kGlLinkStatus) {
    *params = 1;
  } else if (pname == kGlInfoLogLength) {
    *params = 1;
  } else {
    *params = 1;
  }
}

void glGetShaderInfoLog(GLuint /*shader*/, GLsizei buf_size, GLsizei* length,
                        GLchar* info_log) {
  if (!RequireTestGraphicsStub()) {
    CopyString("real GLES backend unavailable", buf_size, length, info_log);
    return;
  }
  CopyString("", buf_size, length, info_log);
}

void glGetProgramInfoLog(GLuint /*program*/, GLsizei buf_size, GLsizei* length,
                         GLchar* info_log) {
  if (!RequireTestGraphicsStub()) {
    CopyString("real GLES backend unavailable", buf_size, length, info_log);
    return;
  }
  CopyString("", buf_size, length, info_log);
}

void glGetActiveUniform(GLuint /*program*/, GLuint /*index*/, GLsizei buf_size,
                        GLsizei* length, GLint* size, GLenum* type,
                        GLchar* name) {
  if (!RequireTestGraphicsStub()) {
    if (size != nullptr) {
      *size = 0;
    }
    if (type != nullptr) {
      *type = 0;
    }
    CopyString("", buf_size, length, name);
    return;
  }
  if (size != nullptr) {
    *size = 1;
  }
  if (type != nullptr) {
    *type = 0x1406;
  }
  CopyString("", buf_size, length, name);
}

GLint glGetUniformLocation(GLuint /*program*/, const GLchar* /*name*/) {
  return RequireTestGraphicsStub() ? 0 : -1;
}

GLenum glCheckFramebufferStatus(GLenum /*target*/) {
  return RequireTestGraphicsStub() ? kGlFramebufferComplete
                                   : kGlFramebufferUnsupported;
}

void glViewport(GLint x, GLint y, GLsizei width, GLsizei height) {
  if (!RequireTestGraphicsStub()) {
    return;
  }
  g_viewport[0] = x;
  g_viewport[1] = y;
  g_viewport[2] = width;
  g_viewport[3] = height;
}

void glActiveTexture(GLenum /*texture*/) { RequireTestGraphicsStub(); }
void glAttachShader(GLuint /*program*/, GLuint /*shader*/) {
  RequireTestGraphicsStub();
}
void glBindAttribLocation(GLuint /*program*/, GLuint /*index*/,
                          const GLchar* /*name*/) {
  RequireTestGraphicsStub();
}
void glBindBuffer(GLenum /*target*/, GLuint /*buffer*/) {
  RequireTestGraphicsStub();
}
void glBindFramebuffer(GLenum /*target*/, GLuint /*framebuffer*/) {
  RequireTestGraphicsStub();
}
void glBindRenderbuffer(GLenum /*target*/, GLuint /*renderbuffer*/) {
  RequireTestGraphicsStub();
}
void glBindTexture(GLenum /*target*/, GLuint /*texture*/) {
  RequireTestGraphicsStub();
}
void glBlendFunc(GLenum /*sfactor*/, GLenum /*dfactor*/) {
  RequireTestGraphicsStub();
}
void glBlendFuncSeparate(GLenum /*src_rgb*/, GLenum /*dst_rgb*/,
                         GLenum /*src_alpha*/, GLenum /*dst_alpha*/) {
  RequireTestGraphicsStub();
}
void glBufferData(GLenum /*target*/, GLsizeiptr /*size*/, const void* /*data*/,
                  GLenum /*usage*/) {
  RequireTestGraphicsStub();
}
void glBufferSubData(GLenum /*target*/, GLintptr /*offset*/,
                     GLsizeiptr /*size*/, const void* /*data*/) {
  RequireTestGraphicsStub();
}
void glClear(GLbitfield /*mask*/) { RequireTestGraphicsStub(); }
void glClearColor(GLfloat /*red*/, GLfloat /*green*/, GLfloat /*blue*/,
                  GLfloat /*alpha*/) {
  RequireTestGraphicsStub();
}
void glClearDepthf(GLfloat /*depth*/) { RequireTestGraphicsStub(); }
void glClearStencil(GLint /*s*/) { RequireTestGraphicsStub(); }
void glColorMask(GLboolean /*red*/, GLboolean /*green*/, GLboolean /*blue*/,
                 GLboolean /*alpha*/) {
  RequireTestGraphicsStub();
}
void glCompileShader(GLuint /*shader*/) { RequireTestGraphicsStub(); }
void glCompressedTexImage2D(GLenum /*target*/, GLint /*level*/,
                            GLenum /*internalformat*/, GLsizei /*width*/,
                            GLsizei /*height*/, GLint /*border*/,
                            GLsizei /*image_size*/, const void* /*data*/) {
  RequireTestGraphicsStub();
}
void glCompressedTexSubImage2D(GLenum /*target*/, GLint /*level*/,
                               GLint /*xoffset*/, GLint /*yoffset*/,
                               GLsizei /*width*/, GLsizei /*height*/,
                               GLenum /*format*/, GLsizei /*image_size*/,
                               const void* /*data*/) {
  RequireTestGraphicsStub();
}
void glCopyTexSubImage2D(GLenum /*target*/, GLint /*level*/, GLint /*xoffset*/,
                         GLint /*yoffset*/, GLint /*x*/, GLint /*y*/,
                         GLsizei /*width*/, GLsizei /*height*/) {
  RequireTestGraphicsStub();
}
void glCullFace(GLenum /*mode*/) { RequireTestGraphicsStub(); }
void glDeleteBuffers(GLsizei /*n*/, const GLuint* /*buffers*/) {
  RequireTestGraphicsStub();
}
void glDeleteFramebuffers(GLsizei /*n*/, const GLuint* /*framebuffers*/) {
  RequireTestGraphicsStub();
}
void glDeleteProgram(GLuint /*program*/) { RequireTestGraphicsStub(); }
void glDeleteRenderbuffers(GLsizei /*n*/, const GLuint* /*renderbuffers*/) {
  RequireTestGraphicsStub();
}
void glDeleteShader(GLuint /*shader*/) { RequireTestGraphicsStub(); }
void glDeleteTextures(GLsizei /*n*/, const GLuint* /*textures*/) {
  RequireTestGraphicsStub();
}
void glDepthFunc(GLenum /*func*/) { RequireTestGraphicsStub(); }
void glDepthMask(GLboolean /*flag*/) { RequireTestGraphicsStub(); }
void glDisable(GLenum /*cap*/) { RequireTestGraphicsStub(); }
void glDisableVertexAttribArray(GLuint /*index*/) { RequireTestGraphicsStub(); }
void glDrawArrays(GLenum /*mode*/, GLint /*first*/, GLsizei /*count*/) {
  RequireTestGraphicsStub();
}
void glDrawElements(GLenum /*mode*/, GLsizei /*count*/, GLenum /*type*/,
                    const void* /*indices*/) {
  RequireTestGraphicsStub();
}
void glEnable(GLenum /*cap*/) { RequireTestGraphicsStub(); }
void glEnableVertexAttribArray(GLuint /*index*/) { RequireTestGraphicsStub(); }
void glFramebufferRenderbuffer(GLenum /*target*/, GLenum /*attachment*/,
                               GLenum /*renderbuffertarget*/,
                               GLuint /*renderbuffer*/) {
  RequireTestGraphicsStub();
}
void glFramebufferTexture2D(GLenum /*target*/, GLenum /*attachment*/,
                            GLenum /*textarget*/, GLuint /*texture*/,
                            GLint /*level*/) {
  RequireTestGraphicsStub();
}
void glGenerateMipmap(GLenum /*target*/) { RequireTestGraphicsStub(); }
void glLinkProgram(GLuint /*program*/) { RequireTestGraphicsStub(); }
void glPixelStorei(GLenum /*pname*/, GLint /*param*/) {
  RequireTestGraphicsStub();
}
void glPolygonOffset(GLfloat /*factor*/, GLfloat /*units*/) {
  RequireTestGraphicsStub();
}
void glReadPixels(GLint /*x*/, GLint /*y*/, GLsizei width, GLsizei height,
                  GLenum /*format*/, GLenum /*type*/, void* pixels) {
  if (!RequireTestGraphicsStub()) {
    return;
  }
  if (pixels != nullptr && width > 0 && height > 0) {
    std::memset(pixels, 0,
                static_cast<size_t>(width) * static_cast<size_t>(height) * 4u);
  }
}
void glReleaseShaderCompiler() { RequireTestGraphicsStub(); }
void glRenderbufferStorage(GLenum /*target*/, GLenum /*internalformat*/,
                           GLsizei /*width*/, GLsizei /*height*/) {
  RequireTestGraphicsStub();
}
void glScissor(GLint /*x*/, GLint /*y*/, GLsizei /*width*/,
               GLsizei /*height*/) {
  RequireTestGraphicsStub();
}
void glShaderSource(GLuint /*shader*/, GLsizei /*count*/,
                    const GLchar* const* /*string*/, const GLint* /*length*/) {
  RequireTestGraphicsStub();
}
void glStencilFunc(GLenum /*func*/, GLint /*ref*/, GLuint /*mask*/) {
  RequireTestGraphicsStub();
}
void glStencilMask(GLuint /*mask*/) { RequireTestGraphicsStub(); }
void glStencilOp(GLenum /*fail*/, GLenum /*zfail*/, GLenum /*zpass*/) {
  RequireTestGraphicsStub();
}
void glTexImage2D(GLenum /*target*/, GLint /*level*/, GLint /*internalformat*/,
                  GLsizei /*width*/, GLsizei /*height*/, GLint /*border*/,
                  GLenum /*format*/, GLenum /*type*/, const void* /*pixels*/) {
  RequireTestGraphicsStub();
}
void glTexParameterf(GLenum /*target*/, GLenum /*pname*/, GLfloat /*param*/) {
  RequireTestGraphicsStub();
}
void glTexParameterfv(GLenum /*target*/, GLenum /*pname*/,
                      const GLfloat* /*params*/) {
  RequireTestGraphicsStub();
}
void glTexParameteri(GLenum /*target*/, GLenum /*pname*/, GLint /*param*/) {
  RequireTestGraphicsStub();
}
void glTexSubImage2D(GLenum /*target*/, GLint /*level*/, GLint /*xoffset*/,
                     GLint /*yoffset*/, GLsizei /*width*/, GLsizei /*height*/,
                     GLenum /*format*/, GLenum /*type*/,
                     const void* /*pixels*/) {
  RequireTestGraphicsStub();
}
void glUniform1i(GLint /*location*/, GLint /*v0*/) {
  RequireTestGraphicsStub();
}
void glUseProgram(GLuint /*program*/) { RequireTestGraphicsStub(); }
void glVertexAttribPointer(GLuint /*index*/, GLint /*size*/, GLenum /*type*/,
                           GLboolean /*normalized*/, GLsizei /*stride*/,
                           const void* /*pointer*/) {
  RequireTestGraphicsStub();
}

}  // extern "C"
