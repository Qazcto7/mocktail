#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>

using EGLBoolean = uint32_t;
using EGLint = int32_t;
using EGLDisplay = void*;
using EGLConfig = void*;
using EGLContext = void*;
using EGLSurface = void*;
using GLenum = uint32_t;
using GLint = int32_t;
using GLuint = uint32_t;

extern "C" {
EGLDisplay eglGetDisplay(void* display_id);
EGLBoolean eglInitialize(EGLDisplay display, EGLint* major, EGLint* minor);
EGLBoolean eglChooseConfig(EGLDisplay display, const EGLint* attrib_list,
                           EGLConfig* configs, EGLint config_size,
                           EGLint* num_config);
EGLContext eglCreateContext(EGLDisplay display, EGLConfig config,
                            EGLContext share_context,
                            const EGLint* attrib_list);
EGLSurface eglCreatePbufferSurface(EGLDisplay display, EGLConfig config,
                                   const EGLint* attrib_list);
EGLBoolean eglMakeCurrent(EGLDisplay display, EGLSurface draw, EGLSurface read,
                          EGLContext context);
EGLSurface eglGetCurrentSurface(EGLint readdraw);
EGLBoolean eglGetConfigAttrib(EGLDisplay display, EGLConfig config,
                              EGLint attribute, EGLint* value);
void* eglGetProcAddress(const char* procname);
EGLContext eglGetCurrentContext();
EGLint eglGetError();
const uint8_t* glGetString(GLenum name);
void glGenTextures(int32_t n, GLuint* textures);
GLuint glCreateShader(GLenum type);
void glGetShaderiv(GLuint shader, GLenum pname, GLint* params);
GLenum glCheckFramebufferStatus(GLenum target);
GLenum glGetError();
void* glFenceSync(GLenum condition, uint32_t flags);
GLenum glClientWaitSync(void* sync, uint32_t flags, uint64_t timeout);
void glDeleteSync(void* sync);
}

namespace {

TEST(HeadlessGraphicsTest, ProductionModeRejectsMissingRealDisplay) {
  ASSERT_EQ(unsetenv("MOCKTAIL_ENABLE_TEST_GRAPHICS_STUBS"), 0);
  EXPECT_EQ(eglGetDisplay(nullptr), nullptr);
  EXPECT_EQ(eglGetError(), 0x3001);
  EXPECT_EQ(glGetString(0x1f02), nullptr);
  EXPECT_EQ(glCreateShader(0x8b31), 0u);
  EXPECT_EQ(glCheckFramebufferStatus(0x8d40), 0x8cddu);
  EXPECT_EQ(glGetError(), 0x0502u);
}

TEST(HeadlessGraphicsTest, EglCreatesCurrentMockContext) {
  ASSERT_EQ(setenv("MOCKTAIL_ENABLE_TEST_GRAPHICS_STUBS", "1", 1), 0);
  EGLDisplay display = eglGetDisplay(nullptr);
  ASSERT_NE(display, nullptr);

  EGLint major = 0;
  EGLint minor = 0;
  EXPECT_EQ(eglInitialize(display, &major, &minor), 1u);
  EXPECT_GE(major, 1);

  EGLConfig config = nullptr;
  EGLint num_config = 0;
  EXPECT_EQ(eglChooseConfig(display, nullptr, &config, 1, &num_config), 1u);
  EXPECT_NE(config, nullptr);
  EXPECT_EQ(num_config, 1);

  const EGLint context_attrs[] = {0x3098, 2, 0x3038};
  EGLContext context =
      eglCreateContext(display, config, nullptr, context_attrs);
  ASSERT_NE(context, nullptr);

  EGLSurface surface = eglCreatePbufferSurface(display, config, nullptr);
  ASSERT_NE(surface, nullptr);
  EXPECT_EQ(eglMakeCurrent(display, surface, surface, context), 1u);
  EXPECT_EQ(eglGetCurrentContext(), context);
  EXPECT_EQ(eglGetCurrentSurface(0x3059), surface);
  EXPECT_EQ(eglGetCurrentSurface(0x305a), surface);

  EGLint min_swap = -1;
  EXPECT_EQ(eglGetConfigAttrib(display, config, 0x303b, &min_swap), 1u);
  EXPECT_EQ(min_swap, 0);
  EGLint renderable = 0;
  EXPECT_EQ(eglGetConfigAttrib(display, config, 0x3040, &renderable), 1u);
  EXPECT_NE(renderable & 0x0040, 0);
  void* vao_proc = eglGetProcAddress("glBindVertexArray");
  ASSERT_NE(vao_proc, nullptr);
  Dl_info info{};
  ASSERT_NE(dladdr(vao_proc, &info), 0);
  ASSERT_NE(info.dli_fname, nullptr);
  EXPECT_NE(std::strstr(info.dli_fname, "libGLESv2.so"), nullptr);
  EXPECT_EQ(std::strstr(info.dli_fname, "libGLESv2.so.2"), nullptr);
  EXPECT_EQ(eglGetError(), 0x3000);
}

TEST(HeadlessGraphicsTest, GlesReportsNoErrorAndSuccessfulObjects) {
  ASSERT_EQ(setenv("MOCKTAIL_ENABLE_TEST_GRAPHICS_STUBS", "1", 1), 0);
  EXPECT_NE(glGetString(0x1f02), nullptr);

  GLuint texture = 0;
  glGenTextures(1, &texture);
  EXPECT_NE(texture, 0u);

  GLuint shader = glCreateShader(0x8b31);
  EXPECT_NE(shader, 0u);

  GLint status = 0;
  glGetShaderiv(shader, 0x8b81, &status);
  EXPECT_EQ(status, 1);

  void* sync = glFenceSync(0x9117, 0);
  ASSERT_NE(sync, nullptr);
  EXPECT_EQ(glClientWaitSync(sync, 0, 0), 0x911au);
  glDeleteSync(sync);

  EXPECT_EQ(glCheckFramebufferStatus(0x8d40), 0x8cd5u);
  EXPECT_EQ(glGetError(), 0u);
}

}  // namespace
