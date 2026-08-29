#include "legacy/symbol_resolver.h"

#include <dlfcn.h>
#include <link.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#include "legacy/runtime_environment.h"
#include "window/window.h"

namespace mocktail::legacy::internal {
namespace {

bool StartsWith(const char* value, const char* prefix) {
  if (value == nullptr || prefix == nullptr) {
    return false;
  }
  return std::strncmp(value, prefix, std::strlen(prefix)) == 0;
}

bool IsMocktailStubGlesPath(const char* path) {
  if (path == nullptr || path[0] == '\0') {
    return true;
  }
  const std::string value(path);
  return value == "libGLESv2.so" ||
         value.find("/build/libGLESv2.so") != std::string::npos;
}

}  // namespace

bool IsGlSymbol(const char* name) { return StartsWith(name, "gl"); }

// dlsym searches the object and its dependency chain, so a stub that
// transitively links SDL or another host library could satisfy EGL/GL/Vulkan
// lookups with unrelated host symbols. Only accept a symbol owned by the stub.
bool StubOwnsSymbolAddress(void* handle, void* address) {
  if (handle == nullptr || address == nullptr) {
    return false;
  }

  Dl_info info = {};
  if (::dladdr(address, &info) == 0 || info.dli_fbase == nullptr) {
    return false;
  }

  link_map* map = nullptr;
  if (::dlinfo(handle, RTLD_DI_LINKMAP, &map) != 0 || map == nullptr) {
    return false;
  }

  return reinterpret_cast<void*>(map->l_addr) == info.dli_fbase;
}

SymbolResolveResult ResolveSymbolForBionic(
    const char* name, bool has_window, void* real_gles_handle,
    const std::vector<void*>& stub_handles) {
  const bool is_gl_symbol = IsGlSymbol(name);
  const bool prefer_real_gles = has_window &&
                                !IsEnabled("MOCKTAIL_GLES_FORCE_STUB") &&
                                !IsEnabled("MOCKTAIL_GLES_NOOP_DRAW_CALLS");
  SymbolResolveResult result;

  if (is_gl_symbol && prefer_real_gles) {
    result.address = mocktail::window::GetGLProcAddress(name);
    if (result.address != nullptr) {
      result.source = SymbolResolveSource::kWindow;
      return result;
    }
  }

  if (is_gl_symbol && prefer_real_gles && real_gles_handle != nullptr) {
    result.address = ::dlsym(real_gles_handle, name);
    if (result.address != nullptr) {
      result.source = SymbolResolveSource::kRealGles;
      return result;
    }
  }

  for (void* handle : stub_handles) {
    void* candidate = ::dlsym(handle, name);
    if (candidate != nullptr && StubOwnsSymbolAddress(handle, candidate)) {
      result.address = candidate;
      result.source = SymbolResolveSource::kStub;
      return result;
    }
  }

  result.address = ::dlsym(RTLD_DEFAULT, name);
  if (result.address != nullptr) {
    result.source = SymbolResolveSource::kHost;
  }
  return result;
}

void* OpenRealGlesLibrary() {
  const char* env_library = std::getenv("MOCKTAIL_GLES_LIBRARY");
  const char* candidates[] = {
      env_library,
      "/usr/lib/libGLESv2.so.2",
      "/usr/lib64/libGLESv2.so.2",
      "libGLESv2.so.2",
      "/usr/lib/chromium/libGLESv2.so",
      "/usr/lib/chromium-browser/libGLESv2.so",
      "/usr/lib/electron42/libGLESv2.so",
      "/usr/lib/electron41/libGLESv2.so",
      "/usr/lib/electron40/libGLESv2.so",
      "/usr/lib/electron39/libGLESv2.so",
      "/usr/lib/cef/libGLESv2.so",
  };
  for (const char* candidate : candidates) {
    if (IsMocktailStubGlesPath(candidate)) {
      continue;
    }
    void* handle = ::dlopen(candidate, RTLD_LAZY | RTLD_LOCAL);
    if (handle != nullptr) {
      std::cout << "  [gles] Using real GLES from " << candidate << '\n';
      return handle;
    }
  }
  std::cerr << "  [gles] real libGLESv2 not found; using Mocktail GLES shim\n";
  return nullptr;
}

}  // namespace mocktail::legacy::internal
