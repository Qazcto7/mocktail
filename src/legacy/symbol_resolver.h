#ifndef MOCKTAIL_LEGACY_SYMBOL_RESOLVER_H_
#define MOCKTAIL_LEGACY_SYMBOL_RESOLVER_H_

#include <vector>

namespace mocktail::legacy::internal {

enum class SymbolResolveSource {
  kMissing = 0,
  kWindow = 1,
  kRealGles = 2,
  kStub = 3,
  kHost = 4,
};

struct SymbolResolveResult {
  void* address = nullptr;
  SymbolResolveSource source = SymbolResolveSource::kMissing;
};

bool IsGlSymbol(const char* name);
bool StubOwnsSymbolAddress(void* handle, void* address);
SymbolResolveResult ResolveSymbolForBionic(
    const char* name, bool has_window, void* real_gles_handle,
    const std::vector<void*>& stub_handles);
void* OpenRealGlesLibrary();

}  // namespace mocktail::legacy::internal

#endif  // MOCKTAIL_LEGACY_SYMBOL_RESOLVER_H_
