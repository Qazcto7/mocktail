#ifndef MOCKTAIL_LEGACY_RUNTIME_PATHS_H_
#define MOCKTAIL_LEGACY_RUNTIME_PATHS_H_

#include <cstddef>
#include <string>

namespace mocktail::legacy::internal {

std::string SoberDataRoot();
std::string SoberCacheRoot();
std::string MocktailCacheRoot();
std::string MocktailConfigRoot();
std::string DefaultSoberAwarePath(const char* sober_path,
                                  const char* fallback_path);
std::string DefaultAssetPath();
std::string RuntimeVulkanAdapterPath();
std::string GetEnvStringDefaultPath(const char* name,
                                    const std::string& default_value);
void EnsureAndroidDirectory(const std::string& android_path);
std::size_t GetEngineStackSize();

}  // namespace mocktail::legacy::internal

#endif  // MOCKTAIL_LEGACY_RUNTIME_PATHS_H_
