#ifndef MOCKTAIL_LEGACY_RUNTIME_ENVIRONMENT_H_
#define MOCKTAIL_LEGACY_RUNTIME_ENVIRONMENT_H_

#include <cstdint>
#include <string>

namespace mocktail::legacy::internal {

void SetLegacyBinaryPatchesAllowed(bool allowed);
bool LegacyBinaryPatchesAllowed();

bool IsEnabled(const char* name);
bool IsDisabled(const char* name);
bool TraceAllEnabled();
bool VerboseOutputEnabled();
bool LibRobloxConstructorTraceEnabled();
void EnableFullTraceIfRequested();

void SetEnvDefault(const char* name, const char* value);
void ApplyRuntimeDefaults();
bool IsHeadlessMode();
bool ShouldRunStartupStep(const char* step_env, bool default_value);
int GetEnvInt(const char* name, int default_value);
std::uintptr_t GetEnvAddress(const char* name, std::uintptr_t default_value);
std::int64_t GetEnvLong(const char* name, std::int64_t default_value);
std::string GetEnvString(const char* name, const char* default_value);
bool HasEnvValue(const char* name);

}  // namespace mocktail::legacy::internal

#endif  // MOCKTAIL_LEGACY_RUNTIME_ENVIRONMENT_H_
