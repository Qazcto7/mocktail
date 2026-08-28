#include "legacy/runtime_environment.h"

#include <atomic>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <unordered_map>

namespace mocktail::legacy::internal {
namespace {

std::atomic<bool> g_legacy_binary_patches_allowed{false};

bool IsLegacyBinaryCompatibilityToggle(const char* name) {
  if (name == nullptr) {
    return false;
  }
  static constexpr const char* kUnsafePrefixes[] = {
      "MOCKTAIL_PATCH_",
      "MOCKTAIL_RECOVER_",
      "MOCKTAIL_STAGE6_",
      "MOCKTAIL_TRACE_STAGE6_",
      "MOCKTAIL_DUMP_STAGE6_",
      "MOCKTAIL_INSTALL_STAGE6_",
      "MOCKTAIL_CALL_STAGE6_",
      "MOCKTAIL_SEED_STAGE6_",
      "MOCKTAIL_RESET_STAGE6_",
      "MOCKTAIL_LIBROBLOX_CTOR_",
      "MOCKTAIL_SKIP_LIBROBLOX_CTOR_",
      "MOCKTAIL_ALLOW_LIBROBLOX_CTOR_",
      "MOCKTAIL_QUARANTINE_LIBROBLOX_",
      "MOCKTAIL_EMUTLS_",
  };
  for (const char* prefix : kUnsafePrefixes) {
    if (std::strncmp(name, prefix, std::strlen(prefix)) == 0) {
      return true;
    }
  }
  static constexpr const char* kUnsafeExactNames[] = {
      "MOCKTAIL_HEADLESS_SIGSEGV_GUARDS",
      // This legacy toggle mutates a Build-ID-specific byte in libroblox.
      // Keep it behind the same profile gate as the PATCH_* toggles even
      // though its historical name does not carry that prefix.
      "MOCKTAIL_DEFER_RBXM_SIGNATURE_CHECK_TO_POST_TTI",
      "MOCKTAIL_KEEP_CONSTRUCTOR_EMUTLS_HELPERS_PATCHED",
      "MOCKTAIL_MAX_LIBROBLOX_CTORS",
      "MOCKTAIL_NO_RECOVER_START_APP",
      "MOCKTAIL_RESTORE_KNOWN_EMUTLS_KEYS",
      "MOCKTAIL_RUN_LIBROBLOX_CTORS",
      "MOCKTAIL_SKIP_CONSTRUCTOR_PATCH_OFFSETS",
  };
  for (const char* unsafe_name : kUnsafeExactNames) {
    if (std::strcmp(name, unsafe_name) == 0) {
      return true;
    }
  }
  return false;
}

const char* CachedGetenv(const char* name) {
  if (name == nullptr) {
    return nullptr;
  }
  // Launch flags are string literals and do not change after startup. Cache by
  // pointer identity so the main-thread pump does not walk environ + allocate
  // on every tick.
  static std::mutex mutex;
  static std::unordered_map<const char*, const char*> cache;
  std::lock_guard<std::mutex> lock(mutex);
  const auto existing = cache.find(name);
  if (existing != cache.end()) {
    return existing->second;
  }
  const char* value = std::getenv(name);
  cache.emplace(name, value);
  return value;
}

}  // namespace

void SetLegacyBinaryPatchesAllowed(bool allowed) {
  g_legacy_binary_patches_allowed.store(allowed, std::memory_order_release);
}

bool LegacyBinaryPatchesAllowed() {
  return g_legacy_binary_patches_allowed.load(std::memory_order_acquire);
}

bool IsEnabled(const char* name) {
  if (!LegacyBinaryPatchesAllowed() &&
      IsLegacyBinaryCompatibilityToggle(name)) {
    return false;
  }
  const char* value = CachedGetenv(name);
  return value != nullptr && value[0] != '\0' && std::strcmp(value, "0") != 0;
}

bool IsDisabled(const char* name) {
  if (!LegacyBinaryPatchesAllowed() &&
      IsLegacyBinaryCompatibilityToggle(name)) {
    return true;
  }
  const char* value = CachedGetenv(name);
  return value != nullptr && std::strcmp(value, "0") == 0;
}

bool TraceAllEnabled() {
  return IsEnabled("MOCKTAIL_TRACE_ALL") || IsEnabled("MOCKTAIL_FULL_TRACE");
}

bool VerboseOutputEnabled() {
  return IsEnabled("MOCKTAIL_VERBOSE") || TraceAllEnabled();
}

bool LibRobloxConstructorTraceEnabled() {
  return IsEnabled("MOCKTAIL_TRACE_LIBROBLOX_CONSTRUCTORS") ||
         TraceAllEnabled();
}

void EnableFullTraceIfRequested() {
  if (!TraceAllEnabled()) {
    return;
  }
  const char* kTraceEnvNames[] = {
      "MOCKTAIL_ENGINE_TRACE",
      "MOCKTAIL_JNI_TRACE",
      "MOCKTAIL_JNI_VM_TRACE",
      "MOCKTAIL_JNI_STRING_TRACE",
      "MOCKTAIL_DNS_TRACE",
      "MOCKTAIL_GL_TRACE",
      "MOCKTAIL_EGL_TRACE",
      "MOCKTAIL_WINDOW_TRACE",
      "MOCKTAIL_ANDROID_TRACE",
      "MOCKTAIL_ASSET_TRACE",
      "MOCKTAIL_TRACE_POST_CLIENT_SETTINGS_JNI",
      "MOCKTAIL_TRACE_START_LUA_JNI",
  };
  for (const char* name : kTraceEnvNames) {
    setenv(name, "1", 1);
  }
}

void SetEnvDefault(const char* name, const char* value) {
  if (name == nullptr || value == nullptr) {
    return;
  }
  const char* current = std::getenv(name);
  if (current == nullptr || current[0] == '\0') {
    setenv(name, value, 1);
  }
}

void ApplyRuntimeDefaults() {
  SetEnvDefault("MOCKTAIL_SOBER_MODE", "1");
  SetEnvDefault("MOCKTAIL_HEADLESS", "0");
  // Startup worker ownership is joined. Returning while it still references
  // JNI, runtime, or stack state is never supported.
  SetEnvDefault("MOCKTAIL_ENGINE_DETACH", "0");
  SetEnvDefault("MOCKTAIL_INIT_CLIENT_SETTINGS", "0");
  SetEnvDefault("MOCKTAIL_POST_CLIENT_SETTINGS", "0");
  SetEnvDefault("MOCKTAIL_ALLOW_NO_COOKIE_LUA_APP", "1");
  // Current Roblox Android builds drive app startup through NativeGLInterface's
  // V2 app bridge path. The legacy NativeAppBridgeInterface entry point stays
  // available by opt-in, but running it in parallel can block V2 init.
  SetEnvDefault("MOCKTAIL_APP_BRIDGE_APP_START", "0");
  SetEnvDefault("MOCKTAIL_APP_BRIDGE_APP_START_THREAD", "0");
  SetEnvDefault("MOCKTAIL_START_LUA_APP_DM", "1");
  SetEnvDefault("MOCKTAIL_START_LUA_APP_DM_INLINE", "0");
  // The shipped APK drives these callbacks in a mostly synchronous ASMA flow.
  // Keep the background worker path opt-in so the default mirrors release
  // ordering and avoids racing heap-sensitive V2 startup state.
  SetEnvDefault("MOCKTAIL_START_LUA_APP_DM_THREAD", "0");
  SetEnvDefault("MOCKTAIL_START_LUA_APP_DM_AFTER_START_APP", "1");
  SetEnvDefault("MOCKTAIL_START_LUA_APP_DM_DELAY_MS", "500");
  SetEnvDefault("MOCKTAIL_APP_BRIDGE_HEADLESS_INIT_PARAMS", "0");
  SetEnvDefault("MOCKTAIL_PLACE_ID", "0");
  // Real V2 init is the path under test. MocktailAppBridgeInit remains the
  // recovery fallback when signal recovery is armed for a Build ID.
  SetEnvDefault("MOCKTAIL_CALL_REAL_APP_BRIDGE_INIT", "1");
  SetEnvDefault("MOCKTAIL_CALL_REAL_APP_BRIDGE_INIT_THREAD", "0");
  SetEnvDefault("MOCKTAIL_APP_BRIDGE_INIT_THREAD_TIMEOUT_MS", "1500");
  SetEnvDefault("MOCKTAIL_CALL_REAL_APP_BRIDGE_START", "1");
  SetEnvDefault("MOCKTAIL_START_GAME_WITH_PARAM", "0");
  SetEnvDefault("MOCKTAIL_SET_APP_BRIDGE_NOTIFICATION_LISTENER", "1");
  // APK ASMA calls nativeAppBridgeV2StartAppWithParams synchronously before
  // driving post-start surface/Lua callbacks. Keep the worker path opt-in so
  // those follow-up callbacks cannot race native StartApp construction.
  SetEnvDefault("MOCKTAIL_CALL_REAL_APP_BRIDGE_START_THREAD", "0");
  SetEnvDefault("MOCKTAIL_ASMA_START_TASK_SCHEDULER_FOREGROUND", "1");
  SetEnvDefault("MOCKTAIL_TASK_SCHEDULER_FOREGROUND_ON_MAIN_THREAD", "1");
  SetEnvDefault("MOCKTAIL_NATIVE_FRAGMENT_START", "1");
  SetEnvDefault("MOCKTAIL_PASS_CURRENT_DISPLAY_REFRESH_RATE", "1");
  SetEnvDefault("MOCKTAIL_PASS_SUPPORTED_REFRESH_RATES", "1");
  SetEnvDefault("MOCKTAIL_PASS_ACTIVITY_TO_GAME_SURFACE_PARAMS", "0");
  SetEnvDefault("MOCKTAIL_PATCH_NATIVE_FLAGS_LOADED", "1");
  SetEnvDefault("MOCKTAIL_DEFER_RBXM_SIGNATURE_CHECK_TO_POST_TTI", "1");
  SetEnvDefault("MOCKTAIL_PATCH_STAGE6_START_LUA_DM_FORCE_SAME_THREAD", "1");
  SetEnvDefault("MOCKTAIL_PATCH_STAGE6_START_LUA_DM_FORCE_SAME_THREAD_GLOBAL",
                "1");
  SetEnvDefault("MOCKTAIL_PATCH_STAGE6_START_LUA_FALLBACK_CALLBACK_TARGET",
                "1");
  SetEnvDefault("MOCKTAIL_PATCH_STAGE6_START_LUA_SINGLE_SURFACE_ENTRY", "1");
  SetEnvDefault("MOCKTAIL_PATCH_STAGE6_START_LUA_TARGET_TABLE", "1");
  SetEnvDefault("MOCKTAIL_PATCH_STAGE6_START_LUA_PRIMARY_FROM_OWNER", "1");
  SetEnvDefault("MOCKTAIL_STAGE6_START_LUA_PRIMARY_SLOT8_SOURCE", "0x850");
  SetEnvDefault("MOCKTAIL_STAGE6_START_LUA_PRIMARY_SLOT10_SOURCE", "0x858");
  SetEnvDefault("MOCKTAIL_STAGE6_START_LUA_PRIMARY_SLOT18_SOURCE", "0x418");
  SetEnvDefault("MOCKTAIL_PATCH_STAGE6_START_LUA_BOXED_TARGET_LOOKUP", "1");
  SetEnvDefault("MOCKTAIL_PATCH_STAGE6_START_LUA_TARGET_CALLBACK_OBJECT", "1");
  SetEnvDefault("MOCKTAIL_PATCH_STAGE6_START_LUA_TARGET_CALL_RESULT", "1");
  SetEnvDefault(
      "MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_RESULT20_PAIR_CALLBACK", "1");
  SetEnvDefault(
      "MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_RESULT20_SPLIT_CALLBACK_ARGS",
      "1");
  SetEnvDefault(
      "MOCKTAIL_PATCH_STAGE6_START_LUA_DISPATCHER_SECOND_PAIR_ARGUMENT", "1");
  SetEnvDefault(
      "MOCKTAIL_PATCH_STAGE6_START_LUA_RESULT20_LOOKUP_LOW_TREE_TARGET_PAIR",
      "1");
  SetEnvDefault(
      "MOCKTAIL_PATCH_STAGE6_START_LUA_RESULT20_FALLBACK_NULL_GLOBAL_SLOT",
      "1");
  // The APK ASMA path schedules StartLua work through Roblox's foreground
  // scheduler. In Mocktail the queue/proc bookkeeping can be left empty after
  // the bionic-to-host handoff, so preserve the selected native proc instead of
  // letting the scheduler spin on a null resolver or xchg through a state
  // value.
  SetEnvDefault("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_TASK_QUEUE_FLAG",
                "1");
  SetEnvDefault("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_QUEUE", "1");
  SetEnvDefault("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_SCHEDULER_PROC", "1");
  SetEnvDefault("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_PROC_MATCH", "1");
  SetEnvDefault("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_ACTIVE_PROC", "1");
  SetEnvDefault("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_CLEANUP_PROC", "1");
  SetEnvDefault("MOCKTAIL_SYNC_START_APP_WITH_GAME", "1");
  // APK ASMA publishes queued ready events after the Lua app startup path has
  // run. Keep this inline by default; the detached worker can outlive teardown.
  SetEnvDefault("MOCKTAIL_SEND_APP_READY", "1");
  SetEnvDefault("MOCKTAIL_SEND_APP_READY_THREAD", "0");
  SetEnvDefault("MOCKTAIL_SEND_GAME_LOADED", "0");
  SetEnvDefault("MOCKTAIL_SEND_GAME_LOADED_THREAD", "0");
  SetEnvDefault("MOCKTAIL_UPDATE_SCREEN_ORIENTATION", "0");
  SetEnvDefault("MOCKTAIL_STEP_UPDATE_SURFACE_APP", "0");
  SetEnvDefault("MOCKTAIL_CALL_REAL_APP_BRIDGE_UPDATE_SURFACE", "0");
  SetEnvDefault("MOCKTAIL_CALL_REAL_APP_BRIDGE_UPDATE_SURFACE_THREAD", "0");
  // Keep the ASMA/V2 NativeGL path as the default. GameActivity's native app
  // glue currently stalls V2 init on surface flags; leave it available opt-in.
  SetEnvDefault("MOCKTAIL_STEP_GAME_ACTIVITY_INIT", "0");
  SetEnvDefault("MOCKTAIL_STEP_GAME_ACTIVITY_SURFACE", "0");
  // GameActivity lifecycle callbacks can block on
  // android_app_set_activity_state in some Linux shims; keep them opt-in to
  // avoid startup dead-ends.
  SetEnvDefault("MOCKTAIL_GAME_ACTIVITY_LIFECYCLE_CALLBACKS", "0");
  SetEnvDefault("MOCKTAIL_NATIVE_SET_USER_ID", "0");
  SetEnvDefault("MOCKTAIL_MAIN_THREAD_MESSAGE_PUMP", "0");
  SetEnvDefault("MOCKTAIL_IGNORE_WINDOW_CLOSE", "0");
  SetEnvDefault("MOCKTAIL_WIN_TITLE", "Roblox");
  SetEnvDefault("MOCKTAIL_GRAPHICS_BACKEND", "angle-vulkan");
  SetEnvDefault("MOCKTAIL_REQUIRE_REAL_GRAPHICS", "0");
}

bool IsHeadlessMode() { return IsEnabled("MOCKTAIL_HEADLESS"); }

bool ShouldRunStartupStep(const char* step_env, bool default_value) {
  if (IsEnabled(step_env)) {
    return true;
  }
  if (IsDisabled(step_env)) {
    return false;
  }
  return default_value;
}

int GetEnvInt(const char* name, int default_value) {
  const char* value = CachedGetenv(name);
  if (value == nullptr || value[0] == '\0') {
    return default_value;
  }
  char* end = nullptr;
  long parsed = std::strtol(value, &end, 10);
  if (end == value) {
    return default_value;
  }
  return static_cast<int>(parsed);
}

std::uintptr_t GetEnvAddress(const char* name, std::uintptr_t default_value) {
  const char* value = CachedGetenv(name);
  if (value == nullptr || value[0] == '\0') {
    return default_value;
  }
  char* end = nullptr;
  unsigned long long parsed = std::strtoull(value, &end, 0);
  if (end == value) {
    return default_value;
  }
  return static_cast<std::uintptr_t>(parsed);
}

std::int64_t GetEnvLong(const char* name, std::int64_t default_value) {
  const char* value = CachedGetenv(name);
  if (value == nullptr || value[0] == '\0') {
    return default_value;
  }
  char* end = nullptr;
  long long parsed = std::strtoll(value, &end, 10);
  if (end == value) {
    return default_value;
  }
  return static_cast<std::int64_t>(parsed);
}

std::string GetEnvString(const char* name, const char* default_value) {
  const char* value = CachedGetenv(name);
  if (value == nullptr || value[0] == '\0') {
    return default_value != nullptr ? default_value : "";
  }
  return value;
}

bool HasEnvValue(const char* name) {
  const char* value = CachedGetenv(name);
  return value != nullptr && value[0] != '\0';
}

}  // namespace mocktail::legacy::internal
