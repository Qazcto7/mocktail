#include <SDL3/SDL_video.h>
#include <arpa/inet.h>
#include <asm/prctl.h>
#include <dlfcn.h>
#include <elf.h>
#include <execinfo.h>
#include <fcntl.h>
#include <jni.h>
#include <link.h>
#include <netdb.h>
#include <poll.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "compat/bionic_abi_exports.h"
#include "compat/bionic_prctl_runtime.h"
#include "compat/bionic_pthread_create_runtime.h"
#include "compat/bionic_socket_runtime.h"
#include "compat/build_profile.h"
#include "compat/elf_build_id.h"
#include "compat/host_abi_experiment.h"
#include "compat/host_abi_profile.h"
#include "compat/host_allocator_bridge.h"
#include "jnivm/jnivm.h"
#include "legacy/bionic_runtime_wrappers.h"
#include "legacy/engine_startup_types.h"
#include "legacy/legacy_runtime.h"
#include "legacy/memory_inspection.h"
#include "legacy/rbxm_diagnostics.h"
#include "legacy/runtime_adapters.h"
#include "legacy/runtime_environment.h"
#include "legacy/runtime_paths.h"
#include "legacy/symbol_resolver.h"
#include "libc_shim/libc_shim.h"
#include "linker/linker.h"
#include "mocktail/graphics/bionic_egl_bridge.h"
#include "runtime/discord_rpc.h"
#include "runtime/environment.h"
#include "runtime/jnivm_platform_web_callbacks.h"
#include "runtime/owned_pthread.h"
#include "runtime/platform_cache_migration.h"
#include "runtime/roblox_app_lifecycle.h"
#include "runtime/roblox_capability_resolver.h"
#include "runtime/roblox_experience_composition.h"
#include "runtime/roblox_game_session_native_adapter.h"
#include "runtime/roblox_platform_web_symbols.h"
#include "runtime/roblox_text_input_jni_bridge.h"
#include "runtime/roblox_window_input_runtime.h"
#include "runtime/runtime_config.h"
#include "runtime/runtime_paths.h"
#include "services/client_settings_service.h"
#include "services/http_client.h"
#include "window/window.h"
#include "window/window_game_surface_bridge.h"

#ifdef MOCKTAIL_USE_BIONIC_LINKER
#include <mcpelauncher/linker.h>
#endif

#ifndef MOCKTAIL_DEFAULT_COMPATIBILITY_MANIFEST
#define MOCKTAIL_DEFAULT_COMPATIBILITY_MANIFEST \
  "config/roblox_compatibility.json"
#endif

#include "legacy/legacy_runtime_core.h"
#include "legacy/stage6_patches.h"

namespace mocktail::legacy::internal {

std::string JStringToString(JNIEnv* env, jstring value) {
  if (!env || !value) {
    return {};
  }
  const char* chars = env->GetStringUTFChars(value, nullptr);
  if (!chars) {
    return {};
  }
  std::string result(chars);
  env->ReleaseStringUTFChars(value, chars);
  return result;
}

void MocktailSetAssetPath(JNIEnv* env, jstring asset_path) {
  std::string path = JStringToString(env, asset_path);
  if (path.empty()) {
    path = DefaultAssetPath();
  }
  setenv("MOCKTAIL_ASSET_ROOT", path.c_str(), 1);
  std::cout << "  [engine] asset root set to " << path << '\n' << std::flush;
}

void MocktailAppBridgeInit(JNIEnv* env, jstring app_params) {
  std::string params = JStringToString(env, app_params);
  if (params.empty()) {
    params = "{}";
  }
  setenv("MOCKTAIL_APP_BRIDGE_PARAMS", params.c_str(), 1);
  setenv("MOCKTAIL_APP_BRIDGE_INIT", "1", 1);
  std::cout << "  [engine] app bridge params staged\n" << std::flush;
}

void MocktailAppBridgeStart(JNIEnv* env, jstring app_params) {
  std::string params = JStringToString(env, app_params);
  if (params.empty()) {
    params = "{}";
  }
  setenv("MOCKTAIL_APP_BRIDGE_START_PARAMS", params.c_str(), 1);
  setenv("MOCKTAIL_APP_STARTED", "1", 1);
  std::cout << "  [engine] app bridge marked started\n" << std::flush;
}

jstring NewStringFromEnvDefault(JNIEnv* env, const char* env_name,
                                const char* default_value) {
  const char* value = std::getenv(env_name);
  if (!value || value[0] == '\0') {
    value = default_value;
  }
  return env->NewStringUTF(value);
}

std::string MocktailCookiePath() { return MocktailConfigRoot() + "/cookie"; }

bool CookieHasAttribute(const std::string& cookie, const char* attribute) {
  std::string lower_cookie = cookie;
  std::string lower_attribute = attribute ? attribute : "";
  std::transform(
      lower_cookie.begin(), lower_cookie.end(), lower_cookie.begin(),
      [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
  std::transform(
      lower_attribute.begin(), lower_attribute.end(), lower_attribute.begin(),
      [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
  return !lower_attribute.empty() &&
         lower_cookie.find(lower_attribute) != std::string::npos;
}

std::string CookieForJNICookieManager(std::string_view cookie_header,
                                      const std::string& domain) {
  if (cookie_header.empty()) {
    return {};
  }
  std::string cookie(cookie_header);
  if (!CookieHasAttribute(cookie, "domain=")) {
    if (!cookie.empty() && cookie.back() != ';') {
      cookie += "; ";
    } else if (!cookie.empty()) {
      cookie += ' ';
    }
    cookie += "Domain=";
    cookie += domain.empty() ? "roblox.com" : domain;
  }
  return cookie;
}

void ApplyAuthStartupDefaults(bool credential_available,
                              bool user_overrode_start_lua_app_dm,
                              bool user_overrode_start_lua_step,
                              bool user_overrode_start_app_step,
                              bool user_overrode_call_start_app) {
  if (credential_available) {
    std::cout << "  [auth] typed Roblox credential ready for native startup\n";
    return;
  }
  if (IsEnabled("MOCKTAIL_ALLOW_NO_COOKIE_LUA_APP")) {
    std::cout
        << "  [auth] no Roblox cookie found; continuing in no-cookie mode\n"
        << std::flush;
    return;
  }

  std::cerr << "  [auth] no Roblox cookie found; continuing in strict mode\n"
            << std::flush;

  if (!user_overrode_start_lua_app_dm) {
    setenv("MOCKTAIL_START_LUA_APP_DM", "0", 1);
  }
  if (!user_overrode_start_lua_step) {
    setenv("MOCKTAIL_STEP_START_LUA_APP_DM", "0", 1);
  }
  if (!user_overrode_start_app_step) {
    setenv("MOCKTAIL_STEP_START_APP_WITH_PARAMS", "0", 1);
  }
  if (!user_overrode_call_start_app) {
    setenv("MOCKTAIL_CALL_REAL_APP_BRIDGE_START", "0", 1);
  }
}

std::string ResolveClientSettingsJson() {
  mocktail::services::ClientSettingsOptions options;
  options.explicit_json = GetEnvString("MOCKTAIL_CLIENT_SETTINGS_JSON", "");
  options.explicit_file =
      GetEnvString("MOCKTAIL_CLIENT_SETTINGS_JSON_FILE", "");
  options.use_bundled = IsEnabled("MOCKTAIL_USE_BUNDLED_CLIENT_SETTINGS");
  options.sober_mode = IsEnabled("MOCKTAIL_SOBER_MODE");
  options.fetch = IsEnabled("MOCKTAIL_FETCH_CLIENT_SETTINGS");
  options.auto_update = !IsDisabled("MOCKTAIL_CLIENT_SETTINGS_AUTO_UPDATE");
  options.application =
      GetEnvString("MOCKTAIL_CLIENT_SETTINGS_APP", "GoogleAndroidApp");
  options.url = GetEnvString("MOCKTAIL_CLIENT_SETTINGS_URL", "");
  options.cache_file = GetEnvString(
      "MOCKTAIL_CLIENT_SETTINGS_CACHE_FILE",
      (MocktailCacheRoot() + "/clientsettings/" + options.application + ".json")
          .c_str());

  static mocktail::services::CurlHttpClient http_client;
  static mocktail::services::ClientSettingsService settings_service(
      http_client);
  const mocktail::services::ClientSettingsResult result =
      settings_service.Resolve(options);

  using mocktail::services::ClientSettingsSource;
  switch (result.source) {
    case ClientSettingsSource::kExplicitJson:
      break;
    case ClientSettingsSource::kExplicitFile:
      std::cout << "  [settings] using explicit client settings file "
                << options.explicit_file << " bytes=" << result.json.size()
                << '\n';
      break;
    case ClientSettingsSource::kBundledFile:
      std::cout << "  [settings] using bundled client settings "
                << options.bundled_file << " bytes=" << result.json.size()
                << '\n';
      break;
    case ClientSettingsSource::kSafeDefaults:
      std::cout << "  [settings] using safe inline client settings\n";
      break;
    case ClientSettingsSource::kDownloaded:
      std::cout << "  [settings] flags "
                << (result.cache_updated ? "updated" : "unchanged") << '\n';
      break;
    case ClientSettingsSource::kCache:
      if (!result.error.empty()) {
        std::cerr
            << "  [settings] CDN fetch failed; using cached flags if present: "
            << result.error << '\n';
      }
      std::cout << "  [settings] using cached flags\n";
      break;
    case ClientSettingsSource::kEmptyDefaults:
      if (!result.error.empty()) {
        std::cerr << "  [settings] CDN fetch failed: " << result.error << '\n';
      }
      std::cerr << "  [settings] no client settings available; using empty "
                   "defaults\n";
      break;
  }
  std::cout << std::flush;
  std::cerr << std::flush;
  return result.json;
}

jstring NewClientSettingsString(JNIEnv* env) {
  std::string content = ResolveClientSettingsJson();
  return env->NewStringUTF(content.c_str());
}

void SetObjectField(JNIEnv* env, jobject object, const char* name,
                    const char* signature, jobject value) {
  if (!env || !object || !name || !signature) {
    return;
  }
  jclass object_class = env->GetObjectClass(object);
  jfieldID field_id = env->GetFieldID(object_class, name, signature);
  env->SetObjectField(object, field_id, value);
}

void SetStringField(JNIEnv* env, jobject object, const char* name,
                    const char* value) {
  SetObjectField(env, object, name, "Ljava/lang/String;",
                 env->NewStringUTF(value ? value : ""));
}

void SetJStringField(JNIEnv* env, jobject object, const char* name,
                     jstring value) {
  if (!env || !object || !name) {
    return;
  }
  jclass object_class = env->GetObjectClass(object);
  jfieldID field_id = env->GetFieldID(object_class, name, "Ljava/lang/String;");
  env->SetObjectField(object, field_id, value);
}

void SetIntField(JNIEnv* env, jobject object, const char* name, jint value) {
  if (!env || !object || !name) {
    return;
  }
  jclass object_class = env->GetObjectClass(object);
  jfieldID field_id = env->GetFieldID(object_class, name, "I");
  env->SetIntField(object, field_id, value);
}

void SetLongField(JNIEnv* env, jobject object, const char* name, jlong value) {
  if (!env || !object || !name) {
    return;
  }
  jclass object_class = env->GetObjectClass(object);
  jfieldID field_id = env->GetFieldID(object_class, name, "J");
  env->SetLongField(object, field_id, value);
}

void SetFloatField(JNIEnv* env, jobject object, const char* name,
                   jfloat value) {
  if (!env || !object || !name) {
    return;
  }
  jclass object_class = env->GetObjectClass(object);
  jfieldID field_id = env->GetFieldID(object_class, name, "F");
  env->SetFloatField(object, field_id, value);
}

void SetBooleanField(JNIEnv* env, jobject object, const char* name,
                     jboolean value) {
  if (!env || !object || !name) {
    return;
  }
  jclass object_class = env->GetObjectClass(object);
  jfieldID field_id = env->GetFieldID(object_class, name, "Z");
  env->SetBooleanField(object, field_id, value);
}

void SetRobloxServiceUrlFields(JNIEnv* env, jobject object) {
  if (!env || !object) {
    return;
  }
  constexpr const char* kBaseUrl = "https://www.roblox.com";
  constexpr const char* kApiUrl = "https://apis.roblox.com";
  constexpr const char* kClientSettingsUrl =
      "https://clientsettingscdn.roblox.com/v2/settings-compressed/"
      "application/AndroidApp.zst";
  constexpr const char* kClientSettingsBaseUrl =
      "https://clientsettingscdn.roblox.com";
  constexpr const char* kEcsv2ClientUrl = "https://ecsv2.roblox.com/client/pbe";
  constexpr const char* kEcsv2TimespentUrl =
      "https://ecsv2.roblox.com/timespent/pbe";
  constexpr const char* kTelemetryUrl =
      "https://apis.roblox.com/experience-signals-ingest/public/v1/"
      "events/single";

  SetStringField(env, object, "baseUrl", kBaseUrl);
  SetStringField(env, object, "baseURL", kBaseUrl);
  SetStringField(env, object, "wwwBaseUrl", kBaseUrl);
  SetStringField(env, object, "apiBaseUrl", kApiUrl);
  SetStringField(env, object, "apiGatewayUrl", kApiUrl);
  SetStringField(env, object, "clientSettingsUrl", kClientSettingsUrl);
  SetStringField(env, object, "settingsUrl", kClientSettingsUrl);
  SetStringField(env, object, "clientSettingsBaseUrl", kClientSettingsBaseUrl);
  SetStringField(env, object, "clientSettingsHost", kClientSettingsBaseUrl);
  SetStringField(env, object, "ecsv2Url", kEcsv2ClientUrl);
  SetStringField(env, object, "ecsUrl", kEcsv2ClientUrl);
  SetStringField(env, object, "eventStreamUrl", kEcsv2ClientUrl);
  SetStringField(env, object, "telemetryUrl", kTelemetryUrl);
  SetStringField(env, object, "telemetryEndpoint", kTelemetryUrl);
  SetStringField(env, object, "timeSpentUrl", kEcsv2TimespentUrl);
}

jobject NewObject(JNIEnv* env, const char* class_name) {
  if (!env || !class_name) {
    return nullptr;
  }
  jclass clazz = env->FindClass(class_name);
  return env->AllocObject(clazz);
}

void InstallNativeGlJavaImplementation(JNIEnv* env,
                                       jclass native_gl_java_class) {
  if (IsDisabled("MOCKTAIL_SET_NATIVE_GL_JAVA_IMPLEMENTATION")) {
    return;
  }
  if (env == nullptr || native_gl_java_class == nullptr) {
    std::cerr << "  [engine] NativeGLJavaInterface.setImplementation skipped: "
              << "missing JNI state\n"
              << std::flush;
    return;
  }

  jobject engine_java_callback =
      NewObject(env, "com/roblox/engine/jni/EngineJavaCallback2");
  if (engine_java_callback == nullptr) {
    std::cerr << "  [engine] NativeGLJavaInterface.setImplementation skipped: "
              << "EngineJavaCallback2 allocation failed\n"
              << std::flush;
    return;
  }

  jmethodID set_implementation =
      env->GetStaticMethodID(native_gl_java_class, "setImplementation",
                             "(Lcom/roblox/engine/jni/EngineJavaCallback2;)V");
  if (set_implementation == nullptr) {
    std::cerr << "  [engine] NativeGLJavaInterface.setImplementation skipped: "
              << "method not found\n"
              << std::flush;
    return;
  }

  std::cout << "  [engine] NativeGLJavaInterface.setImplementation\n"
            << std::flush;
  env->CallStaticVoidMethod(native_gl_java_class, set_implementation,
                            engine_java_callback);
  std::cout << "  [engine] NativeGLJavaInterface.setImplementation returned\n"
            << std::flush;
}

jobject BuildPlatformParams(JNIEnv* env, jobject surface, bool is_headless);

jobject BuildDeviceParams(JNIEnv* env) {
  jobject params = NewObject(env, "com/roblox/engine/jni/model/DeviceParams");
  if (!params) {
    return nullptr;
  }

  const std::string device_name =
      GetEnvString("MOCKTAIL_DEVICE_NAME", "Mocktail Linux");
  const std::string manufacturer =
      GetEnvString("MOCKTAIL_DEVICE_MANUFACTURER", "Mocktail");
  const std::string device_sku =
      GetEnvString("MOCKTAIL_DEVICE_SKU", "mocktail-x86_64");
  const std::string soc_model =
      GetEnvString("MOCKTAIL_DEVICE_SOC_MODEL", "x86_64");
  SetStringField(env, params, "osVersion", "33");
  SetStringField(env, params, "deviceName", device_name.c_str());
  const std::string app_version =
      GetEnvString("MOCKTAIL_ROBLOX_VERSION", "unknown");
  SetStringField(env, params, "appVersion", app_version.c_str());
  SetStringField(env, params, "country", "US");
  SetStringField(env, params, "manufacturer", manufacturer.c_str());
  SetStringField(env, params, "displayResolution", "1280x720");
  SetStringField(env, params, "networkType", "wifi");
  SetStringField(env, params, "deviceSku", device_sku.c_str());
  SetStringField(env, params, "socModel", soc_model.c_str());
  SetStringField(env, params, "appBuildVariant", "googleProdRelease");
  SetStringField(env, params, "testDeviceName", device_name.c_str());

  const bool is_low_ram = !IsEnabled("MOCKTAIL_DISABLE_LOW_RAM_DEVICE");
  SetIntField(env, params, "deviceTotalMemoryMB", is_low_ram ? 2048 : 4096);
  SetIntField(env, params, "displayPhysicalWidthPixels", 1280);
  SetIntField(env, params, "displayPhysicalHeightPixels", 720);
  SetIntField(env, params, "memoryClass", is_low_ram ? 256 : 512);
  SetIntField(env, params, "largeMemoryClass", is_low_ram ? 512 : 1024);
  SetLongField(env, params, "lowMemoryKillerBackgroundAppThreshold",
               is_low_ram ? 256 : 0);
  SetLongField(env, params, "lowMemoryKillerForegroundAppThreshold",
               is_low_ram ? 512 : 0);
  SetBooleanField(env, params, "cpu64Bit", JNI_TRUE);
  SetBooleanField(env, params, "isChrome", JNI_FALSE);
  SetBooleanField(env, params, "isLowRamDevice",
                  is_low_ram ? JNI_TRUE : JNI_FALSE);
  return params;
}

jobject BuildAppBridgeInitParams(JNIEnv* env, jstring client_settings,
                                 jstring fast_flags, jstring app_params,
                                 jstring asset_path, bool is_headless) {
  jobject params = NewObject(env, "com/roblox/engine/jni/autovalue/InitParams");
  if (!params) {
    return nullptr;
  }

  jobject activity = NewObject(env, "com/roblox/client/RobloxActivity");
  jobject context = NewObject(env, "android/content/Context");
  jobject asset_manager = NewObject(env, "android/content/res/AssetManager");
  jobject resources = NewObject(env, "android/content/res/Resources");
  jobject class_loader = NewObject(env, "java/lang/ClassLoader");
  jobject package_manager = NewObject(env, "android/content/pm/PackageManager");
  jobject window = NewObject(env, "android/view/Window");
  jobject display = NewObject(env, "android/view/Display");
  jobject surface = NewObject(env, "android/view/Surface");
  jobject platform_params = BuildPlatformParams(env, surface, is_headless);
  jobject device_params = BuildDeviceParams(env);
  jobject surface_holder = NewObject(env, "android/view/SurfaceHolder");
  jobject view = NewObject(env, "android/view/View");

  SetObjectField(env, params, "platformParams",
                 "Lcom/roblox/engine/jni/model/PlatformParams;",
                 platform_params);
  jobject start_game_device_params =
      IsEnabled("MOCKTAIL_START_GAME_DEVICE_PARAMS_NON_NULL") ? device_params
                                                              : nullptr;
  SetObjectField(env, params, "deviceParams",
                 "Lcom/roblox/engine/jni/model/DeviceParams;",
                 start_game_device_params);
  SetStringField(env, params, "baseURL", "https://www.roblox.com");
  const std::string user_agent = GetEnvString(
      "MOCKTAIL_USER_AGENT", "Roblox/unknown (Linux; Android 33; Mocktail)");
  SetStringField(env, params, "userAgent", user_agent.c_str());
  SetBooleanField(env, params, "isTablet", JNI_FALSE);
  SetBooleanField(env, params, "isPotato", JNI_FALSE);
  SetBooleanField(env, params, "isVrDevice", JNI_FALSE);
  SetStringField(env, params, "buildVariant", "googleProdRelease");
  SetObjectField(env, params, "vrContext", "Landroid/app/Activity;", activity);

  SetObjectField(env, params, "activity", "Lcom/roblox/client/RobloxActivity;",
                 activity);
  SetObjectField(env, params, "robloxActivity",
                 "Lcom/roblox/client/RobloxActivity;", activity);
  SetObjectField(env, params, "mainActivity",
                 "Lcom/roblox/client/RobloxActivity;", activity);
  SetObjectField(env, params, "context", "Landroid/content/Context;", context);
  SetObjectField(env, params, "applicationContext", "Landroid/content/Context;",
                 context);
  SetObjectField(env, params, "assetManager",
                 "Landroid/content/res/AssetManager;", asset_manager);
  SetObjectField(env, params, "assets", "Landroid/content/res/AssetManager;",
                 asset_manager);
  SetObjectField(env, params, "resources", "Landroid/content/res/Resources;",
                 resources);
  SetObjectField(env, params, "classLoader", "Ljava/lang/ClassLoader;",
                 class_loader);
  SetObjectField(env, params, "packageManager",
                 "Landroid/content/pm/PackageManager;", package_manager);
  SetObjectField(env, params, "window", "Landroid/view/Window;", window);
  SetObjectField(env, params, "display", "Landroid/view/Display;", display);
  SetObjectField(env, params, "surface", "Landroid/view/Surface;", surface);
  SetObjectField(env, params, "surfaceHolder", "Landroid/view/SurfaceHolder;",
                 surface_holder);
  SetObjectField(env, params, "view", "Landroid/view/View;", view);
  SetObjectField(env, params, "decorView", "Landroid/view/View;", view);
  SetObjectField(env, params, "rootView", "Landroid/view/View;", view);

  SetObjectField(env, params, "clientSettingsJson", "Ljava/lang/String;",
                 client_settings);
  SetObjectField(env, params, "clientSettings", "Ljava/lang/String;",
                 client_settings);
  SetObjectField(env, params, "fastFlagsJson", "Ljava/lang/String;",
                 fast_flags);
  SetObjectField(env, params, "fastFlags", "Ljava/lang/String;", fast_flags);
  SetObjectField(env, params, "appParamsJson", "Ljava/lang/String;",
                 app_params);
  SetObjectField(env, params, "appParams", "Ljava/lang/String;", app_params);
  SetObjectField(env, params, "launchParams", "Ljava/lang/String;", app_params);
  SetObjectField(env, params, "assetPath", "Ljava/lang/String;", asset_path);

  SetStringField(env, params, "packageName", "com.roblox.client");
  SetStringField(env, params, "platformName", "Android");
  const std::string init_app_version =
      GetEnvString("MOCKTAIL_ROBLOX_VERSION", "unknown");
  SetStringField(env, params, "appVersion", init_app_version.c_str());
  const std::string init_device_name =
      GetEnvString("MOCKTAIL_DEVICE_NAME", "Mocktail Headless");
  SetStringField(env, params, "deviceName", init_device_name.c_str());
  SetStringField(env, params, "locale", "en_us");
  SetRobloxServiceUrlFields(env, params);

  SetIntField(env, params, "screenWidth", 1280);
  SetIntField(env, params, "screenHeight", 720);
  SetIntField(env, params, "densityDpi", 160);
  SetIntField(env, params, "sdkVersion", 33);
  jboolean headless = is_headless ? JNI_TRUE : JNI_FALSE;
  SetBooleanField(env, params, "headless", headless);
  SetBooleanField(env, params, "isHeadless", headless);
  SetBooleanField(env, params, "isFirstInstall", JNI_FALSE);
  SetBooleanField(env, params, "isLowMemoryDevice", JNI_FALSE);

  return params;
}

jobject BuildApplicationExitInfoList(JNIEnv* env) {
  jobject list = NewObject(env, "java/util/ArrayList");
  if (!list) {
    list = NewObject(env, "java/util/List");
  }
  return list;
}

jobject BuildPlatformParams(JNIEnv* env, jobject surface, bool is_headless) {
  jobject params = NewObject(env, "com/roblox/engine/jni/model/PlatformParams");
  if (!params) {
    return nullptr;
  }

  SetObjectField(env, params, "surface", "Landroid/view/Surface;", surface);
  SetStringField(env, params, "platform", "Android");
  const std::string platform_device_name =
      GetEnvString("MOCKTAIL_DEVICE_NAME", "Mocktail Headless");
  SetStringField(env, params, "deviceName", platform_device_name.c_str());
  SetStringField(env, params, "locale", "en_us");
  SetStringField(env, params, "assetFolderPath", DefaultAssetPath().c_str());
  SetIntField(env, params, "width", 1280);
  SetIntField(env, params, "height", 720);
  SetIntField(env, params, "screenWidth", 1280);
  SetIntField(env, params, "screenHeight", 720);
  SetIntField(env, params, "densityDpi", 160);
  SetIntField(env, params, "viewportWidthMm", 203);
  SetIntField(env, params, "viewportHeightMm", 114);
  SetFloatField(env, params, "dpiScale", 1.0f);
  SetBooleanField(
      env, params, "isKeyboardDevice",
      IsEnabled("MOCKTAIL_KEYBOARD_ENABLED_INTERNAL") ? JNI_TRUE : JNI_FALSE);
  SetBooleanField(
      env, params, "isMouseDevice",
      IsEnabled("MOCKTAIL_MOUSE_ENABLED_INTERNAL") ? JNI_TRUE : JNI_FALSE);
  SetBooleanField(
      env, params, "isTouchDevice",
      IsEnabled("MOCKTAIL_TOUCH_ENABLED_INTERNAL") ? JNI_TRUE : JNI_FALSE);
  SetBooleanField(env, params, "isLuaHomePageEnabled", JNI_TRUE);
  SetBooleanField(env, params, "isLuaGamesPageEnabled", JNI_TRUE);
  SetBooleanField(env, params, "isLuaChatEnabled", JNI_TRUE);
  SetBooleanField(env, params, "isTablet", JNI_FALSE);
  jboolean headless = is_headless ? JNI_TRUE : JNI_FALSE;
  SetBooleanField(env, params, "headless", headless);
  SetBooleanField(env, params, "isHeadless", headless);
  return params;
}

jobject BuildStartAppParams(JNIEnv* env, jstring app_params,
                            jobject platform_params, jobject surface,
                            bool is_headless, const char* launch_mode,
                            const jnivm::RobloxAuthIdentity& identity) {
  jobject params =
      NewObject(env, "com/roblox/engine/jni/autovalue/StartAppParams");
  if (!params) {
    return nullptr;
  }

  jobject activity = NewObject(env, "com/roblox/client/RobloxActivity");
  jobject context = NewObject(env, "android/content/Context");
  jobject asset_manager = NewObject(env, "android/content/res/AssetManager");
  jobject resources = NewObject(env, "android/content/res/Resources");
  jobject class_loader = NewObject(env, "java/lang/ClassLoader");
  jobject package_manager = NewObject(env, "android/content/pm/PackageManager");
  jobject window = NewObject(env, "android/view/Window");
  jobject display = NewObject(env, "android/view/Display");
  jobject surface_holder = NewObject(env, "android/view/SurfaceHolder");
  jobject view = NewObject(env, "android/view/View");

  SetObjectField(env, params, "surface", "Landroid/view/Surface;", surface);
  SetObjectField(env, params, "platformParams",
                 "Lcom/roblox/engine/jni/model/PlatformParams;",
                 platform_params);
  SetStringField(env, params, "appStarterPlace",
                 "rbxasset://places/Mobile.rbxl");
  SetStringField(env, params, "appStarterScript", "LuaAppStarterScript");
  SetLongField(env, params, "appUserId", identity.user_id);
  SetBooleanField(env, params, "isUnder13", JNI_FALSE);
  SetStringField(env, params, "username", identity.username.c_str());
  SetIntField(env, params, "membershipType",
              GetEnvInt("MOCKTAIL_ROBLOX_MEMBERSHIP_TYPE", 0));
  const char* theme = std::getenv("MOCKTAIL_RESOLVED_THEME_INTERNAL");
  SetStringField(env, params, "selectedTheme",
                 theme != nullptr ? theme : "Dark");
  SetObjectField(env, params, "vrContext", "Landroid/app/Activity;", activity);

  SetObjectField(env, params, "appParams", "Ljava/lang/String;", app_params);
  SetObjectField(env, params, "appParamsJson", "Ljava/lang/String;",
                 app_params);
  SetObjectField(env, params, "launchParams", "Ljava/lang/String;", app_params);
  SetObjectField(env, params, "activity", "Lcom/roblox/client/RobloxActivity;",
                 activity);
  SetObjectField(env, params, "robloxActivity",
                 "Lcom/roblox/client/RobloxActivity;", activity);
  SetObjectField(env, params, "mainActivity",
                 "Lcom/roblox/client/RobloxActivity;", activity);
  SetObjectField(env, params, "context", "Landroid/content/Context;", context);
  SetObjectField(env, params, "applicationContext", "Landroid/content/Context;",
                 context);
  SetObjectField(env, params, "assetManager",
                 "Landroid/content/res/AssetManager;", asset_manager);
  SetObjectField(env, params, "assets", "Landroid/content/res/AssetManager;",
                 asset_manager);
  SetObjectField(env, params, "resources", "Landroid/content/res/Resources;",
                 resources);
  SetObjectField(env, params, "classLoader", "Ljava/lang/ClassLoader;",
                 class_loader);
  SetObjectField(env, params, "packageManager",
                 "Landroid/content/pm/PackageManager;", package_manager);
  SetObjectField(env, params, "window", "Landroid/view/Window;", window);
  SetObjectField(env, params, "display", "Landroid/view/Display;", display);
  SetObjectField(env, params, "surfaceHolder", "Landroid/view/SurfaceHolder;",
                 surface_holder);
  SetObjectField(env, params, "view", "Landroid/view/View;", view);
  SetObjectField(env, params, "decorView", "Landroid/view/View;", view);
  SetObjectField(env, params, "rootView", "Landroid/view/View;", view);
  const char* mode = launch_mode;
  if (mode == nullptr || mode[0] == '\0') {
    mode = is_headless ? "headless" : "normal";
  }
  SetStringField(env, params, "launchMode", mode);
  SetStringField(env, params, "joinData", "{}");
  SetStringField(env, params, "packageName", "com.roblox.client");
  SetStringField(env, params, "platformName", "Android");
  const std::string start_app_version =
      GetEnvString("MOCKTAIL_ROBLOX_VERSION", "unknown");
  SetStringField(env, params, "appVersion", start_app_version.c_str());
  const std::string start_device_name =
      GetEnvString("MOCKTAIL_DEVICE_NAME", "Mocktail Linux");
  SetStringField(env, params, "deviceName", start_device_name.c_str());
  SetStringField(env, params, "locale", "en_us");
  SetRobloxServiceUrlFields(env, params);
  SetIntField(env, params, "width", 1280);
  SetIntField(env, params, "height", 720);
  SetIntField(env, params, "screenWidth", 1280);
  SetIntField(env, params, "screenHeight", 720);
  SetIntField(env, params, "densityDpi", 160);
  SetIntField(env, params, "sdkVersion", 33);
  SetIntField(env, params, "placeId", 0);
  jboolean headless = is_headless ? JNI_TRUE : JNI_FALSE;
  SetBooleanField(env, params, "headless", headless);
  SetBooleanField(env, params, "isHeadless", headless);
  SetBooleanField(env, params, "isFirstInstall", JNI_FALSE);
  SetBooleanField(env, params, "isLowMemoryDevice", JNI_FALSE);
  return params;
}

jobject BuildStartGameParams(JNIEnv* env, jobject platform_params,
                             jobject device_params, jobject surface,
                             jobject vr_context, const char* launch_data_env,
                             const jnivm::RobloxAuthIdentity& identity) {
  std::cout << "  [engine] BuildStartGameParams begin\n" << std::flush;
  if (!env) {
    std::cerr << "  [engine] BuildStartGameParams: env is null\n" << std::flush;
    return nullptr;
  }
  jclass start_game_params_class =
      env->FindClass("com/roblox/engine/jni/autovalue/StartGameParams");
  if (!start_game_params_class) {
    std::cerr
        << "  [engine] BuildStartGameParams: StartGameParams class not found\n"
        << std::flush;
    return nullptr;
  }
  const jlong place_id = GetEnvLong("MOCKTAIL_PLACE_ID", 0);
  const jlong join_target_user_id = GetEnvLong("MOCKTAIL_GAME_JOIN_USER_ID", 0);
  const jlong conversation_id = GetEnvLong("MOCKTAIL_GAME_CONVERSATION_ID", 0);
  const jlong referred_by_player_id =
      GetEnvLong("MOCKTAIL_REFERRED_BY_PLAYER_ID", 0);
  const jint join_request_type =
      GetEnvInt("MOCKTAIL_GAME_JOIN_REQUEST_TYPE", -1);
  const std::string access_code_value =
      GetEnvString("MOCKTAIL_GAME_ACCESS_CODE", "");
  const std::string link_code_value =
      GetEnvString("MOCKTAIL_GAME_LINK_CODE", "");
  const std::string reserved_server_access_code_value =
      GetEnvString("MOCKTAIL_GAME_RESERVED_SERVER_ACCESS_CODE", "");
  const std::string call_id_value = GetEnvString("MOCKTAIL_GAME_CALL_ID", "");
  const std::string event_id_value = GetEnvString("MOCKTAIL_GAME_EVENT_ID", "");
  const std::string join_attempt_id_value =
      GetEnvString("MOCKTAIL_GAME_JOIN_ATTEMPT_ID", "");
  const std::string join_attempt_origin_value =
      GetEnvString("MOCKTAIL_GAME_JOIN_ATTEMPT_ORIGIN", "");
  const std::string iso_context_value =
      GetEnvString("MOCKTAIL_GAME_ISO_CONTEXT", "");
  const std::string& username_value = identity.username;
  const std::string launch_data_value =
      GetEnvString(launch_data_env != nullptr ? launch_data_env
                                              : "MOCKTAIL_GAME_PARAMS_JSON",
                   "");
  const std::string game_id_value = GetEnvString("MOCKTAIL_GAME_ID", "");
  const std::string referral_page_value =
      GetEnvString("MOCKTAIL_REFERRAL_PAGE", "");
  const std::string game_join_context_value =
      GetEnvString("MOCKTAIL_GAME_JOIN_CONTEXT", "");
  if (EngineTraceEnabled()) {
    std::cout << "  [engine] StartGame params: place_id=" << place_id
              << " join_target_user_id=" << join_target_user_id
              << " game_id=" << game_id_value
              << " join_request_type=" << join_request_type << '\n'
              << std::flush;
  }

  const jstring access_code = env->NewStringUTF(access_code_value.c_str());
  const jstring link_code = env->NewStringUTF(link_code_value.c_str());
  const jstring reserved_server_access_code =
      env->NewStringUTF(reserved_server_access_code_value.c_str());
  const jstring call_id = env->NewStringUTF(call_id_value.c_str());
  const jstring event_id = env->NewStringUTF(event_id_value.c_str());
  const jstring join_attempt_id =
      env->NewStringUTF(join_attempt_id_value.c_str());
  const jstring join_attempt_origin =
      env->NewStringUTF(join_attempt_origin_value.c_str());
  const jstring iso_context = env->NewStringUTF(iso_context_value.c_str());
  jstring username = env->NewStringUTF(username_value.c_str());
  jstring launch_data = env->NewStringUTF(launch_data_value.c_str());
  jstring game_id = env->NewStringUTF(game_id_value.c_str());
  jstring referral_page = env->NewStringUTF(referral_page_value.c_str());
  jstring game_join_context =
      env->NewStringUTF(game_join_context_value.c_str());

  jobject params =
      NewObject(env, "com/roblox/engine/jni/autovalue/StartGameParams");
  if (!params) {
    return nullptr;
  }

  SetObjectField(env, params, "surface", "Landroid/view/Surface;", surface);
  SetObjectField(env, params, "platformParams",
                 "Lcom/roblox/engine/jni/model/PlatformParams;",
                 platform_params);
  SetObjectField(env, params, "deviceParams",
                 "Lcom/roblox/engine/jni/model/DeviceParams;", nullptr);
  SetLongField(env, params, "placeId", place_id);
  SetLongField(env, params, "userId", join_target_user_id);
  SetJStringField(env, params, "accessCode", access_code);
  SetJStringField(env, params, "callId", call_id);
  SetJStringField(env, params, "linkCode", link_code);
  SetJStringField(env, params, "reservedServerAccessCode",
                  reserved_server_access_code);
  SetLongField(env, params, "conversationId", conversation_id);
  SetIntField(env, params, "joinRequestType", join_request_type);
  SetJStringField(env, params, "gameId", game_id);
  SetBooleanField(env, params, "isUnder13", JNI_FALSE);
  SetJStringField(env, params, "username", username);
  SetJStringField(env, params, "referralPage", referral_page);
  SetJStringField(env, params, "launchData", launch_data);
  SetJStringField(env, params, "gameJoinContext", game_join_context);
  SetJStringField(env, params, "eventId", event_id);
  SetJStringField(env, params, "joinAttemptId", join_attempt_id);
  SetJStringField(env, params, "joinAttemptOrigin", join_attempt_origin);
  SetJStringField(env, params, "isoContext", iso_context);
  SetLongField(env, params, "referredByPlayerId", referred_by_player_id);
  SetObjectField(env, params, "vrContext", "Landroid/app/Activity;",
                 vr_context);

  return params;
}

jobject BuildMockSurface(JNIEnv* env) {
  jobject surface = NewObject(env, "android/view/Surface");
  if (!surface) {
    return nullptr;
  }
  SetIntField(env, surface, "width", 1280);
  SetIntField(env, surface, "height", 720);
  SetBooleanField(env, surface, "valid", JNI_TRUE);
  SetBooleanField(env, surface, "isValid", JNI_TRUE);
  return surface;
}

jobject BuildConfiguration(JNIEnv* env) {
  return jnivm::CreateAndroidConfiguration(env);
}

void ConfigureNativeSettings(JNIEnv* env, jclass settings_class,
                             const EngineStartupContext* context) {
  if (!env || !settings_class || !context) {
    return;
  }

  const std::string sober_data_root = SoberDataRoot();
  const std::string sober_cache_root = SoberCacheRoot();
  std::string data_dir = GetEnvStringDefaultPath(
      "MOCKTAIL_ANDROID_DATA_DIR",
      DefaultSoberAwarePath(sober_data_root.c_str(),
                            "/data/user/0/com.roblox.client"));
  std::string files_dir = GetEnvStringDefaultPath(
      "MOCKTAIL_ANDROID_FILES_DIR",
      DefaultSoberAwarePath((sober_data_root + "/files").c_str(),
                            "/data/user/0/com.roblox.client/files"));
  std::string settings_cache_dir = GetEnvStringDefaultPath(
      "MOCKTAIL_ANDROID_SETTINGS_CACHE_DIR",
      DefaultSoberAwarePath(sober_cache_root.c_str(),
                            "/data/user/0/com.roblox.client"));
  std::string cache_dir = GetEnvStringDefaultPath(
      "MOCKTAIL_ANDROID_CACHE_DIR",
      DefaultSoberAwarePath((sober_cache_root + "/cache").c_str(),
                            "/data/user/0/com.roblox.client/cache"));
  std::string external_base = GetEnvStringDefaultPath(
      "MOCKTAIL_ANDROID_EXTERNAL_BASE_DIR",
      DefaultSoberAwarePath((sober_data_root + "/sdcard/Android/data/"
                                               "com.roblox.client")
                                .c_str(),
                            "/sdcard/Android/data/com.roblox.client"));
  std::string external_dir = GetEnvStringDefaultPath(
      "MOCKTAIL_ANDROID_EXTERNAL_DIR",
      DefaultSoberAwarePath((external_base + "/files").c_str(),
                            "/sdcard/Android/data/com.roblox.client/files"));
  std::string preferences_file =
      GetEnvString("MOCKTAIL_ANDROID_PREFERENCES_FILE", "prefs");
  std::string default_policy_file = GetEnvString(
      "MOCKTAIL_DEFAULT_APP_POLICY_FILE",
      "content/guac/defaultConfigs/GuacDefaultPolicy-GlobalDist.json");
  std::string base_url =
      GetEnvString("MOCKTAIL_BASE_URL", "https://www.roblox.com/");
  std::string api_url =
      GetEnvString("MOCKTAIL_API_URL", "https://api.roblox.com/");
  std::string roblox_channel =
      GetEnvString("MOCKTAIL_ROBLOX_CHANNEL", "production");
  std::string channel_platform_name =
      GetEnvString("MOCKTAIL_CHANNEL_PLATFORM_NAME", "GoogleAndroidApp");
  std::string roblox_version =
      GetEnvString("MOCKTAIL_ROBLOX_VERSION", "unknown");
  std::string exception_reason_filename = GetEnvString(
      "MOCKTAIL_EXCEPTION_REASON_FILENAME", "exception_reason.txt");
  std::string http_proxy_host = GetEnvString("MOCKTAIL_HTTP_PROXY_HOST", "");
  jlong http_proxy_port =
      static_cast<jlong>(GetEnvInt("MOCKTAIL_HTTP_PROXY_PORT", 0));
  std::string cookie_base_url =
      GetEnvString("MOCKTAIL_COOKIE_BASE_URL", "https://www.roblox.com/");
  std::string cookie_domain =
      GetEnvString("MOCKTAIL_COOKIE_DOMAIN", "roblox.com");
  const mocktail::runtime::SecureRobloxCredential* credential =
      context->roblox_credential;
  const std::string_view roblox_cookies =
      credential != nullptr ? credential->view() : std::string_view();
  std::string cookie_manager_cookies =
      CookieForJNICookieManager(roblox_cookies, cookie_domain);
  if (!roblox_cookies.empty()) {
    std::cout << "  [engine] typed credential prepared bytes="
              << roblox_cookies.size() << '\n'
              << std::flush;
  } else if (IsEnabled("MOCKTAIL_ALLOW_NO_COOKIE_LUA_APP")) {
    std::cout << "  [engine] no Roblox cookie found; proceeding without login\n"
              << std::flush;
  } else {
    std::cout << "  [engine] WARNING: no Roblox cookie found at "
              << MocktailCookiePath() << '\n'
              << std::flush;
  }
  std::string android_id =
      GetEnvString("MOCKTAIL_ANDROID_ID", "0000000000000000");
  std::string advertising_id = GetEnvString("MOCKTAIL_ADVERTISING_ID", "");
  const jnivm::RobloxAuthIdentity& account_identity = context->account_identity;
  std::string account_user_id = std::to_string(account_identity.user_id);

  EnsureAndroidDirectory(data_dir);
  EnsureAndroidDirectory(files_dir);
  EnsureAndroidDirectory(settings_cache_dir);
  EnsureAndroidDirectory(cache_dir);
  EnsureAndroidDirectory(external_base);
  EnsureAndroidDirectory(external_dir);
  EnsureAndroidDirectory(data_dir + "/rbx-storage");
  EnsureAndroidDirectory(data_dir + "/appData");
  EnsureAndroidDirectory(data_dir + "/appData/LocalStorage");
  EnsureAndroidDirectory(data_dir + "/appData/rbx-storage");
  EnsureAndroidDirectory(files_dir + "/rbx-storage");
  EnsureAndroidDirectory(files_dir + "/appData");
  EnsureAndroidDirectory(files_dir + "/appData/LocalStorage");
  EnsureAndroidDirectory(files_dir + "/appData/OTAPatchBackups");
  EnsureAndroidDirectory(files_dir + "/appData/rbx-storage");
  EnsureAndroidDirectory(cache_dir + "/ContentProvider_2");
  EnsureAndroidDirectory(cache_dir + "/rbx-storage");
  EnsureAndroidDirectory(cache_dir + "/sounds");

  jstring data_dir_string = env->NewStringUTF(data_dir.c_str());
  jstring files_dir_string = env->NewStringUTF(files_dir.c_str());
  jstring settings_cache_dir_string =
      env->NewStringUTF(settings_cache_dir.c_str());
  jstring external_base_string = env->NewStringUTF(external_base.c_str());
  jstring external_dir_string = env->NewStringUTF(external_dir.c_str());
  jstring preferences_file_string = env->NewStringUTF(preferences_file.c_str());
  jstring default_policy_file_string =
      env->NewStringUTF(default_policy_file.c_str());
  jstring base_url_string = env->NewStringUTF(base_url.c_str());
  jstring api_url_string = env->NewStringUTF(api_url.c_str());
  jstring roblox_channel_string = env->NewStringUTF(roblox_channel.c_str());
  jstring channel_platform_name_string =
      env->NewStringUTF(channel_platform_name.c_str());
  jstring roblox_version_string = env->NewStringUTF(roblox_version.c_str());
  jstring exception_reason_filename_string =
      env->NewStringUTF(exception_reason_filename.c_str());
  jstring http_proxy_host_string = env->NewStringUTF(http_proxy_host.c_str());
  jstring cookie_base_url_string = env->NewStringUTF(cookie_base_url.c_str());
  jstring cookie_domain_string = env->NewStringUTF(cookie_domain.c_str());
  jstring roblox_cookies_string =
      env->NewStringUTF(credential != nullptr ? credential->c_str() : "");
  jstring cookie_manager_cookies_string =
      env->NewStringUTF(cookie_manager_cookies.c_str());
  jstring android_id_string = env->NewStringUTF(android_id.c_str());
  jstring advertising_id_string = env->NewStringUTF(advertising_id.c_str());
  jstring googleplay_string = env->NewStringUTF("googleplay");
  jstring user_id_string = env->NewStringUTF(account_user_id.c_str());
  auto run_native_setting = [](const char* name, auto call) -> bool {
    if (sigsetjmp(g_native_settings_jmp_buf, 1) == 0) {
      g_native_settings_recovery_name = name;
      g_native_settings_recovery_in_progress = 1;
      call();
      g_native_settings_recovery_in_progress = 0;
      g_native_settings_recovery_name = nullptr;
      return true;
    }
    g_native_settings_recovery_in_progress = 0;
    std::cerr << "  [engine] NativeSettings " << name
              << " recovered from crash\n"
              << std::flush;
    g_native_settings_recovery_name = nullptr;
    return false;
  };

  if (context->native_set_http_client_proxy &&
      ShouldRunStartupStep("MOCKTAIL_NATIVE_SET_HTTP_CLIENT_PROXY", false)) {
    std::cout << "  [engine] NativeSettings httpClientProxy host="
              << http_proxy_host << " port=" << http_proxy_port << '\n'
              << std::flush;
    run_native_setting("httpClientProxy", [&]() {
      context->native_set_http_client_proxy(
          env, settings_class, http_proxy_host_string, http_proxy_port);
    });
  }
  if (context->native_set_exception_reason_filename &&
      ShouldRunStartupStep("MOCKTAIL_NATIVE_SET_EXCEPTION_REASON_FILENAME",
                           true)) {
    std::cout << "  [engine] NativeSettings exceptionReasonFilename="
              << exception_reason_filename << '\n'
              << std::flush;
    run_native_setting("exceptionReasonFilename", [&]() {
      context->native_set_exception_reason_filename(
          env, settings_class, exception_reason_filename_string);
    });
  }
  if (context->native_set_base_url &&
      ShouldRunStartupStep("MOCKTAIL_NATIVE_SET_BASE_URL", true)) {
    std::cout << "  [engine] NativeSettings baseUrl=" << base_url
              << " apiUrl=" << api_url << '\n'
              << std::flush;
    run_native_setting("baseUrl", [&]() {
      context->native_set_base_url(env, settings_class, base_url_string,
                                   api_url_string);
    });
  }
  if (context->native_set_roblox_channel &&
      ShouldRunStartupStep("MOCKTAIL_NATIVE_SET_ROBLOX_CHANNEL", false)) {
    std::cout << "  [engine] NativeSettings robloxChannel=" << roblox_channel
              << '\n'
              << std::flush;
    run_native_setting("robloxChannel", [&]() {
      context->native_set_roblox_channel(env, settings_class,
                                         roblox_channel_string);
    });
  }
  if (context->native_override_channel_platform_name &&
      ShouldRunStartupStep("MOCKTAIL_NATIVE_OVERRIDE_CHANNEL_PLATFORM_NAME",
                           true)) {
    std::cout << "  [engine] NativeSettings channelPlatformName="
              << channel_platform_name << '\n'
              << std::flush;
    run_native_setting("channelPlatformName", [&]() {
      context->native_override_channel_platform_name(
          env, settings_class, channel_platform_name_string);
    });
  }
  if (context->native_set_roblox_version &&
      ShouldRunStartupStep("MOCKTAIL_NATIVE_SET_ROBLOX_VERSION", true)) {
    std::cout << "  [engine] NativeSettings robloxVersion=" << roblox_version
              << '\n'
              << std::flush;
    run_native_setting("robloxVersion", [&]() {
      context->native_set_roblox_version(env, settings_class,
                                         roblox_version_string);
    });
  }
  if (context->native_set_device_info &&
      ShouldRunStartupStep("MOCKTAIL_NATIVE_SET_DEVICE_INFO", true)) {
    std::cout << "  [engine] NativeSettings deviceInfo\n" << std::flush;
    jobject device_params = BuildDeviceParams(env);
    run_native_setting("deviceInfo", [&]() {
      context->native_set_device_info(env, settings_class, device_params);
    });
  }

  if (ShouldRunStartupStep("MOCKTAIL_NATIVE_SET_BASE_DATA_DIRS", true)) {
    run_native_setting("baseDataDirectories", [&]() {
      context->native_set_base_data_directories(
          env, settings_class, data_dir_string, external_base_string);
    });
  }
  if (ShouldRunStartupStep("MOCKTAIL_NATIVE_SET_CACHE_DIR", true)) {
    run_native_setting("cacheDirectory", [&]() {
      context->native_set_cache_directory(env, settings_class,
                                          settings_cache_dir_string);
    });
  }
  if (ShouldRunStartupStep("MOCKTAIL_NATIVE_SET_FILES_DIR", true)) {
    run_native_setting("filesDirectory", [&]() {
      context->native_set_files_directory(env, settings_class,
                                          files_dir_string);
    });
  }
  if (ShouldRunStartupStep("MOCKTAIL_NATIVE_SET_EXTERNAL_DIR", true)) {
    run_native_setting("externalDirectory", [&]() {
      context->native_set_external_directory(env, settings_class,
                                             external_dir_string);
    });
  }
  if (ShouldRunStartupStep("MOCKTAIL_NATIVE_SET_PREFERENCES_FILE", true)) {
    run_native_setting("preferencesFile", [&]() {
      context->native_set_preferences_file(env, settings_class,
                                           preferences_file_string);
    });
  }
  if (ShouldRunStartupStep("MOCKTAIL_NATIVE_SET_DEFAULT_POLICY_FILE", false)) {
    run_native_setting("defaultPolicyFile", [&]() {
      context->native_set_default_app_policy_file(env, settings_class,
                                                  default_policy_file_string);
    });
  }
  if (context->native_init_fast_log &&
      ShouldRunStartupStep("MOCKTAIL_NATIVE_INIT_FAST_LOG", true)) {
    std::cout << "  [engine] NativeSettings initFastLog\n" << std::flush;
    run_native_setting("initFastLog", [&]() {
      context->native_init_fast_log(env, settings_class);
    });
  }

  jclass cookie_manager_class = nullptr;
  auto find_cookie_manager_class = [&]() -> jclass {
    if (cookie_manager_class == nullptr) {
      cookie_manager_class =
          env->FindClass("com/roblox/universalapp/cookie/JNICookieManager");
    }
    return cookie_manager_class;
  };
  if (context->native_cookie_manager_set_cookie &&
      !cookie_manager_cookies.empty() &&
      // This native path expects Roblox's full cookie backend singleton. In
      // Mocktail it currently reaches heap function pointers, so keep it
      // opt-in.
      ShouldRunStartupStep("MOCKTAIL_JNI_COOKIE_MANAGER_SET_COOKIE", false)) {
    jclass cls = find_cookie_manager_class();
    if (cls != nullptr) {
      std::cout << "  [engine] JNICookieManager.setCookie domain="
                << cookie_domain << " bytes=" << cookie_manager_cookies.size()
                << '\n'
                << std::flush;
      if (IsEnabled("MOCKTAIL_UNSAFE_NATIVE_COOKIE_SETTER")) {
        if (sigsetjmp(g_cookie_setter_jmp_buf, 1) == 0) {
          g_cookie_setter_recovery_in_progress = 1;
          context->native_cookie_manager_set_cookie(
              env, cls, cookie_domain_string, cookie_manager_cookies_string);
          g_cookie_setter_recovery_in_progress = 0;
          std::cout << "  [engine] JNICookieManager.setCookie returned\n"
                    << std::flush;
        } else {
          g_cookie_setter_recovery_in_progress = 0;
          std::cerr << "  [engine] JNICookieManager.setCookie recovered; "
                    << "native cookie singleton is not ready\n"
                    << std::flush;
        }
      } else {
        std::cerr << "  [engine] JNICookieManager.setCookie blocked; set "
                  << "MOCKTAIL_UNSAFE_NATIVE_COOKIE_SETTER=1 to run the "
                  << "known-crashing native path\n"
                  << std::flush;
      }
    }
  } else if (!cookie_manager_cookies.empty() &&
             context->native_cookie_manager_set_cookie != nullptr) {
    std::cout << "  [engine] JNICookieManager.setCookie skipped; set "
              << "MOCKTAIL_JNI_COOKIE_MANAGER_SET_COOKIE=1 to force\n"
              << std::flush;
  } else if (!cookie_manager_cookies.empty() &&
             context->native_cookie_manager_set_cookie == nullptr) {
    std::cout << "  [engine] WARNING: JNICookieManager.setCookie unavailable\n"
              << std::flush;
  }

  if (context->native_set_multiple_cookies && !roblox_cookies.empty() &&
      ShouldRunStartupStep("MOCKTAIL_NATIVE_SET_MULTIPLE_COOKIES", true)) {
    std::cout << "  [engine] NativeSettings multipleCookies base="
              << cookie_base_url << " bytes=" << roblox_cookies.size() << '\n'
              << std::flush;
    run_native_setting("multipleCookies", [&]() {
      context->native_set_multiple_cookies(
          env, settings_class, cookie_base_url_string, roblox_cookies_string);
    });
    std::cout << "  [engine] NativeSettings multipleCookies returned\n"
              << std::flush;
  }
  if (context->native_set_platform_headers_with_idfa &&
      ShouldRunStartupStep("MOCKTAIL_NATIVE_SET_PLATFORM_HEADERS", false)) {
    std::cout << "  [engine] NativeSettings platformHeaders androidId="
              << android_id << '\n'
              << std::flush;
    run_native_setting("platformHeaders", [&]() {
      context->native_set_platform_headers_with_idfa(
          env, settings_class, android_id_string, googleplay_string,
          advertising_id_string);
    });
  }
  if (context->native_set_user_id &&
      ShouldRunStartupStep("MOCKTAIL_NATIVE_SET_USER_ID", false)) {
    std::cout << "  [engine] NativeSettings userId=" << account_user_id << '\n'
              << std::flush;
    run_native_setting("userId", [&]() {
      context->native_set_user_id(env, settings_class, user_id_string);
    });
  }
  mocktail::runtime::SecurelyClearString(&cookie_manager_cookies);
}

void ConfigureLocalStorage(JNIEnv* env, const EngineStartupContext* context) {
  if (!env || !context) {
    return;
  }
  const std::string sober_data_root = SoberDataRoot();
  const std::string sober_cache_root = SoberCacheRoot();
  std::string data_dir = GetEnvStringDefaultPath(
      "MOCKTAIL_ANDROID_DATA_DIR",
      DefaultSoberAwarePath(sober_data_root.c_str(),
                            "/data/user/0/com.roblox.client"));
  std::string files_dir = GetEnvStringDefaultPath(
      "MOCKTAIL_ANDROID_FILES_DIR",
      DefaultSoberAwarePath((sober_data_root + "/files").c_str(),
                            "/data/user/0/com.roblox.client/files"));
  std::string cache_dir = GetEnvStringDefaultPath(
      "MOCKTAIL_ANDROID_CACHE_DIR",
      DefaultSoberAwarePath((sober_cache_root + "/cache").c_str(),
                            "/data/user/0/com.roblox.client/cache"));
  EnsureAndroidDirectory(files_dir + "/appData");
  EnsureAndroidDirectory(files_dir + "/appData/LocalStorage");
  EnsureAndroidDirectory(files_dir + "/appData/OTAPatchBackups");
  EnsureAndroidDirectory(files_dir + "/appData/rbx-storage");
  EnsureAndroidDirectory(data_dir + "/rbx-storage");
  EnsureAndroidDirectory(data_dir + "/shared_prefs");
  EnsureAndroidDirectory(cache_dir);
  EnsureAndroidDirectory(cache_dir + "/ContentProvider_2");
  EnsureAndroidDirectory(cache_dir + "/rbx-storage");
  EnsureAndroidDirectory(cache_dir + "/sounds");

  jobject asset_manager = nullptr;
  auto get_asset_manager = [&]() -> jobject {
    if (asset_manager == nullptr) {
      asset_manager = NewObject(env, "android/content/res/AssetManager");
    }
    return asset_manager;
  };

  if (context->native_init_asset_manager &&
      ShouldRunStartupStep("MOCKTAIL_JNI_ASSET_MANAGER_SETUP", true)) {
    jclass asset_manager_setup_class =
        env->FindClass("com/roblox/client/JNIAAssetManagerSetup");
    std::cout << "  [engine] JNIAAssetManagerSetup.initNative\n" << std::flush;
    context->native_init_asset_manager(env, asset_manager_setup_class,
                                       get_asset_manager());
    std::cout << "  [engine] JNIAAssetManagerSetup.initNative returned\n"
              << std::flush;
  }

  if (context->native_local_storage_set_platform_impl &&
      ShouldRunStartupStep("MOCKTAIL_LOCAL_STORAGE_SET_PLATFORM_IMPL", false)) {
    jobject platform_handler = NewObject(
        env,
        "com/roblox/protocols/localstorageplatforminterface/generated/"
        "IPlatformLocalStorageHandler");
    jobject shared_preferences =
        NewObject(env, "android/content/SharedPreferences");
    const std::string shared_prefs_file =
        data_dir + "/shared_prefs/LOCAL_STORAGE_SHARED_PREFS.xml";
    SetObjectField(env, platform_handler, "sharedPreferences",
                   "Landroid/content/SharedPreferences;", shared_preferences);
    SetStringField(env, platform_handler, "sharedPrefsFile",
                   shared_prefs_file.c_str());
    SetStringField(env, platform_handler, "dataDir", data_dir.c_str());

    jclass core_class = env->FindClass(
        "com/roblox/protocols/localstorageplatforminterface/generated/"
        "ILocalStorageHandlerCore");
    std::cout << "  [engine] LocalStorage setPlatformImpl sharedPrefs="
              << shared_prefs_file << '\n'
              << std::flush;
    jobject core = context->native_local_storage_set_platform_impl(
        env, core_class, platform_handler);
    std::cout << "  [engine] LocalStorage setPlatformImpl returned " << core
              << '\n'
              << std::flush;
  }

  if (!context->native_init_storage_manager ||
      !ShouldRunStartupStep("MOCKTAIL_LOCAL_STORAGE_INIT_STORAGE_MANAGER",
                            true)) {
    return;
  }

  jobject local_storage_manager =
      NewObject(env, "com/roblox/client/LocalStorageManager");
  jstring files_dir_string = env->NewStringUTF(files_dir.c_str());
  jstring cache_dir_string = env->NewStringUTF(cache_dir.c_str());
  std::cout
      << "  [engine] LocalStorageManager.initStorageManagerNativeV3 files="
      << files_dir << " cache=" << cache_dir << '\n'
      << std::flush;
  context->native_init_storage_manager(env, local_storage_manager,
                                       get_asset_manager(), files_dir_string,
                                       cache_dir_string);
  std::cout
      << "  [engine] LocalStorageManager.initStorageManagerNativeV3 returned\n"
      << std::flush;
}

void* AppBridgeInitWithParamsThread(void* arg) {
  auto* context = static_cast<AppBridgeInitWithParamsContext*>(arg);
  if (!context || !context->vm || !context->java_vm ||
      !context->native_init_with_params || !context->init_params) {
    std::cerr << "  [engine] nativeAppBridgeV2InitWithParams thread has "
              << "invalid context\n"
              << std::flush;
    if (context) {
      context->recovered.store(1);
      context->finished.store(1);
    }
    return nullptr;
  }

  void* raw_env = nullptr;
  jint attach_result = context->java_vm->AttachCurrentThread(&raw_env, nullptr);
  std::cout << "  [engine] nativeAppBridgeV2InitWithParams thread "
            << "AttachCurrentThread result=" << attach_result
            << " raw_env=" << raw_env << '\n'
            << std::flush;
  JNIEnv* env = attach_result == JNI_OK ? static_cast<JNIEnv*>(raw_env)
                                        : context->vm->GetJNIEnv();
  if (!env) {
    std::cerr << "  [engine] nativeAppBridgeV2InitWithParams thread could not "
              << "get JNIEnv\n"
              << std::flush;
    context->recovered.store(1);
    context->finished.store(1);
    return nullptr;
  }

  PublishCurrentJniEnv(env);
  context->vm->RestoreFunctions();
  env = context->vm->GetJNIEnv();
  jclass native_gl_class =
      env->FindClass("com/roblox/engine/jni/NativeGLInterface");

  std::cout << "  [engine] nativeAppBridgeV2InitWithParams thread entered\n"
            << std::flush;
  if (sigsetjmp(g_init_with_params_jmp_buf, 1) == 0) {
    g_init_with_params_recovery_in_progress = 1;
    context->native_init_with_params(env, native_gl_class,
                                     context->init_params);
    g_init_with_params_recovery_in_progress = 0;
  } else {
    g_init_with_params_recovery_in_progress = 0;
    AbortStage6InitWithParamsStaticGuards(
        "nativeAppBridgeV2InitWithParams thread");
    context->recovered.store(1);
    std::cerr << "  [engine] nativeAppBridgeV2InitWithParams thread recovered\n"
              << std::flush;
  }
  std::cout << "  [engine] nativeAppBridgeV2InitWithParams thread returned\n"
            << std::flush;
  DumpStage6AppBridgeStaticState("after V2 init thread");
  context->java_vm->DetachCurrentThread();
  context->finished.store(1);
  return nullptr;
}

void CallStartLuaDirectClosureIfRequested(const char* label) {
  if (!IsEnabled("MOCKTAIL_CALL_START_LUA_DIRECT_CLOSURE")) {
    return;
  }
  uintptr_t base = static_cast<uintptr_t>(g_libroblox_base);
  if (base == 0) {
    std::cerr << "  [engine] " << label
              << " direct StartLua closure skipped: libroblox base is null\n"
              << std::flush;
    return;
  }
  auto* direct_start_lua = reinterpret_cast<NativeDirectNoArgFn>(
      base + kStage6StartLuaDirectClosureOffset);
  std::cout << "  [engine] " << label
            << " nativeAppBridgeStartLuaAppDM direct closure\n"
            << std::flush;
  ResetStage6AppBridgeStaticGuards(label);
  direct_start_lua();
  std::cout << "  [engine] " << label
            << " nativeAppBridgeStartLuaAppDM direct closure returned\n"
            << std::flush;
}

void* DelayedStartLuaAppThread(void* arg) {
  std::unique_ptr<DelayedStartLuaAppContext> context(
      static_cast<DelayedStartLuaAppContext*>(arg));
  if (!context || !context->vm || !context->java_vm ||
      !context->native_start_lua_app_dm) {
    std::cerr << "  [engine] delayed StartLuaAppDM has invalid context\n"
              << std::flush;
    return nullptr;
  }

  if (context->delay_ms > 0) {
    std::cout << "  [engine] delayed StartLuaAppDM wait " << context->delay_ms
              << " ms\n"
              << std::flush;
    usleep(static_cast<useconds_t>(context->delay_ms) * 1000);
  }

  void* raw_env = nullptr;
  jint attach_result = context->java_vm->AttachCurrentThread(&raw_env, nullptr);
  std::cout << "  [engine] delayed StartLuaAppDM AttachCurrentThread result="
            << attach_result << " raw_env=" << raw_env << '\n'
            << std::flush;
  JNIEnv* env = attach_result == JNI_OK ? static_cast<JNIEnv*>(raw_env)
                                        : context->vm->GetJNIEnv();
  if (!env) {
    std::cerr << "  [engine] delayed StartLuaAppDM could not get JNIEnv\n"
              << std::flush;
    return nullptr;
  }

  PublishCurrentJniEnv(env);
  context->vm->RestoreFunctions();
  env = context->vm->GetJNIEnv();
  jclass native_gl_class =
      env->FindClass("com/roblox/engine/jni/NativeGLInterface");

  if (IsEnabled("MOCKTAIL_TRACE_START_LUA_JNI")) {
    setenv("MOCKTAIL_JNI_TRACE", "1", 1);
  }

  std::cout << "  [engine] delayed nativeAppBridgeStartLuaAppDM\n"
            << std::flush;
  if (sigsetjmp(g_start_lua_app_dm_jmp_buf, 1) == 0) {
    g_stage6_empty_gl_helper_returns = 0;
    g_start_lua_app_dm_recovery_in_progress = kStage6RecoveryWorker;
    context->native_start_lua_app_dm(env, native_gl_class);
    CallStartLuaDirectClosureIfRequested("delayed");
    g_start_lua_app_dm_recovery_in_progress = kStage6RecoveryInactive;
  } else {
    g_start_lua_app_dm_recovery_in_progress = kStage6RecoveryInactive;
    std::cerr << "  [engine] delayed nativeAppBridgeStartLuaAppDM recovered\n"
              << std::flush;
  }
  std::cout << "  [engine] delayed nativeAppBridgeStartLuaAppDM returned\n"
            << std::flush;
  DumpStage6AppBridgeStaticState("after delayed StartLuaAppDM");
  context->java_vm->DetachCurrentThread();
  return nullptr;
}

void* AppBridgeAppStartThread(void* arg) {
  std::unique_ptr<AppBridgeAppStartContext> context(
      static_cast<AppBridgeAppStartContext*>(arg));
  if (!context || !context->vm || !context->java_vm ||
      !context->native_app_bridge_app_start) {
    std::cerr << "  [engine] nativeAppBridgeAppStart thread has invalid "
              << "context\n"
              << std::flush;
    return nullptr;
  }

  void* raw_env = nullptr;
  jint attach_result = context->java_vm->AttachCurrentThread(&raw_env, nullptr);
  std::cout << "  [engine] nativeAppBridgeAppStart thread "
            << "AttachCurrentThread result=" << attach_result
            << " raw_env=" << raw_env << '\n'
            << std::flush;
  JNIEnv* env = attach_result == JNI_OK ? static_cast<JNIEnv*>(raw_env)
                                        : context->vm->GetJNIEnv();
  if (!env) {
    std::cerr << "  [engine] nativeAppBridgeAppStart thread could not get "
              << "JNIEnv\n"
              << std::flush;
    return nullptr;
  }

  PublishCurrentJniEnv(env);
  context->vm->RestoreFunctions();
  env = context->vm->GetJNIEnv();

  std::cout << "  [engine] nativeAppBridgeAppStart thread entered\n"
            << std::flush;
  if (sigsetjmp(g_app_bridge_app_start_jmp_buf, 1) == 0) {
    g_app_bridge_app_start_recovery_in_progress = 1;
    context->native_app_bridge_app_start(
        env, context->native_app_bridge_class, context->base_url,
        context->user_agent, JNI_FALSE, context->android_id,
        context->launch_source, context->empty_string);
    g_app_bridge_app_start_recovery_in_progress = 0;
  } else {
    g_app_bridge_app_start_recovery_in_progress = 0;
    std::cerr << "  [engine] nativeAppBridgeAppStart thread recovered\n"
              << std::flush;
  }
  std::cout << "  [engine] nativeAppBridgeAppStart thread returned\n"
            << std::flush;
  context->java_vm->DetachCurrentThread();
  return nullptr;
}

void* DelayedUpdateSurfaceAppThread(void* arg) {
  auto* context = static_cast<DelayedUpdateSurfaceAppContext*>(arg);
  if (!context || !context->vm || !context->java_vm ||
      !context->native_update_surface_app) {
    std::cerr << "  [engine] delayed UpdateSurfaceApp has invalid context\n"
              << std::flush;
    delete context;
    return nullptr;
  }

  void* raw_env = nullptr;
  jint attach_result = context->java_vm->AttachCurrentThread(&raw_env, nullptr);
  std::cout << "  [engine] delayed UpdateSurfaceApp AttachCurrentThread result="
            << attach_result << " raw_env=" << raw_env << '\n'
            << std::flush;
  JNIEnv* env = attach_result == JNI_OK ? static_cast<JNIEnv*>(raw_env)
                                        : context->vm->GetJNIEnv();
  if (!env) {
    std::cerr << "  [engine] delayed UpdateSurfaceApp could not get JNIEnv\n"
              << std::flush;
    return nullptr;
  }

  PublishCurrentJniEnv(env);
  context->vm->RestoreFunctions();
  env = context->vm->GetJNIEnv();
  const bool has_real_graphics_context = HasRealGraphicsContext();
  volatile sig_atomic_t graphics_locked = 0;
  volatile sig_atomic_t made_current = 0;
  if (has_real_graphics_context) {
    pthread_mutex_lock(&g_engine_gl_mutex);
    graphics_locked = 1;
    if (mocktail::window::MakeCurrentOnThread()) {
      made_current = 1;
    }
  }

  std::cout << "  [engine] delayed "
               "nativeAppBridgeV2UpdateSurfaceAppWithPlatformParams\n"
            << std::flush;
  volatile sig_atomic_t update_surface_recovered = 0;
  if (sigsetjmp(g_update_surface_app_jmp_buf, 1) == 0) {
    g_stage6_empty_gl_helper_returns = 0;
    g_update_surface_app_recovery_in_progress = kStage6RecoveryWorker;
    context->native_update_surface_app(env, context->native_gl_class,
                                       context->surface,
                                       context->platform_params);
    g_update_surface_app_recovery_in_progress = kStage6RecoveryInactive;
    std::cout
        << "  [engine] delayed "
           "nativeAppBridgeV2UpdateSurfaceAppWithPlatformParams returned\n"
        << std::flush;
  } else {
    update_surface_recovered = 1;
    g_update_surface_app_recovery_in_progress = kStage6RecoveryInactive;
    std::cerr
        << "  [engine] delayed UpdateSurfaceAppWithPlatformParams recovered\n"
        << std::flush;
  }
  if (made_current != 0) {
    mocktail::window::ReleaseCurrentOnThread();
  }
  if (graphics_locked != 0) {
    pthread_mutex_unlock(&g_engine_gl_mutex);
  }
  DumpStage6AppBridgeStaticState("after delayed UpdateSurfaceApp");
  if (update_surface_recovered == 0) {
    context->java_vm->DetachCurrentThread();
  }
  // Roblox can corrupt host heap state while we recover from the incomplete GL
  // helper path. Keep this tiny context alive instead of freeing through a
  // potentially damaged allocator.
  return nullptr;
}

void* DelayedStartAppThread(void* arg) {
  auto* context = static_cast<DelayedStartAppContext*>(arg);
  if (!context || !context->vm || !context->java_vm ||
      !context->native_start_app_with_params) {
    std::cerr << "  [engine] delayed StartApp has invalid context\n"
              << std::flush;
    delete context;
    return nullptr;
  }

  void* raw_env = nullptr;
  jint attach_result = context->java_vm->AttachCurrentThread(&raw_env, nullptr);
  std::cout << "  [engine] delayed StartApp AttachCurrentThread result="
            << attach_result << " raw_env=" << raw_env << '\n'
            << std::flush;
  JNIEnv* env = attach_result == JNI_OK ? static_cast<JNIEnv*>(raw_env)
                                        : context->vm->GetJNIEnv();
  if (!env) {
    std::cerr << "  [engine] delayed StartApp could not get JNIEnv\n"
              << std::flush;
    return nullptr;
  }
  if (!InitializeActiveHostAbiThread()) {
    std::cerr << "  [engine] delayed StartApp allocator TLS init failed\n"
              << std::flush;
    return nullptr;
  }

  PublishCurrentJniEnv(env);
  context->vm->RestoreFunctions();
  env = context->vm->GetJNIEnv();

  std::cout << "  [engine] delayed nativeAppBridgeV2StartAppWithParams\n"
            << std::flush;
  volatile sig_atomic_t graphics_locked = 0;
  volatile sig_atomic_t made_current = 0;
  if (HasRealGraphicsContext()) {
    std::cout << "  [engine] delayed StartApp waiting for graphics mutex\n"
              << std::flush;
    pthread_mutex_lock(&g_engine_gl_mutex);
    graphics_locked = 1;
    std::cout << "  [engine] delayed StartApp acquired graphics mutex\n"
              << std::flush;
    if (mocktail::window::MakeCurrentOnThread()) {
      made_current = 1;
    }
  }
  volatile sig_atomic_t start_app_recovered = 0;
  if (sigsetjmp(g_start_app_with_params_jmp_buf, 1) == 0) {
    g_stage6_empty_gl_helper_returns = 0;
    g_start_app_with_params_recovery_in_progress = kStage6RecoveryWorker;
    context->native_start_app_with_params(env, context->native_gl_class,
                                          context->start_app_params);
    g_start_app_with_params_recovery_in_progress = kStage6RecoveryInactive;
  } else {
    start_app_recovered = 1;
    g_start_app_with_params_recovery_in_progress = kStage6RecoveryInactive;
    std::cerr
        << "  [engine] delayed nativeAppBridgeV2StartAppWithParams recovered\n"
        << std::flush;
  }
  if (made_current != 0) {
    mocktail::window::ReleaseCurrentOnThread();
  }
  if (graphics_locked != 0) {
    pthread_mutex_unlock(&g_engine_gl_mutex);
    graphics_locked = 0;
    std::cout << "  [engine] delayed StartApp released graphics mutex\n"
              << std::flush;
  }
  std::cout
      << "  [engine] delayed nativeAppBridgeV2StartAppWithParams returned\n"
      << std::flush;
  DumpStage6AppBridgeStaticState("after delayed StartAppWithParams");
  if (start_app_recovered) {
    std::cerr << "  [engine] delayed start_app recovery may prevent graphics "
                 "startup\n"
              << std::flush;
  }
  if (start_app_recovered == 0) {
    context->java_vm->DetachCurrentThread();
  }
  // See DelayedUpdateSurfaceAppThread: this is intentionally leaked after a
  // recovered native graphics call to avoid freeing through corrupted heap.
  return nullptr;
}

void* DelayedSendAppReadyThread(void* arg) {
  auto* context = static_cast<DelayedSendAppEventContext*>(arg);
  std::unique_ptr<DelayedSendAppEventContext> owned_context(context);
  if (!context || !context->vm || !context->java_vm ||
      !context->native_send_app_ready) {
    std::cerr << "  [engine] delayed AppReady has invalid context\n"
              << std::flush;
    return nullptr;
  }

  void* raw_env = nullptr;
  jint attach_result = context->java_vm->AttachCurrentThread(&raw_env, nullptr);
  std::cout << "  [engine] delayed AppReady AttachCurrentThread result="
            << attach_result << " raw_env=" << raw_env << '\n'
            << std::flush;
  JNIEnv* env = attach_result == JNI_OK ? static_cast<JNIEnv*>(raw_env)
                                        : context->vm->GetJNIEnv();
  if (!env) {
    std::cerr << "  [engine] delayed AppReady could not get JNIEnv\n"
              << std::flush;
    return nullptr;
  }

  PublishCurrentJniEnv(env);
  context->vm->RestoreFunctions();
  env = context->vm->GetJNIEnv();
  jclass native_gl_class =
      env->FindClass("com/roblox/engine/jni/NativeGLInterface");

  std::cout << "  [engine] delayed nativeAppBridgeV2SendAppEventOnAppReady\n"
            << std::flush;
  volatile sig_atomic_t recovered = 0;
  if (sigsetjmp(g_send_app_ready_jmp_buf, 1) == 0) {
    g_send_app_ready_recovery_in_progress = kStage6RecoveryWorker;
    jstring empty_ready_arg = env->NewStringUTF("");
    jstring home_feature = env->NewStringUTF("Home");
    context->native_send_app_ready(env, native_gl_class, empty_ready_arg,
                                   empty_ready_arg, empty_ready_arg,
                                   home_feature);
    g_send_app_ready_recovery_in_progress = kStage6RecoveryInactive;
    std::cout << "  [engine] delayed nativeAppBridgeV2SendAppEventOnAppReady "
                 "returned\n"
              << std::flush;
  } else {
    recovered = 1;
    g_send_app_ready_recovery_in_progress = kStage6RecoveryInactive;
    std::cerr << "  [engine] delayed nativeAppBridgeV2SendAppEventOnAppReady "
                 "recovered\n"
              << std::flush;
  }
  if (recovered == 0) {
    context->java_vm->DetachCurrentThread();
  }
  return nullptr;
}

void* DelayedSendGameLoadedThread(void* arg) {
  auto* context = static_cast<DelayedSendAppEventContext*>(arg);
  std::unique_ptr<DelayedSendAppEventContext> owned_context(context);
  if (!context || !context->vm || !context->java_vm ||
      !context->native_send_game_loaded) {
    std::cerr << "  [engine] delayed GameLoaded has invalid context\n"
              << std::flush;
    return nullptr;
  }

  void* raw_env = nullptr;
  jint attach_result = context->java_vm->AttachCurrentThread(&raw_env, nullptr);
  std::cout << "  [engine] delayed GameLoaded AttachCurrentThread result="
            << attach_result << " raw_env=" << raw_env << '\n'
            << std::flush;
  JNIEnv* env = attach_result == JNI_OK ? static_cast<JNIEnv*>(raw_env)
                                        : context->vm->GetJNIEnv();
  if (!env) {
    std::cerr << "  [engine] delayed GameLoaded could not get JNIEnv\n"
              << std::flush;
    return nullptr;
  }

  PublishCurrentJniEnv(env);
  context->vm->RestoreFunctions();
  env = context->vm->GetJNIEnv();
  jclass native_gl_class =
      env->FindClass("com/roblox/engine/jni/NativeGLInterface");

  std::cout << "  [engine] delayed nativeAppBridgeV2SendAppEventOnGameLoaded\n"
            << std::flush;
  volatile sig_atomic_t recovered = 0;
  if (sigsetjmp(g_send_game_loaded_jmp_buf, 1) == 0) {
    g_send_game_loaded_recovery_in_progress = kStage6RecoveryWorker;
    jstring empty_game_loaded_arg = env->NewStringUTF("");
    jstring home_feature = env->NewStringUTF("Home");
    context->native_send_game_loaded(env, native_gl_class, home_feature,
                                     empty_game_loaded_arg,
                                     empty_game_loaded_arg);
    g_send_game_loaded_recovery_in_progress = kStage6RecoveryInactive;
    std::cout << "  [engine] delayed nativeAppBridgeV2SendAppEventOnGameLoaded "
                 "returned\n"
              << std::flush;
  } else {
    recovered = 1;
    g_send_game_loaded_recovery_in_progress = kStage6RecoveryInactive;
    std::cerr << "  [engine] delayed nativeAppBridgeV2SendAppEventOnGameLoaded "
                 "recovered\n"
              << std::flush;
  }
  if (recovered == 0) {
    context->java_vm->DetachCurrentThread();
  }
  return nullptr;
}

void* EngineStartupThread(void* arg) {
  auto* context = static_cast<EngineStartupContext*>(arg);
  if (context == nullptr) {
    std::cerr << "  [engine] invalid startup context\n" << std::flush;
    return nullptr;
  }
  std::cout << "  [engine] EngineStartupThread entered, context=" << context
            << "\n"
            << std::flush;
  std::cout << "  [engine] context flags: prepare=" << context->run_prepare_jni
            << " setAsset=" << context->run_set_asset_path
            << " initWithParams=" << context->run_init_with_params << '\n'
            << std::flush;

  EngineLog("thread entered");
  EngineLogPtr("context", context);
  EngineLogPtr("JavaVM", context->java_vm);
  std::cout << "  [engine] thread java_vm=" << context->java_vm
            << " shared_vm=" << context->vm << '\n'
            << std::flush;
  bool attached_to_thread = false;
  JNIEnv* env = nullptr;
  const bool skip_attach = IsEnabled("MOCKTAIL_ENGINE_SKIP_ATTACH");
  if (skip_attach) {
    std::cout << "  [engine] skipping AttachCurrentThread "
                 "(MOCKTAIL_ENGINE_SKIP_ATTACH)\n"
              << std::flush;
    EngineLog("AttachCurrentThread skipped");
  } else if (context->java_vm) {
    std::cout << "  [engine] entering AttachCurrentThread\n" << std::flush;
    EngineLog("AttachCurrentThread");
    void* raw_env = nullptr;
    jint attach_result =
        context->java_vm->AttachCurrentThread(&raw_env, nullptr);
    std::cout << "  [engine] AttachCurrentThread result=" << attach_result
              << " raw_env=" << raw_env << '\n'
              << std::flush;
    if (attach_result == JNI_OK) {
      env = static_cast<JNIEnv*>(raw_env);
      g_stage6_jni_env = reinterpret_cast<uintptr_t>(env);
      attached_to_thread = true;
    }
    EngineLog("AttachCurrentThread returned");
    EngineLogPtr("attached JNIEnv", env);
  }
  if (!env) {
    EngineLog("fallback GetJNIEnv");
  }
  if (!env) {
    env = context->vm->GetJNIEnv();
    g_stage6_jni_env = reinterpret_cast<uintptr_t>(env);
  }
  auto ensure_env = [&]() -> JNIEnv* {
    if (!env) {
      env = context->vm->GetJNIEnv();
    }
    return env;
  };
  if (!env) {
    std::cerr << "  [engine] failed to acquire JNIEnv\n";
    return nullptr;
  }
  if (!InitializeActiveHostAbiThread()) {
    std::cerr << "  [engine] allocator TLS init failed on startup thread\n"
              << std::flush;
    return nullptr;
  }
  std::cout << "  [engine] native allocator TLS initialized\n" << std::flush;
  EngineLogPtr("reset JNIEnv", env);
  EngineLog("PublishCurrentJniEnv");
  PublishCurrentJniEnv(env);

  // Keep EGL unbound by default so the worker that runs real Roblox surface
  // calls can become the first owner of the context. Binding here makes later
  // worker MakeCurrent fail with EGL_BAD_ACCESS on Mesa/Wayland.
  if (mocktail::window::IsInitialised() &&
      IsEnabled("MOCKTAIL_BIND_EGL_ON_STARTUP_THREAD")) {
    std::cout << "  [engine] binding EGL context on engine thread\n"
              << std::flush;
    mocktail::window::MakeCurrentOnThread();
  }
  // JNI_OnLoad replaces env->functions; Stage 6 needs the pseudo-VM table.
  if (env && context->vm) {
    context->vm->RestoreFunctions();
    env = context->vm->GetJNIEnv();
    g_stage6_jni_functions = reinterpret_cast<uintptr_t>(env->functions);
    std::cerr << "  [engine] env->functions restored: " << (void*)env->functions
              << "\n"
              << std::flush;
  }
  EngineLogPtr("JNIEnv", env);
  EngineLogPtr("JNIEnv.functions", env ? env->functions : nullptr);

  if (!context->run_prepare_jni) {
    EngineLog("JNI prep disabled");
    if (attached_to_thread) {
      EngineLog("DetachCurrentThread");
      jint detach_result = context->java_vm->DetachCurrentThread();
      if (detach_result != JNI_OK) {
        std::cerr << "  [engine] DetachCurrentThread failed: " << detach_result
                  << '\n'
                  << std::flush;
      }
      attached_to_thread = false;
    }
    return nullptr;
  }

  EngineLog("FindClass NativeGLInterface");
  jclass native_gl_class =
      env->FindClass("com/roblox/engine/jni/NativeGLInterface");
  jclass native_input_class =
      env->FindClass("com/roblox/engine/jni/NativeInputInterface");
  if (!native_input_class) {
    native_input_class = native_gl_class;
  }
  jclass native_settings_class =
      env->FindClass("com/roblox/engine/jni/NativeSettingsInterface");
  jclass native_app_bridge_class =
      env->FindClass("com/roblox/engine/jni/NativeAppBridgeInterface");
  jclass native_gl_java_class =
      env->FindClass("com/roblox/engine/jni/NativeGLJavaInterface");
  if (!native_app_bridge_class) {
    native_app_bridge_class = native_gl_class;
  }
  jclass startup_activity_class =
      env->FindClass("com/roblox/client/startup/MainGameActivity");
  if (!startup_activity_class) {
    startup_activity_class = native_gl_class;
  }
  EngineLog("FindClass returned");
  EngineLog("NewStringUTF args");
  jstring empty_string = env->NewStringUTF("");
  jstring base_url = env->NewStringUTF("https://www.roblox.com/");
  jstring user_agent =
      NewStringFromEnvDefault(env, "MOCKTAIL_USER_AGENT",
                              "Roblox/unknown (Linux; Android 33; Mocktail)");
  jstring android_id =
      NewStringFromEnvDefault(env, "MOCKTAIL_ANDROID_ID", "0000000000000000");
  jstring launch_source =
      NewStringFromEnvDefault(env, "MOCKTAIL_LAUNCH_SOURCE", "AppAndroidV");
  jstring client_settings = NewClientSettingsString(env);
  jstring client_settings_overrides = NewStringFromEnvDefault(
      env, "MOCKTAIL_CLIENT_SETTINGS_OVERRIDES_JSON", "{}");
  jstring client_settings_signature =
      NewStringFromEnvDefault(env, "MOCKTAIL_CLIENT_SETTINGS_SIGNATURE", "");
  jstring client_settings_group = NewStringFromEnvDefault(
      env, "MOCKTAIL_CLIENT_SETTINGS_GROUP", "GoogleAndroidApp");
  jstring fast_flags =
      NewStringFromEnvDefault(env, "MOCKTAIL_FAST_FLAGS_JSON", "{}");
  const bool is_headless = IsHeadlessMode();
  const char* launch_mode = std::getenv("MOCKTAIL_LAUNCH_MODE");
  const char* default_launch_mode = is_headless ? "headless" : "normal";
  std::string default_app_params =
      std::string("{\"launchMode\":\"") +
      (launch_mode != nullptr && launch_mode[0] != '\0' ? launch_mode
                                                        : default_launch_mode) +
      "\",\"placeId\":0}";
  jstring app_params = NewStringFromEnvDefault(env, "MOCKTAIL_APP_PARAMS_JSON",
                                               default_app_params.c_str());
  EngineLogPtr("JNIEnv.functions", env ? env->functions : nullptr);
  jstring asset_path = env->NewStringUTF(
      GetEnvStringDefaultPath("MOCKTAIL_ASSET_PATH", DefaultAssetPath())
          .c_str());
  std::string asset_path_value = JStringToString(env, asset_path);
  if (asset_path_value.empty()) {
    asset_path_value = DefaultAssetPath();
    asset_path = env->NewStringUTF(asset_path_value.c_str());
  }
  const bool app_bridge_init_headless =
      is_headless || IsEnabled("MOCKTAIL_APP_BRIDGE_HEADLESS_INIT_PARAMS");
  if (app_bridge_init_headless != is_headless) {
    std::cout << "  [engine] AppBridge init uses headless params while "
              << "windowed surface/start stay enabled\n"
              << std::flush;
  }
  if (IsEnabled("MOCKTAIL_ENGINE_TRACE")) {
    std::cout << "  [engine] asset path prepared: " << asset_path_value << '\n'
              << std::flush;
  }
  jobject surface = BuildMockSurface(env);
  jobject game_activity =
      NewObject(env, "com/roblox/client/startup/MainGameActivity");
  jobject game_surface_activity =
      IsEnabled("MOCKTAIL_PASS_ACTIVITY_TO_GAME_SURFACE_PARAMS") ? game_activity
                                                                 : nullptr;
  jobject app_bridge_notification_listener =
      NewObject(env, "com/roblox/engine/jni/OnAppBridgeNotificationListener");
  jobject game_activity_asset_manager =
      NewObject(env, "android/content/res/AssetManager");
  jobject game_activity_config = BuildConfiguration(env);
  jobject platform_params = BuildPlatformParams(env, surface, is_headless);
  jobject device_params = BuildDeviceParams(env);
  const jnivm::RobloxAuthIdentity& account_identity = context->account_identity;
  jobject start_game_params = BuildStartGameParams(
      env, platform_params, device_params, surface, game_activity,
      "MOCKTAIL_GAME_PARAMS_JSON", account_identity);
  jobject start_app_params =
      BuildStartAppParams(env, app_params, platform_params, surface,
                          is_headless, launch_mode, account_identity);
  InstallNativeGlJavaImplementation(env, native_gl_java_class);
  EngineLog("NewStringUTF returned");

  jlong game_activity_handle = 0;
  bool game_activity_init_attempted = false;
  auto run_game_activity_initialize = [&]() -> jlong {
    if (!context->run_game_activity_init ||
        context->native_game_activity_init == nullptr) {
      return 0;
    }
    if (game_activity_init_attempted) {
      return game_activity_handle;
    }
    game_activity_init_attempted = true;
    env = ensure_env();
    std::cout << "  [engine] GameActivity.initializeNativeCode\n" << std::flush;
    jstring internal_data_dir =
        env->NewStringUTF("/data/user/0/com.roblox.client/files");
    jstring obb_dir =
        env->NewStringUTF("/sdcard/Android/obb/com.roblox.client");
    jstring external_data_dir =
        env->NewStringUTF("/sdcard/Android/data/com.roblox.client/files");
    if (sigsetjmp(g_game_activity_init_jmp_buf, 1) == 0) {
      g_game_activity_init_recovery_in_progress = 1;
      g_saved_game_activity = game_activity;
      game_activity_handle = context->native_game_activity_init(
          env, game_activity, internal_data_dir, obb_dir, external_data_dir,
          game_activity_asset_manager, nullptr, game_activity_config);
      g_game_activity_init_recovery_in_progress = 0;
    } else {
      g_game_activity_init_recovery_in_progress = 0;
      game_activity_handle = 0;
      std::cerr << "  [engine] GameActivity.initializeNativeCode recovered\n"
                << std::flush;
    }
    g_game_activity_native_handle =
        static_cast<uintptr_t>(game_activity_handle);
    std::cout << "  [engine] GameActivity.initializeNativeCode returned "
              << game_activity_handle << '\n'
              << std::flush;
    if (game_activity_handle != 0 &&
        IsEnabled("MOCKTAIL_DUMP_GAME_ACTIVITY_HANDLE")) {
      auto** game_activity_slots = reinterpret_cast<void**>(
          static_cast<uintptr_t>(game_activity_handle));
      std::cout << "  [engine] GameActivity handle slots:";
      for (int i = 0; i < 40; ++i) {
        std::cout << " [" << i << "]=" << game_activity_slots[i];
      }
      std::cout << '\n' << std::flush;
    }
    return game_activity_handle;
  };

  if (context->run_game_activity_init) {
    run_game_activity_initialize();
  }

  if (context->run_set_asset_path) {
    env = ensure_env();
    std::cout << "  [engine] nativeSetAssetPath\n" << std::flush;
    if (context->call_real_set_asset_path) {
      if (sigsetjmp(g_set_asset_path_jmp_buf, 1) == 0) {
        g_set_asset_path_recovery_in_progress = 1;
        if (EngineTraceEnabled()) {
          std::cerr << "  [engine] nativeSetAssetPath env=" << (void*)env
                    << " class=" << (void*)startup_activity_class
                    << " path=" << asset_path_value << '\n'
                    << std::flush;
        }
        context->native_set_asset_path(env, startup_activity_class, asset_path);
        g_set_asset_path_recovery_in_progress = 0;
      } else {
        std::cerr << "  [engine] nativeSetAssetPath recovered\n" << std::flush;
        MocktailSetAssetPath(env, asset_path);
      }
    } else {
      MocktailSetAssetPath(env, asset_path);
    }
    std::cout << "  [engine] nativeSetAssetPath returned\n" << std::flush;
  }

  if (context->run_native_settings) {
    env = ensure_env();
    std::cout << "  [engine] NativeSettings directories\n" << std::flush;
    ConfigureNativeSettings(env, native_settings_class, context);
    ConfigureLocalStorage(env, context);
    if (context->native_base_url_protocol_init != nullptr) {
      jclass base_url_protocol_class =
          env->FindClass("com/roblox/universalapp/linking/JNIBaseUrlProtocol");
      std::cout << "  [engine] JNIBaseUrlProtocol.init\n" << std::flush;
      context->native_base_url_protocol_init(env, base_url_protocol_class,
                                             game_activity);
      std::cout << "  [engine] JNIBaseUrlProtocol.init returned\n"
                << std::flush;
    }
    DumpRobloxUrlGlobals("after NativeSettings");
    std::cout << "  [engine] NativeSettings directories returned\n"
              << std::flush;
  }

  if (context->run_global_init) {
    env = ensure_env();
    std::cout << "  [engine] nativeGameGlobalInit\n" << std::flush;
    g_stage6_empty_gl_helper_returns = 0;
    if (sigsetjmp(g_game_global_init_jmp_buf, 1) == 0) {
      g_game_global_init_recovery_in_progress = 1;
      context->native_global_init(env, native_gl_class);
      g_game_global_init_recovery_in_progress = 0;
    } else {
      g_game_global_init_recovery_in_progress = 0;
      const char msg[] = "  [engine] nativeGameGlobalInit recovered\n";
      write(2, msg, sizeof(msg) - 1);
    }
    const char msg[] = "  [engine] nativeGameGlobalInit returned\n";
    write(1, msg, sizeof(msg) - 1);
  }

  if (context->native_update_adapter_init &&
      !IsDisabled("MOCKTAIL_UPDATE_ADAPTER_INIT")) {
    env = ensure_env();
    std::cout << "  [engine] nativeUpdateAdapterInit\n" << std::flush;
    context->native_update_adapter_init(env, native_gl_class);
    std::cout << "  [engine] nativeUpdateAdapterInit returned\n" << std::flush;
  }

  if (context->run_update_screen_orientation &&
      context->native_update_screen_orientation != nullptr) {
    env = ensure_env();
    if (sigsetjmp(g_update_screen_orientation_jmp_buf, 1) == 0) {
      const jint orientation =
          static_cast<jint>(GetEnvInt("MOCKTAIL_SCREEN_ORIENTATION", 2));
      std::cout << "  [engine] nativeUpdateScreenOrientation orientation="
                << orientation << '\n'
                << std::flush;
      g_update_screen_orientation_recovery_in_progress = 1;
      context->native_update_screen_orientation(env, native_input_class,
                                                orientation);
      g_update_screen_orientation_recovery_in_progress = 0;
      std::cout << "  [engine] nativeUpdateScreenOrientation returned\n"
                << std::flush;
      DumpStage6AppBridgeStaticState("after nativeUpdateScreenOrientation");
    } else {
      g_update_screen_orientation_recovery_in_progress = 0;
      std::cerr << "  [engine] nativeUpdateScreenOrientation recovered\n"
                << std::flush;
    }
  }

  if (context->run_init_client_settings) {
    env = ensure_env();
    std::cout << "  [engine] nativeInitClientSettings\n" << std::flush;
    if (sigsetjmp(g_init_client_settings_jmp_buf, 1) == 0) {
      g_init_client_settings_recovery_in_progress = 1;
      const char* variant =
          std::getenv("MOCKTAIL_INIT_CLIENT_SETTINGS_VARIANT");
      if (variant == nullptr || variant[0] == '\0') {
        variant = "classic";
      }
      jint settings_result = 0;
      const jlong client_settings_timestamp_seconds =
          static_cast<jlong>(time(nullptr));
      if (std::strcmp(variant, "compressed") == 0 &&
          context->native_init_client_settings_cached_compressed != nullptr) {
        jbyteArray empty_compressed_settings = env->NewByteArray(0);
        settings_result =
            context->native_init_client_settings_cached_compressed(
                env, native_gl_class, empty_compressed_settings,
                client_settings_overrides, client_settings_group, empty_string,
                client_settings_timestamp_seconds, JNI_FALSE);
      } else if (std::strcmp(variant, "cached") == 0 &&
                 context->native_init_client_settings_cached != nullptr) {
        settings_result = context->native_init_client_settings_cached(
            env, native_gl_class, client_settings, client_settings_overrides,
            client_settings_group, empty_string,
            client_settings_timestamp_seconds);
      } else if (std::strcmp(variant, "signed") == 0 &&
                 context->native_init_client_settings_signed != nullptr) {
        settings_result = context->native_init_client_settings_signed(
            env, native_gl_class, client_settings, client_settings_signature,
            client_settings_overrides, client_settings_group);
      } else if (context->native_init_client_settings != nullptr) {
        variant = "classic";
        settings_result = context->native_init_client_settings(
            env, native_gl_class, client_settings, client_settings_overrides,
            client_settings_group);
      } else {
        std::cerr << "  [engine] nativeInitClientSettings has no usable "
                  << "variant\n"
                  << std::flush;
      }
      g_init_client_settings_recovery_in_progress = 0;
      std::cout << "  [engine] nativeInitClientSettings returned "
                << settings_result << " via " << variant << '\n'
                << std::flush;
      DumpRobloxUrlGlobals("after nativeInitClientSettings");
      if (context->run_native_settings &&
          ShouldRunStartupStep("MOCKTAIL_REAPPLY_NATIVE_SETTINGS_AFTER_INIT",
                               true)) {
        std::cout << "  [engine] reapplying NativeSettings after "
                  << "nativeInitClientSettings\n"
                  << std::flush;
        ConfigureNativeSettings(env, native_settings_class, context);
        DumpRobloxUrlGlobals("after NativeSettings reapply");
      }
    } else {
      g_init_client_settings_recovery_in_progress = 0;
      std::cerr << "  [engine] nativeInitClientSettings recovered\n"
                << std::flush;
      DumpRobloxUrlGlobals("after nativeInitClientSettings recovery");
    }
  }

  if (context->run_post_client_settings) {
    env = ensure_env();
    std::cout << "  [engine] nativePostClientSettingsLoadedInitialization3\n"
              << std::flush;
    if (IsEnabled("MOCKTAIL_TRACE_POST_CLIENT_SETTINGS_JNI")) {
      setenv("MOCKTAIL_JNI_TRACE", "1", 1);
    }
    if (sigsetjmp(g_post_client_settings_jmp_buf, 1) == 0) {
      g_post_client_settings_recovery_in_progress = 1;
      jobject application_exit_info_list = BuildApplicationExitInfoList(env);
      context->native_post_client_settings(env, native_gl_class,
                                           application_exit_info_list);
      g_post_client_settings_recovery_in_progress = 0;
    } else {
      g_post_client_settings_recovery_in_progress = 0;
      std::cerr << "  [engine] nativePostClientSettingsLoadedInitialization3 "
                   "recovered\n"
                << std::flush;
    }
    std::cout
        << "  [engine] nativePostClientSettingsLoadedInitialization3 returned\n"
        << std::flush;
  }

  if (context->native_initialize_native_flags != nullptr &&
      ShouldRunStartupStep("MOCKTAIL_INITIALIZE_NATIVE_FLAGS", false)) {
    env = ensure_env();
    std::cout << "  [engine] nativeInitializeNativeFlags\n" << std::flush;
    jclass flag_jni_class =
        env->FindClass("com/roblox/client/flags/FlagJniInterface");
    jclass string_class = env->FindClass("java/lang/String");
    jobjectArray native_flag_keys =
        env->NewObjectArray(0, string_class, nullptr);
    if (sigsetjmp(g_initialize_native_flags_jmp_buf, 1) == 0) {
      g_initialize_native_flags_recovery_in_progress = 1;
      jobject init_result = context->native_initialize_native_flags(
          env, flag_jni_class, native_flag_keys);
      g_initialize_native_flags_recovery_in_progress = 0;
      std::cout << "  [engine] nativeInitializeNativeFlags returned "
                << init_result << '\n'
                << std::flush;
    } else {
      g_initialize_native_flags_recovery_in_progress = 0;
      std::cerr << "  [engine] nativeInitializeNativeFlags recovered\n"
                << std::flush;
    }
  }
  ForceNativeFlagsLoadedForTaskScheduler("after-native-flags-init");
  ForceStage6DataModelPatcherForceLocalFlag("after-native-flags-init");
  ForceStage6DeferRbxmSignatureCheckToPostTtiFlag("after-native-flags-init");
  ForceStage6StartLuaSelfReferenceCallbackFlag("after-native-flags-init");

  if (context->run_set_init_params) {
    env = ensure_env();
    if (!context->run_native_settings && context->native_set_device_info &&
        ShouldRunStartupStep("MOCKTAIL_NATIVE_SET_DEVICE_INFO", true)) {
      std::cout << "  [engine] NativeSettings deviceInfo\n" << std::flush;
      jobject device_params = BuildDeviceParams(env);
      context->native_set_device_info(env, native_settings_class,
                                      device_params);
      std::cout << "  [engine] NativeSettings deviceInfo returned\n"
                << std::flush;
    }
    std::cout << "  [engine] nativeAppBridgeSetInitParams\n" << std::flush;
    jobject init_params = BuildAppBridgeInitParams(
        env, client_settings, fast_flags, app_params, asset_path, is_headless);
    context->native_set_init_params(env, startup_activity_class, init_params);
    std::cout << "  [engine] nativeAppBridgeSetInitParams returned\n"
              << std::flush;
    if (context->native_retry_init && IsEnabled("MOCKTAIL_RETRY_INIT")) {
      std::cout << "  [engine] nativeRetryInit\n" << std::flush;
      context->native_retry_init(env, startup_activity_class);
      std::cout << "  [engine] nativeRetryInit returned\n" << std::flush;
    }
  }

  if (!context->run_app_bridge_app_start &&
      IsEnabled("MOCKTAIL_SET_APP_BRIDGE_NOTIFICATION_LISTENER") &&
      native_gl_java_class && app_bridge_notification_listener) {
    env = ensure_env();
    std::cout << "  [engine] NativeGLJavaInterface."
              << "setAppBridgeNotificationListener\n"
              << std::flush;
    jmethodID set_listener = env->GetStaticMethodID(
        native_gl_java_class, "setAppBridgeNotificationListener",
        "(Lcom/roblox/engine/jni/OnAppBridgeNotificationListener;)V");
    env->CallStaticVoidMethod(native_gl_java_class, set_listener,
                              app_bridge_notification_listener);
    std::cout << "  [engine] NativeGLJavaInterface."
              << "setAppBridgeNotificationListener returned\n"
              << std::flush;
  }

  if (context->run_app_bridge_app_start &&
      context->native_app_bridge_app_start) {
    env = ensure_env();
    if (IsEnabled("MOCKTAIL_TRACE_APP_BRIDGE_APP_START_JNI")) {
      setenv("MOCKTAIL_JNI_TRACE", "1", 1);
    }
    if (context->native_set_is_first_install) {
      std::cout << "  [engine] NativeAppBridgeInterface.setIsFirstInstall\n"
                << std::flush;
      context->native_set_is_first_install(env, native_app_bridge_class,
                                           JNI_FALSE);
      std::cout << "  [engine] NativeAppBridgeInterface.setIsFirstInstall "
                << "returned\n"
                << std::flush;
    }
    if (native_gl_java_class && app_bridge_notification_listener &&
        ShouldRunStartupStep("MOCKTAIL_SET_APP_BRIDGE_NOTIFICATION_LISTENER",
                             true)) {
      std::cout << "  [engine] NativeGLJavaInterface."
                << "setAppBridgeNotificationListener\n"
                << std::flush;
      jmethodID set_listener = env->GetStaticMethodID(
          native_gl_java_class, "setAppBridgeNotificationListener",
          "(Lcom/roblox/engine/jni/OnAppBridgeNotificationListener;)V");
      env->CallStaticVoidMethod(native_gl_java_class, set_listener,
                                app_bridge_notification_listener);
      std::cout << "  [engine] NativeGLJavaInterface."
                << "setAppBridgeNotificationListener returned\n"
                << std::flush;
    }
    std::cout << "  [engine] nativeAppBridgeAppStart\n" << std::flush;
    if (IsEnabled("MOCKTAIL_APP_BRIDGE_APP_START_THREAD")) {
      auto* app_start_context = new AppBridgeAppStartContext{
          context->vm,
          context->java_vm,
          context->native_app_bridge_app_start,
          native_app_bridge_class,
          base_url,
          user_agent,
          android_id,
          launch_source,
          empty_string,
      };
      pthread_t app_start_thread{};
      pthread_attr_t app_start_attr;
      pthread_attr_init(&app_start_attr);
      pthread_attr_setdetachstate(&app_start_attr, PTHREAD_CREATE_DETACHED);
      int create_result =
          pthread_create(&app_start_thread, &app_start_attr,
                         AppBridgeAppStartThread, app_start_context);
      pthread_attr_destroy(&app_start_attr);
      if (create_result != 0) {
        delete app_start_context;
        std::cerr << "  [engine] failed to create nativeAppBridgeAppStart "
                  << "thread: " << create_result << '\n'
                  << std::flush;
      } else {
        std::cout << "  [engine] nativeAppBridgeAppStart scheduled on worker "
                  << "thread\n"
                  << std::flush;
      }
    } else {
      if (sigsetjmp(g_app_bridge_app_start_jmp_buf, 1) == 0) {
        g_app_bridge_app_start_recovery_in_progress = 1;
        context->native_app_bridge_app_start(
            env, native_app_bridge_class, base_url, user_agent, JNI_FALSE,
            android_id, launch_source, empty_string);
        g_app_bridge_app_start_recovery_in_progress = 0;
      } else {
        g_app_bridge_app_start_recovery_in_progress = 0;
        std::cerr << "  [engine] nativeAppBridgeAppStart recovered\n"
                  << std::flush;
      }
      std::cout << "  [engine] nativeAppBridgeAppStart returned\n"
                << std::flush;
    }
  }

  if (context->run_init_with_params) {
    env = ensure_env();
    std::cout << "  [engine] nativeAppBridgeV2InitWithParams\n" << std::flush;
    if (context->call_real_init_with_params) {
      jobject init_params =
          BuildAppBridgeInitParams(env, client_settings, fast_flags, app_params,
                                   asset_path, app_bridge_init_headless);
      if (IsEnabled("MOCKTAIL_CALL_REAL_APP_BRIDGE_INIT_THREAD")) {
        auto* init_context = new AppBridgeInitWithParamsContext{
            context->vm,
            context->java_vm,
            context->native_init_with_params,
            init_params,
            0,
            0,
        };
        pthread_t init_thread{};
        pthread_attr_t init_attr;
        pthread_attr_init(&init_attr);
        pthread_attr_setdetachstate(&init_attr, PTHREAD_CREATE_DETACHED);
        int create_result =
            pthread_create(&init_thread, &init_attr,
                           AppBridgeInitWithParamsThread, init_context);
        pthread_attr_destroy(&init_attr);
        if (create_result != 0) {
          delete init_context;
          std::cerr << "  [engine] failed to create "
                    << "nativeAppBridgeV2InitWithParams thread: "
                    << create_result << '\n'
                    << std::flush;
          MocktailAppBridgeInit(env, app_params);
        } else {
          std::cout << "  [engine] nativeAppBridgeV2InitWithParams scheduled "
                    << "on worker thread\n"
                    << std::flush;
          const int timeout_ms =
              GetEnvInt("MOCKTAIL_APP_BRIDGE_INIT_THREAD_TIMEOUT_MS", 1500);
          const uint64_t start_ms = MonotonicMillis();
          while (init_context->finished.load() == 0) {
            if (IsEnabled("MOCKTAIL_APP_BRIDGE_INIT_THREAD_PUMP")) {
              PumpRobloxMainThreadMessagesOnce();
            }
            if (timeout_ms >= 0) {
              const uint64_t now_ms = MonotonicMillis();
              if (now_ms >= start_ms &&
                  now_ms - start_ms >= static_cast<uint64_t>(timeout_ms)) {
                break;
              }
            }
            usleep(10 * 1000);
          }
          if (init_context->finished.load() != 0) {
            const bool recovered = init_context->recovered.load() != 0;
            delete init_context;
            if (recovered) {
              MocktailAppBridgeInit(env, app_params);
            }
          } else {
            std::cerr << "  [engine] nativeAppBridgeV2InitWithParams timed "
                      << "out after " << timeout_ms
                      << " ms; continuing with Mocktail app bridge staging\n"
                      << std::flush;
            MocktailAppBridgeInit(env, app_params);
            // The detached Roblox worker can still be inside a native futex
            // wait, so keep its tiny context alive for the rest of the run.
          }
        }
      } else {
        if (sigsetjmp(g_init_with_params_jmp_buf, 1) == 0) {
          g_init_with_params_recovery_in_progress = 1;
          context->native_init_with_params(env, native_gl_class, init_params);
          g_init_with_params_recovery_in_progress = 0;
        } else {
          AbortStage6InitWithParamsStaticGuards(
              "nativeAppBridgeV2InitWithParams inline");
          std::cerr << "  [engine] nativeAppBridgeV2InitWithParams recovered\n"
                    << std::flush;
          MocktailAppBridgeInit(env, app_params);
        }
      }
    } else {
      MocktailAppBridgeInit(env, app_params);
    }
    std::cout << "  [engine] nativeAppBridgeV2InitWithParams returned\n"
              << std::flush;
    DumpStage6AppBridgeStaticState("after V2 init");
    g_main_thread_message_pump_ready.store(1);
    if (IsEnabled("MOCKTAIL_TRACE_MAIN_THREAD_PUMP")) {
      std::cerr << "  [engine] nativeCallMessagesFromMainThread pump ready\n"
                << std::flush;
    }
  }

  if (context->run_game_activity_init && context->native_game_activity_init) {
    env = ensure_env();
    jlong handle = run_game_activity_initialize();
    if (context->run_game_activity_surface && handle != 0) {
      if (!IsDisabled("MOCKTAIL_GAME_ACTIVITY_CLEAR_APP_CMD_SLOT")) {
        auto** game_activity_slots =
            reinterpret_cast<void**>(static_cast<uintptr_t>(handle));
        std::cout << "  [engine] GameActivity slot[1] before clear="
                  << game_activity_slots[1] << '\n'
                  << std::flush;
        game_activity_slots[1] = nullptr;
      }
      auto* on_start = reinterpret_cast<GameActivityLifecycleFn>(
          mocktail_gameactivity_on_start_native);
      auto* on_resume = reinterpret_cast<GameActivityLifecycleFn>(
          mocktail_gameactivity_on_resume_native);
      auto* on_surface_created = reinterpret_cast<GameActivitySurfaceCreatedFn>(
          mocktail_gameactivity_on_surface_created_native);
      auto* on_surface_changed = reinterpret_cast<GameActivitySurfaceChangedFn>(
          mocktail_gameactivity_on_surface_changed_native);
      auto* on_surface_redraw_needed =
          reinterpret_cast<GameActivitySurfaceCreatedFn>(
              mocktail_gameactivity_on_surface_redraw_needed_native);
      std::cout << "  [engine] GameActivity callbacks:"
                << " start=" << reinterpret_cast<void*>(on_start)
                << " resume=" << reinterpret_cast<void*>(on_resume)
                << " created=" << reinterpret_cast<void*>(on_surface_created)
                << " changed=" << reinterpret_cast<void*>(on_surface_changed)
                << " redraw="
                << reinterpret_cast<void*>(on_surface_redraw_needed) << '\n'
                << std::flush;
      const bool run_lifecycle_callbacks =
          IsEnabled("MOCKTAIL_GAME_ACTIVITY_LIFECYCLE_CALLBACKS");
      if (sigsetjmp(g_game_activity_surface_jmp_buf, 1) == 0) {
        g_game_activity_surface_recovery_in_progress = 1;
        if (run_lifecycle_callbacks && on_start) {
          on_start(env, game_activity, handle);
        }
        if (run_lifecycle_callbacks && on_resume) {
          on_resume(env, game_activity, handle);
        }
        if (run_lifecycle_callbacks && on_surface_created) {
          on_surface_created(env, game_activity, handle, surface);
        }
        if (run_lifecycle_callbacks && on_surface_changed) {
          on_surface_changed(env, game_activity, handle, surface, 4, 1280, 720);
        }
        if (run_lifecycle_callbacks && on_surface_redraw_needed) {
          on_surface_redraw_needed(env, game_activity, handle, surface);
        }
        g_game_activity_surface_recovery_in_progress = 0;
        std::cout << "  [engine] GameActivity surface callbacks returned\n"
                  << std::flush;
      } else {
        g_game_activity_surface_recovery_in_progress = 0;
        std::cerr << "  [engine] GameActivity surface callbacks recovered\n"
                  << std::flush;
      }
    }
  }

  if (context->run_activity_lifecycle) {
    env = ensure_env();
    if (context->vm != nullptr) {
      context->vm->RestoreFunctions();
      env = context->vm->GetJNIEnv();
      PublishCurrentJniEnv(env);
    }
    jobject lifecycle_callbacks =
        NewObject(env,
                  "com/roblox/universalapp/activitylifecyclecallbacks/"
                  "JNIActivityLifecycleCallbacks");
    const char* activity_name_env =
        std::getenv("MOCKTAIL_ACTIVITY_LIFECYCLE_ACTIVITY_NAME");
    const char* activity_name =
        activity_name_env != nullptr && activity_name_env[0] != '\0'
            ? activity_name_env
            : "MainGameActivity";
    jstring activity_name_string = env->NewStringUTF(activity_name);
    std::cout << "  [engine] activity lifecycle for " << activity_name << '\n'
              << std::flush;
    auto invoke_lifecycle_callback =
        [&](const char* label, NativeActivityLifecycleStringFn callback) {
          if (callback == nullptr) {
            return;
          }
          std::cout << "  [engine] JNIActivityLifecycleCallbacks." << label
                    << '\n'
                    << std::flush;
          if (sigsetjmp(g_activity_lifecycle_jmp_buf, 1) == 0) {
            g_activity_lifecycle_recovery_in_progress = 1;
            callback(env, lifecycle_callbacks, activity_name_string);
            g_activity_lifecycle_recovery_in_progress = 0;
            std::cout << "  [engine] JNIActivityLifecycleCallbacks." << label
                      << " returned\n"
                      << std::flush;
          } else {
            g_activity_lifecycle_recovery_in_progress = 0;
            std::cerr << "  [engine] JNIActivityLifecycleCallbacks." << label
                      << " recovered from crash\n"
                      << std::flush;
          }
        };
    invoke_lifecycle_callback(
        "nativeOnPreCreated",
        context->activity_lifecycle_callbacks.on_pre_created);
    invoke_lifecycle_callback("nativeOnCreated",
                              context->activity_lifecycle_callbacks.on_created);
    invoke_lifecycle_callback(
        "nativeOnPostCreated",
        context->activity_lifecycle_callbacks.on_post_created);
    invoke_lifecycle_callback(
        "nativeOnPreStarted",
        context->activity_lifecycle_callbacks.on_pre_started);
    invoke_lifecycle_callback("nativeOnStarted",
                              context->activity_lifecycle_callbacks.on_started);
    invoke_lifecycle_callback(
        "nativeOnPostStarted",
        context->activity_lifecycle_callbacks.on_post_started);
    invoke_lifecycle_callback(
        "nativeOnPreResumed",
        context->activity_lifecycle_callbacks.on_pre_resumed);
    invoke_lifecycle_callback("nativeOnResumed",
                              context->activity_lifecycle_callbacks.on_resumed);
    invoke_lifecycle_callback(
        "nativeOnPostResumed",
        context->activity_lifecycle_callbacks.on_post_resumed);
    std::cout << "  [engine] activity lifecycle returned\n" << std::flush;
  }

  if (context->run_app_lifecycle_active &&
      context->native_app_lifecycle_set_active) {
    env = ensure_env();
    std::cout << "  [engine] JNIAppLifecycleNativeAdapter.setActive\n"
              << std::flush;
    context->native_app_lifecycle_set_active(env, native_gl_class);
    std::cout << "  [engine] JNIAppLifecycleNativeAdapter.setActive returned\n"
              << std::flush;
  }

  if (context->run_native_fragment_start && context->native_on_fragment_start) {
    env = ensure_env();
    std::cout << "  [engine] NativeGLInterface.nativeOnFragmentStart\n"
              << std::flush;
    if (sigsetjmp(g_native_fragment_start_jmp_buf, 1) == 0) {
      g_native_fragment_start_recovery_in_progress = kStage6RecoveryInline;
      context->native_on_fragment_start(env, native_gl_class);
      g_native_fragment_start_recovery_in_progress = kStage6RecoveryInactive;
      std::cout
          << "  [engine] NativeGLInterface.nativeOnFragmentStart returned\n"
          << std::flush;
    } else {
      g_native_fragment_start_recovery_in_progress = kStage6RecoveryInactive;
      std::cerr
          << "  [engine] NativeGLInterface.nativeOnFragmentStart recovered\n"
          << std::flush;
    }
  }

  const mocktail::platform::DisplayRefreshCapabilities display_refresh =
      mocktail::window::GetDisplayRefreshCapabilities();
  if (context->run_display_refresh_rate && display_refresh.valid() &&
      context->native_pass_current_display_refresh_rate) {
    env = ensure_env();
    std::cout
        << "  [engine] NativeGLInterface.nativePassCurrentDisplayRefreshRate "
        << display_refresh.current_hz << '\n'
        << std::flush;
    if (sigsetjmp(g_display_refresh_rate_jmp_buf, 1) == 0) {
      g_display_refresh_rate_recovery_in_progress = kStage6RecoveryInline;
      context->native_pass_current_display_refresh_rate(
          env, native_gl_class, display_refresh.current_hz);
      g_display_refresh_rate_recovery_in_progress = kStage6RecoveryInactive;
      std::cout
          << "  [engine] NativeGLInterface.nativePassCurrentDisplayRefreshRate "
             "returned\n"
          << std::flush;
    } else {
      g_display_refresh_rate_recovery_in_progress = kStage6RecoveryInactive;
      std::cerr
          << "  [engine] NativeGLInterface.nativePassCurrentDisplayRefreshRate "
             "recovered\n"
          << std::flush;
    }
  }

  if (context->run_display_refresh_rate && display_refresh.valid() &&
      context->native_pass_supported_refresh_rates &&
      IsEnabled("MOCKTAIL_PASS_SUPPORTED_REFRESH_RATES")) {
    env = ensure_env();
    std::cout << "  [engine] NativeGLInterface.nativePassSupportedRefreshRates"
              << " count=" << display_refresh.supported_hz.size() << '\n'
              << std::flush;
    if (sigsetjmp(g_display_refresh_rate_jmp_buf, 1) == 0) {
      g_display_refresh_rate_recovery_in_progress = kStage6RecoveryInline;
      const jsize count =
          static_cast<jsize>(display_refresh.supported_hz.size());
      jfloatArray refresh_rates = env->NewFloatArray(count);
      if (refresh_rates != nullptr && count > 0) {
        env->SetFloatArrayRegion(refresh_rates, 0, count,
                                 display_refresh.supported_hz.data());
        context->native_pass_supported_refresh_rates(env, native_gl_class,
                                                     refresh_rates);
      }
      g_display_refresh_rate_recovery_in_progress = kStage6RecoveryInactive;
      std::cout
          << "  [engine] NativeGLInterface.nativePassSupportedRefreshRates "
             "returned\n"
          << std::flush;
    } else {
      g_display_refresh_rate_recovery_in_progress = kStage6RecoveryInactive;
      std::cerr
          << "  [engine] NativeGLInterface.nativePassSupportedRefreshRates "
             "recovered\n"
          << std::flush;
    }
  }

  if (context->native_update_app_ui_sizes &&
      ShouldRunStartupStep("MOCKTAIL_UPDATE_APP_UI_SIZES", false)) {
    env = ensure_env();
    std::cout << "  [engine] updateAppUISizes\n" << std::flush;
    context->native_update_app_ui_sizes(env, native_gl_class, 1280, 720, 0, 0,
                                        0);
    std::cout << "  [engine] updateAppUISizes returned\n" << std::flush;
  }

  int init_delay_ms = GetEnvInt("MOCKTAIL_APPBRIDGE_INIT_DELAY_MS", 0);
  if (init_delay_ms > 0) {
    std::cout << "  [engine] wait after AppBridge init: " << init_delay_ms
              << " ms\n"
              << std::flush;
    usleep(static_cast<useconds_t>(init_delay_ms) * 1000);
  }

  if (context->run_start_lua_app_dm && context->native_start_lua_app_dm &&
      !IsEnabled("MOCKTAIL_START_LUA_APP_DM_AFTER_START_APP")) {
    int delay_ms = GetEnvInt("MOCKTAIL_START_LUA_APP_DM_DELAY_MS", 1500);
    if (IsEnabled("MOCKTAIL_START_LUA_APP_DM_INLINE")) {
      if (delay_ms > 0) {
        std::cout << "  [engine] nativeAppBridgeStartLuaAppDM wait " << delay_ms
                  << " ms\n"
                  << std::flush;
        usleep(static_cast<useconds_t>(delay_ms) * 1000);
      }
      env = ensure_env();
      if (IsEnabled("MOCKTAIL_TRACE_START_LUA_JNI")) {
        setenv("MOCKTAIL_JNI_TRACE", "1", 1);
      }
      std::cout << "  [engine] nativeAppBridgeStartLuaAppDM\n" << std::flush;
      if (sigsetjmp(g_start_lua_app_dm_jmp_buf, 1) == 0) {
        g_stage6_empty_gl_helper_returns = 0;
        g_start_lua_app_dm_recovery_in_progress = kStage6RecoveryInline;
        context->native_start_lua_app_dm(env, native_gl_class);
        CallStartLuaDirectClosureIfRequested("inline");
        g_start_lua_app_dm_recovery_in_progress = kStage6RecoveryInactive;
      } else {
        g_start_lua_app_dm_recovery_in_progress = kStage6RecoveryInactive;
        std::cerr << "  [engine] nativeAppBridgeStartLuaAppDM recovered\n"
                  << std::flush;
      }
      std::cout << "  [engine] nativeAppBridgeStartLuaAppDM returned\n"
                << std::flush;
      DumpStage6AppBridgeStaticState("after inline StartLuaAppDM");
    } else if (IsEnabled("MOCKTAIL_START_LUA_APP_DM_THREAD")) {
      auto* delayed_context = new DelayedStartLuaAppContext{
          context->vm,
          context->java_vm,
          context->native_start_lua_app_dm,
          delay_ms,
      };
      pthread_t start_lua_thread{};
      pthread_attr_t start_lua_attr;
      pthread_attr_init(&start_lua_attr);
      pthread_attr_setdetachstate(&start_lua_attr, PTHREAD_CREATE_DETACHED);
      int create_result =
          pthread_create(&start_lua_thread, &start_lua_attr,
                         DelayedStartLuaAppThread, delayed_context);
      pthread_attr_destroy(&start_lua_attr);
      if (create_result != 0) {
        delete delayed_context;
        std::cerr
            << "  [engine] failed to create delayed StartLuaAppDM thread: "
            << create_result << '\n'
            << std::flush;
      } else {
        std::cout
            << "  [engine] delayed nativeAppBridgeStartLuaAppDM scheduled on "
            << "worker thread\n"
            << std::flush;
      }
    } else {
      g_pending_main_thread_start_lua_app_dm = context->native_start_lua_app_dm;
      g_pending_main_thread_start_lua_due_ms =
          MonotonicMillis() + static_cast<uint64_t>(delay_ms);
      g_pending_main_thread_start_lua_started = false;
      std::cout
          << "  [engine] delayed nativeAppBridgeStartLuaAppDM scheduled on "
          << "main thread\n"
          << std::flush;
    }
  }

  if (context->run_update_surface_app) {
    env = ensure_env();
    std::cout
        << "  [engine] nativeAppBridgeV2UpdateSurfaceAppWithPlatformParams\n"
        << std::flush;
    if (context->call_real_update_surface_app) {
      if (IsEnabled("MOCKTAIL_CALL_REAL_APP_BRIDGE_UPDATE_SURFACE_THREAD")) {
        if (mocktail::window::IsInitialised()) {
          mocktail::window::ReleaseCurrentOnThread();
        }
        auto* delayed_context = new DelayedUpdateSurfaceAppContext{
            context->vm,
            context->java_vm,
            context->native_update_surface_app,
            native_gl_class,
            surface,
            platform_params,
        };
        pthread_t update_surface_thread{};
        pthread_attr_t update_surface_attr;
        pthread_attr_init(&update_surface_attr);
        pthread_attr_setdetachstate(&update_surface_attr,
                                    PTHREAD_CREATE_DETACHED);
        int create_result =
            pthread_create(&update_surface_thread, &update_surface_attr,
                           DelayedUpdateSurfaceAppThread, delayed_context);
        pthread_attr_destroy(&update_surface_attr);
        if (create_result != 0) {
          delete delayed_context;
          std::cerr
              << "  [engine] failed to create delayed UpdateSurfaceApp thread: "
              << create_result << '\n'
              << std::flush;
          if (sigsetjmp(g_update_surface_app_jmp_buf, 1) == 0) {
            g_stage6_empty_gl_helper_returns = 0;
            g_update_surface_app_recovery_in_progress = kStage6RecoveryInline;
            context->native_update_surface_app(env, native_gl_class, surface,
                                               platform_params);
            g_update_surface_app_recovery_in_progress = kStage6RecoveryInactive;
            std::cout << "  [engine] "
                         "nativeAppBridgeV2UpdateSurfaceAppWithPlatformParams "
                         "returned\n"
                      << std::flush;
            DumpStage6AppBridgeStaticState("after inline UpdateSurfaceApp");
          } else {
            g_update_surface_app_recovery_in_progress = kStage6RecoveryInactive;
            std::cerr << "  [engine] UpdateSurfaceAppWithPlatformParams "
                         "recovered from crash\n"
                      << std::flush;
          }
        } else {
          std::cout << "  [engine] delayed "
                       "nativeAppBridgeV2UpdateSurfaceAppWithPlatformParams "
                       "scheduled on worker thread\n"
                    << std::flush;
        }
      } else {
        if (sigsetjmp(g_update_surface_app_jmp_buf, 1) == 0) {
          g_stage6_empty_gl_helper_returns = 0;
          g_update_surface_app_recovery_in_progress = kStage6RecoveryInline;
          context->native_update_surface_app(env, native_gl_class, surface,
                                             platform_params);
          g_update_surface_app_recovery_in_progress = kStage6RecoveryInactive;
          std::cout << "  [engine] "
                       "nativeAppBridgeV2UpdateSurfaceAppWithPlatformParams "
                       "returned\n"
                    << std::flush;
          DumpStage6AppBridgeStaticState("after inline UpdateSurfaceApp");
        } else {
          g_update_surface_app_recovery_in_progress = kStage6RecoveryInactive;
          std::cerr << "  [engine] UpdateSurfaceAppWithPlatformParams "
                       "recovered from crash\n"
                    << std::flush;
        }
      }
    } else {
      std::cout
          << "  [engine] nativeAppBridgeV2UpdateSurfaceAppWithPlatformParams "
             "bypassed\n"
          << std::flush;
    }
  }

  if (IsEnabled("MOCKTAIL_ASMA_START_TASK_SCHEDULER_FOREGROUND") &&
      context->native_set_task_scheduler_background_mode) {
    env = ensure_env();
    if (!RunTaskSchedulerForegroundOnMainThread(
            context->native_set_task_scheduler_background_mode,
            native_gl_class)) {
      InvokeTaskSchedulerForeground(
          env, native_gl_class,
          context->native_set_task_scheduler_background_mode, "engine");
    }
  }

  const bool effective_run_start_app_with_params =
      HasEnvValue("MOCKTAIL_STEP_START_APP_WITH_PARAMS")
          ? IsEnabled("MOCKTAIL_STEP_START_APP_WITH_PARAMS")
          : context->run_start_app_with_params;
  const bool effective_call_real_start_app_with_params =
      effective_run_start_app_with_params &&
      (HasEnvValue("MOCKTAIL_CALL_REAL_APP_BRIDGE_START")
           ? IsEnabled("MOCKTAIL_CALL_REAL_APP_BRIDGE_START")
           : context->call_real_start_app_with_params);
  const bool effective_start_game_with_params =
      IsEnabled("MOCKTAIL_START_GAME_WITH_PARAM") &&
      context->game_session_runtime != nullptr;
  const bool force_inline_start_app_with_params =
      effective_start_game_with_params &&
      IsEnabled("MOCKTAIL_SYNC_START_APP_WITH_GAME");
  if (context->run_start_app_with_params !=
          effective_run_start_app_with_params ||
      context->call_real_start_app_with_params !=
          effective_call_real_start_app_with_params) {
    std::cerr << "  [engine] start-app flags drifted: "
                 "context_run_start_app_with_params="
              << (context->run_start_app_with_params ? 1 : 0)
              << " effective=" << (effective_run_start_app_with_params ? 1 : 0)
              << " context_call_real_start_app_with_params="
              << (context->call_real_start_app_with_params ? 1 : 0)
              << " effective_call_real_start_app_with_params="
              << (effective_call_real_start_app_with_params ? 1 : 0) << '\n'
              << std::flush;
  }

  if (effective_run_start_app_with_params) {
    env = ensure_env();
    std::cout << "  [engine] nativeAppBridgeV2StartAppWithParams\n"
              << std::flush;
    volatile sig_atomic_t start_app_recovered = 0;
    if (effective_call_real_start_app_with_params) {
      const bool use_start_app_thread =
          IsEnabled("MOCKTAIL_CALL_REAL_APP_BRIDGE_START_THREAD") &&
          !force_inline_start_app_with_params;
      if (use_start_app_thread) {
        if (mocktail::window::IsInitialised()) {
          mocktail::window::ReleaseCurrentOnThread();
        }
        auto* delayed_context = new DelayedStartAppContext{
            context->vm,
            context->java_vm,
            context->native_start_app_with_params,
            native_gl_class,
            start_app_params,
        };
        pthread_t start_app_thread{};
        pthread_attr_t start_app_attr;
        pthread_attr_init(&start_app_attr);
        pthread_attr_setdetachstate(&start_app_attr, PTHREAD_CREATE_DETACHED);
        int create_result =
            pthread_create(&start_app_thread, &start_app_attr,
                           DelayedStartAppThread, delayed_context);
        pthread_attr_destroy(&start_app_attr);
        if (create_result != 0) {
          delete delayed_context;
          std::cerr << "  [engine] failed to create delayed StartApp thread: "
                    << create_result << '\n'
                    << std::flush;
          if (sigsetjmp(g_start_app_with_params_jmp_buf, 1) == 0) {
            g_stage6_empty_gl_helper_returns = 0;
            g_start_app_with_params_recovery_in_progress =
                kStage6RecoveryInline;
            context->native_start_app_with_params(env, native_gl_class,
                                                  start_app_params);
            g_start_app_with_params_recovery_in_progress =
                kStage6RecoveryInactive;
          } else {
            start_app_recovered = 1;
            g_start_app_with_params_recovery_in_progress =
                kStage6RecoveryInactive;
            std::cerr
                << "  [engine] nativeAppBridgeV2StartAppWithParams recovered\n"
                << std::flush;
          }
        } else {
          std::cout << "  [engine] delayed nativeAppBridgeV2StartAppWithParams "
                       "scheduled on worker thread\n"
                    << std::flush;
        }
      } else {
        if (force_inline_start_app_with_params) {
          std::cout << "  [engine] forcing inline StartAppWithParams because "
                       "StartGameWithParam is enabled\n"
                    << std::flush;
        }
        if (sigsetjmp(g_start_app_with_params_jmp_buf, 1) == 0) {
          g_stage6_empty_gl_helper_returns = 0;
          g_start_app_with_params_recovery_in_progress = kStage6RecoveryInline;
          context->native_start_app_with_params(env, native_gl_class,
                                                start_app_params);
          g_start_app_with_params_recovery_in_progress =
              kStage6RecoveryInactive;
        } else {
          start_app_recovered = 1;
          g_start_app_with_params_recovery_in_progress =
              kStage6RecoveryInactive;
          std::cerr
              << "  [engine] nativeAppBridgeV2StartAppWithParams recovered\n"
              << std::flush;
        }
      }
    } else {
      MocktailAppBridgeStart(env, app_params);
    }
    std::cout << "  [engine] nativeAppBridgeV2StartAppWithParams returned\n"
              << std::flush;
    DumpStage6AppBridgeStaticState("after StartAppWithParams");
    if (start_app_recovered) {
      std::cerr << "  [engine] startup path cannot continue after start_app "
                   "recovery\n"
                << std::flush;
      pthread_exit(nullptr);
    }
  }

  if (IsEnabled("MOCKTAIL_UPDATE_SURFACE_APP_AFTER_START_APP") &&
      context->native_update_surface_app) {
    env = ensure_env();
    std::cout << "  [engine] post-StartApp "
                 "nativeAppBridgeV2UpdateSurfaceAppWithPlatformParams\n"
              << std::flush;
    if (IsEnabled("MOCKTAIL_CALL_REAL_APP_BRIDGE_UPDATE_SURFACE")) {
      if (sigsetjmp(g_update_surface_app_jmp_buf, 1) == 0) {
        g_stage6_empty_gl_helper_returns = 0;
        g_update_surface_app_recovery_in_progress = kStage6RecoveryInline;
        context->native_update_surface_app(env, native_gl_class, surface,
                                           platform_params);
        g_update_surface_app_recovery_in_progress = kStage6RecoveryInactive;
        std::cout
            << "  [engine] post-StartApp "
               "nativeAppBridgeV2UpdateSurfaceAppWithPlatformParams returned\n"
            << std::flush;
        DumpStage6AppBridgeStaticState("after post-StartApp UpdateSurfaceApp");
      } else {
        g_update_surface_app_recovery_in_progress = kStage6RecoveryInactive;
        std::cerr << "  [engine] post-StartApp "
                     "UpdateSurfaceAppWithPlatformParams recovered from crash\n"
                  << std::flush;
      }
    } else {
      std::cout
          << "  [engine] post-StartApp "
             "nativeAppBridgeV2UpdateSurfaceAppWithPlatformParams bypassed\n"
          << std::flush;
    }
  }

  if (IsEnabled("MOCKTAIL_START_LUA_APP_DM_AFTER_START_APP") &&
      context->run_start_lua_app_dm && context->native_start_lua_app_dm) {
    int delay_ms = GetEnvInt("MOCKTAIL_START_LUA_APP_DM_DELAY_MS", 0);
    if (delay_ms > 0) {
      std::cout << "  [engine] post-StartApp nativeAppBridgeStartLuaAppDM wait "
                << delay_ms << " ms\n"
                << std::flush;
      usleep(static_cast<useconds_t>(delay_ms) * 1000);
    }
    env = ensure_env();
    if (IsEnabled("MOCKTAIL_TRACE_START_LUA_JNI")) {
      setenv("MOCKTAIL_JNI_TRACE", "1", 1);
    }
    std::cout << "  [engine] post-StartApp nativeAppBridgeStartLuaAppDM\n"
              << std::flush;
    if (sigsetjmp(g_start_lua_app_dm_jmp_buf, 1) == 0) {
      g_stage6_empty_gl_helper_returns = 0;
      g_start_lua_app_dm_recovery_in_progress = kStage6RecoveryInline;
      context->native_start_lua_app_dm(env, native_gl_class);
      CallStartLuaDirectClosureIfRequested("post-StartApp");
      g_start_lua_app_dm_recovery_in_progress = kStage6RecoveryInactive;
    } else {
      g_start_lua_app_dm_recovery_in_progress = kStage6RecoveryInactive;
      std::cerr
          << "  [engine] post-StartApp nativeAppBridgeStartLuaAppDM recovered\n"
          << std::flush;
    }
    std::cout
        << "  [engine] post-StartApp nativeAppBridgeStartLuaAppDM returned\n"
        << std::flush;
    DumpStage6AppBridgeStaticState("after post-StartApp StartLuaAppDM");
  }

  if (context->game_session_runtime != nullptr) {
    env = ensure_env();
    mocktail::runtime::GameSessionPrincipal principal;
    principal.kind =
        context->account_identity.user_id > 0
            ? mocktail::runtime::GameSessionPrincipalKind::kAuthenticated
            : mocktail::runtime::GameSessionPrincipalKind::kLocalGuest;
    principal.generation = 1;
    principal.principal_id =
        context->account_identity.user_id > 0
            ? std::to_string(context->account_identity.user_id)
            : std::string();
    principal.base_url = "https://www.roblox.com/";
    std::string launch_parameters =
        GetEnvString("MOCKTAIL_GAME_PARAMS_JSON", "{}");
    if (launch_parameters.empty()) {
      launch_parameters = "{}";
    }
    mocktail::runtime::GameJoinRequest request{
        1, GetEnvLong("MOCKTAIL_PLACE_ID", 0), std::move(launch_parameters)};
    const mocktail::window::WindowSurfaceSnapshot window_surface =
        mocktail::window::GetWindowSurfaceSnapshot();
    if (!window_surface.available) {
      std::cerr << "  [game-session] initial typed window surface is "
                   "unavailable\n";
      return nullptr;
    }
    mocktail::runtime::GameSurface game_surface{
        window_surface.generation, window_surface.native_window,
        window_surface.width, window_surface.height};
    mocktail::runtime::RobloxGameSessionBinding binding{
        {native_gl_class, surface, platform_params, game_surface_activity,
         start_game_params},
        principal,
        request,
        game_surface};
    const mocktail::Status status =
        context->game_session_runtime->InitializeAndStart(
            binding, std::move(principal), std::move(request), game_surface);
    if (!status.ok()) {
      std::cerr << "  [game-session] typed lifecycle startup failed: "
                << status.message() << '\n'
                << std::flush;
      return nullptr;
    }
    std::cout << "  [game-session] typed lifecycle startup completed: "
              << mocktail::runtime::GameSessionStateName(
                     context->game_session_runtime->Snapshot().state)
              << '\n'
              << std::flush;
  }

  if (context->native_send_app_ready &&
      ShouldRunStartupStep("MOCKTAIL_SEND_APP_READY", false)) {
    if (IsEnabled("MOCKTAIL_SEND_APP_READY_THREAD")) {
      auto* delayed_context = new DelayedSendAppEventContext{
          context->vm,
          context->java_vm,
          context->native_send_app_ready,
          nullptr,
      };
      pthread_t send_app_ready_thread{};
      pthread_attr_t send_app_ready_attr;
      pthread_attr_init(&send_app_ready_attr);
      pthread_attr_setdetachstate(&send_app_ready_attr,
                                  PTHREAD_CREATE_DETACHED);
      int create_result =
          pthread_create(&send_app_ready_thread, &send_app_ready_attr,
                         DelayedSendAppReadyThread, delayed_context);
      pthread_attr_destroy(&send_app_ready_attr);
      if (create_result != 0) {
        delete delayed_context;
        std::cerr << "  [engine] failed to create delayed AppReady thread: "
                  << create_result << '\n'
                  << std::flush;
      } else {
        std::cout
            << "  [engine] delayed nativeAppBridgeV2SendAppEventOnAppReady "
               "scheduled on worker thread\n"
            << std::flush;
      }
    } else {
      env = ensure_env();
      volatile sig_atomic_t send_app_ready_recovered = 0;
      std::cout << "  [engine] nativeAppBridgeV2SendAppEventOnAppReady\n"
                << std::flush;
      if (sigsetjmp(g_send_app_ready_jmp_buf, 1) == 0) {
        g_send_app_ready_recovery_in_progress = kStage6RecoveryInline;
        jstring empty_ready_arg = env->NewStringUTF("");
        jstring home_feature = env->NewStringUTF("Home");
        context->native_send_app_ready(env, native_gl_class, empty_ready_arg,
                                       empty_ready_arg, empty_ready_arg,
                                       home_feature);
        g_send_app_ready_recovery_in_progress = kStage6RecoveryInactive;
      } else {
        send_app_ready_recovered = 1;
        g_send_app_ready_recovery_in_progress = kStage6RecoveryInactive;
        std::cerr
            << "  [engine] nativeAppBridgeV2SendAppEventOnAppReady recovered\n"
            << std::flush;
      }
      if (send_app_ready_recovered == 0) {
        std::cout
            << "  [engine] nativeAppBridgeV2SendAppEventOnAppReady returned\n"
            << std::flush;
      }
    }
  }

  if (context->native_send_game_loaded &&
      ShouldRunStartupStep("MOCKTAIL_SEND_GAME_LOADED", false)) {
    if (IsEnabled("MOCKTAIL_SEND_GAME_LOADED_THREAD")) {
      auto* delayed_context = new DelayedSendAppEventContext{
          context->vm,
          context->java_vm,
          nullptr,
          context->native_send_game_loaded,
      };
      pthread_t send_game_loaded_thread{};
      pthread_attr_t send_game_loaded_attr;
      pthread_attr_init(&send_game_loaded_attr);
      pthread_attr_setdetachstate(&send_game_loaded_attr,
                                  PTHREAD_CREATE_DETACHED);
      int create_result =
          pthread_create(&send_game_loaded_thread, &send_game_loaded_attr,
                         DelayedSendGameLoadedThread, delayed_context);
      pthread_attr_destroy(&send_game_loaded_attr);
      if (create_result != 0) {
        delete delayed_context;
        std::cerr << "  [engine] failed to create delayed GameLoaded thread: "
                  << create_result << '\n'
                  << std::flush;
      } else {
        std::cout
            << "  [engine] delayed nativeAppBridgeV2SendAppEventOnGameLoaded "
               "scheduled on worker thread\n"
            << std::flush;
      }
    } else {
      env = ensure_env();
      volatile sig_atomic_t send_game_loaded_recovered = 0;
      std::cout << "  [engine] nativeAppBridgeV2SendAppEventOnGameLoaded\n"
                << std::flush;
      if (sigsetjmp(g_send_game_loaded_jmp_buf, 1) == 0) {
        g_send_game_loaded_recovery_in_progress = kStage6RecoveryInline;
        jstring empty_game_loaded_arg = env->NewStringUTF("");
        jstring home_feature = env->NewStringUTF("Home");
        context->native_send_game_loaded(env, native_gl_class, home_feature,
                                         empty_game_loaded_arg,
                                         empty_game_loaded_arg);
        g_send_game_loaded_recovery_in_progress = kStage6RecoveryInactive;
      } else {
        send_game_loaded_recovered = 1;
        g_send_game_loaded_recovery_in_progress = kStage6RecoveryInactive;
        std::cerr << "  [engine] nativeAppBridgeV2SendAppEventOnGameLoaded "
                     "recovered\n"
                  << std::flush;
      }
      if (send_game_loaded_recovered == 0) {
        std::cout
            << "  [engine] nativeAppBridgeV2SendAppEventOnGameLoaded returned\n"
            << std::flush;
      }
    }
  }

  int keepalive_ms = GetEnvInt("MOCKTAIL_KEEPALIVE_MS", 0);
  if (keepalive_ms > 0) {
    std::cout << "  [engine] keepalive: " << keepalive_ms << " ms\n"
              << std::flush;
    usleep(static_cast<useconds_t>(keepalive_ms) * 1000);
    std::cout << "  [engine] keepalive returned\n" << std::flush;
  }

  if (IsEnabled("MOCKTAIL_KEEPALIVE")) {
    std::cout << "  [engine] keepalive: forever\n" << std::flush;
    while (true) {
      sleep(1);
    }
  }

  if (attached_to_thread) {
    EngineLog("DetachCurrentThread");
    jint detach_result = context->java_vm->DetachCurrentThread();
    if (detach_result != JNI_OK) {
      std::cerr << "  [engine] DetachCurrentThread failed: " << detach_result
                << '\n'
                << std::flush;
    }
    attached_to_thread = false;
  }

  return nullptr;
}

}  // namespace mocktail::legacy::internal
