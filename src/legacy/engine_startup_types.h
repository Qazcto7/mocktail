#ifndef MOCKTAIL_LEGACY_ENGINE_STARTUP_TYPES_H_
#define MOCKTAIL_LEGACY_ENGINE_STARTUP_TYPES_H_

#include <jni.h>

#include <atomic>

#include "jnivm/jnivm.h"
#include "runtime/auth_runtime_composition.h"
#include "runtime/roblox_game_session_native_adapter.h"

namespace mocktail::legacy::internal {

using JniOnLoadFn = jint (*)(JavaVM*, void*);
using NativeGameGlobalInitFn = void (*)(JNIEnv*, jclass);
using NativeInitClientSettingsFn = jint (*)(JNIEnv*, jclass, jstring, jstring,
                                            jstring);
using NativeInitClientSettingsSignedFn = jint (*)(JNIEnv*, jclass, jstring,
                                                  jstring, jstring, jstring);
using NativeInitClientSettingsCachedFn = jint (*)(JNIEnv*, jclass, jstring,
                                                  jstring, jstring, jstring,
                                                  jlong);
using NativeInitClientSettingsCachedCompressedFn = jint (*)(JNIEnv*, jclass,
                                                            jbyteArray, jstring,
                                                            jstring, jstring,
                                                            jlong, jboolean);
using NativePostClientSettingsFn = void (*)(JNIEnv*, jclass, jobject);
using NativeInitializeNativeFlagsFn = jobject (*)(JNIEnv*, jclass,
                                                  jobjectArray);
using NativeAppBridgeAppStartFn = void (*)(JNIEnv*, jclass, jstring, jstring,
                                           jboolean, jstring, jstring, jstring);
using NativeSetIsFirstInstallFn = void (*)(JNIEnv*, jclass, jboolean);
using NativeAppBridgeObjectParamsFn = void (*)(JNIEnv*, jclass, jobject);
using NativeAppBridgeSetInitParamsFn = void (*)(JNIEnv*, jclass, jobject);
using NativeUpdateSurfaceAppFn = void (*)(JNIEnv*, jclass, jobject, jobject);
using NativeUpdateAppUiSizesFn = void (*)(JNIEnv*, jclass, jint, jint, jint,
                                          jint, jint);
using NativeUpdateScreenOrientationFn = void (*)(JNIEnv*, jclass, jint);
using NativeSendAppReadyFn = void (*)(JNIEnv*, jclass, jstring, jstring,
                                      jstring, jstring);
using NativeSendGameLoadedFn = void (*)(JNIEnv*, jclass, jstring, jstring,
                                        jstring);
using NativePassSupportedRefreshRatesFn = void (*)(JNIEnv*, jclass,
                                                   jfloatArray);
using NativePassCurrentDisplayRefreshRateFn = void (*)(JNIEnv*, jclass, jfloat);
using NativeSetStringParamFn = void (*)(JNIEnv*, jclass, jstring);
using NativeSetBaseUrlFn = void (*)(JNIEnv*, jclass, jstring, jstring);
using NativeSetTaskSchedulerBackgroundModeFn = void (*)(JNIEnv*, jclass,
                                                        jboolean, jstring);
using NativeObjectInitFn = void (*)(JNIEnv*, jclass, jobject);
using NativeSetTwoStringParamsFn = void (*)(JNIEnv*, jclass, jstring, jstring);
using NativeSetThreeStringParamsFn = void (*)(JNIEnv*, jclass, jstring, jstring,
                                              jstring);
using NativeSetHttpClientProxyFn = void (*)(JNIEnv*, jclass, jstring, jlong);
using NativeInitStorageManagerFn = void (*)(JNIEnv*, jobject, jobject, jstring,
                                            jstring);
using NativeSetPlatformImplFn = jobject (*)(JNIEnv*, jclass, jobject);
using NativeActivityLifecycleStringFn = void (*)(JNIEnv*, jobject, jstring);
using NativeNoArgFn = void (*)(JNIEnv*, jclass);
using NativeDirectNoArgFn = void (*)();
using NativeGameActivityInitFn = jlong (*)(JNIEnv*, jobject, jstring, jstring,
                                           jstring, jobject, jbyteArray,
                                           jobject);
using GameActivityLifecycleFn = void (*)(JNIEnv*, jobject, jlong);
using GameActivitySurfaceCreatedFn = void (*)(JNIEnv*, jobject, jlong, jobject);
using GameActivitySurfaceChangedFn = void (*)(JNIEnv*, jobject, jlong, jobject,
                                              jint, jint, jint);

struct NativeActivityLifecycleCallbacks {
  NativeActivityLifecycleStringFn on_pre_created;
  NativeActivityLifecycleStringFn on_created;
  NativeActivityLifecycleStringFn on_post_created;
  NativeActivityLifecycleStringFn on_pre_started;
  NativeActivityLifecycleStringFn on_started;
  NativeActivityLifecycleStringFn on_post_started;
  NativeActivityLifecycleStringFn on_pre_resumed;
  NativeActivityLifecycleStringFn on_resumed;
  NativeActivityLifecycleStringFn on_post_resumed;
};

struct JniOnLoadAsyncContext {
  JniOnLoadFn fn;
  jint result = JNI_ERR;
  jnivm::VM* vm;
};

struct EngineStartupContext {
  jnivm::VM* vm;
  JavaVM* java_vm;
  jnivm::RobloxAuthIdentity account_identity;
  const mocktail::runtime::SecureRobloxCredential* roblox_credential;
  mocktail::runtime::RobloxGameSessionRuntime* game_session_runtime;
  bool run_prepare_jni;
  bool run_set_asset_path;
  bool call_real_set_asset_path;
  bool run_global_init;
  bool run_init_client_settings;
  bool run_post_client_settings;
  bool run_app_bridge_app_start;
  bool run_native_settings;
  bool run_set_init_params;
  bool run_init_with_params;
  bool call_real_init_with_params;
  bool run_update_screen_orientation;
  bool run_update_surface_app;
  bool call_real_update_surface_app;
  bool run_start_app_with_params;
  bool call_real_start_app_with_params;
  bool run_activity_lifecycle;
  bool run_game_activity_init;
  bool run_game_activity_surface;
  bool run_app_lifecycle_active;
  bool run_native_fragment_start;
  bool run_display_refresh_rate;
  bool run_start_lua_app_dm;
  NativeGameGlobalInitFn native_global_init;
  NativeInitClientSettingsFn native_init_client_settings;
  NativeInitClientSettingsSignedFn native_init_client_settings_signed;
  NativeInitClientSettingsCachedFn native_init_client_settings_cached;
  NativeInitClientSettingsCachedCompressedFn
      native_init_client_settings_cached_compressed;
  NativePostClientSettingsFn native_post_client_settings;
  NativeInitializeNativeFlagsFn native_initialize_native_flags;
  NativeAppBridgeAppStartFn native_app_bridge_app_start;
  NativeSetIsFirstInstallFn native_set_is_first_install;
  NativeSetBaseUrlFn native_set_base_url;
  NativeObjectInitFn native_set_device_info;
  NativeObjectInitFn native_base_url_protocol_init;
  NativeSetStringParamFn native_set_roblox_channel;
  NativeSetStringParamFn native_override_channel_platform_name;
  NativeSetStringParamFn native_set_roblox_version;
  NativeSetStringParamFn native_set_exception_reason_filename;
  NativeSetTwoStringParamsFn native_set_base_data_directories;
  NativeSetStringParamFn native_set_cache_directory;
  NativeSetStringParamFn native_set_files_directory;
  NativeSetStringParamFn native_set_external_directory;
  NativeSetStringParamFn native_set_preferences_file;
  NativeSetStringParamFn native_set_default_app_policy_file;
  NativeSetHttpClientProxyFn native_set_http_client_proxy;
  NativeNoArgFn native_init_fast_log;
  NativeSetTwoStringParamsFn native_set_multiple_cookies;
  NativeSetTwoStringParamsFn native_cookie_manager_set_cookie;
  NativeSetThreeStringParamsFn native_set_platform_headers_with_idfa;
  NativeSetStringParamFn native_set_user_id;
  NativeObjectInitFn native_init_asset_manager;
  NativeInitStorageManagerFn native_init_storage_manager;
  NativeSetPlatformImplFn native_local_storage_set_platform_impl;
  NativeAppBridgeSetInitParamsFn native_set_init_params;
  NativeNoArgFn native_retry_init;
  NativeAppBridgeObjectParamsFn native_init_with_params;
  NativeNoArgFn native_update_adapter_init;
  NativeUpdateScreenOrientationFn native_update_screen_orientation;
  NativeUpdateAppUiSizesFn native_update_app_ui_sizes;
  NativeSetTaskSchedulerBackgroundModeFn
      native_set_task_scheduler_background_mode;
  NativeUpdateSurfaceAppFn native_update_surface_app;
  NativeAppBridgeObjectParamsFn native_start_app_with_params;
  NativeSendAppReadyFn native_send_app_ready;
  NativeSendGameLoadedFn native_send_game_loaded;
  NativeSetStringParamFn native_set_asset_path;
  NativeActivityLifecycleCallbacks activity_lifecycle_callbacks;
  NativeGameActivityInitFn native_game_activity_init;
  NativeNoArgFn native_app_lifecycle_set_active;
  NativeNoArgFn native_on_fragment_start;
  NativePassSupportedRefreshRatesFn native_pass_supported_refresh_rates;
  NativePassCurrentDisplayRefreshRateFn
      native_pass_current_display_refresh_rate;
  NativeNoArgFn native_start_lua_app_dm;
};

struct DelayedStartLuaAppContext {
  jnivm::VM* vm;
  JavaVM* java_vm;
  NativeNoArgFn native_start_lua_app_dm;
  int delay_ms;
};

struct AppBridgeInitWithParamsContext {
  jnivm::VM* vm;
  JavaVM* java_vm;
  NativeAppBridgeObjectParamsFn native_init_with_params;
  jobject init_params;
  std::atomic<int> finished;
  std::atomic<int> recovered;
};

struct AppBridgeAppStartContext {
  jnivm::VM* vm;
  JavaVM* java_vm;
  NativeAppBridgeAppStartFn native_app_bridge_app_start;
  jclass native_app_bridge_class;
  jstring base_url;
  jstring user_agent;
  jstring android_id;
  jstring launch_source;
  jstring empty_string;
};

struct DelayedUpdateSurfaceAppContext {
  jnivm::VM* vm;
  JavaVM* java_vm;
  NativeUpdateSurfaceAppFn native_update_surface_app;
  jclass native_gl_class;
  jobject surface;
  jobject platform_params;
};

struct DelayedStartAppContext {
  jnivm::VM* vm;
  JavaVM* java_vm;
  NativeAppBridgeObjectParamsFn native_start_app_with_params;
  jclass native_gl_class;
  jobject start_app_params;
};

struct DelayedSendAppEventContext {
  jnivm::VM* vm;
  JavaVM* java_vm;
  NativeSendAppReadyFn native_send_app_ready;
  NativeSendGameLoadedFn native_send_game_loaded;
};

}  // namespace mocktail::legacy::internal

#endif  // MOCKTAIL_LEGACY_ENGINE_STARTUP_TYPES_H_
