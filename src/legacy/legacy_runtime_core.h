#ifndef MOCKTAIL_LEGACY_LEGACY_RUNTIME_CORE_H_
#define MOCKTAIL_LEGACY_LEGACY_RUNTIME_CORE_H_

#include <jni.h>
#include <pthread.h>
#include <setjmp.h>
#include <ucontext.h>

#include <atomic>
#include <csignal>
#include <cstddef>
#include <cstdint>
#include <string>

#include "compat/host_abi_experiment.h"
#include "compat/host_abi_profile.h"
#include "legacy/engine_startup_types.h"

extern std::atomic<bool> g_allow_host_abi_bridges;
extern std::atomic<bool> g_allow_host_constructor_replay;
extern std::atomic<const mocktail::compat::HostAbiProfile*>
    g_active_host_abi_profile;

namespace mocktail::legacy::internal {

extern compat::HostAbiExperimentResult g_host_abi_install_result;
extern bool g_host_abi_install_attempted;
extern volatile sig_atomic_t g_current_stage;
extern volatile sig_atomic_t g_skipped_headless_null_writes;
extern volatile std::uintptr_t g_libroblox_base;
extern std::uintptr_t g_libroblox_base_static;
extern volatile std::uintptr_t g_stage6_jni_env;
extern volatile std::uintptr_t g_stage6_jni_functions;
extern volatile std::uintptr_t g_game_activity_native_handle;
extern jobject g_saved_game_activity;
extern thread_local std::uintptr_t g_stage6_string_field_value_scratch_source;
extern thread_local unsigned char g_stage6_string_field_value_scratch[0x20];
extern thread_local sigjmp_buf g_libroblox_ctor_jmp_buf;
extern thread_local volatile sig_atomic_t g_libroblox_ctor_recovery_in_progress;
extern thread_local volatile sig_atomic_t g_libroblox_ctor_recovered_signo;
extern thread_local volatile std::uintptr_t g_libroblox_ctor_recovered_rip;
extern thread_local volatile std::uintptr_t g_libroblox_ctor_recovered_si_addr;
extern volatile sig_atomic_t g_jni_onload_in_progress;
extern volatile sig_atomic_t g_jni_onload_timings_printed;
extern volatile sig_atomic_t g_jni_onload_soft_timeout;
extern volatile sig_atomic_t g_jni_onload_jmp_armed;
extern thread_local sigjmp_buf g_jni_onload_jmp_buf;

extern NativeNoArgFn g_native_call_messages_from_main_thread;
extern NativeNoArgFn g_pending_main_thread_start_lua_app_dm;
extern jclass g_native_gl_class_for_main_thread;
extern jnivm::VM* g_vm_for_main_thread_pump;
extern std::uint64_t g_pending_main_thread_start_lua_due_ms;
extern bool g_pending_main_thread_start_lua_started;
extern std::atomic<int> g_main_thread_message_pump_ready;
extern pthread_mutex_t g_engine_gl_mutex;

extern thread_local volatile sig_atomic_t g_stage6_empty_gl_helper_returns;
extern thread_local sigjmp_buf g_init_with_params_jmp_buf;
extern thread_local volatile sig_atomic_t
    g_init_with_params_recovery_in_progress;
extern thread_local sigjmp_buf g_start_app_with_params_jmp_buf;
extern thread_local volatile sig_atomic_t
    g_start_app_with_params_recovery_in_progress;
extern thread_local sigjmp_buf g_start_lua_app_dm_jmp_buf;
extern thread_local volatile sig_atomic_t
    g_start_lua_app_dm_recovery_in_progress;
extern thread_local sigjmp_buf g_send_app_ready_jmp_buf;
extern thread_local volatile sig_atomic_t g_send_app_ready_recovery_in_progress;
extern thread_local sigjmp_buf g_send_game_loaded_jmp_buf;
extern thread_local volatile sig_atomic_t
    g_send_game_loaded_recovery_in_progress;
extern thread_local sigjmp_buf g_set_asset_path_jmp_buf;
extern thread_local volatile sig_atomic_t g_set_asset_path_recovery_in_progress;
extern thread_local sigjmp_buf g_game_global_init_jmp_buf;
extern thread_local volatile sig_atomic_t
    g_game_global_init_recovery_in_progress;
extern thread_local sigjmp_buf g_init_client_settings_jmp_buf;
extern thread_local volatile sig_atomic_t
    g_init_client_settings_recovery_in_progress;
extern thread_local sigjmp_buf g_post_client_settings_jmp_buf;
extern thread_local volatile sig_atomic_t
    g_post_client_settings_recovery_in_progress;
extern thread_local sigjmp_buf g_initialize_native_flags_jmp_buf;
extern thread_local volatile sig_atomic_t
    g_initialize_native_flags_recovery_in_progress;
extern thread_local sigjmp_buf g_cookie_setter_jmp_buf;
extern thread_local volatile sig_atomic_t g_cookie_setter_recovery_in_progress;
extern thread_local sigjmp_buf g_native_settings_jmp_buf;
extern thread_local volatile sig_atomic_t
    g_native_settings_recovery_in_progress;
extern thread_local const char* g_native_settings_recovery_name;
extern thread_local sigjmp_buf g_app_bridge_app_start_jmp_buf;
extern thread_local volatile sig_atomic_t
    g_app_bridge_app_start_recovery_in_progress;
extern thread_local sigjmp_buf g_game_activity_init_jmp_buf;
extern thread_local volatile sig_atomic_t
    g_game_activity_init_recovery_in_progress;
extern thread_local sigjmp_buf g_game_activity_surface_jmp_buf;
extern thread_local volatile sig_atomic_t
    g_game_activity_surface_recovery_in_progress;
extern thread_local sigjmp_buf g_activity_lifecycle_jmp_buf;
extern thread_local volatile sig_atomic_t
    g_activity_lifecycle_recovery_in_progress;
extern thread_local sigjmp_buf g_update_screen_orientation_jmp_buf;
extern thread_local volatile sig_atomic_t
    g_update_screen_orientation_recovery_in_progress;
extern thread_local sigjmp_buf g_update_surface_app_jmp_buf;
extern thread_local volatile sig_atomic_t
    g_update_surface_app_recovery_in_progress;
extern thread_local sigjmp_buf g_native_fragment_start_jmp_buf;
extern thread_local volatile sig_atomic_t
    g_native_fragment_start_recovery_in_progress;
extern thread_local sigjmp_buf g_display_refresh_rate_jmp_buf;
extern thread_local volatile sig_atomic_t
    g_display_refresh_rate_recovery_in_progress;

inline constexpr sig_atomic_t kStage6RecoveryInactive = 0;
inline constexpr sig_atomic_t kStage6RecoveryInline = 1;
inline constexpr sig_atomic_t kStage6RecoveryWorker = 2;
inline constexpr std::uintptr_t kStage6StartLuaDirectClosureOffset = 0x243eb94;

void* ResolveRobloxCapabilitySymbol(void* context, const char* symbol_name);
void RestoreGameSessionJniEnvironment(void* context);
extern "C" int mocktail_recover_stack_chk_fail();

void ApplyAuthStartupDefaults(bool credential_available,
                              bool user_overrode_start_lua_app_dm,
                              bool user_overrode_start_lua_step,
                              bool user_overrode_start_app_step,
                              bool user_overrode_call_start_app);
void InstallHeadlessSegvHandler();
void PrintStage(int stage, const char* description);
bool EngineTraceEnabled();
void EngineLog(const char* message);
void EngineLogPtr(const char* name, const void* pointer);
bool PatchCode(void* address, const unsigned char* bytes, std::size_t size);
void WriteLibcxxString(void* out, const std::string& value);
std::uintptr_t SeedStage6StringFieldValueScratch(std::uintptr_t source_string);
std::uintptr_t NullVtableStub();
bool InitializeActiveHostAbiThread();
void DumpRobloxUrlGlobals(const char* label);
void AbortStage6InitWithParamsStaticGuards(const char* reason);
bool ResetStage6AppBridgeStaticGuards(const char* reason);
bool HasRealGraphicsContext();
bool InvokeTaskSchedulerForeground(
    JNIEnv* env, jclass native_gl_class,
    NativeSetTaskSchedulerBackgroundModeFn native_set_background_mode,
    const char* log_scope);
bool RunTaskSchedulerForegroundOnMainThread(
    NativeSetTaskSchedulerBackgroundModeFn native_set_background_mode,
    jclass native_gl_class);
void PreloadPthreadSymbols();
bool HostAbiExperimentRequested();
void PublishCurrentJniEnv(JNIEnv* env);
void* RunJniOnLoadWorker(void* arg);
void JniOnLoadTimeoutAlarm(int signo, siginfo_t* info, void* context);
void InstallLibRobloxConstructorAlarm();
void DisarmLibRobloxConstructorAlarm();
void ArmLibRobloxConstructorAlarm();
void** ExpandedSegmentTable();
greg_t* Stage5RegisterSlotById(ucontext_t* ucontext, int reg_id);
void* ResolveRobloxTaggedPointer(std::uintptr_t handle,
                                 std::uintptr_t libroblox_base);
void* ResolveRobloxTaggedEntry(std::uintptr_t handle,
                               std::uintptr_t libroblox_base);

void PrintStepDecision(const char* name, bool enabled);
void PrintNativeBypass(const char* name, const char* flag);
void* EngineStartupThread(void* arg);
void PumpStartupOwnerThread(void* context);
std::uint64_t MonotonicMillis();
std::uint64_t MonotonicNanos();
JNIEnv* AttachMainThreadJniEnv();
void RunPendingMainThreadTaskSchedulerForeground();
void PumpRobloxMainThreadMessagesOnce();
void CallStartLuaDirectClosureIfRequested(const char* label);
void DumpStage6AppBridgeStaticState(const char* label);

}  // namespace mocktail::legacy::internal

#endif  // MOCKTAIL_LEGACY_LEGACY_RUNTIME_CORE_H_
