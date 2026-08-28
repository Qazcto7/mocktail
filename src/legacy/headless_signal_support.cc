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
#include "legacy/headless_signal_helpers.h"
#include "legacy/headless_signal_state.h"
#include "legacy/legacy_runtime.h"
#include "legacy/legacy_runtime_core.h"
#include "legacy/memory_inspection.h"
#include "legacy/rbxm_diagnostics.h"
#include "legacy/runtime_adapters.h"
#include "legacy/runtime_environment.h"
#include "legacy/runtime_paths.h"
#include "legacy/stage6_offsets.h"
#include "legacy/stage6_rbxm_fallbacks.h"
#include "legacy/stage6_runtime.h"
#include "legacy/stage6_signal_recovery.h"
#include "legacy/stage6_start_lua_fallbacks.h"
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

namespace jnivm {
extern void* my_segment[100000];
extern void* my_segment_table[];
}  // namespace jnivm

std::atomic<bool> g_allow_host_abi_bridges{false};
std::atomic<bool> g_allow_host_constructor_replay{false};
std::atomic<const mocktail::compat::HostAbiProfile*> g_active_host_abi_profile{
    nullptr};

namespace mocktail::legacy::internal {

void* ResolveRobloxCapabilitySymbol(void* context, const char* symbol_name) {
  if (context == nullptr || symbol_name == nullptr) {
    return nullptr;
  }
  auto* handle = static_cast<linker::LibraryHandle*>(context);
  return linker::ResolveSymbol(*handle, symbol_name);
}

void RestoreGameSessionJniEnvironment(void* context) {
  auto* vm = static_cast<jnivm::VM*>(context);
  if (vm != nullptr) {
    vm->RestoreFunctions();
  }
}

volatile sig_atomic_t g_skipped_headless_null_writes = 0;
volatile sig_atomic_t g_current_stage = 0;
volatile sig_atomic_t g_restored_stage6_jni_table_logs = 0;
volatile sig_atomic_t g_stage6_segment_read_logs = 0;
volatile sig_atomic_t g_appstart_scheduler_guard_logs = 0;
volatile sig_atomic_t g_appstart_cleanup_guard_logs = 0;
volatile sig_atomic_t g_start_app_null_manager_guard_logs = 0;
volatile sig_atomic_t g_start_app_manager_scratch_logs = 0;
volatile sig_atomic_t g_stage6_low_memcpy_redirect_logs = 0;
volatile sig_atomic_t g_stage6_invalid_r13_read_logs = 0;
volatile sig_atomic_t g_stage6_linked_list_low_write_logs = 0;
volatile sig_atomic_t g_stage6_gl_state_scratch_logs = 0;
volatile sig_atomic_t g_stage6_string_map_scratch_logs = 0;
volatile sig_atomic_t g_stage6_string_field_assign_logs = 0;
volatile sig_atomic_t g_stage6_string_field_old_value_logs = 0;
volatile sig_atomic_t g_stage6_unsupported_message_slot_logs = 0;
volatile sig_atomic_t g_stage6_start_lua_unsupported_message_slot_logs = 0;
volatile sig_atomic_t g_stage6_hash_lookup_low_table_logs = 0;
volatile sig_atomic_t g_stage6_map_lookup_low_owner_logs = 0;
volatile sig_atomic_t g_stage6_audio_callback_table_logs = 0;
volatile sig_atomic_t g_stage6_start_app_null_callback_owner_logs = 0;
volatile sig_atomic_t g_stage6_start_app_null_callback_owner_free_logs = 0;
volatile sig_atomic_t g_stage6_start_app_null_callback_owner_table_logs = 0;
volatile sig_atomic_t g_stage6_start_app_zero_stride_divisor_logs = 0;
volatile sig_atomic_t g_stage6_start_app_null_state_object_logs = 0;
volatile sig_atomic_t g_stage6_start_lua_observer_list_logs = 0;
volatile sig_atomic_t g_stage6_erroneous_function_pointer_call_logs = 0;
thread_local volatile sig_atomic_t g_stage6_empty_gl_helper_returns = 0;
thread_local volatile sig_atomic_t
    g_stage6_string_field_null_current_loop_count = 0;
thread_local uintptr_t g_stage6_string_field_null_current_last_value = 0;
thread_local uintptr_t g_stage6_string_field_value_scratch_source = 0;
alignas(
    16) thread_local unsigned char g_stage6_string_field_value_scratch[0x20] = {
    0};
volatile uintptr_t g_stage6_jni_env = 0;
volatile uintptr_t g_stage6_jni_functions = 0;
volatile uintptr_t g_libroblox_base = 0;
volatile uintptr_t g_game_activity_native_handle = 0;
jobject g_saved_game_activity = nullptr;
extern "C" void* mocktail_gameactivity_on_trim_memory_native;
const char g_empty_c_string[] = "";
volatile uintptr_t g_stage5_last_fallback_rip = 0;
volatile sig_atomic_t g_jni_onload_in_progress = 0;
volatile sig_atomic_t g_jni_onload_timings_printed = 0;
volatile sig_atomic_t g_jni_onload_soft_timeout = 0;
volatile sig_atomic_t g_jni_onload_jmp_armed = 0;
pthread_mutex_t g_engine_gl_mutex = PTHREAD_MUTEX_INITIALIZER;
thread_local sigjmp_buf g_jni_onload_jmp_buf;
thread_local sigjmp_buf g_init_with_params_jmp_buf;
thread_local volatile sig_atomic_t g_init_with_params_recovery_in_progress = 0;
thread_local sigjmp_buf g_start_app_with_params_jmp_buf;
thread_local volatile sig_atomic_t
    g_start_app_with_params_recovery_in_progress = 0;
thread_local sigjmp_buf g_start_lua_app_dm_jmp_buf;
thread_local volatile sig_atomic_t g_start_lua_app_dm_recovery_in_progress = 0;
thread_local sigjmp_buf g_start_game_with_param_jmp_buf;
thread_local volatile sig_atomic_t
    g_start_game_with_param_recovery_in_progress = 0;
thread_local sigjmp_buf g_send_app_ready_jmp_buf;
thread_local volatile sig_atomic_t g_send_app_ready_recovery_in_progress = 0;
thread_local sigjmp_buf g_send_game_loaded_jmp_buf;
thread_local volatile sig_atomic_t g_send_game_loaded_recovery_in_progress = 0;
thread_local sigjmp_buf g_set_asset_path_jmp_buf;
thread_local volatile sig_atomic_t g_set_asset_path_recovery_in_progress = 0;
thread_local sigjmp_buf g_game_global_init_jmp_buf;
thread_local volatile sig_atomic_t g_game_global_init_recovery_in_progress = 0;
thread_local sigjmp_buf g_init_client_settings_jmp_buf;
thread_local volatile sig_atomic_t g_init_client_settings_recovery_in_progress =
    0;
thread_local sigjmp_buf g_post_client_settings_jmp_buf;
thread_local volatile sig_atomic_t g_post_client_settings_recovery_in_progress =
    0;
thread_local sigjmp_buf g_initialize_native_flags_jmp_buf;
thread_local volatile sig_atomic_t
    g_initialize_native_flags_recovery_in_progress = 0;
thread_local sigjmp_buf g_cookie_setter_jmp_buf;
thread_local volatile sig_atomic_t g_cookie_setter_recovery_in_progress = 0;
thread_local sigjmp_buf g_native_settings_jmp_buf;
thread_local volatile sig_atomic_t g_native_settings_recovery_in_progress = 0;
thread_local const char* g_native_settings_recovery_name = nullptr;
thread_local sigjmp_buf g_app_bridge_app_start_jmp_buf;
thread_local volatile sig_atomic_t g_app_bridge_app_start_recovery_in_progress =
    0;
thread_local sigjmp_buf g_game_activity_init_jmp_buf;
thread_local volatile sig_atomic_t g_game_activity_init_recovery_in_progress =
    0;
thread_local sigjmp_buf g_game_activity_surface_jmp_buf;
thread_local volatile sig_atomic_t
    g_game_activity_surface_recovery_in_progress = 0;
thread_local sigjmp_buf g_activity_lifecycle_jmp_buf;
thread_local volatile sig_atomic_t g_activity_lifecycle_recovery_in_progress =
    0;
thread_local sigjmp_buf g_update_screen_orientation_jmp_buf;
thread_local volatile sig_atomic_t
    g_update_screen_orientation_recovery_in_progress = 0;
thread_local sigjmp_buf g_update_surface_app_jmp_buf;
thread_local volatile sig_atomic_t g_update_surface_app_recovery_in_progress =
    0;
thread_local sigjmp_buf g_call_messages_from_main_thread_jmp_buf;
thread_local volatile sig_atomic_t
    g_call_messages_from_main_thread_recovery_in_progress = 0;
thread_local sigjmp_buf g_native_fragment_start_jmp_buf;
thread_local volatile sig_atomic_t
    g_native_fragment_start_recovery_in_progress = 0;
thread_local sigjmp_buf g_display_refresh_rate_jmp_buf;
thread_local volatile sig_atomic_t g_display_refresh_rate_recovery_in_progress =
    0;
thread_local sigjmp_buf g_libroblox_ctor_jmp_buf;
thread_local volatile sig_atomic_t g_libroblox_ctor_recovery_in_progress = 0;
thread_local volatile sig_atomic_t g_libroblox_ctor_recovered_signo = 0;
thread_local volatile uintptr_t g_libroblox_ctor_recovered_rip = 0;
thread_local volatile uintptr_t g_libroblox_ctor_recovered_si_addr = 0;
extern "C" int mocktail_recover_stack_chk_fail() {
  const uintptr_t caller =
      reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  auto roblox_offset = [](uintptr_t address) -> uintptr_t {
    const uintptr_t base = static_cast<uintptr_t>(g_libroblox_base);
    return base != 0 && address >= base && address < base + 0x08000000
               ? address - base
               : 0;
  };
  uintptr_t rbp = 0;
#if defined(__x86_64__)
  asm volatile("movq %%rbp, %0" : "=r"(rbp));
#endif
  uintptr_t frame_ret = 0;
  uintptr_t parent_rbp = 0;
  uintptr_t parent_ret = 0;
  uintptr_t grand_rbp = 0;
  uintptr_t grand_ret = 0;
  if (IsReadableMemoryRange(rbp, sizeof(uintptr_t) * 2)) {
    const auto* frame = reinterpret_cast<const uintptr_t*>(rbp);
    parent_rbp = frame[0];
    frame_ret = frame[1];
  }
  if (IsReadableMemoryRange(parent_rbp, sizeof(uintptr_t) * 2)) {
    const auto* frame = reinterpret_cast<const uintptr_t*>(parent_rbp);
    grand_rbp = frame[0];
    parent_ret = frame[1];
  }
  if (IsReadableMemoryRange(grand_rbp, sizeof(uintptr_t) * 2)) {
    const auto* frame = reinterpret_cast<const uintptr_t*>(grand_rbp);
    grand_ret = frame[1];
  }
  char entry_msg[320];
  int entry_len = snprintf(
      entry_msg, sizeof(entry_msg),
      "  [patch] stack check bridge entered caller=%p caller_off=0x%lx "
      "frame_ret_off=0x%lx parent_ret_off=0x%lx grand_ret_off=0x%lx "
      "rbp=%p parent_rbp=%p grand_rbp=%p\n",
      reinterpret_cast<void*>(caller),
      static_cast<unsigned long>(roblox_offset(caller)),
      static_cast<unsigned long>(roblox_offset(frame_ret)),
      static_cast<unsigned long>(roblox_offset(parent_ret)),
      static_cast<unsigned long>(roblox_offset(grand_ret)),
      reinterpret_cast<void*>(rbp), reinterpret_cast<void*>(parent_rbp),
      reinterpret_cast<void*>(grand_rbp));
  if (entry_len > 0) {
    write(2, entry_msg, static_cast<size_t>(entry_len));
  }
  if (g_current_stage < 6) {
    return 0;
  }
  if (g_init_client_settings_recovery_in_progress != 0) {
    g_init_client_settings_recovery_in_progress = 0;
    const char msg[] =
        "  [patch] recovered from stack check in nativeInitClientSettings\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_init_client_settings_jmp_buf, 1);
  }
  if (g_post_client_settings_recovery_in_progress != 0) {
    g_post_client_settings_recovery_in_progress = 0;
    const char msg[] =
        "  [patch] recovered from stack check in "
        "nativePostClientSettingsLoadedInitialization3\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_post_client_settings_jmp_buf, 1);
  }
  if (g_initialize_native_flags_recovery_in_progress != 0) {
    g_initialize_native_flags_recovery_in_progress = 0;
    const char msg[] =
        "  [patch] recovered from stack check in nativeInitializeNativeFlags\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_initialize_native_flags_jmp_buf, 1);
  }
  if (g_cookie_setter_recovery_in_progress != 0) {
    g_cookie_setter_recovery_in_progress = 0;
    const char msg[] =
        "  [patch] recovered from stack check in native cookie setter\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_cookie_setter_jmp_buf, 1);
  }
  if (g_native_settings_recovery_in_progress != 0) {
    g_native_settings_recovery_in_progress = 0;
    const char msg[] =
        "  [patch] recovered from stack check in NativeSettings setter\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_native_settings_jmp_buf, 1);
  }
  if (g_app_bridge_app_start_recovery_in_progress != 0) {
    g_app_bridge_app_start_recovery_in_progress = 0;
    const char msg[] =
        "  [patch] recovered from stack check in nativeAppBridgeAppStart\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_app_bridge_app_start_jmp_buf, 1);
  }
  if (g_init_with_params_recovery_in_progress != 0) {
    g_init_with_params_recovery_in_progress = 0;
    const char msg[] =
        "  [patch] recovered from stack check in "
        "nativeAppBridgeV2InitWithParams\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_init_with_params_jmp_buf, 1);
  }
  if (g_start_app_with_params_recovery_in_progress != 0) {
    g_start_app_with_params_recovery_in_progress = 0;
    const char msg[] =
        "  [patch] recovered from stack check in "
        "nativeAppBridgeV2StartAppWithParams\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_start_app_with_params_jmp_buf, 1);
  }
  if (g_start_lua_app_dm_recovery_in_progress != 0) {
    g_start_lua_app_dm_recovery_in_progress = 0;
    const char msg[] =
        "  [patch] recovered from stack check in "
        "nativeAppBridgeStartLuaAppDM\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_start_lua_app_dm_jmp_buf, 1);
  }
  if (g_update_screen_orientation_recovery_in_progress != 0) {
    g_update_screen_orientation_recovery_in_progress = 0;
    const char msg[] =
        "  [patch] recovered from stack check in "
        "nativeUpdateScreenOrientation\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_update_screen_orientation_jmp_buf, 1);
  }
  if (g_start_game_with_param_recovery_in_progress != 0) {
    g_start_game_with_param_recovery_in_progress = 0;
    const char msg[] =
        "  [patch] recovered from stack check in "
        "nativeAppBridgeV2StartGameWithParam\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_start_game_with_param_jmp_buf, 1);
  }
  if (g_send_app_ready_recovery_in_progress != 0) {
    g_send_app_ready_recovery_in_progress = 0;
    const char msg[] =
        "  [patch] recovered from stack check in "
        "nativeAppBridgeV2SendAppEventOnAppReady\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_send_app_ready_jmp_buf, 1);
  }
  if (g_send_game_loaded_recovery_in_progress != 0) {
    g_send_game_loaded_recovery_in_progress = 0;
    const char msg[] =
        "  [patch] recovered from stack check in "
        "nativeAppBridgeV2SendAppEventOnGameLoaded\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_send_game_loaded_jmp_buf, 1);
  }
  const char no_recovery_msg[] =
      "  [patch] stack check bridge had no active recovery target\n";
  write(2, no_recovery_msg, sizeof(no_recovery_msg) - 1);
  return 0;
}

void PublishCurrentJniEnv(JNIEnv* env);

void* RunJniOnLoadWorker(void* arg) {
  auto* context = static_cast<JniOnLoadAsyncContext*>(arg);
  if (context == nullptr || context->vm == nullptr) {
    return nullptr;
  }
  auto context_class = context->vm->RegisterClass("android/content/Context");
  auto activity_class =
      context->vm->RegisterClass("com/roblox/client/RobloxActivity");
  auto lifecycle_callbacks_class = context->vm->RegisterClass(
      "com/roblox/universalapp/activitylifecyclecallbacks/"
      "JNIActivityLifecycleCallbacks");
  auto settings_class = context->vm->RegisterClass("rbx/JNIRobloxSettings");
  settings_class->RegisterMethod(
      "nativeInitClientSettings", "()V", [](JNIEnv* /*env*/, jobject /*obj*/) {
        std::cout << "  [JNI callback] nativeInitClientSettings invoked\n";
      });
  static_cast<void>(context_class);
  static_cast<void>(activity_class);
  static_cast<void>(lifecycle_callbacks_class);
  PublishCurrentJniEnv(context->vm->GetJNIEnv());
  context->result = context->fn(context->vm->GetJavaVM(), nullptr);
  return nullptr;
}

alignas(16) unsigned char g_stage5_fallback_region[kStage5FallbackScratchSize];
alignas(
    16) thread_local unsigned char g_stage6_gl_scratch[kStage6GlScratchSize];
alignas(16) unsigned char g_stage6_gl_global_scratch[kStage6GlScratchSize];
alignas(64) thread_local unsigned char g_stage6_gl_queue_lane_storage
    [kStage6GlQueueLaneStorageSize];
alignas(64) unsigned char g_stage6_gl_global_queue_lane_storage
    [kStage6GlQueueLaneStorageSize];
alignas(64) unsigned char g_stage6_app_bridge_hash_scratch
    [kStage6AppBridgeHashScratchSize];
alignas(64) unsigned char g_stage6_app_bridge_vector_scratch
    [kStage6AppBridgeHashScratchSize];
alignas(64) unsigned char g_stage6_start_app_params_vector_backing_scratch
    [kStage6AppBridgeHashScratchSize];
alignas(64) unsigned char g_stage6_start_app_params_field0_scratch
    [kStage6AppBridgeHashScratchSize];
alignas(64) unsigned char g_stage6_start_app_params_field20_scratch
    [kStage6AppBridgeHashScratchSize];
alignas(64) unsigned char g_stage6_start_app_params_field40_scratch
    [kStage6AppBridgeHashScratchSize];
alignas(64) unsigned char g_stage6_start_app_params_field60_scratch
    [kStage6AppBridgeHashScratchSize];
alignas(16) unsigned char g_stage6_start_app_release_owner_scratch[0x100];
alignas(8) uintptr_t g_stage6_start_app_release_owner_empty_slot;
alignas(16) unsigned char g_stage6_start_app_payload_owner_scratch[0x100];
alignas(16) unsigned char g_stage6_start_app_payload_map_lookup_owner_scratch
    [0x100];
alignas(8) thread_local uintptr_t g_stage6_start_app_payload_link_slot;
alignas(16) unsigned char g_stage6_init_params_holder_scratch[0x80];
alignas(16) unsigned char g_stage6_post_client_settings_singleton_lock_scratch
    [0x100];
alignas(64) unsigned char g_stage6_vector_insert_scratch[0x4000];
alignas(16) unsigned char g_stage6_app_bridge_xml_name_primary_backing[0x20];
alignas(16) unsigned char g_stage6_app_bridge_xml_name_secondary_backing[0x20];
alignas(16) unsigned char g_stage6_app_bridge_xml_name_tertiary_backing[0x20];
alignas(16) unsigned char g_stage6_app_bridge_xml_name_quaternary_backing[0x20];
alignas(16) unsigned char g_stage6_app_bridge_xml_name_quinary_backing[0x20];
alignas(16) unsigned char g_stage6_app_bridge_xml_name_senary_backing[0x20];
alignas(16) unsigned char g_stage6_app_bridge_xml_name_septenary_backing[0x20];
alignas(16) unsigned char g_stage6_gl_global_tls_storage[0x1000];
alignas(
    16) unsigned char g_start_app_manager_scratch[kStartAppManagerScratchSize];
alignas(16) unsigned char g_stage6_start_lua_state_scratch[0x400];
alignas(16) unsigned char g_stage6_start_lua_anchor_scratch[0x80];
alignas(16) unsigned char g_stage6_start_lua_callback_scratch[0x80];
alignas(16) uintptr_t g_stage6_start_lua_callback_bucket_scratch[16];
alignas(16) uintptr_t g_stage6_start_lua_callback_target_vtable[32];
alignas(16) uintptr_t g_stage6_start_lua_callback_target_object[8];
alignas(16) uintptr_t g_stage6_start_lua_target_callback_object_vtable[32];
alignas(16) uintptr_t g_stage6_start_lua_target_callback_object[0x100];
alignas(16) uintptr_t g_stage6_start_lua_fake_event_vtable[8];
alignas(16) uintptr_t g_stage6_start_lua_fake_event_object[8];
alignas(16) uintptr_t g_stage6_start_lua_refcount_vtable[8];
alignas(16) unsigned char g_stage6_start_lua_refcount_scratch[0x80];
alignas(
    16) unsigned char g_stage6_shared_ptr_invalid_addref_control_block[0x40];
alignas(16) unsigned char g_stage6_start_lua_target_table_scratch[0x900];
alignas(16) static uintptr_t g_stage6_start_lua_target_table_vtable_storage[34];
alignas(16) uintptr_t g_stage6_start_lua_returner_target_vtable[8];
alignas(16) unsigned char g_stage6_start_lua_returner_target_object[0x300];
alignas(16) unsigned char g_stage6_start_lua_result20_lookup_node_scratch[0x40];
alignas(16) uintptr_t g_stage6_start_lua_result20_callback_context_scratch[2];
alignas(
    16) unsigned char g_stage6_start_lua_result20_callback_control_block[0x40];
uintptr_t g_stage6_start_lua_result20_callback_split_callback = 0;
uintptr_t g_stage6_start_lua_result20_callback_split_source_pair = 0;
uintptr_t g_stage6_start_lua_result20_callback_split_context = 0;
alignas(16) unsigned char g_stage6_start_lua_synthetic_instance_object[0x300];
alignas(16) uintptr_t g_stage6_start_lua_synthetic_instance_vtable[48];
alignas(
    16) unsigned char g_stage6_start_lua_synthetic_instance_control_block[0x40];
alignas(16) unsigned char g_stage6_start_lua_synthetic_instance_name[24];
alignas(16) unsigned char g_stage6_start_lua_system_dialog_object_scratch[0x80];
alignas(16) unsigned char g_stage6_start_lua_system_dialog_list_scratch[0x80];
alignas(16) unsigned char g_stage6_start_lua_system_dialog_item_scratch[0x40];
alignas(16) uintptr_t
    g_stage6_start_lua_unsupported_message_empty_vector_scratch[3];
uintptr_t g_stage6_start_lua_owner_slot_028 = 0;
uintptr_t g_stage6_start_lua_owner_slot_030 = 0;
uintptr_t g_stage6_start_lua_owner_slot_038 = 0;
uintptr_t g_stage6_last_app_bridge_owner = 0;
uintptr_t g_stage6_last_app_bridge_owner_state = 0;
alignas(64) unsigned char g_stage6_start_game_base_scratch[0xc000];

void SeedStage6FakeIntrusiveRefcount(unsigned char* object, size_t size) {
  if (object == nullptr || size < 0x28) {
    return;
  }
  *reinterpret_cast<uint64_t*>(object + 0x20) = kStage6FakeIntrusiveRefcount;
}
alignas(16) unsigned char g_channel_string_backing[0x20];
alignas(16) unsigned char g_base_url_owner_string_backing[0x20];
alignas(16) unsigned char g_base_url_global_string_backing[0x20];
alignas(16) unsigned char g_stage6_platform_headers_empty_entry[0x60];
alignas(16) unsigned char g_stage6_platform_headers_zero_string[0x20] = {0x02,
                                                                         '0'};
alignas(64) unsigned char g_stage6_platform_headers_vector_scratch
    [kStage6AppBridgeHashScratchSize];
alignas(16) static unsigned char g_stage6_gl_unsupported_message_object[0x20];
alignas(16) void* g_stage6_gl_unsupported_message_slot = nullptr;
alignas(16) unsigned char g_stage6_audio_callback_table_scratch[0x400];
alignas(
    16) static unsigned char g_stage6_start_app_null_allocator_arena[1 << 20];
thread_local size_t g_stage6_start_app_null_allocator_cursor = 0;

void InitialiseStage6GlScratchWithTls(unsigned char* region,
                                      unsigned char* tls_storage,
                                      unsigned char* queue_lane_storage) {
  uintptr_t scratch = reinterpret_cast<uintptr_t>(region);
  uintptr_t state = scratch + 0x1000;
  uintptr_t queue = scratch + 0x1800;
  uintptr_t lanes = reinterpret_cast<uintptr_t>(queue_lane_storage);
  uintptr_t queue_counter = scratch + 0x1a00;
  uintptr_t queue_counter_alt = scratch + 0x1a10;
  uintptr_t queue_limit = scratch + 0x1a20;
  uintptr_t tls = reinterpret_cast<uintptr_t>(tls_storage);
  if (tls != 0) {
    std::memset(tls_storage, 0, 0x1000);
    *reinterpret_cast<uint64_t*>(tls + 0x400) = static_cast<uint64_t>(state);
    *reinterpret_cast<uint64_t*>(tls + 0x408) = static_cast<uint64_t>(queue);
    *reinterpret_cast<uint64_t*>(tls + 0x410) = static_cast<uint64_t>(queue);
    *reinterpret_cast<uint64_t*>(tls + 0x3f0) = 0;
  }
  *reinterpret_cast<uint64_t*>(scratch + 0x70) = static_cast<uint64_t>(state);
  *reinterpret_cast<uint64_t*>(scratch + 0x68) = static_cast<uint64_t>(queue);
  *reinterpret_cast<uint64_t*>(scratch + 0x400) = static_cast<uint64_t>(state);
  *reinterpret_cast<uint64_t*>(scratch + 0x408) = static_cast<uint64_t>(queue);
  *reinterpret_cast<uint64_t*>(scratch + 0x410) = static_cast<uint64_t>(queue);
  *reinterpret_cast<uint64_t*>(scratch + 0x3f0) = 0;
  if (lanes != 0) {
    *reinterpret_cast<uint64_t*>(state + 0x08) = static_cast<uint64_t>(lanes);
    *reinterpret_cast<uint64_t*>(queue + 0x08) = static_cast<uint64_t>(lanes);
    for (size_t i = 0; i < kStage6GlQueueLaneCount; ++i) {
      uintptr_t lane = lanes + i * kStage6GlQueueLaneStride;
      *reinterpret_cast<uint64_t*>(lane + 0x08) = static_cast<uint64_t>(lane);
      *reinterpret_cast<uint64_t*>(lane + 0x10) = static_cast<uint64_t>(lane);
      *reinterpret_cast<uint64_t*>(lane + 0x18) = static_cast<uint64_t>(lane);
      *reinterpret_cast<uint64_t*>(lane + 0x40) = static_cast<uint64_t>(lane);
    }
  }
  *reinterpret_cast<uint64_t*>(queue + 0x60) = 0;
  *reinterpret_cast<uint64_t*>(queue + 0x68) = queue;
  *reinterpret_cast<uint64_t*>(queue + 0x70) = queue;
  *reinterpret_cast<uint64_t*>(queue + 0x58) =
      tls != 0 ? static_cast<uint64_t>(tls) : static_cast<uint64_t>(scratch);
  *reinterpret_cast<uint32_t*>(scratch + 0x20) = 0;
  *reinterpret_cast<uint32_t*>(scratch) = 0;
  *reinterpret_cast<uint64_t*>(state + 0x68) = state;
  *reinterpret_cast<uint64_t*>(state + 0x70) = state;
  *reinterpret_cast<uint64_t*>(state + 0xd260) = queue_counter;
  *reinterpret_cast<uint64_t*>(state + 0xd268) = queue_counter_alt;
  *reinterpret_cast<uint64_t*>(state + 0xd270) = queue_limit;
  *reinterpret_cast<uint32_t*>(queue_counter) = 0;
  *reinterpret_cast<uint32_t*>(queue_counter_alt) = 0;
  *reinterpret_cast<uint32_t*>(queue_limit) = 0;
}

void InitialiseStage6GlScratch(unsigned char* region) {
  unsigned char* lanes = region == g_stage6_gl_global_scratch
                             ? g_stage6_gl_global_queue_lane_storage
                             : g_stage6_gl_queue_lane_storage;
  InitialiseStage6GlScratchWithTls(region, region, lanes);
}

bool HasRealGraphicsContext() {
  return mocktail::window::IsInitialised() &&
         mocktail::window::GetEGLDisplay() != nullptr &&
         mocktail::window::GetEGLSurface() != nullptr &&
         mocktail::window::GetEGLContext() != nullptr;
}

[[noreturn]] void ExitCurrentThreadImmediately() {
  syscall(SYS_exit, 0);
  __builtin_unreachable();
}

bool TryRecoverRepeatedStage6GuardLoop() {
  if (g_stage6_empty_gl_helper_returns <= 128) {
    return false;
  }
  if (g_game_global_init_recovery_in_progress != 0) {
    g_game_global_init_recovery_in_progress = 0;
    const char msg[] =
        "  [patch] recovered nativeGameGlobalInit after repeated Stage6 guard "
        "loop\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_game_global_init_jmp_buf, 1);
  }
  if (IsEnabled("MOCKTAIL_EXIT_EMPTY_GL_HELPER_LOOP") &&
      g_start_lua_app_dm_recovery_in_progress == kStage6RecoveryWorker) {
    g_start_lua_app_dm_recovery_in_progress = kStage6RecoveryInactive;
    const char msg[] =
        "  [patch] exiting worker after repeated Stage6 guard loop in "
        "nativeAppBridgeStartLuaAppDM\n";
    write(2, msg, sizeof(msg) - 1);
    ExitCurrentThreadImmediately();
  }
  if (IsEnabled("MOCKTAIL_EXIT_EMPTY_GL_HELPER_LOOP") &&
      g_update_surface_app_recovery_in_progress == kStage6RecoveryWorker) {
    g_update_surface_app_recovery_in_progress = kStage6RecoveryInactive;
    const char msg[] =
        "  [patch] recovering worker after repeated Stage6 guard loop in "
        "UpdateSurfaceAppWithPlatformParams\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_update_surface_app_jmp_buf, 1);
  }
  if (IsEnabled("MOCKTAIL_EXIT_EMPTY_GL_HELPER_LOOP") &&
      g_start_app_with_params_recovery_in_progress == kStage6RecoveryWorker) {
    g_start_app_with_params_recovery_in_progress = kStage6RecoveryInactive;
    const char msg[] =
        "  [patch] recovering worker after repeated Stage6 guard loop in "
        "nativeAppBridgeV2StartAppWithParams\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_start_app_with_params_jmp_buf, 1);
  }
  if (g_start_lua_app_dm_recovery_in_progress != 0) {
    g_start_lua_app_dm_recovery_in_progress = kStage6RecoveryInactive;
    const char msg[] =
        "  [patch] recovered nativeAppBridgeStartLuaAppDM after repeated "
        "Stage6 guard loop\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_start_lua_app_dm_jmp_buf, 1);
  }
  if (g_update_surface_app_recovery_in_progress != 0) {
    g_update_surface_app_recovery_in_progress = kStage6RecoveryInactive;
    const char msg[] =
        "  [patch] recovered UpdateSurfaceAppWithPlatformParams after repeated "
        "Stage6 guard loop\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_update_surface_app_jmp_buf, 1);
  }
  if (g_update_screen_orientation_recovery_in_progress != 0) {
    g_update_screen_orientation_recovery_in_progress = 0;
    const char msg[] =
        "  [patch] recovered nativeUpdateScreenOrientation after repeated "
        "Stage6 guard loop\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_update_screen_orientation_jmp_buf, 1);
  }
  if (g_start_app_with_params_recovery_in_progress != 0) {
    g_start_app_with_params_recovery_in_progress = kStage6RecoveryInactive;
    const char msg[] =
        "  [patch] recovered nativeAppBridgeV2StartAppWithParams after "
        "repeated Stage6 guard loop\n";
    write(2, msg, sizeof(msg) - 1);
    siglongjmp(g_start_app_with_params_jmp_buf, 1);
  }
  if (IsEnabled("MOCKTAIL_EXIT_EMPTY_GL_HELPER_LOOP")) {
    const char msg[] =
        "  [patch] exiting worker after repeated Stage6 guard loop without "
        "native recovery context\n";
    write(2, msg, sizeof(msg) - 1);
    ExitCurrentThreadImmediately();
  }
  return false;
}

bool TryReturnFromRepeatedStage6StringFieldLoop(ucontext_t* ucontext,
                                                uintptr_t libroblox_base,
                                                uintptr_t libroblox_offset,
                                                uintptr_t value) {
  if (g_stage6_string_field_null_current_loop_count <=
      kStage6StringFieldNullLoopLimit) {
    return false;
  }
  const sig_atomic_t repeats = g_stage6_string_field_null_current_loop_count;
  if (repeats == kStage6StringFieldNullLoopLimit + 1 ||
      repeats % kStage6StringFieldNullLoopLimit == 0) {
    char msg[440];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 string field null current loop: returning from "
        "helper "
        "rip_off=0x%lx repeats=%d value=%p object=%p return_off=0x%lx\n",
        static_cast<unsigned long>(libroblox_offset), static_cast<int>(repeats),
        reinterpret_cast<void*>(value),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
        static_cast<unsigned long>(kStage6StringFieldLoopReturnOffset));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
  }
  ++g_skipped_headless_null_writes;
  ucontext->uc_mcontext.gregs[REG_RIP] =
      static_cast<greg_t>(libroblox_base + kStage6StringFieldLoopReturnOffset);
  return true;
}

bool ShouldLogStage6Repeated(volatile sig_atomic_t* counter) {
  if (counter == nullptr) {
    return true;
  }
  const sig_atomic_t count = ++(*counter);
  return count <= 16 || count % 256 == 0;
}

bool IsLikelyUserPointer(uintptr_t value) {
  return value >= kStage5LowAddressThreshold &&
         value < kMaxCanonicalUserPointer;
}

uintptr_t AllocateStage6StartAppNullAllocatorArena(uintptr_t requested_size,
                                                   bool* arena_wrapped,
                                                   uintptr_t* total_size_out) {
  const uintptr_t payload_size = requested_size == 0 ? 1 : requested_size;
  constexpr uintptr_t kHeaderSize = 8;
  constexpr uintptr_t kAlignment = 16;
  uintptr_t total_size = payload_size + kHeaderSize;
  total_size = (total_size + kAlignment - 1) & ~(kAlignment - 1);
  bool wrapped = false;
  if (total_size > sizeof(g_stage6_start_app_null_allocator_arena)) {
    total_size = sizeof(g_stage6_start_app_null_allocator_arena);
    wrapped = true;
  }
  if (g_stage6_start_app_null_allocator_cursor + total_size >
      sizeof(g_stage6_start_app_null_allocator_arena)) {
    g_stage6_start_app_null_allocator_cursor = 0;
    wrapped = true;
  }
  unsigned char* raw = g_stage6_start_app_null_allocator_arena +
                       g_stage6_start_app_null_allocator_cursor;
  g_stage6_start_app_null_allocator_cursor += total_size;
  std::memset(raw, 0, static_cast<size_t>(total_size));
  const uint32_t native_size =
      payload_size > 0xfffffff0u
          ? 0xfffffff8u
          : static_cast<uint32_t>(payload_size + kHeaderSize);
  *reinterpret_cast<uint32_t*>(raw + 0x00) = native_size;
  *reinterpret_cast<uint32_t*>(raw + 0x04) = 0;
  if (arena_wrapped != nullptr) {
    *arena_wrapped = wrapped;
  }
  if (total_size_out != nullptr) {
    *total_size_out = total_size;
  }
  return reinterpret_cast<uintptr_t>(raw + kHeaderSize);
}

bool IsStage6StartAppNullAllocatorArenaAllocation(uintptr_t allocation) {
  const uintptr_t arena_begin =
      reinterpret_cast<uintptr_t>(g_stage6_start_app_null_allocator_arena);
  const uintptr_t arena_end =
      arena_begin + sizeof(g_stage6_start_app_null_allocator_arena);
  return allocation >= arena_begin + 8 && allocation < arena_end &&
         IsReadableMemoryRange(allocation - 8, 8);
}

bool TryReturnFromStage6StartAppNullAllocatorFree(ucontext_t* ucontext,
                                                  uintptr_t libroblox_offset) {
  if (ucontext == nullptr ||
      libroblox_offset != kStage6StartAppNullCallbackOwnerFreeReadOffset ||
      ucontext->uc_mcontext.gregs[REG_R15] != 0) {
    return false;
  }

  const uintptr_t allocation =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
  if (!IsStage6StartAppNullAllocatorArenaAllocation(allocation)) {
    return false;
  }

  const uintptr_t rbp =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
  if (rbp < 0x1000 || (rbp & 7) != 0 ||
      !IsReadableMemoryRange(rbp - 0x30, 0x40)) {
    return false;
  }

  const auto* frame = reinterpret_cast<const uintptr_t*>(rbp);
  const uintptr_t saved_rbp = frame[0];
  const uintptr_t return_address = frame[1];
  if (!IsLikelyUserPointer(return_address)) {
    return false;
  }

  ucontext->uc_mcontext.gregs[REG_R15] =
      static_cast<greg_t>(*reinterpret_cast<const uintptr_t*>(rbp - 0x08));
  ucontext->uc_mcontext.gregs[REG_R14] =
      static_cast<greg_t>(*reinterpret_cast<const uintptr_t*>(rbp - 0x10));
  ucontext->uc_mcontext.gregs[REG_R13] =
      static_cast<greg_t>(*reinterpret_cast<const uintptr_t*>(rbp - 0x18));
  ucontext->uc_mcontext.gregs[REG_R12] =
      static_cast<greg_t>(*reinterpret_cast<const uintptr_t*>(rbp - 0x20));
  ucontext->uc_mcontext.gregs[REG_RBX] =
      static_cast<greg_t>(*reinterpret_cast<const uintptr_t*>(rbp - 0x28));
  ucontext->uc_mcontext.gregs[REG_RBP] = static_cast<greg_t>(saved_rbp);
  ucontext->uc_mcontext.gregs[REG_RSP] = static_cast<greg_t>(rbp + 0x10);
  ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(return_address);
  ucontext->uc_mcontext.gregs[REG_RAX] = 0;

  if (ShouldLogStage6Repeated(
          &g_stage6_start_app_null_callback_owner_free_logs)) {
    char msg[360];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartApp null allocator owner: skipped arena free "
        "rip_off=0x%lx allocation=%p return=%p\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(allocation),
        reinterpret_cast<void*>(return_address));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
  }
  ++g_skipped_headless_null_writes;
  return true;
}

bool TryHandleStage6StartAppZeroStrideDivisor(int signo,
                                              uintptr_t libroblox_base,
                                              uintptr_t libroblox_offset,
                                              ucontext_t* ucontext,
                                              const unsigned char* instruction,
                                              bool instruction_readable) {
  if (signo != SIGFPE || ucontext == nullptr || libroblox_base == 0 ||
      !instruction_readable ||
      libroblox_offset != kStage6StartAppZeroStrideDivisorOffset ||
      instruction[0] != 0xf7 || instruction[1] != 0xb3 ||
      instruction[2] != 0xd8 || instruction[3] != 0x06 ||
      instruction[4] != 0x00 || instruction[5] != 0x00) {
    return false;
  }

  const uintptr_t object =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
  const uintptr_t divisor_slot = object + 0x6d8;
  const uintptr_t total_slot = object + 0x6dc;
  if (object < kStage5LowAddressThreshold ||
      !IsReadableMemoryRange(divisor_slot, sizeof(uint32_t)) ||
      !IsReadableMemoryRange(total_slot, sizeof(uint32_t)) ||
      !EnsureWritablePage(reinterpret_cast<void*>(divisor_slot))) {
    return false;
  }

  const uint32_t old_divisor = ReadU32IfReadable(divisor_slot);
  const uint32_t old_total = ReadU32IfReadable(total_slot);
  if (old_divisor != 0) {
    return false;
  }

  *reinterpret_cast<uint32_t*>(divisor_slot) = 1;
  ucontext->uc_mcontext.gregs[REG_RAX] = 0;
  ucontext->uc_mcontext.gregs[REG_RDX] = 0;
  if (ShouldLogStage6Repeated(&g_stage6_start_app_zero_stride_divisor_logs)) {
    char msg[420];
    int len =
        snprintf(msg, sizeof(msg),
                 "  [patch] Stage6 StartApp zero stride divisor: seeded "
                 "divisor=1 rip_off=0x%lx object=%p old_total=0x%x "
                 "result_out=%p\n",
                 static_cast<unsigned long>(libroblox_offset),
                 reinterpret_cast<void*>(object), old_total,
                 reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R14]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
  }
  ++g_skipped_headless_null_writes;
  return true;
}

bool TryHandleStage6StartAppNullStateObjectRead(
    int signo, siginfo_t* info, uintptr_t libroblox_base,
    uintptr_t libroblox_offset, ucontext_t* ucontext,
    const unsigned char* instruction, bool instruction_readable) {
  if (signo != SIGSEGV || info == nullptr || ucontext == nullptr ||
      libroblox_base == 0 || !instruction_readable ||
      libroblox_offset != kStage6StartAppNullStateObjectReadOffset ||
      instruction[0] != 0x48 || instruction[1] != 0x83 ||
      instruction[2] != 0xb8 || instruction[3] != 0x00 ||
      instruction[4] != 0x04 || instruction[5] != 0x00 ||
      instruction[6] != 0x00 ||
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]) != 0 ||
      reinterpret_cast<uintptr_t>(info->si_addr) != 0x400) {
    return false;
  }

  const uintptr_t object =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
  if (ShouldLogStage6Repeated(&g_stage6_start_app_null_state_object_logs)) {
    char msg[420];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartApp null state object: skipping optional "
        "state update rip_off=0x%lx object=%p state_slot=%p skip_off=0x%lx\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(object),
        reinterpret_cast<void*>(ReadPointerIfReadable(object + 0x670)),
        static_cast<unsigned long>(kStage6StartAppNullStateObjectSkipOffset));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
  }
  ++g_skipped_headless_null_writes;
  ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
      libroblox_base + kStage6StartAppNullStateObjectSkipOffset);
  return true;
}

bool TryHandleStage6StartLuaObserverListInvalidCursor(
    int signo, siginfo_t* info, uintptr_t libroblox_base,
    uintptr_t libroblox_offset, ucontext_t* ucontext,
    const unsigned char* instruction, bool instruction_readable) {
  if (signo != SIGSEGV || info == nullptr || ucontext == nullptr ||
      libroblox_base == 0 || !instruction_readable ||
      libroblox_offset != kStage6StartLuaObserverListCursorReadOffset ||
      instruction[0] != 0x48 || instruction[1] != 0x8b ||
      instruction[2] != 0x8f || instruction[3] != 0x78 ||
      instruction[4] != 0x01 || instruction[5] != 0x00 ||
      instruction[6] != 0x00) {
    return false;
  }

  const uintptr_t cursor =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
  const uintptr_t fault = reinterpret_cast<uintptr_t>(info->si_addr);
  bool invalid_cursor =
      cursor < kStage5LowAddressThreshold || cursor >= kMaxCanonicalUserPointer;
  if (!invalid_cursor) {
    invalid_cursor = !IsReadableMemoryRange(cursor + 0x178, sizeof(uintptr_t));
  }
  const bool invalid_fault =
      fault < kStage5LowAddressThreshold || fault >= kMaxCanonicalUserPointer;
  if (!invalid_cursor && !invalid_fault) {
    return false;
  }

  if (ShouldLogStage6Repeated(&g_stage6_start_lua_observer_list_logs)) {
    char msg[520];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] Stage6 StartLua observer list invalid cursor: "
        "returning empty rip_off=0x%lx cursor=%p fault=%p sentinel=%p "
        "target=%p done_off=0x%lx\n",
        static_cast<unsigned long>(libroblox_offset),
        reinterpret_cast<void*>(cursor), reinterpret_cast<void*>(fault),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R14]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX]),
        static_cast<unsigned long>(kStage6StartLuaObserverListDoneOffset));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
  }
  ++g_skipped_headless_null_writes;
  ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(
      libroblox_base + kStage6StartLuaObserverListDoneOffset);
  return true;
}

bool TryReturnFromStage6ErroneousFunctionPointerCall(int signo, siginfo_t* info,
                                                     ucontext_t* ucontext) {
  if (signo != SIGSEGV || info == nullptr || ucontext == nullptr ||
      g_current_stage < 6 || g_libroblox_base == 0 ||
      (g_start_app_with_params_recovery_in_progress == 0 &&
       g_start_lua_app_dm_recovery_in_progress == 0)) {
    return false;
  }

  const uintptr_t fault_rip =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RIP]);
  const uintptr_t fault_address = reinterpret_cast<uintptr_t>(info->si_addr);
  if (fault_address != fault_rip ||
      (info->si_code != SEGV_ACCERR && info->si_code != SEGV_MAPERR)) {
    return false;
  }

  const uintptr_t rsp =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
  if (!IsLikelyUserPointer(rsp)) {
    return false;
  }

  const uintptr_t return_address = *reinterpret_cast<const uintptr_t*>(rsp);
  const uintptr_t libroblox_base = static_cast<uintptr_t>(g_libroblox_base);
  if (return_address < libroblox_base ||
      return_address >= libroblox_base + 0x08000000) {
    return false;
  }

  const uintptr_t return_offset = return_address - libroblox_base;
  const uintptr_t fault_offset =
      (fault_rip >= libroblox_base && fault_rip < libroblox_base + 0x08000000)
          ? fault_rip - libroblox_base
          : 0;
  if (ShouldLogStage6Repeated(&g_stage6_erroneous_function_pointer_call_logs)) {
    char msg[520];
    int len =
        snprintf(msg, sizeof(msg),
                 "  [patch] skipped erroneous Stage6 function-pointer call "
                 "rip=%p off=0x%lx return_off=0x%lx scope=%s si_code=%d\n",
                 reinterpret_cast<void*>(fault_rip),
                 static_cast<unsigned long>(fault_offset),
                 static_cast<unsigned long>(return_offset),
                 g_start_app_with_params_recovery_in_progress != 0 ? "StartApp"
                                                                   : "StartLua",
                 info->si_code);
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
  }
  ++g_skipped_headless_null_writes;
  ucontext->uc_mcontext.gregs[REG_RAX] = 0;
  ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(return_address);
  ucontext->uc_mcontext.gregs[REG_RSP] =
      static_cast<greg_t>(rsp + sizeof(uintptr_t));
  return true;
}

bool TryReturnFromStage6UpdateSurfaceNonCodeCallback(int signo, siginfo_t* info,
                                                     ucontext_t* ucontext) {
  if (signo != SIGSEGV || info == nullptr || ucontext == nullptr ||
      g_current_stage < 6 || g_libroblox_base == 0 ||
      g_update_surface_app_recovery_in_progress == 0) {
    return false;
  }

  const uintptr_t fault_rip =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RIP]);
  if (reinterpret_cast<uintptr_t>(info->si_addr) != fault_rip) {
    return false;
  }

  const uintptr_t libroblox_base = static_cast<uintptr_t>(g_libroblox_base);
  const bool rip_is_libroblox_text =
      fault_rip >= libroblox_base + kLibrobloxTextStartOffset &&
      fault_rip < libroblox_base + kLibrobloxExecutableSegmentEndOffset;
  if (rip_is_libroblox_text) {
    return false;
  }

  const uintptr_t rsp =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
  if (!IsReadableMemoryRange(rsp, sizeof(uintptr_t) * 2)) {
    return false;
  }

  const uintptr_t stack0 = ReadPointerIfReadable(rsp);
  const uintptr_t stack1 = ReadPointerIfReadable(rsp + sizeof(uintptr_t));
  uintptr_t return_address = 0;
  size_t stack_words = 0;
  if (stack0 >= libroblox_base + kLibrobloxTextStartOffset &&
      stack0 < libroblox_base + kLibrobloxExecutableSegmentEndOffset) {
    return_address = stack0;
    stack_words = 1;
  } else if (stack1 >= libroblox_base + kLibrobloxTextStartOffset &&
             stack1 < libroblox_base + kLibrobloxExecutableSegmentEndOffset) {
    return_address = stack1;
    stack_words = 2;
  }
  if (return_address == 0) {
    return false;
  }

  if (ShouldLogStage6Repeated(&g_stage6_erroneous_function_pointer_call_logs)) {
    char msg[620];
    int len = snprintf(
        msg, sizeof(msg),
        "  [patch] skipped Stage6 UpdateSurface non-code callback target "
        "target=%p return_off=0x%lx stack_words=%zu rax=%p rdi=%p\n",
        reinterpret_cast<void*>(fault_rip),
        static_cast<unsigned long>(return_address - libroblox_base),
        stack_words,
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX]),
        reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]));
    if (len > 0) {
      write(2, msg, static_cast<size_t>(len));
    }
  }
  ++g_skipped_headless_null_writes;
  ucontext->uc_mcontext.gregs[REG_RAX] = 0;
  ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(return_address);
  ucontext->uc_mcontext.gregs[REG_RSP] =
      static_cast<greg_t>(rsp + sizeof(uintptr_t) * stack_words);
  return true;
}

void LogStage6RecoverySignal(const char* label, ucontext_t* ucontext,
                             siginfo_t* info, int signo,
                             uintptr_t libroblox_offset) {
  uintptr_t stack0 = 0;
  uintptr_t stack1 = 0;
  uintptr_t stack2 = 0;
  uintptr_t stack3 = 0;
  uintptr_t stack4 = 0;
  uintptr_t stack5 = 0;
  uintptr_t stack0_off = 0;
  uintptr_t stack1_off = 0;
  uintptr_t stack2_off = 0;
  uintptr_t stack3_off = 0;
  uintptr_t stack4_off = 0;
  uintptr_t stack5_off = 0;
  uintptr_t frame0_ret = 0;
  uintptr_t frame1_ret = 0;
  uintptr_t frame2_ret = 0;
  uintptr_t frame0_ret_off = 0;
  uintptr_t frame1_ret_off = 0;
  uintptr_t frame2_ret_off = 0;
  if (ucontext != nullptr) {
    uintptr_t base = static_cast<uintptr_t>(g_mocktail_abort_libroblox_base);
    auto* stack =
        reinterpret_cast<uintptr_t*>(ucontext->uc_mcontext.gregs[REG_RSP]);
    if (IsReadableMemoryRange(reinterpret_cast<uintptr_t>(stack),
                              sizeof(uintptr_t) * 6)) {
      stack0 = stack[0];
      stack1 = stack[1];
      stack2 = stack[2];
      stack3 = stack[3];
      stack4 = stack[4];
      stack5 = stack[5];
      if (base != 0 && stack0 >= base) {
        stack0_off = stack0 - base;
      }
      if (base != 0 && stack1 >= base) {
        stack1_off = stack1 - base;
      }
      if (base != 0 && stack2 >= base) {
        stack2_off = stack2 - base;
      }
      if (base != 0 && stack3 >= base) {
        stack3_off = stack3 - base;
      }
      if (base != 0 && stack4 >= base) {
        stack4_off = stack4 - base;
      }
      if (base != 0 && stack5 >= base) {
        stack5_off = stack5 - base;
      }
    }

    uintptr_t frame =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    uintptr_t previous_frame = 0;
    for (int frame_index = 0; frame_index < 3; ++frame_index) {
      if (frame < 0x1000 || (frame & 7) != 0 || frame <= previous_frame ||
          !IsReadableMemoryRange(frame, sizeof(uintptr_t) * 2)) {
        break;
      }
      const uintptr_t next_frame = ReadPointerIfReadable(frame);
      const uintptr_t return_address =
          ReadPointerIfReadable(frame + sizeof(uintptr_t));
      uintptr_t return_offset = 0;
      if (base != 0 && return_address >= base) {
        return_offset = return_address - base;
      }
      if (frame_index == 0) {
        frame0_ret = return_address;
        frame0_ret_off = return_offset;
      } else if (frame_index == 1) {
        frame1_ret = return_address;
        frame1_ret_off = return_offset;
      } else {
        frame2_ret = return_address;
        frame2_ret_off = return_offset;
      }
      previous_frame = frame;
      frame = next_frame;
    }
  }
  char dbg[1450];
  int n = snprintf(
      dbg, sizeof(dbg),
      "  [patch] SIG in %s: RIP=%p off=0x%lx si_addr=%p signo=%d "
      "rsp=%p rbp=%p rax=%p rbx=%p rcx=%p rdx=%p rsi=%p rdi=%p "
      "r8=%p r9=%p r10=%p r11=%p r12=%p r13=%p r14=%p r15=%p "
      "stack0=%p/off=0x%lx stack1=%p/off=0x%lx "
      "stack2=%p/off=0x%lx stack3=%p/off=0x%lx "
      "stack4=%p/off=0x%lx stack5=%p/off=0x%lx "
      "frame0_ret=%p/off=0x%lx frame1_ret=%p/off=0x%lx "
      "frame2_ret=%p/off=0x%lx\n",
      label,
      ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RIP])
               : nullptr,
      static_cast<unsigned long>(libroblox_offset),
      info ? info->si_addr : nullptr, signo,
      ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSP])
               : nullptr,
      ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBP])
               : nullptr,
      ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RAX])
               : nullptr,
      ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RBX])
               : nullptr,
      ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RCX])
               : nullptr,
      ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDX])
               : nullptr,
      ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RSI])
               : nullptr,
      ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI])
               : nullptr,
      ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R8])
               : nullptr,
      ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R9])
               : nullptr,
      ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R10])
               : nullptr,
      ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R11])
               : nullptr,
      ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R12])
               : nullptr,
      ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R13])
               : nullptr,
      ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R14])
               : nullptr,
      ucontext ? reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_R15])
               : nullptr,
      reinterpret_cast<void*>(stack0), static_cast<unsigned long>(stack0_off),
      reinterpret_cast<void*>(stack1), static_cast<unsigned long>(stack1_off),
      reinterpret_cast<void*>(stack2), static_cast<unsigned long>(stack2_off),
      reinterpret_cast<void*>(stack3), static_cast<unsigned long>(stack3_off),
      reinterpret_cast<void*>(stack4), static_cast<unsigned long>(stack4_off),
      reinterpret_cast<void*>(stack5), static_cast<unsigned long>(stack5_off),
      reinterpret_cast<void*>(frame0_ret),
      static_cast<unsigned long>(frame0_ret_off),
      reinterpret_cast<void*>(frame1_ret),
      static_cast<unsigned long>(frame1_ret_off),
      reinterpret_cast<void*>(frame2_ret),
      static_cast<unsigned long>(frame2_ret_off));
  if (n > 0) {
    write(2, dbg, static_cast<size_t>(n));
  }
  if (ucontext != nullptr &&
      libroblox_offset == kStage6StoullNoConversionThrowOffset &&
      stack3_off == kStage6StoullNoConversionCallReturnOffset) {
    const uintptr_t saved_stoull_input = stack1;
    const uintptr_t stoull_frame = stack2;
    const uintptr_t caller_return =
        ReadPointerIfReadable(stoull_frame + sizeof(uintptr_t));
    uintptr_t caller_return_off = 0;
    uintptr_t base = static_cast<uintptr_t>(g_mocktail_abort_libroblox_base);
    if (base != 0 && caller_return >= base) {
      caller_return_off = caller_return - base;
    }
    char saved_stoull_preview[72];
    size_t preview_len = 0;
    while (preview_len + 1 < sizeof(saved_stoull_preview) &&
           IsReadableMemoryRange(saved_stoull_input + preview_len, 1)) {
      const unsigned char ch = *reinterpret_cast<const unsigned char*>(
          saved_stoull_input + preview_len);
      if (ch == '\0') {
        break;
      }
      saved_stoull_preview[preview_len++] =
          (ch >= 0x20 && ch <= 0x7e) ? static_cast<char>(ch) : '.';
    }
    saved_stoull_preview[preview_len] = '\0';
    char stoull_dbg[560];
    int stoull_n =
        snprintf(stoull_dbg, sizeof(stoull_dbg),
                 "  [patch] Stage6 stoull no-conversion detail "
                 "saved_stoull_input=%p saved_stoull_preview=\"%s\" "
                 "stoull_frame=%p caller_return=%p/off=0x%lx\n",
                 reinterpret_cast<void*>(saved_stoull_input),
                 saved_stoull_preview, reinterpret_cast<void*>(stoull_frame),
                 reinterpret_cast<void*>(caller_return),
                 static_cast<unsigned long>(caller_return_off));
    if (stoull_n > 0) {
      write(2, stoull_dbg, static_cast<size_t>(stoull_n));
    }
  }
  if (ucontext != nullptr &&
      (stack0_off == 0x2c18f12 || stack0_off == 0x2c18f1e)) {
    uintptr_t key_address =
        static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    uintptr_t base = static_cast<uintptr_t>(g_mocktail_abort_libroblox_base);
    bool key_is_static_libroblox_data =
        base != 0 && key_address >= base &&
        key_address + sizeof(uint64_t) * 4 >= key_address &&
        key_address + sizeof(uint64_t) * 4 <= base + 0x9000000;
    if (key_is_static_libroblox_data ||
        IsReadableMemoryRange(key_address, sizeof(uint64_t) * 4)) {
      const auto* key = reinterpret_cast<const uint64_t*>(key_address);
      char key_dbg[360];
      int key_n = snprintf(
          key_dbg, sizeof(key_dbg),
          "  [patch] emutls initializer fault key=%p "
          "size=0x%llx align=0x%llx index=0x%llx init=0x%llx "
          "value=%p bytes=0x%llx\n",
          reinterpret_cast<void*>(key_address),
          static_cast<unsigned long long>(key[0]),
          static_cast<unsigned long long>(key[1]),
          static_cast<unsigned long long>(key[2]),
          static_cast<unsigned long long>(key[3]),
          reinterpret_cast<void*>(ucontext->uc_mcontext.gregs[REG_RDI]),
          static_cast<unsigned long long>(
              ucontext->uc_mcontext.gregs[REG_RDX]));
      if (key_n > 0) {
        write(2, key_dbg, static_cast<size_t>(key_n));
      }
    }
  }
}

bool TryReturnFromStage6ActivityLifecycleNullObserver(
    ucontext_t* ucontext, uintptr_t libroblox_offset) {
  constexpr uintptr_t kActivityLifecycleObserverNullReadOffset = 0x2319499;
  constexpr uintptr_t kActivityLifecycleObserverNullReadOffset2 = 0x231a123;
  if (IsDisabled("MOCKTAIL_SKIP_EMPTY_ACTIVITY_LIFECYCLE_CALLBACKS") ||
      ucontext == nullptr ||
      (libroblox_offset != kActivityLifecycleObserverNullReadOffset &&
       libroblox_offset != kActivityLifecycleObserverNullReadOffset2) ||
      ucontext->uc_mcontext.gregs[REG_RAX] != 0) {
    return false;
  }

  const uintptr_t rbp =
      static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
  if (rbp < 64 || !IsReadableMemoryRange(rbp - 40, 64)) {
    return false;
  }

  auto* frame = reinterpret_cast<uintptr_t*>(rbp);
  ucontext->uc_mcontext.gregs[REG_RBX] =
      static_cast<greg_t>(*reinterpret_cast<uintptr_t*>(rbp - 40));
  ucontext->uc_mcontext.gregs[REG_R12] =
      static_cast<greg_t>(*reinterpret_cast<uintptr_t*>(rbp - 32));
  ucontext->uc_mcontext.gregs[REG_R13] =
      static_cast<greg_t>(*reinterpret_cast<uintptr_t*>(rbp - 24));
  ucontext->uc_mcontext.gregs[REG_R14] =
      static_cast<greg_t>(*reinterpret_cast<uintptr_t*>(rbp - 16));
  ucontext->uc_mcontext.gregs[REG_R15] =
      static_cast<greg_t>(*reinterpret_cast<uintptr_t*>(rbp - 8));
  ucontext->uc_mcontext.gregs[REG_RBP] = static_cast<greg_t>(frame[0]);
  ucontext->uc_mcontext.gregs[REG_RSP] = static_cast<greg_t>(rbp + 16);
  ucontext->uc_mcontext.gregs[REG_RIP] = static_cast<greg_t>(frame[1]);
  ucontext->uc_mcontext.gregs[REG_RAX] = 0;

  const char msg[] =
      "  [patch] skipped empty activity lifecycle observer dispatch\n";
  write(2, msg, sizeof(msg) - 1);
  return true;
}

void DumpThreadPcSignalHandler(int signo, siginfo_t* info, void* context) {
#if defined(__x86_64__)
  auto* ucontext = reinterpret_cast<ucontext_t*>(context);
  uintptr_t rip = 0;
  uintptr_t rsp = 0;
  uintptr_t rbp = 0;
  uintptr_t rax = 0;
  uintptr_t rbx = 0;
  uintptr_t rcx = 0;
  uintptr_t rdx = 0;
  uintptr_t rsi = 0;
  uintptr_t rdi = 0;
  if (ucontext != nullptr) {
    rip = static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RIP]);
    rsp = static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSP]);
    rbp = static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBP]);
    rax = static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RAX]);
    rbx = static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RBX]);
    rcx = static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RCX]);
    rdx = static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDX]);
    rsi = static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RSI]);
    rdi = static_cast<uintptr_t>(ucontext->uc_mcontext.gregs[REG_RDI]);
  }
  uintptr_t base = static_cast<uintptr_t>(g_mocktail_abort_libroblox_base);
  uintptr_t off = (base != 0 && rip >= base) ? rip - base : 0;
  char msg[560];
  int n =
      snprintf(msg, sizeof(msg),
               "  [diag] thread PC dump signal=%d si_addr=%p rip=%p off=0x%lx "
               "rsp=%p rbp=%p rax=%p rbx=%p rcx=%p rdx=%p rsi=%p rdi=%p\n",
               signo, info != nullptr ? info->si_addr : nullptr,
               reinterpret_cast<void*>(rip), static_cast<unsigned long>(off),
               reinterpret_cast<void*>(rsp), reinterpret_cast<void*>(rbp),
               reinterpret_cast<void*>(rax), reinterpret_cast<void*>(rbx),
               reinterpret_cast<void*>(rcx), reinterpret_cast<void*>(rdx),
               reinterpret_cast<void*>(rsi), reinterpret_cast<void*>(rdi));
  if (n > 0) {
    write(2, msg, static_cast<size_t>(n));
  }
#else
  (void)signo;
  (void)info;
  (void)context;
#endif
}

void ResetStartAppManagerScratch() {
  for (size_t i = 0; i < kStartAppManagerScratchSize; ++i) {
    g_start_app_manager_scratch[i] = 0;
  }
}

void SeedStage6GlUnsupportedMessageSlot() {
  if (g_stage6_gl_unsupported_message_slot != nullptr) {
    return;
  }
  std::memset(g_stage6_gl_unsupported_message_object, 0,
              sizeof(g_stage6_gl_unsupported_message_object));
  g_stage6_gl_unsupported_message_object[0x19] = 1;
  g_stage6_gl_unsupported_message_slot = g_stage6_gl_unsupported_message_object;
}

void AbortStage6StaticInitGuard(uintptr_t guard_offset, const char* guard_name,
                                const char* reason) {
  if (g_libroblox_base == 0) {
    return;
  }
  auto* guard =
      reinterpret_cast<unsigned char*>(g_libroblox_base + guard_offset);
  if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(guard), 8)) {
    return;
  }
  const unsigned char before0 = guard[0];
  const unsigned char before1 = guard[1];
  uint32_t before_owner = 0;
  std::memcpy(&before_owner, guard + 4, sizeof(before_owner));
  if (before0 != 0 || (before1 & 0x6) == 0) {
    return;
  }

  auto* guard_mutex = reinterpret_cast<pthread_mutex_t*>(
      g_libroblox_base + kStage6LibcxxGuardMutexOffset);
  auto* guard_cond = reinterpret_cast<pthread_cond_t*>(
      g_libroblox_base + kStage6LibcxxGuardCondOffset);
  const int lock_result = mocktail_pthread_mutex_trylock(guard_mutex);
  std::memset(guard + 1, 0, 7);
  if (lock_result == 0) {
    mocktail_pthread_mutex_unlock(guard_mutex);
  }
  mocktail_pthread_cond_broadcast(guard_cond);

  char msg[360];
  int len = snprintf(msg, sizeof(msg),
                     "  [patch] Stage6 static guard aborted after %s name=%s "
                     "off=0x%lx guard=%p before={%u,%u owner=%u} lock_rc=%d\n",
                     reason ? reason : "recovery",
                     guard_name ? guard_name : "(unknown)",
                     static_cast<unsigned long>(guard_offset),
                     static_cast<void*>(guard), static_cast<unsigned>(before0),
                     static_cast<unsigned>(before1), before_owner, lock_result);
  if (len > 0) {
    write(2, msg, static_cast<size_t>(len));
  }
}

void AbortStage6InitWithParamsStaticGuards(const char* reason) {
  AbortStage6StaticInitGuard(kStage6InitWithParamsStaticGuardOffset,
                             "init-with-params singleton", reason);
  AbortStage6StaticInitGuard(kStage6InitWithParamsSecondaryStaticGuardOffset,
                             "init-with-params secondary", reason);
}

void* ResolveRobloxTaggedPointer(uintptr_t handle, uintptr_t libroblox_base) {
  if (libroblox_base == 0) {
    return nullptr;
  }
  if ((handle >> 32) != 0 && IsLikelyUserPointer(handle)) {
    return reinterpret_cast<void*>(handle);
  }
  const uint32_t low_handle = static_cast<uint32_t>(handle);
  const uint32_t segment_page = low_handle >> 29;
  const uint32_t slot_offset = (low_handle >> 13) & 0xfff8u;
  const uint32_t slot_index = slot_offset / 8u;
  auto*** segment_table_ptr =
      reinterpret_cast<void***>(libroblox_base + 0x75a2a40);
  if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(segment_table_ptr),
                             sizeof(void**))) {
    return nullptr;
  }
  void** segment_table = *segment_table_ptr;
  if (!IsReadableMemoryRange(
          reinterpret_cast<uintptr_t>(segment_table + segment_page),
          sizeof(void*))) {
    return nullptr;
  }
  auto** segment = reinterpret_cast<void**>(segment_table[segment_page]);
  if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(segment + slot_index),
                             sizeof(void*))) {
    return nullptr;
  }
  auto* entry = reinterpret_cast<unsigned char*>(segment[slot_index]);
  if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(entry) + 0x28,
                             sizeof(void*))) {
    return nullptr;
  }
  return *reinterpret_cast<void**>(entry + 0x28);
}

void* ResolveRobloxTaggedEntry(uintptr_t handle, uintptr_t libroblox_base) {
  if (libroblox_base == 0) {
    return nullptr;
  }
  const uint32_t low_handle = static_cast<uint32_t>(handle);
  const uint32_t segment_page = low_handle >> 29;
  const uint32_t slot_offset = (low_handle >> 13) & 0xfff8u;
  const uint32_t slot_index = slot_offset / 8u;
  auto*** segment_table_ptr =
      reinterpret_cast<void***>(libroblox_base + 0x75a2a40);
  if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(segment_table_ptr),
                             sizeof(void**))) {
    return nullptr;
  }
  void** segment_table = *segment_table_ptr;
  if (!IsReadableMemoryRange(
          reinterpret_cast<uintptr_t>(segment_table + segment_page),
          sizeof(void*))) {
    return nullptr;
  }
  auto** segment = reinterpret_cast<void**>(segment_table[segment_page]);
  if (!IsReadableMemoryRange(reinterpret_cast<uintptr_t>(segment + slot_index),
                             sizeof(void*))) {
    return nullptr;
  }
  return segment[slot_index];
}

struct ThreadScratch {
  pid_t tid;
  alignas(16) unsigned char buffer[16384];
};

constexpr int kMaxScratchThreads = 64;
static ThreadScratch g_thread_scratch_pool[kMaxScratchThreads];
static volatile sig_atomic_t g_thread_scratch_count = 0;

void* GetThreadScratchBuffer(pid_t tid) {
  for (int i = 0; i < g_thread_scratch_count; ++i) {
    if (g_thread_scratch_pool[i].tid == tid) {
      return g_thread_scratch_pool[i].buffer;
    }
  }
  int idx = __sync_fetch_and_add(&g_thread_scratch_count, 1);
  if (idx < kMaxScratchThreads) {
    g_thread_scratch_pool[idx].tid = tid;
    std::memset(g_thread_scratch_pool[idx].buffer, 0,
                sizeof(g_thread_scratch_pool[idx].buffer));
    return g_thread_scratch_pool[idx].buffer;
  }
  return g_thread_scratch_pool[0].buffer;
}

// Covers every libroblox vtable offset observed through slot 31 (+0xf8).
uintptr_t NullVtableStub() { return 0; }
const uintptr_t kFallbackVtable[32] = {
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
    reinterpret_cast<uintptr_t>(&NullVtableStub),
};
// Lets a recovered `mov rax,[rsi]` continue through the fallback vtable.
const uintptr_t kFallbackObject[4] = {
    reinterpret_cast<uintptr_t>(kFallbackVtable),
    0,
    0,
    0,
};

extern "C" void* mocktail_stage6_start_lua_return_self_1a0(void* self);
extern "C" void* mocktail_stage6_start_lua_return_size_40000(void* self);

void SeedStage6StartLuaTargetTableScratchVtable() {
  std::memset(g_stage6_start_lua_target_table_vtable_storage, 0,
              sizeof(g_stage6_start_lua_target_table_vtable_storage));
  g_stage6_start_lua_target_table_vtable_storage[0] = 0;
  g_stage6_start_lua_target_table_vtable_storage[1] = 0;
  std::memcpy(g_stage6_start_lua_target_table_vtable_storage + 2,
              kFallbackVtable, sizeof(kFallbackVtable));
  uintptr_t slot6_returner =
      reinterpret_cast<uintptr_t>(&mocktail_stage6_start_lua_return_self_1a0);
  const char* slot6_source =
      std::getenv("MOCKTAIL_STAGE6_START_LUA_TARGET_TABLE_SLOT6_SOURCE");
  if (slot6_source != nullptr && std::strcmp(slot6_source, "size_40000") == 0) {
    slot6_returner = reinterpret_cast<uintptr_t>(
        &mocktail_stage6_start_lua_return_size_40000);
  }
  g_stage6_start_lua_target_table_vtable_storage[2 + 6] = slot6_returner;
  *reinterpret_cast<uintptr_t*>(g_stage6_start_lua_target_table_scratch) =
      reinterpret_cast<uintptr_t>(
          g_stage6_start_lua_target_table_vtable_storage + 2);
}

}  // namespace mocktail::legacy::internal
