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

namespace mocktail::legacy::internal {

NativeNoArgFn g_native_call_messages_from_main_thread = nullptr;
NativeNoArgFn g_pending_main_thread_start_lua_app_dm = nullptr;
jclass g_native_gl_class_for_main_thread = nullptr;
jnivm::VM* g_vm_for_main_thread_pump = nullptr;
std::atomic<int> g_main_thread_message_pump_ready{0};
uint64_t g_pending_main_thread_start_lua_due_ms = 0;
bool g_pending_main_thread_start_lua_started = false;
NativeSetTaskSchedulerBackgroundModeFn
    g_pending_main_thread_task_scheduler_background_mode = nullptr;
jclass g_pending_main_thread_task_scheduler_class = nullptr;
std::atomic<int> g_pending_main_thread_task_scheduler_state{0};
std::atomic<int> g_pending_main_thread_task_scheduler_recovered{0};
constexpr int kMainThreadTaskSchedulerIdle = 0;
constexpr int kMainThreadTaskSchedulerPending = 1;
constexpr int kMainThreadTaskSchedulerRunning = 2;
constexpr int kMainThreadTaskSchedulerComplete = 3;
constexpr int kMainThreadTaskSchedulerTimedOut = 4;

uint64_t MonotonicMillis() {
  timespec ts{};
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return static_cast<uint64_t>(ts.tv_sec) * 1000ULL +
         static_cast<uint64_t>(ts.tv_nsec) / 1000000ULL;
}

uint64_t MonotonicNanos() {
  timespec ts{};
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
    return 0;
  }
  return static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL +
         static_cast<uint64_t>(ts.tv_nsec);
}

JNIEnv* AttachMainThreadJniEnv() {
  if (g_vm_for_main_thread_pump == nullptr) {
    return nullptr;
  }
  JNIEnv* env = nullptr;
  JavaVM* java_vm = g_vm_for_main_thread_pump->GetJavaVM();
  if (java_vm != nullptr) {
    void* raw_env = nullptr;
    jint attach_result = java_vm->AttachCurrentThread(&raw_env, nullptr);
    if (attach_result == JNI_OK && raw_env != nullptr) {
      env = static_cast<JNIEnv*>(raw_env);
    } else if (IsEnabled("MOCKTAIL_TRACE_MAIN_THREAD_PUMP")) {
      std::cerr << "  [main] AttachCurrentThread failed in pump: "
                << attach_result << '\n'
                << std::flush;
    }
  }
  if (env == nullptr) {
    env = g_vm_for_main_thread_pump->GetJNIEnv();
  }
  g_vm_for_main_thread_pump->RestoreFunctions();
  PublishCurrentJniEnv(env);
  return env;
}

bool InvokeTaskSchedulerForeground(
    JNIEnv* env, jclass native_gl_class,
    NativeSetTaskSchedulerBackgroundModeFn
        native_set_task_scheduler_background_mode,
    const char* log_scope) {
  if (env == nullptr || native_gl_class == nullptr ||
      native_set_task_scheduler_background_mode == nullptr) {
    std::cerr << "  [" << log_scope
              << "] NativeGLInterface.setTaskSchedulerBackgroundMode skipped: "
              << "missing JNI state\n"
              << std::flush;
    return false;
  }

  jstring reason = env->NewStringUTF("ASMA.start");
  std::cout << "  [" << log_scope
            << "] NativeGLInterface.setTaskSchedulerBackgroundMode(false, "
            << "ASMA.start)\n"
            << std::flush;
  if (sigsetjmp(g_update_surface_app_jmp_buf, 1) == 0) {
    g_stage6_empty_gl_helper_returns = 0;
    g_update_surface_app_recovery_in_progress = kStage6RecoveryInline;
    native_set_task_scheduler_background_mode(env, native_gl_class, JNI_FALSE,
                                              reason);
    g_update_surface_app_recovery_in_progress = kStage6RecoveryInactive;
    std::cout << "  [" << log_scope
              << "] NativeGLInterface.setTaskSchedulerBackgroundMode returned\n"
              << std::flush;
    return true;
  }

  g_update_surface_app_recovery_in_progress = kStage6RecoveryInactive;
  std::cerr << "  [" << log_scope
            << "] setTaskSchedulerBackgroundMode recovered from crash\n"
            << std::flush;
  return false;
}

void RunPendingMainThreadTaskSchedulerForeground() {
  int expected = kMainThreadTaskSchedulerPending;
  if (!g_pending_main_thread_task_scheduler_state.compare_exchange_strong(
          expected, kMainThreadTaskSchedulerRunning,
          std::memory_order_acq_rel)) {
    return;
  }

  JNIEnv* env = AttachMainThreadJniEnv();
  const bool invoked = InvokeTaskSchedulerForeground(
      env, g_pending_main_thread_task_scheduler_class,
      g_pending_main_thread_task_scheduler_background_mode, "main");
  g_pending_main_thread_task_scheduler_recovered.store(
      invoked ? 0 : 1, std::memory_order_release);
  g_pending_main_thread_task_scheduler_state.store(
      kMainThreadTaskSchedulerComplete, std::memory_order_release);
}

bool RunTaskSchedulerForegroundOnMainThread(
    NativeSetTaskSchedulerBackgroundModeFn
        native_set_task_scheduler_background_mode,
    jclass native_gl_class) {
  if (IsDisabled("MOCKTAIL_TASK_SCHEDULER_FOREGROUND_ON_MAIN_THREAD") ||
      IsEnabled("MOCKTAIL_ENGINE_INLINE") ||
      !mocktail::window::IsInitialised()) {
    return false;
  }
  if (native_set_task_scheduler_background_mode == nullptr ||
      native_gl_class == nullptr) {
    return false;
  }

  g_pending_main_thread_task_scheduler_background_mode =
      native_set_task_scheduler_background_mode;
  g_pending_main_thread_task_scheduler_class = native_gl_class;
  g_pending_main_thread_task_scheduler_recovered.store(
      0, std::memory_order_release);
  g_pending_main_thread_task_scheduler_state.store(
      kMainThreadTaskSchedulerPending, std::memory_order_release);
  std::cout << "  [engine] NativeGLInterface.setTaskSchedulerBackgroundMode "
            << "scheduled on main thread\n"
            << std::flush;

  const int timeout_ms = GetEnvInt(
      "MOCKTAIL_TASK_SCHEDULER_FOREGROUND_MAIN_THREAD_TIMEOUT_MS", 3000);
  const uint64_t start_ms = MonotonicMillis();
  while (true) {
    const int state = g_pending_main_thread_task_scheduler_state.load(
        std::memory_order_acquire);
    if (state == kMainThreadTaskSchedulerComplete) {
      const bool recovered =
          g_pending_main_thread_task_scheduler_recovered.load(
              std::memory_order_acquire) != 0;
      g_pending_main_thread_task_scheduler_state.store(
          kMainThreadTaskSchedulerIdle, std::memory_order_release);
      if (recovered) {
        std::cerr << "  [engine] main-thread "
                  << "setTaskSchedulerBackgroundMode recovered from crash\n"
                  << std::flush;
      } else {
        std::cout << "  [engine] main-thread "
                  << "setTaskSchedulerBackgroundMode returned\n"
                  << std::flush;
      }
      return true;
    }

    if (timeout_ms >= 0) {
      const uint64_t now_ms = MonotonicMillis();
      if (now_ms >= start_ms &&
          now_ms - start_ms >= static_cast<uint64_t>(timeout_ms)) {
        g_pending_main_thread_task_scheduler_state.store(
            kMainThreadTaskSchedulerTimedOut, std::memory_order_release);
        std::cerr << "  [engine] main-thread "
                  << "setTaskSchedulerBackgroundMode timed out after "
                  << timeout_ms << " ms\n"
                  << std::flush;
        return true;
      }
    }
    usleep(1000);
  }
}

void PumpRobloxMainThreadMessagesOnce() {
  static const bool force_early =
      IsEnabled("MOCKTAIL_FORCE_EARLY_MAIN_THREAD_MESSAGE_PUMP");
  static const bool pump_disabled =
      IsDisabled("MOCKTAIL_MAIN_THREAD_MESSAGE_PUMP");
  static const bool trace_pump = IsEnabled("MOCKTAIL_TRACE_MAIN_THREAD_PUMP");
  static const int pump_limit =
      GetEnvInt("MOCKTAIL_MAIN_THREAD_MESSAGE_PUMP_LIMIT", 0);
  if (g_main_thread_message_pump_ready.load() == 0 && !force_early) {
    static bool logged_not_ready = false;
    if (!logged_not_ready && trace_pump) {
      logged_not_ready = true;
      std::cerr << "  [main] nativeCallMessagesFromMainThread pump not ready\n"
                << std::flush;
    }
    return;
  }

  if (g_native_call_messages_from_main_thread == nullptr ||
      g_vm_for_main_thread_pump == nullptr ||
      g_native_gl_class_for_main_thread == nullptr || pump_disabled) {
    static bool logged_unavailable = false;
    if (!logged_unavailable && trace_pump) {
      logged_unavailable = true;
      std::cerr << "  [main] nativeCallMessagesFromMainThread pump unavailable"
                << " fn="
                << reinterpret_cast<const void*>(
                       g_native_call_messages_from_main_thread)
                << " vm=" << static_cast<void*>(g_vm_for_main_thread_pump)
                << " class="
                << reinterpret_cast<const void*>(
                       g_native_gl_class_for_main_thread)
                << " disabled=" << pump_disabled << '\n'
                << std::flush;
    }
    return;
  }

  JNIEnv* env = AttachMainThreadJniEnv();
  if (env == nullptr) {
    static bool logged_missing_env = false;
    if (!logged_missing_env && trace_pump) {
      logged_missing_env = true;
      std::cerr
          << "  [main] nativeCallMessagesFromMainThread pump has no JNIEnv\n"
          << std::flush;
    }
    return;
  }
  static int pump_count = 0;
  ++pump_count;
  if (pump_limit > 0 && pump_count > pump_limit) {
    return;
  }
  if (trace_pump) {
    if (pump_count <= 10 || pump_count % 100 == 0) {
      std::cerr << "  [main] nativeCallMessagesFromMainThread pump #"
                << pump_count << " env=" << static_cast<void*>(env) << '\n'
                << std::flush;
    }
  }
  if (sigsetjmp(g_call_messages_from_main_thread_jmp_buf, 0) == 0) {
    g_call_messages_from_main_thread_recovery_in_progress = 1;
    g_stage6_empty_gl_helper_returns = 0;
    g_native_call_messages_from_main_thread(env,
                                            g_native_gl_class_for_main_thread);
    g_call_messages_from_main_thread_recovery_in_progress = 0;
    if (trace_pump) {
      if (pump_count <= 10 || pump_count % 100 == 0) {
        std::cerr << "  [main] nativeCallMessagesFromMainThread returned #"
                  << pump_count << '\n'
                  << std::flush;
      }
    }
  } else {
    g_call_messages_from_main_thread_recovery_in_progress = 0;
    std::cerr << "  [main] nativeCallMessagesFromMainThread recovered\n"
              << std::flush;
  }
}

void PumpStartupOwnerThread(void* /*context*/) {
  RunPendingMainThreadTaskSchedulerForeground();
  PumpRobloxMainThreadMessagesOnce();
}

}  // namespace mocktail::legacy::internal
