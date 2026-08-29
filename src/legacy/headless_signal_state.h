#ifndef MOCKTAIL_LEGACY_HEADLESS_SIGNAL_STATE_H_
#define MOCKTAIL_LEGACY_HEADLESS_SIGNAL_STATE_H_

#include <setjmp.h>
#include <signal.h>

#include <cstdint>

#include "legacy/stage6_offsets.h"

namespace mocktail::legacy::internal {

extern volatile sig_atomic_t g_restored_stage6_jni_table_logs;
extern volatile sig_atomic_t g_stage6_segment_read_logs;
extern volatile sig_atomic_t g_appstart_scheduler_guard_logs;
extern volatile sig_atomic_t g_appstart_cleanup_guard_logs;
extern volatile sig_atomic_t g_start_app_null_manager_guard_logs;
extern volatile sig_atomic_t g_start_app_manager_scratch_logs;
extern volatile sig_atomic_t g_stage6_low_memcpy_redirect_logs;
extern volatile sig_atomic_t g_stage6_invalid_r13_read_logs;
extern volatile sig_atomic_t g_stage6_linked_list_low_write_logs;
extern volatile sig_atomic_t g_stage6_gl_state_scratch_logs;
extern volatile sig_atomic_t g_stage6_string_map_scratch_logs;
extern volatile sig_atomic_t g_stage6_string_field_assign_logs;
extern volatile sig_atomic_t g_stage6_string_field_old_value_logs;
extern volatile sig_atomic_t g_stage6_unsupported_message_slot_logs;
extern volatile sig_atomic_t g_stage6_start_lua_unsupported_message_slot_logs;
extern volatile sig_atomic_t g_stage6_hash_lookup_low_table_logs;
extern volatile sig_atomic_t g_stage6_map_lookup_low_owner_logs;
extern volatile sig_atomic_t g_stage6_audio_callback_table_logs;
extern volatile sig_atomic_t g_stage6_start_app_null_callback_owner_logs;
extern volatile sig_atomic_t g_stage6_start_app_null_callback_owner_table_logs;

extern thread_local volatile sig_atomic_t
    g_stage6_string_field_null_current_loop_count;
extern thread_local std::uintptr_t
    g_stage6_string_field_null_current_last_value;
extern volatile std::uintptr_t g_stage5_last_fallback_rip;
extern const char g_empty_c_string[];

extern thread_local sigjmp_buf g_start_game_with_param_jmp_buf;
extern thread_local volatile sig_atomic_t
    g_start_game_with_param_recovery_in_progress;
extern thread_local sigjmp_buf g_call_messages_from_main_thread_jmp_buf;
extern thread_local volatile sig_atomic_t
    g_call_messages_from_main_thread_recovery_in_progress;

extern thread_local unsigned char g_stage6_gl_scratch[kStage6GlScratchSize];
extern unsigned char g_stage6_start_app_release_owner_scratch[0x100];
extern std::uintptr_t g_stage6_start_app_release_owner_empty_slot;
extern unsigned char g_stage6_start_app_payload_owner_scratch[0x100];
extern unsigned char g_stage6_start_app_payload_map_lookup_owner_scratch[0x100];
extern thread_local std::uintptr_t g_stage6_start_app_payload_link_slot;
extern unsigned char g_stage6_init_params_holder_scratch[0x80];
extern unsigned char
    g_stage6_post_client_settings_singleton_lock_scratch[0x100];
extern unsigned char g_stage6_vector_insert_scratch[0x4000];
extern unsigned char g_start_app_manager_scratch[kStartAppManagerScratchSize];
extern unsigned char g_stage6_shared_ptr_invalid_addref_control_block[0x40];
extern std::uintptr_t
    g_stage6_start_lua_unsupported_message_empty_vector_scratch[3];
extern unsigned char g_stage6_start_game_base_scratch[0xc000];
extern unsigned char
    g_stage6_platform_headers_vector_scratch[kStage6AppBridgeHashScratchSize];
extern void* g_stage6_gl_unsupported_message_slot;
extern unsigned char g_stage6_audio_callback_table_scratch[0x400];

}  // namespace mocktail::legacy::internal

#endif  // MOCKTAIL_LEGACY_HEADLESS_SIGNAL_STATE_H_
