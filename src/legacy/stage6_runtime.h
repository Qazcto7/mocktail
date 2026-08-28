#ifndef MOCKTAIL_LEGACY_STAGE6_RUNTIME_H_
#define MOCKTAIL_LEGACY_STAGE6_RUNTIME_H_

#include <cstddef>
#include <cstdint>

#include "legacy/stage6_offsets.h"

namespace mocktail::legacy::internal {

extern unsigned char g_stage6_gl_global_scratch[kStage6GlScratchSize];
extern unsigned char g_stage5_fallback_region[kStage5FallbackScratchSize];
extern unsigned char
    g_stage6_app_bridge_hash_scratch[kStage6AppBridgeHashScratchSize];
extern unsigned char
    g_stage6_app_bridge_vector_scratch[kStage6AppBridgeHashScratchSize];
extern unsigned char g_stage6_start_app_params_vector_backing_scratch
    [kStage6AppBridgeHashScratchSize];
extern unsigned char
    g_stage6_start_app_params_field0_scratch[kStage6AppBridgeHashScratchSize];
extern unsigned char
    g_stage6_start_app_params_field20_scratch[kStage6AppBridgeHashScratchSize];
extern unsigned char
    g_stage6_start_app_params_field40_scratch[kStage6AppBridgeHashScratchSize];
extern unsigned char
    g_stage6_start_app_params_field60_scratch[kStage6AppBridgeHashScratchSize];
extern unsigned char
    g_stage6_gl_global_queue_lane_storage[kStage6GlQueueLaneStorageSize];
extern unsigned char g_stage6_gl_global_tls_storage[0x1000];
extern unsigned char g_channel_string_backing[0x20];
extern unsigned char g_base_url_owner_string_backing[0x20];
extern unsigned char g_base_url_global_string_backing[0x20];
extern unsigned char g_stage6_app_bridge_xml_name_primary_backing[0x20];
extern unsigned char g_stage6_app_bridge_xml_name_secondary_backing[0x20];
extern unsigned char g_stage6_app_bridge_xml_name_tertiary_backing[0x20];
extern unsigned char g_stage6_app_bridge_xml_name_quaternary_backing[0x20];
extern unsigned char g_stage6_app_bridge_xml_name_quinary_backing[0x20];
extern unsigned char g_stage6_app_bridge_xml_name_senary_backing[0x20];
extern unsigned char g_stage6_app_bridge_xml_name_septenary_backing[0x20];
extern unsigned char g_stage6_platform_headers_empty_entry[0x60];
extern unsigned char g_stage6_platform_headers_zero_string[0x20];
extern unsigned char g_stage6_start_lua_state_scratch[0x400];
extern unsigned char g_stage6_start_lua_anchor_scratch[0x80];
extern unsigned char g_stage6_start_lua_callback_scratch[0x80];
extern std::uintptr_t g_stage6_start_lua_callback_bucket_scratch[16];
extern std::uintptr_t g_stage6_start_lua_callback_target_vtable[32];
extern std::uintptr_t g_stage6_start_lua_callback_target_object[8];
extern std::uintptr_t g_stage6_start_lua_target_callback_object_vtable[32];
extern std::uintptr_t g_stage6_start_lua_target_callback_object[0x100];
extern std::uintptr_t g_stage6_start_lua_fake_event_vtable[8];
extern std::uintptr_t g_stage6_start_lua_fake_event_object[8];
extern std::uintptr_t g_stage6_start_lua_refcount_vtable[8];
extern unsigned char g_stage6_start_lua_refcount_scratch[0x80];
extern unsigned char g_stage6_start_lua_target_table_scratch[0x900];
extern std::uintptr_t g_stage6_start_lua_returner_target_vtable[8];
extern unsigned char g_stage6_start_lua_returner_target_object[0x300];
extern std::uintptr_t g_stage6_start_lua_result20_callback_context_scratch[2];
extern unsigned char g_stage6_start_lua_result20_lookup_node_scratch[0x40];
extern unsigned char g_stage6_start_lua_result20_callback_control_block[0x40];
extern std::uintptr_t g_stage6_start_lua_result20_callback_split_callback;
extern std::uintptr_t g_stage6_start_lua_result20_callback_split_source_pair;
extern std::uintptr_t g_stage6_start_lua_result20_callback_split_context;
extern unsigned char g_stage6_start_lua_synthetic_instance_object[0x300];
extern std::uintptr_t g_stage6_start_lua_synthetic_instance_vtable[48];
extern unsigned char g_stage6_start_lua_synthetic_instance_control_block[0x40];
extern unsigned char g_stage6_start_lua_synthetic_instance_name[24];
extern unsigned char g_stage6_start_lua_system_dialog_object_scratch[0x80];
extern unsigned char g_stage6_start_lua_system_dialog_list_scratch[0x80];
extern unsigned char g_stage6_start_lua_system_dialog_item_scratch[0x40];
extern std::uintptr_t g_stage6_start_lua_owner_slot_028;
extern std::uintptr_t g_stage6_start_lua_owner_slot_030;
extern std::uintptr_t g_stage6_start_lua_owner_slot_038;
extern std::uintptr_t g_stage6_last_app_bridge_owner;
extern std::uintptr_t g_stage6_last_app_bridge_owner_state;
extern const std::uintptr_t kFallbackVtable[32];

void InitialiseStage6GlScratchWithTls(unsigned char* region,
                                      unsigned char* tls_storage,
                                      unsigned char* queue_lane_storage);
void SeedStage6FakeIntrusiveRefcount(unsigned char* object, std::size_t size);
void SeedStage6StartLuaTargetTableScratchVtable();

}  // namespace mocktail::legacy::internal

#endif  // MOCKTAIL_LEGACY_STAGE6_RUNTIME_H_
