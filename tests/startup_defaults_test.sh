#!/usr/bin/env bash
# Copyright 2026 Mocktail Project Authors
#
# Licensed under the Apache License, Version 2.0 (the "License")

set -euo pipefail

main_cc="${1:?usage: startup_defaults_test.sh /path/to/src/main.cc}"

if ! rg -Uq 'GetEnvString\("MOCKTAIL_BASE_URL",\s*"https://www\.roblox\.com/"\)' "${main_cc}" ||
   ! rg -Uq 'GetEnvString\("MOCKTAIL_API_URL",\s*"https://api\.roblox\.com/"\)' "${main_cc}" ||
   ! rg -Uq 'ShouldRunStartupStep\("MOCKTAIL_NATIVE_SET_BASE_URL",\s*true\)' "${main_cc}" ||
   ! rg -Uq 'native_set_base_url\(env, settings_class, base_url_string,\s*api_url_string\)' "${main_cc}"; then
  echo "NativeSettings must enable the APK base-URL step with canonical www and api endpoints" >&2
  exit 1
fi

if ! rg -Uq 'GetEnvString\("MOCKTAIL_CHANNEL_PLATFORM_NAME",\s*"GoogleAndroidApp"\)' "${main_cc}"; then
  echo "NativeSettings channel platform must match the APK GoogleAndroidApp client-settings group" >&2
  exit 1
fi

if rg -Fq 'NewObject(env, "com/roblox/client/JNIBaseUrlSetter")' "${main_cc}" ||
   ! rg -Uq 'native_base_url_protocol_init\(env, base_url_protocol_class,\s*game_activity\)' "${main_cc}"; then
  echo "JNIBaseUrlProtocol.init must receive the MainGameActivity Context" >&2
  exit 1
fi

line_of() {
  local pattern="${1}"
  rg -n -m1 "${pattern}" "${main_cc}" | cut -d: -f1
}

asset_line="$(line_of 'nativeSetAssetPath returned')"
settings_line="$(line_of 'ConfigureNativeSettings\(env, native_settings_class, context\)')"
storage_line="$(line_of 'ConfigureLocalStorage\(env, context\)')"
protocol_line="$(line_of 'context->native_base_url_protocol_init\(env, base_url_protocol_class,')"
global_line="$(line_of 'std::cout << "  \[engine\] nativeGameGlobalInit\\n"')"
adapter_line="$(line_of 'std::cout << "  \[engine\] nativeUpdateAdapterInit\\n"')"
if [[ -z "${asset_line}" || -z "${settings_line}" || -z "${storage_line}" ||
      -z "${protocol_line}" || -z "${global_line}" || -z "${adapter_line}" ]] ||
   ! ((asset_line < settings_line && settings_line < storage_line &&
       storage_line < protocol_line && protocol_line < global_line &&
       global_line < adapter_line)); then
  echo "APK bootstrap order must be asset path -> NativeSettings/storage/base URL protocol -> global init -> adapter init" >&2
  exit 1
fi

if ! rg -Uq 'context->native_set_multiple_cookies\s*&&\s*!roblox_cookies\.empty\(\)\s*&&\s*ShouldRunStartupStep\("MOCKTAIL_NATIVE_SET_MULTIPLE_COOKIES",\s*true\)' "${main_cc}" ||
   ! rg -Uq 'ShouldRunStartupStep\("MOCKTAIL_JNI_COOKIE_MANAGER_SET_COOKIE",\s*false\)' "${main_cc}" ||
   rg -q 'native_cookie_manager_set_cookies_from_disk|MOCKTAIL_JNI_COOKIE_MANAGER_SET_COOKIES_FROM_DISK|setCookiesFromDisk' "${main_cc}"; then
  echo "production NativeSettings cookie injection must use the composed credential without a second disk read; the unused setCookie path stays opt-in" >&2
  exit 1
fi

if rg -q 'setenv\("MOCKTAIL_CALL_REAL_APP_BRIDGE_UPDATE_SURFACE", "1", 1\)' "${main_cc}"; then
  echo "windowed startup must not auto-enable real pre-start UpdateSurfaceAppWithPlatformParams" >&2
  exit 1
fi

if ! rg -q 'windowed startup: leaving real UpdateSurfaceAppWithPlatformParams opt-in' "${main_cc}"; then
  echo "missing explicit log for opt-in real UpdateSurfaceAppWithPlatformParams policy" >&2
  exit 1
fi

if rg -q 'SetEnvDefault\("MOCKTAIL_STEP_UPDATE_SURFACE_APP", "1"\)' "${main_cc}" ||
   rg -Uq 'run_update_surface_app[\s\S]{0,180}has_window \|\| IsEnabled\("MOCKTAIL_UPDATE_SURFACE_APP"\)' "${main_cc}"; then
  echo "APK ASMA startup must not run pre-StartApp UpdateSurfaceAppWithPlatformParams by default; initial Surface belongs in StartAppParams" >&2
  exit 1
fi

if ! rg -q 'SetEnvDefault\("MOCKTAIL_CALL_REAL_APP_BRIDGE_START", "1"\)' "${main_cc}" ||
	   ! rg -q 'SetEnvDefault\("MOCKTAIL_CALL_REAL_APP_BRIDGE_START_THREAD", "0"\)' "${main_cc}" ||
	   ! rg -q 'SetEnvDefault\("MOCKTAIL_SET_APP_BRIDGE_NOTIFICATION_LISTENER", "1"\)' "${main_cc}" ||
	   ! rg -q 'SetEnvDefault\("MOCKTAIL_START_LUA_APP_DM", "1"\)' "${main_cc}" ||
   ! rg -q 'SetEnvDefault\("MOCKTAIL_START_LUA_APP_DM_AFTER_START_APP", "1"\)' "${main_cc}" ||
   ! rg -q 'SetEnvDefault\("MOCKTAIL_START_LUA_APP_DM_DELAY_MS", "500"\)' "${main_cc}" ||
   ! rg -q 'SetEnvDefault\("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_TASK_QUEUE_FLAG", "1"\)' "${main_cc}" ||
   ! rg -q 'SetEnvDefault\("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_QUEUE", "1"\)' "${main_cc}" ||
   ! rg -q 'SetEnvDefault\("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_SCHEDULER_PROC", "1"\)' "${main_cc}" ||
   ! rg -q 'SetEnvDefault\("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_PROC_MATCH", "1"\)' "${main_cc}" ||
   ! rg -q 'SetEnvDefault\("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_ACTIVE_PROC", "1"\)' "${main_cc}" ||
   ! rg -q 'SetEnvDefault\("MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_CLEANUP_PROC", "1"\)' "${main_cc}" ||
   ! rg -q 'SetEnvDefault\("MOCKTAIL_ASMA_START_TASK_SCHEDULER_FOREGROUND", "1"\)' "${main_cc}" ||
   ! rg -q 'SetEnvDefault\("MOCKTAIL_TASK_SCHEDULER_FOREGROUND_ON_MAIN_THREAD", "1"\)' "${main_cc}" ||
   ! rg -q 'SetEnvDefault\("MOCKTAIL_NATIVE_FRAGMENT_START", "1"\)' "${main_cc}" ||
   ! rg -q 'NativeGLInterface.nativeOnFragmentStart' "${main_cc}" ||
   ! rg -q 'SetEnvDefault\("MOCKTAIL_PASS_CURRENT_DISPLAY_REFRESH_RATE", "1"\)' "${main_cc}" ||
   ! rg -q 'NativeGLInterface.nativePassCurrentDisplayRefreshRate' "${main_cc}" ||
   ! rg -q 'SetEnvDefault\("MOCKTAIL_PASS_SUPPORTED_REFRESH_RATES", "1"\)' "${main_cc}" ||
   ! rg -q 'SetEnvDefault\("MOCKTAIL_PASS_ACTIVITY_TO_GAME_SURFACE_PARAMS", "0"\)' "${main_cc}" ||
   ! rg -q 'SetEnvDefault\("MOCKTAIL_PATCH_NATIVE_FLAGS_LOADED", "1"\)' "${main_cc}" ||
   ! rg -q 'ForceNativeFlagsLoadedForTaskScheduler\("after-native-flags-init"\)' "${main_cc}"; then
  echo "windowed no-cookie startup must follow the APK ASMA path: synchronous real StartApp, app-bridge notification listener, post-start StartLuaAppDM, foreground scheduler, fragment-start lifecycle, and display refresh-rate publication" >&2
  exit 1
fi

if ! rg -Uq 'kStage6DataModelPatcherForceLocalFlagOffset\s*=\s*0x73cf2d8' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_PATCH_STAGE6_DATAMODEL_FORCE_LOCAL' "${main_cc}" ||
   ! rg -q 'ForceStage6DataModelPatcherForceLocalFlag\("after-native-flags-init"\)' "${main_cc}" ||
   ! rg -Fq '*flag = static_cast<unsigned char>(*flag | 0x01)' "${main_cc}"; then
  echo "DataModelPatch force-local flag must be opt-in and re-applied after native flag initialization" >&2
  exit 1
fi

if ! rg -Uq 'kStage6DeferRbxmSignatureCheckToPostTtiFlagOffset\s*=\s*0x73cf288' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_DEFER_RBXM_SIGNATURE_CHECK_TO_POST_TTI' "${main_cc}" ||
   ! rg -q 'ForceStage6DeferRbxmSignatureCheckToPostTtiFlag' "${main_cc}" ||
   ! rg -q 'after-datamodel-patch-telemetry-descriptor' "${main_cc}" ||
   ! rg -q 'DeferRbxmSignatureCheckToPostTti flag forced' "${main_cc}"; then
  echo "DataModelPatch local RBXM path must defer signature verification after descriptor reconstruction so UniversalApp can produce a verified patch candidate" >&2
  exit 1
fi

if ! rg -Uq 'kStage6RbxmClassDescriptorIndexBuildOffset\s*=\s*0x671e93c' "${main_cc}" ||
   ! rg -q 'CallStage6RbxmClassDescriptorIndexBuildWithRecovery' "${main_cc}" ||
   ! rg -q 'Stage6 RBXM class descriptor index build' "${main_cc}" ||
   ! rg -q 'rbxm-class-descriptor-index' "${main_cc}" ||
   ! rg -q 'descriptor_vectors' "${main_cc}" ||
   ! rg -q 'property_vector_counts' "${main_cc}" ||
   ! rg -Fq 'uintptr_t descriptor = 0;' "${main_cc}" ||
   ! rg -Fq '&descriptor' "${main_cc}"; then
  echo "Stage6 RBXM class descriptors must log source property vector counts and rebuild the native property-name index at +0x278 after reflection descriptor registration" >&2
  exit 1
fi

if ! rg -Uq 'kStage6RbxmInstanceStaticDescriptorInitOffset\s*=\s*0x22821bb' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_CALL_STAGE6_RBXM_INSTANCE_STATIC_DESCRIPTOR_INIT' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_SEED_STAGE6_RBXM_PROPERTY_GROUPS' "${main_cc}" ||
   ! rg -q 'seed_stage6_rbxm_property_groups' "${main_cc}" ||
   ! rg -q 'g_stage6_rbxm_instance_static_descriptor_init_result' "${main_cc}" ||
   ! rg -q 'result_name' "${main_cc}" ||
   ! rg -q 'rbxm-static-descriptor-init' "${main_cc}"; then
  echo "Stage6 RBXM diagnostics must support recovered execution of the Instance static descriptor initializer when explicitly requested or when property-group seeding needs Name/property descriptor globals" >&2
  exit 1
fi

if ! rg -Uq 'kStage6RbxmPropertyDescriptorRegistryHeadGlobalOffset\s*=\s*0x75a81e0' "${main_cc}" ||
   ! rg -q 'ReadRbxmDescriptorRegistryPreview' "${main_cc}" ||
   ! rg -q 'ReadRbxmDescriptorRegistryNodePreview' "${main_cc}" ||
   ! rg -Uq 'kStage6RbxmDescriptorRegistryPreviewSize\s*=\s*8192' "${main_cc}" ||
   ! rg -Fq 'registry_preview[kStage6RbxmDescriptorRegistryPreviewSize]' "${main_cc}" ||
   ! rg -q 'registry_node_preview' "${main_cc}" ||
   ! rg -q 'descriptor10_name' "${main_cc}" ||
   ! rg -q 'descriptor38_name' "${main_cc}" ||
   ! rg -q 'rbxm-descriptor-registry' "${main_cc}" ||
   ! rg -q 'property_descriptor_registry' "${main_cc}"; then
  echo "Stage6 RBXM diagnostics must log the global descriptor registries and first-node fields so missing per-class property vectors can be traced to descriptor creation versus class binding" >&2
  exit 1
fi

if ! rg -q 'FindRbxmDescriptorByNameInRegistry' "${main_cc}" ||
   ! rg -q 'FindRbxmDescriptorByNameInStaticGlobals' "${main_cc}" ||
   ! rg -q 'IsLikelyCallableRbxmPropertyDescriptor' "${main_cc}" ||
   ! rg -q 'IsExecutableMemoryRange' "${main_cc}" ||
   ! rg -Fq 'ReadPointerIfReadable(vtable + 0xd0)' "${main_cc}" ||
   ! rg -q 'rbxm-property-descriptor-reject' "${main_cc}" ||
   ! rg -Uq 'kStage6RbxmInstanceStaticDescriptorGlobalsStartOffset\s*=\s*0x73e4600' "${main_cc}" ||
   ! rg -q 'SeedStage6RbxmClassPropertyGroup' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_SEED_STAGE6_RBXM_PROPERTY_GROUPS' "${main_cc}" ||
   ! rg -q 'rbxm-property-group-seed' "${main_cc}" ||
   ! rg -q 'g_stage6_rbxm_instance_property_group_seed' "${main_cc}"; then
  echo "Stage6 RBXM property descriptors must be bindable into class descriptor source groups before rebuilding the native property-name index, and candidate descriptors must expose an executable setter slot" >&2
  exit 1
fi

if ! rg -q 'RunTaskSchedulerForegroundOnMainThread' "${main_cc}" ||
   ! rg -q 'RunPendingMainThreadTaskSchedulerForeground' "${main_cc}" ||
   ! rg -q 'g_pending_main_thread_task_scheduler_background_mode' "${main_cc}"; then
  echo "ASMA.start foreground scheduler must be marshalled to the main thread before StartApp" >&2
  exit 1
fi

if ! rg -q 'NativeGLJavaInterface\.setImplementation' "${main_cc}" ||
   ! rg -Fq 'NewObject(env, "com/roblox/engine/jni/EngineJavaCallback2")' "${main_cc}" ||
   ! rg -Fq 'CallStaticVoidMethod(native_gl_java_class, set_implementation' "${main_cc}"; then
  echo "ASMA startup must install NativeGLJavaInterface.sImplementation like the APK fragment path" >&2
  exit 1
fi

if ! rg -Uq 'SetEnvDefault\(\s*"MOCKTAIL_PATCH_STAGE6_START_LUA_DM_FORCE_SAME_THREAD",\s*"1"\s*\)' "${main_cc}" ||
   ! rg -Uq 'SetEnvDefault\(\s*"MOCKTAIL_PATCH_STAGE6_START_LUA_DM_FORCE_SAME_THREAD_GLOBAL",\s*"1"\s*\)' "${main_cc}" ||
   ! rg -Uq 'SetEnvDefault\(\s*"MOCKTAIL_PATCH_STAGE6_START_LUA_FALLBACK_CALLBACK_TARGET",\s*"1"\s*\)' "${main_cc}" ||
   ! rg -q 'PatchStage6StartLuaDmForceSameThread\(g_libroblox_base\)' "${main_cc}"; then
  echo "default StartLuaAppDM must use the same-thread ASMA path with a real fallback callback target, without requiring trace flags" >&2
  exit 1
fi

if ! rg -q 'recovered empty activity-lifecycle observer inside StartAppWithParams' "${main_cc}"; then
  echo "StartAppWithParams must recover the same empty activity-lifecycle observer path as explicit lifecycle callbacks" >&2
  exit 1
fi

if ! rg -q 'globally recovered empty activity-lifecycle observer dispatch' "${main_cc}"; then
  echo "asynchronous StartApp observer crashes must be handled by the global signal path" >&2
  exit 1
fi

if ! rg -Uq 'kAlignedAllocatorWrapperEntryOffset\s*=\s*0x1f76aa5' "${main_cc}" ||
   ! rg -q 'Roblox aligned allocator wrapper bridge' "${main_cc}" ||
   ! rg -q 'mocktail_roblox_aligned_alloc_bridge' "${main_cc}"; then
  echo "Roblox aligned allocator wrapper must use the host allocation bridge instead of returning repeated native OOM nulls" >&2
  exit 1
fi

if ! rg -q 'Stage6 StartApp non-code target detail' "${main_cc}" ||
   ! rg -Fq 'PrintAddressMapForRip(rip)' "${main_cc}" ||
   ! rg -Fq 'ReadPointerIfReadable(rbp + 0x08)' "${main_cc}" ||
   ! rg -Fq 'caller_return=' "${main_cc}" ||
   ! rg -Fq 'source_preview' "${main_cc}" ||
   ! rg -Fq 'ReadPointerIfReadable(r13 + 0x20)' "${main_cc}" ||
   ! rg -Fq 'ReadPointerIfReadable(rcx + 0x20)' "${main_cc}" ||
   ! rg -Fq 'ReadPointerIfReadable(rbx + 0x20)' "${main_cc}"; then
  echo "StartApp non-code target recovery must log memory maps and object slots before longjmping away from heap-RIP crashes" >&2
  exit 1
fi

if ! rg -Uq 'kStage6SharedPtrCopyNullSourceRefcountOffset\s*=\s*0x2e1781e' "${main_cc}" ||
   ! rg -Uq 'kStage6SharedPtrCopyNullSourceReturnOffset\s*=\s*0x2e17822' "${main_cc}" ||
   ! rg -q 'Stage6 shared pointer copy null source: skipping addref' "${main_cc}" ||
   ! rg -Fq 'ReadPointerIfReadable(rbx)' "${main_cc}" ||
   ! rg -Fq 'stack_return=' "${main_cc}"; then
  echo "Stage6 nullable shared-pointer copy helper must skip addref when the copied source is null and log the callsite context" >&2
  exit 1
fi

if ! rg -Uq 'kStage6SharedPtrInvalidAddrefOffset\s*=\s*0x2bc5990' "${main_cc}" ||
   ! rg -Uq 'kStage6SharedPtrInvalidAddrefCopyReturnOffset\s*=\s*0x2c2fb0b' "${main_cc}" ||
   ! rg -Uq 'kStage6SharedPtrInvalidAddrefCopySuccessReturnOffset\s*=\s*0x2c2fb14' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_PATCH_STAGE6_START_LUA_SHARED_PTR_INVALID_ADDREF_CONTROL_BLOCK' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_PATCH_STAGE6_START_LUA_SHARED_PTR_INVALID_ADDREF_EMPTY_OBJECT' "${main_cc}" ||
   ! rg -Uq 'Stage6 StartLua shared pointer invalid addref:[\s\S]{0,120}using scratch control block' "${main_cc}" ||
   ! rg -Uq 'Stage6 StartLua shared pointer invalid object:[\s\S]{0,120}returning empty copy' "${main_cc}" ||
   ! rg -Fq 'return_offset == kStage6SharedPtrInvalidAddrefCopyReturnOffset' "${main_cc}"; then
  echo "Stage6 StartLua invalid shared-pointer addref must be explicitly guarded to the observed copy-helper return site and use a readable scratch control block" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StartAppUnsupportedMessageProxyObjectReadOffset\s*=\s*0x38b4122' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppUnsupportedMessageProxyObjectStateTestOffset\s*=\s*0x38b412e' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppUnsupportedMessageProxyObjectReturnOffset\s*=\s*0x38b427a' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_PATCH_STAGE6_START_LUA_UNSUPPORTED_MESSAGE_NULL_PROXY' "${main_cc}" ||
   ! rg -Uq 'Stage6 StartLua unsupported-message null proxy:[\s\S]{0,80}taking empty return' "${main_cc}"; then
  echo "Stage6 StartLua unsupported-message proxy fallback must return through the observed function epilogue when the proxy object is invalid" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StartLuaUnsupportedMessageVectorReadOffset\s*=\s*0x233c470' "${main_cc}" ||
   ! rg -q 'g_stage6_start_lua_unsupported_message_empty_vector_scratch' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_PATCH_STAGE6_START_LUA_UNSUPPORTED_MESSAGE_EMPTY_VECTOR' "${main_cc}" ||
   ! rg -Uq 'Stage6 StartLua unsupported-message empty vector:[\s\S]{0,120}using scratch vector' "${main_cc}"; then
  echo "Stage6 StartLua unsupported-message vector fallback must substitute a real empty vector for invalid helper returns" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StartLuaUnsupportedMessageParentThreadStateReadOffset\s*=\s*0x233e7c0' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaUnsupportedMessageParentThreadStateReturnOffset\s*=\s*0x233e7dc' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_PATCH_STAGE6_START_LUA_UNSUPPORTED_MESSAGE_NULL_PARENT_STATE' "${main_cc}" ||
   ! rg -Uq 'Stage6 StartLua unsupported-message null parent state:[\s\S]{0,120}taking empty return' "${main_cc}" ||
   ! rg -Fq 'REG_R15' "${main_cc}"; then
  echo "Stage6 StartLua unsupported-message parent thread-state fallback must skip the observed null r15 state read" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StartLuaUnsupportedMessageLeafThreadStateReadOffset\s*=\s*0x233eb39' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaUnsupportedMessageLeafThreadStateReturnOffset\s*=\s*0x233eb61' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_PATCH_STAGE6_START_LUA_UNSUPPORTED_MESSAGE_NULL_LEAF_STATE' "${main_cc}" ||
   ! rg -Uq 'Stage6 StartLua unsupported-message null leaf state:[\s\S]{0,120}taking empty return' "${main_cc}" ||
   ! rg -Fq 'REG_RBX' "${main_cc}"; then
  echo "Stage6 StartLua unsupported-message leaf thread-state fallback must return null through the observed helper epilogue" >&2
  exit 1
fi

if ! rg -Uq 'kStage6SharedPtrReleaseNullSourceRefcountOffset\s*=\s*0x2df8b40' "${main_cc}" ||
   ! rg -Uq 'kStage6SharedPtrReleaseNullSourceReturnOffset\s*=\s*0x2df8b55' "${main_cc}" ||
   ! rg -q 'Stage6 shared pointer null release: skipping release' "${main_cc}" ||
   ! rg -Fq 'release_slot_value=' "${main_cc}"; then
  echo "Stage6 nullable shared-pointer release helper must skip release when the source slot is null and log the callsite context" >&2
  exit 1
fi

if rg -q 'PatchStage6PlatformHeadersLookupReturnNull' "${main_cc}" ||
   rg -q 'Stage6 platform headers lookup return-null' "${main_cc}" ||
   rg -q 'kReturnNull' "${main_cc}" ||
   rg -Fq 'reinterpret_cast<uintptr_t>(g_stage6_platform_headers_empty_string)' "${main_cc}" ||
   ! rg -q 'PatchStage6PlatformHeadersLookupReturnEmptyEntry' "${main_cc}" ||
   ! rg -q 'g_stage6_platform_headers_empty_entry' "${main_cc}" ||
   ! rg -Fq 'WriteLibcxxString(g_stage6_platform_headers_empty_entry + 0x28, "")' "${main_cc}" ||
   ! rg -q 'Stage6 platform headers lookup return-empty-entry' "${main_cc}"; then
  echo "Stage6 platform-header lookup must return a valid entry object with an empty libc++ string at +0x28 instead of null or a bare string" >&2
  exit 1
fi

if ! rg -Uq 'kStage6PlatformHeaderValueNullTestOffset\s*=\s*0x2380195' "${main_cc}" ||
   ! rg -q 'g_stage6_platform_headers_zero_string' "${main_cc}" ||
   ! rg -Fq 'WriteLibcxxString(g_stage6_platform_headers_zero_string, "0")' "${main_cc}" ||
   ! rg -q 'Stage6 platform header numeric value null: using zero string' "${main_cc}" ||
   ! rg -Fq 'ReadPointerIfReadable(rbp - 0x80)' "${main_cc}" ||
   ! rg -Fq 'const uintptr_t value_slot = object + 0x268' "${main_cc}" ||
   ! rg -Fq 'const uintptr_t current_value = ReadPointerIfReadable(value_slot)' "${main_cc}" ||
   ! rg -Fq 'EnsureWritablePage(reinterpret_cast<void*>(value_slot))' "${main_cc}" ||
   ! rg -Fq '*reinterpret_cast<uintptr_t*>(value_slot) =' "${main_cc}" ||
   ! rg -Fq 'gregs[REG_R14] = reinterpret_cast<greg_t>(g_stage6_platform_headers_zero_string)' "${main_cc}"; then
  echo "Stage6 platform-header numeric consumers must seed the source object field with a libc++ \"0\" string backing and log the getter context" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StoullNoConversionThrowOffset\s*=\s*0x2bc972c' "${main_cc}" ||
   ! rg -Uq 'kStage6StoullNoConversionCallReturnOffset\s*=\s*0x2bc8785' "${main_cc}" ||
   ! rg -q 'Stage6 stoull no-conversion detail' "${main_cc}" ||
   ! rg -Fq 'saved_stoull_input=' "${main_cc}" ||
   ! rg -Fq 'caller_return=' "${main_cc}" ||
   ! rg -Fq 'saved_stoull_preview' "${main_cc}"; then
  echo "Stage6 stoull no-conversion recovery must log the saved input string and caller return offset" >&2
  exit 1
fi

if ! rg -Uq 'kStage6SystemDialogSingletonObjectGlobalOffset\s*=\s*0x71c3da8' "${main_cc}" ||
   ! rg -Uq 'kStage6SystemDialogSingletonGuardPointerGlobalOffset\s*=\s*0x71c3db0' "${main_cc}" ||
   ! rg -q 'g_stage6_system_dialog_singleton_guard' "${main_cc}" ||
   ! rg -q 'InstallStage6SystemDialogSingletonGuardFallback' "${main_cc}" ||
   ! rg -Fq '*guard_slot = &g_stage6_system_dialog_singleton_guard' "${main_cc}" ||
   ! rg -q 'installed Stage6 system-dialog singleton guard fallback' "${main_cc}"; then
  echo "Stage6 system-dialog singleton must seed the skipped constructor guard pointer so Roblox can run its own initializer" >&2
  exit 1
fi

if ! rg -Uq 'kStage6SystemDialogDependencySingletonObjectGlobalOffset\s*=\s*0x73d2c78' "${main_cc}" ||
   ! rg -Uq 'kStage6SystemDialogDependencySingletonGuardPointerGlobalOffset\s*=\s*0x73d2c80' "${main_cc}" ||
   ! rg -q 'g_stage6_system_dialog_dependency_singleton_guard' "${main_cc}" ||
   ! rg -q 'InstallStage6SystemDialogDependencySingletonGuardFallback' "${main_cc}" ||
   ! rg -Fq '*guard_slot = &g_stage6_system_dialog_dependency_singleton_guard' "${main_cc}" ||
   ! rg -q 'installed Stage6 system-dialog dependency singleton guard fallback' "${main_cc}"; then
  echo "Stage6 system-dialog dependency singleton must seed the nested skipped constructor guard pointer before 0x5fe799a dereferences it" >&2
  exit 1
fi

if ! rg -Uq 'kStage6SystemDialogDescriptorPrimaryGlobalOffset\s*=\s*0x71c3d08' "${main_cc}" ||
   ! rg -Uq 'kStage6SystemDialogDescriptorPrimaryNameOffset\s*=\s*0x4da4c5' "${main_cc}" ||
   ! rg -q 'InstallStage6SystemDialogDescriptorFallbacks' "${main_cc}" ||
   ! rg -Fq 'descriptor + 0x00' "${main_cc}" ||
   ! rg -Fq 'libroblox_base + kStage6SystemDialogDescriptorPrimaryNameOffset' "${main_cc}" ||
   ! rg -q 'installed Stage6 system-dialog descriptor fallback' "${main_cc}"; then
  echo "Stage6 system-dialog descriptor globals must be restored from constructor-derived rodata offsets before string helpers read 0x71c3d08" >&2
  exit 1
fi

if ! rg -Uq 'kStage6IxpDescriptorPrimaryGlobalOffset\s*=\s*0x709e5a8' "${main_cc}" ||
   ! rg -Uq 'kStage6IxpDescriptorPrimaryNameOffset\s*=\s*0x3459dd' "${main_cc}" ||
   ! rg -q 'InstallStage6IxpDescriptorFallbacks' "${main_cc}" ||
   ! rg -Fq 'ixp_descriptor + 0x00' "${main_cc}" ||
   ! rg -Fq 'libroblox_base + kStage6IxpDescriptorPrimaryNameOffset' "${main_cc}" ||
   ! rg -q 'installed Stage6 IXP descriptor fallback' "${main_cc}"; then
  echo "Stage6 IXP descriptor globals must be restored from constructor-derived rodata offsets before HASH startup paths read 0x709e5a8" >&2
  exit 1
fi

if ! rg -Uq 'kStage6DataModelPatchAnalyticsDescriptorPrimaryGlobalOffset\s*=\s*0x73cebb0' "${main_cc}" ||
   ! rg -Uq 'kStage6DataModelPatchAnalyticsDescriptorPrimaryNameOffset\s*=\s*0x3c268e' "${main_cc}" ||
   ! rg -q 'InstallStage6DataModelPatchAnalyticsDescriptorFallbacks' "${main_cc}" ||
   ! rg -Fq 'kStage6DataModelPatchAnalyticsDescriptorPrimaryStringGlobalOffset' "${main_cc}" ||
   ! rg -Uq 'WriteLibcxxString\([\s\S]{0,160}kStage6DataModelPatchAnalyticsDescriptorPrimaryStringGlobalOffset' "${main_cc}" ||
   ! rg -Uq 'installed Stage6 DataModel patch analytics descriptor[\s\S]{0,80}fallback' "${main_cc}"; then
  echo "Stage6 DataModel patch analytics descriptor globals must be restored from constructor-derived offsets before telemetry StartApp paths read 0x73cebb0" >&2
  exit 1
fi

if ! rg -Uq 'kStage6DataModelPatchTelemetryDescriptorRootGlobalOffset\s*=\s*0x73cf210' "${main_cc}" ||
   ! rg -Uq 'kStage6DataModelPatchTelemetryDescriptorRootNameOffset\s*=\s*0x2875bc' "${main_cc}" ||
   ! rg -q 'InstallStage6DataModelPatchTelemetryDescriptorFallbacks' "${main_cc}" ||
   ! rg -Uq 'write_relative_pointer\(\s*kStage6DataModelPatchTelemetryDescriptorRootGlobalOffset,\s*kStage6DataModelPatchTelemetryDescriptorRootNameOffset\s*\)' "${main_cc}" ||
   ! rg -Uq 'installed Stage6 DataModel patch telemetry descriptor[\s\S]{0,80}fallback' "${main_cc}"; then
  echo "Stage6 DataModel patch telemetry descriptor root must be restored before StartApp local RBXM telemetry reads 0x73cf210" >&2
  exit 1
fi

if ! rg -q 'ReadMemoryHexPreview' "${main_cc}" ||
   ! rg -q 'build_input_preview' "${main_cc}" ||
   ! rg -q 'build_input0_preview' "${main_cc}" ||
   ! rg -q 'prepared_input0_preview' "${main_cc}" ||
   ! rg -q 'parent_ref_preview' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmInstIdsReturnProbeOffset\s*=\s*0x2dea129' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmInstModeBranchProbeOffset\s*=\s*0x2dea25d' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmInstProviderReturnProbeOffset\s*=\s*0x2dea393' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmInstFactoryResultProbeOffset\s*=\s*0x2dea56a' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmInstTableInsertReturnProbeOffset\s*=\s*0x2dea5f1' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmPrntChildIdsReturnProbeOffset\s*=\s*0x2de949c' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmPrntParentIdsReturnProbeOffset\s*=\s*0x2de9906' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmInstClassLookupProbeOffset\s*=\s*0x2de9556' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmPropDescriptorLookupProbeOffset\s*=\s*0x2de9556' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmPrntObjectLookupProbeOffset\s*=\s*0x2de9c73' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmPrntParentBranchProbeOffset\s*=\s*0x2de9c90' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmPrntRootAppendReturnProbeOffset\s*=\s*0x2de9d28' "${main_cc}" ||
	   ! rg -q 'inst-ids-return' "${main_cc}" ||
	   ! rg -q 'inst-mode-branch' "${main_cc}" ||
	   ! rg -q 'inst-provider-return' "${main_cc}" ||
		   ! rg -q 'inst-factory-result' "${main_cc}" ||
		   ! rg -q 'inst-table-insert-return' "${main_cc}" ||
	   ! rg -q 'inst-class-lookup' "${main_cc}" ||
	   ! rg -q 'prop-descriptor-lookup' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmPropApplyCallProbeOffset\s*=\s*0x2de9bb8' "${main_cc}" ||
	   ! rg -q 'prop-apply-call' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmPropApplyReturnProbeOffset\s*=\s*0x2de9bbd' "${main_cc}" ||
	   ! rg -q 'prop-apply-return' "${main_cc}" ||
	   ! rg -q 'apply_args' "${main_cc}" ||
	   ! rg -q 'ReadRbxmValueContextStringVectorPreview' "${main_cc}" ||
	   ! rg -q 'value_context_strings' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmPropertyApplyStreamByteProbeOffset\s*=\s*0x2deceb5' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmPropertyApplyLoopDecisionProbeOffset\s*=\s*0x2ded059' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmPropertyApplyTypeBranchProbeOffset\s*=\s*0x2ded719' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmGenericSetterCallProbeOffset\s*=\s*0x2dedadc' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmGenericSetterReturnProbeOffset\s*=\s*0x2dedae2' "${main_cc}" ||
	   ! rg -q 'property-apply-stream-byte' "${main_cc}" ||
	   ! rg -q 'property-apply-loop-decision' "${main_cc}" ||
	   ! rg -q 'property-apply-type-branch' "${main_cc}" ||
	   ! rg -q 'property-generic-setter-call' "${main_cc}" ||
	   ! rg -q 'property-generic-setter-return' "${main_cc}" ||
	   ! rg -q 'PatchStage6RbxmNameSlotApplyRepair' "${main_cc}" ||
	   ! rg -q 'RepairStage6RbxmInstanceNameSlotFromValue' "${main_cc}" ||
	   ! rg -q 'name-slot-apply-repair' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmPropertySetterCallProbeOffset\s*=\s*0x2ded268' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmPropertySetterModeBranchProbeOffset\s*=\s*0x2ded1c2' "${main_cc}" ||
	   ! rg -q 'property-setter-mode-branch' "${main_cc}" ||
	   ! rg -q 'property-setter-call' "${main_cc}" ||
	   ! rg -q 'value_variant' "${main_cc}" ||
	   ! rg -q 'ReadRbxmInstanceNameSlotPreview' "${main_cc}" ||
	   ! rg -q 'PromoteStage6RbxmSeedDescriptorForRbxmApply' "${main_cc}" ||
	   ! rg -q 'rbxm-property-descriptor-promote' "${main_cc}" ||
	   ! rg -Uq 'kStage6RbxmStringTypeDescriptorInitOffset\s*=\s*0x1f44c8e' "${main_cc}" ||
	   ! rg -Uq 'descriptor \+ 0x60' "${main_cc}" ||
	   ! rg -q 'RepairStage6RbxmNameDescriptorForRbxmApply' "${main_cc}" ||
	   ! rg -q 'name-descriptor-live-repair' "${main_cc}" ||
	   ! rg -q 'prnt-child-ids-return' "${main_cc}" ||
	   ! rg -q 'prnt-object-lookup' "${main_cc}" ||
	   ! rg -q 'prnt-parent-branch' "${main_cc}" ||
   ! rg -q 'prnt-root-append-return' "${main_cc}" ||
	   ! rg -Fq 'ReadVectorElementCountIfReadable(rbp - 0x50, 0x04)' "${main_cc}" ||
	   ! rg -Uq 'mode == 1u \? 0x2dea26c : 0x2dea302' "${main_cc}" ||
	   ! rg -Uq 'object_pair == 0 \? 0x2dea5b1 : 0x2dea576' "${main_cc}" ||
	   ! rg -Uq 'object_pair != 0 &&\s*rbxm_prnt_object_lookup_logs < 160' "${main_cc}" ||
	   ! rg -Uq 'const uintptr_t next_offset\s*=\s*parent_id == 0xffffffffu \? 0x2de9cf5 : 0x2de9c95' "${main_cc}"; then
  echo "Stage6 DataModel patch load-step trace must preview deserializer input bytes before patch-load assertions" >&2
  exit 1
fi

if ! rg -q 'kStage6RbxmFileManagerEntryProbeOffset' "${main_cc}" ||
   ! rg -q 'kStage6RbxmFileManagerCacheRegistryGlobalOffset' "${main_cc}" ||
   ! rg -q 'kStage6RbxmFileManagerCacheRegistryInitOffset' "${main_cc}" ||
   ! rg -q 'kStage6RbxmFileManagerLocalStorageUnavailableProbeOffset' "${main_cc}" ||
   ! rg -q 'kStage6RbxmFileManagerCachingDisabledProbeOffset' "${main_cc}" ||
   ! rg -q 'kStage6RbxmFileManagerNoLocalStorageStatusProbeOffset' "${main_cc}" ||
   ! rg -q 'kStage6RbxmFileManagerPendingStatusProbeOffset' "${main_cc}" ||
   ! rg -q 'kStage6RbxmFileManagerSuccessStatusProbeOffset' "${main_cc}" ||
   ! rg -q 'RbxmFileManager status' "${main_cc}" ||
   ! rg -q 'enabled_cache_fields' "${main_cc}" ||
   ! rg -q 'local-storage-unavailable' "${main_cc}" ||
   ! rg -q 'caching-disabled' "${main_cc}" ||
   ! rg -q 'pending-one' "${main_cc}"; then
  echo "Stage6 DataModel patch load-step trace must expose RbxmFileManager local RBXM status transitions" >&2
  exit 1
fi

if ! rg -q 'InstallStage6RbxmFileManagerCacheRegistryFallback' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_INSTALL_STAGE6_RBXM_FILE_MANAGER_CACHE_REGISTRY' "${main_cc}" ||
   ! rg -q 'rbxasset://models/UniversalApp/UniversalApp.rbxm' "${main_cc}" ||
   ! rg -q 'installed Stage6 RbxmFileManager cache registry fallback' "${main_cc}"; then
  echo "Stage6 startup must restore the constructor-populated RbxmFileManager UniversalApp cache registry when libroblox constructors are skipped" >&2
  exit 1
fi

if ! rg -q 'kStage6RbxmFileManagerFeatureRegistryGlobalOffset' "${main_cc}" ||
   ! rg -q 'kStage6RbxmFileManagerFeatureRegistryHashOffset' "${main_cc}" ||
   ! rg -q 'InstallStage6RbxmFileManagerFeatureRegistryFallback' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_INSTALL_STAGE6_RBXM_FILE_MANAGER_FEATURE_REGISTRY' "${main_cc}" ||
   ! rg -q 'feature_cache_fields' "${main_cc}" ||
   ! rg -q 'node_flags' "${main_cc}" ||
   ! rg -q 'installed Stage6 RbxmFileManager feature registry fallback' "${main_cc}"; then
  echo "Stage6 startup must restore the constructor-populated RbxmFileManager UniversalApp feature registry when libroblox constructors are skipped" >&2
  exit 1
fi

if ! rg -Uq 'kStage6RbxmCoreClassRegistryGlobalOffset\s*=\s*0x73edf90' "${main_cc}" ||
   ! rg -Uq 'kStage6RbxmInstanceClassInitOffset\s*=\s*0x1f43205' "${main_cc}" ||
   ! rg -Uq 'kStage6RbxmFolderClassInitOffset\s*=\s*0x2098d20' "${main_cc}" ||
   ! rg -Uq 'kStage6RbxmModuleScriptClassInitOffset\s*=\s*0x1f587bf' "${main_cc}" ||
   ! rg -Uq 'kStage6RbxmStringValueClassInitOffset\s*=\s*0x20e7fbc' "${main_cc}" ||
   ! rg -q 'InstallStage6RbxmCoreClassRegistryFallback' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_INSTALL_STAGE6_RBXM_CORE_CLASS_REGISTRY' "${main_cc}" ||
   ! rg -q 'rbxm-core-class-registry' "${main_cc}" ||
   ! rg -Fq 'sigsetjmp(g_libroblox_ctor_jmp_buf' "${main_cc}" ||
   ! rg -q 'installed Stage6 RBXM core class registry fallback' "${main_cc}"; then
  echo "Stage6 startup must restore constructor-populated RBXM core class providers before UniversalApp deserialization" >&2
  exit 1
fi

if ! rg -Uq 'kStage6RbxmInstanceReflectionInitOffset\s*=\s*0x1f43796' "${main_cc}" ||
   ! rg -Uq 'kStage6RbxmInstancePropertyDescriptorInitOffset\s*=\s*0x2040d80' "${main_cc}" ||
   ! rg -Uq 'kStage6RbxmFolderReflectionInitOffset\s*=\s*0x2098b62' "${main_cc}" ||
   ! rg -Uq 'kStage6RbxmModuleScriptReflectionInitOffset\s*=\s*0x1f5835f' "${main_cc}" ||
   ! rg -Uq 'kStage6RbxmStringValueReflectionInitOffset\s*=\s*0x20e7db3' "${main_cc}" ||
   ! rg -q 'InstallStage6RbxmReflectionDescriptorFallback' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_INSTALL_STAGE6_RBXM_REFLECTION_DESCRIPTOR_FALLBACK' "${main_cc}" ||
   ! rg -q 'rbxm-reflection-descriptor' "${main_cc}" ||
   ! rg -q 'installed Stage6 RBXM reflection descriptor fallback' "${main_cc}"; then
  echo "Stage6 startup must restore constructor-populated RBXM reflection descriptors before PRNT child-name lookups" >&2
  exit 1
fi

if ! rg -Uq 'kStage6RbxmChildNameStringReadOffset\s*=\s*0x65bc0f0' "${main_cc}" ||
   ! rg -q 'skipped Stage6 RBXM child-name null string' "${main_cc}" ||
   ! rg -Fq 'ReadRawStringPreview(target_name' "${main_cc}" ||
   ! rg -Fq 'libroblox_base + 0x65bc121' "${main_cc}"; then
  echo "Stage6 RBXM child-name lookup must skip nameless deserialized children locally so StartApp can continue past incomplete property descriptors" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StartAppInitialInstanceNameStringReadOffset\s*=\s*0x245919d' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppInitialInstanceNameSkipOffset\s*=\s*0x2459405' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppPeerInstanceNameStringReadOffset\s*=\s*0x24591f9' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppPeerInstanceNameSkipOffset\s*=\s*0x24595f2' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppDeepInstanceNameStringReadOffset\s*=\s*0x247d1c8' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppDeepInstanceNameSkipOffset\s*=\s*0x247d219' "${main_cc}" ||
   ! rg -q 'kStage6StartAppPostHashInstanceNameStringReadOffset' "${main_cc}" ||
   ! rg -q '0x24981f2' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppPostHashInstanceNameSkipOffset\s*=\s*0x249824f' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppInstanceNameStringReadOffset\s*=\s*0x245e1a0' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppInstanceNameSkipOffset\s*=\s*0x245e1f1' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppFallbackInstanceNameStringReadOffset\s*=\s*0x245e9cc' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppFallbackInstanceNameSkipOffset\s*=\s*0x245ea1d' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppSecondFallbackInstanceNameStringReadOffset\s*=\s*0x246ca0a' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppSecondFallbackInstanceNameSkipOffset\s*=\s*0x246ca5b' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppThirdFallbackInstanceNameStringReadOffset\s*=\s*0x24705ec' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppThirdFallbackInstanceNameSkipOffset\s*=\s*0x247063d' "${main_cc}" ||
   ! rg -q 'skipped Stage6 StartApp instance-name null string' "${main_cc}" ||
   ! rg -Fq 'g_start_lua_app_dm_recovery_in_progress != 0' "${main_cc}" ||
   ! rg -Fq 'kStage6StartAppInstanceNameSkipOffset' "${main_cc}" ||
   ! rg -Fq 'kStage6StartAppPostHashInstanceNameSkipOffset' "${main_cc}" ||
   ! rg -Fq 'kStage6StartAppFallbackInstanceNameSkipOffset' "${main_cc}" ||
   ! rg -Fq 'kStage6StartAppSecondFallbackInstanceNameSkipOffset' "${main_cc}" ||
   ! rg -Fq 'kStage6StartAppThirdFallbackInstanceNameSkipOffset' "${main_cc}"; then
  echo "Stage6 StartApp Instance-name helpers must skip the Instance-specific branch when object+0xb0 is still null" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StartLuaReverseStringCopyNullDestStoreOffset\s*=\s*0x2491c55' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaReverseStringCopyDoneOffset\s*=\s*0x2491c5f' "${main_cc}" ||
   ! rg -q 'skipped Stage6 StartLua reverse-copy null destination' "${main_cc}" ||
   ! rg -Fq 'g_start_lua_app_dm_recovery_in_progress != 0' "${main_cc}" ||
   ! rg -Fq 'instruction[0] == 0x88 && instruction[1] == 0x11' "${main_cc}"; then
  echo "Stage6 StartLua reverse string copy must skip the null destination loop locally instead of longjmp recovery" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StartLuaDMInvokerReverseStringCopyStoreOffset\s*=\s*0x230948b' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaDMInvokerReverseStringCopyDoneOffset\s*=\s*0x2309495' "${main_cc}" ||
   ! rg -Uq 'skipped Stage6 StartLuaDM invoker reverse-copy[\s\S]{0,80}invalid destination' "${main_cc}" ||
   ! rg -Fq 'g_init_with_params_recovery_in_progress != 0' "${main_cc}" ||
   ! rg -Fq 'g_start_app_with_params_recovery_in_progress != 0' "${main_cc}" ||
   ! rg -Fq 'g_update_surface_app_recovery_in_progress != 0' "${main_cc}"; then
  echo "Stage6 StartLuaDM invoker reverse copy must skip invalid async output destinations locally so InitWithParams and StartApp do not longjmp out" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StartLuaUnsupportedMessageSlotDerefOffset\s*=\s*0x246cd98' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaUnsupportedMessagePromptSlotDerefOffset\s*=\s*0x246ceef' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaUnsupportedMessageEntrySlotDerefOffset\s*=\s*0x246cf7d' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaUnsupportedMessageEnumSlotDerefOffset\s*=\s*0x246d3f9' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaUnsupportedMessageLoopSlotDerefOffset\s*=\s*0x246d97f' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaUnsupportedMessageTailSlotDerefOffset\s*=\s*0x246dcb3' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaUnsupportedMessageTail2SlotDerefOffset\s*=\s*0x246dd9c' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaUnsupportedMessageTail3SlotDerefOffset\s*=\s*0x246de9b' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaUnsupportedMessageTail4SlotDerefOffset\s*=\s*0x246e132' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaUnsupportedMessageTail5SlotDerefOffset\s*=\s*0x246e25f' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaUnsupportedMessageTail6SlotDerefOffset\s*=\s*0x246efc9' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaUnsupportedMessageTail7SlotDerefOffset\s*=\s*0x246f141' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaUnsupportedMessageTail8SlotDerefOffset\s*=\s*0x246f30e' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaUnsupportedMessageThreadStateReadOffset\s*=\s*0x245c4c3' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaUnsupportedMessageThreadStateReturnOffset\s*=\s*0x245c4e0' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaPreviousStateFlagReadOffset\s*=\s*0x233d5e3' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaCurrentStateFlagReadOffset\s*=\s*0x233d5ff' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppUnsupportedMessageSlotDerefOffset\s*=\s*0x245c7a3' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppUnsupportedMessageDetailSlotDerefOffset\s*=\s*0x245c9fb' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppUnsupportedMessagePostInstanceSlotDerefOffset\s*=\s*0x247472c' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppUnsupportedMessageDeepSlotDerefOffset\s*=\s*0x38b414b' "${main_cc}" ||
   ! rg -q 'kStage6StartAppUnsupportedMessagePostHashSlotDerefOffset' "${main_cc}" ||
   ! rg -q '0x249d7c4' "${main_cc}" ||
   ! rg -Fq 'g_stage6_start_lua_unsupported_message_slot_logs' "${main_cc}" ||
   ! rg -q 'Stage6 unsupported-message slot null: using fallback' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_PATCH_STAGE6_START_LUA_UNSUPPORTED_MESSAGE_NULL_THREAD_STATE' "${main_cc}" ||
   ! rg -q 'Stage6 StartLua unsupported-message null thread state' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_PATCH_STAGE6_START_LUA_STATE_FLAG_NULL_SOURCE' "${main_cc}" ||
   ! rg -q 'Stage6 StartLua state flag null source' "${main_cc}" ||
   ! rg -Fq 'instruction[2] == 0x18' "${main_cc}" ||
   ! rg -Fq 'instruction[2] == 0x30' "${main_cc}" ||
   ! rg -Fq 'stage6_unsupported_message_slot_load' "${main_cc}"; then
  echo "Stage6 StartLua unsupported-message helper derefs must use the fallback slot when the patched helper returns null" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StartAppAudioCallbackTableWriteOffset\s*=\s*0x2fc0788' "${main_cc}" ||
   ! rg -Fq 'g_stage6_audio_callback_table_scratch' "${main_cc}" ||
   ! rg -Fq 'Stage6 StartApp audio callback table null: using scratch ' "${main_cc}" ||
   ! rg -Fq 'instruction[3] == 0x60' "${main_cc}" ||
   ! rg -Fq 'ucontext->uc_mcontext.gregs[REG_RCX]' "${main_cc}"; then
  echo "Stage6 StartApp audio callback table null writes must use a scratch callback table" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StartAppNullCallbackOwnerReadOffset\s*=\s*0x592d5e3' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppNullCallbackOwnerFreeReadOffset\s*=\s*0x592ddf1' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppNullCallbackOwnerReturnOffset\s*=\s*0x592d899' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppNullCallbackOwnerTableWriteOffset\s*=\s*0x594e22f' "${main_cc}" ||
   ! rg -Fq 'g_stage6_start_app_null_allocator_arena' "${main_cc}" ||
   ! rg -q 'Stage6 StartApp null allocator owner: returning' "${main_cc}" ||
   ! rg -q 'Stage6 StartApp null allocator owner: skipped arena free' "${main_cc}" ||
   ! rg -q 'Stage6 StartApp null allocator owner table: ' "${main_cc}" ||
   ! rg -Fq 'IsStage6StartAppNullAllocatorArenaAllocation' "${main_cc}" ||
   ! rg -Fq 'AllocateStage6StartAppNullAllocatorArena' "${main_cc}" ||
   ! rg -Fq '*reinterpret_cast<uint32_t*>(raw + 0x00) = native_size' "${main_cc}" ||
   ! rg -Fq 'g_start_lua_app_dm_recovery_in_progress != 0' "${main_cc}" ||
   ! rg -Fq 'ucontext->uc_mcontext.gregs[REG_R12] =' "${main_cc}" ||
   ! rg -Fq 'ucontext->uc_mcontext.gregs[REG_RAX] =' "${main_cc}" ||
   ! rg -Fq 'ucontext->uc_mcontext.gregs[REG_RSP] = static_cast<greg_t>(rbp + 0x10)' "${main_cc}" ||
   ! rg -Fq 'ucontext->uc_mcontext.gregs[REG_RIP]' "${main_cc}"; then
  echo "Stage6 StartApp null allocator owners must return native-shaped arena allocations and skip freeing those allocations without a native owner" >&2
  exit 1
fi

if ! rg -Uq 'kStage6DataModelPatchNoVerifiedPatchTrapResumeOffset\s*=\s*0x25fcd68' "${main_cc}" ||
   ! rg -Uq 'kStage6DataModelPatchNoVerifiedPatchEmptyResultOffset\s*=\s*0x2464a08' "${main_cc}" ||
   ! rg -Uq 'bypassed Stage6 DataModelPatch no-verified-patch\s*"\s*"trap' "${main_cc}" ||
   ! rg -q 'empty_path' "${main_cc}" ||
   ! rg -Uq 'return_offset\s*==\s*0x2464a6e' "${main_cc}" ||
   ! rg -Fq 'ucontext->uc_mcontext.gregs[REG_RSP] += sizeof(uintptr_t)' "${main_cc}"; then
  echo "Stage6 no-verified-patch int3 must resume through the native empty-result cleanup path instead of longjmping all of StartApp" >&2
  exit 1
fi

if ! rg -q 'native_init_asset_manager' "${main_cc}" ||
   ! rg -q 'Java_com_roblox_client_JNIAAssetManagerSetup_initNative' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_JNI_ASSET_MANAGER_SETUP' "${main_cc}" ||
   ! rg -q 'JNIAAssetManagerSetup.initNative' "${main_cc}"; then
  echo "Stage6 startup must call JNIAAssetManagerSetup.initNative before DataModelPatch embedded asset reads" >&2
  exit 1
fi

if ! rg -Uq 'ShouldRunStartupStep\("MOCKTAIL_LOCAL_STORAGE_INIT_STORAGE_MANAGER",\s*true\)' "${main_cc}"; then
  echo "Stage6 startup must run LocalStorageManager.initStorageManagerNativeV3 by default, matching RobloxApplication after JNIAAssetManagerSetup" >&2
  exit 1
fi

if ! rg -q 'LocalStorageManager.initStorageManagerNativeV3 files=' "${main_cc}" ||
   ! rg -q 'LocalStorageManager.initStorageManagerNativeV3 returned' "${main_cc}"; then
  echo "Stage6 startup must trace LocalStorageManager.initStorageManagerNativeV3 before DataModelPatch asset reads" >&2
  exit 1
fi

if ! rg -q 'kRobloxChannelPointerOffset = 0x73f8958' "${main_cc}" ||
   ! rg -q 'g_channel_string_backing' "${main_cc}" ||
   ! rg -Fq 'WriteLibcxxString(g_channel_string_backing, "production")' "${main_cc}"; then
  echo "Stage6 URL/channel fallback setup must seed the channel string pointer global" >&2
  exit 1
fi

if ! rg -q 'callback_owner_matches_installed_owner' "${main_cc}" ||
   ! rg -q 'callback_owner_matches_installed_owner \? callback_owner : self_owner' "${main_cc}"; then
  echo "Stage6 StartLua fallback callback must keep the installed StartLua owner authoritative" >&2
  exit 1
fi

if ! rg -q 'userDidLogin-deep-call' "${main_cc}" ||
   ! rg -q 'state = InstallStage6StartLuaFallbackState' "${main_cc}"; then
  echo "Stage6 userDidLogin must seed a fallback StartLua state before deep StartLua receives null" >&2
  exit 1
fi

if ! rg -q 'Stage6 StartLua gate payload seeded' "${main_cc}" ||
   ! rg -Fq 'SeedStage6StartLuaGatePayload(payload, "userDidLogin-deep-call")' "${main_cc}"; then
  echo "Stage6 userDidLogin must seed a positive gate payload before StartLuaAppDM returns through the empty gate path" >&2
  exit 1
fi

if ! rg -Fq 'SeedStage6StartLuaGatePayload(payload, "gate-state-load")' "${main_cc}"; then
  echo "Stage6 StartLua gate trace must reseed payload immediately before the native gate compares payload0" >&2
  exit 1
fi

if ! rg -Fq 'ReadPointerIfReadable(payload + 0x08)' "${main_cc}" ||
   ! rg -Fq '*reinterpret_cast<uintptr_t*>(payload + 0x08)' "${main_cc}"; then
  echo "Stage6 StartLua gate payload seed must provide the payload+0x08 list copied into state+0x140" >&2
  exit 1
fi

if ! rg -q 'single-surface-startLuaApp' "${main_cc}" ||
   ! rg -Fq 'InstallStage6StartLuaFallbackCallbackTarget(arg0' "${main_cc}" ||
   ! rg -Fq 'InstallStage6StartLuaFallbackState(arg0' "${main_cc}"; then
  echo "Stage6 single-surface startLuaApp entry must seed fallback callback/state before native StartApp uses empty owner slots" >&2
  exit 1
fi

if ! rg -Uq 'SetEnvDefault\(\s*"MOCKTAIL_PATCH_STAGE6_START_LUA_SINGLE_SURFACE_ENTRY",\s*"1"\s*\)' "${main_cc}" ||
   ! rg -q 'PatchStage6StartLuaSingleSurfaceEntrySetup' "${main_cc}" ||
   ! rg -q 'PatchStage6StartLuaSingleSurfaceEntrySetup\(g_libroblox_base\)' "${main_cc}"; then
  echo "Stage6 single-surface startLuaApp entry setup must be armed by default, independently of verbose deep tracing" >&2
  exit 1
fi

if ! rg -Uq 'SetEnvDefault\(\s*"MOCKTAIL_PATCH_STAGE6_START_LUA_TARGET_TABLE",\s*"1"\s*\)' "${main_cc}" ||
   ! rg -Uq 'SetEnvDefault\(\s*"MOCKTAIL_PATCH_STAGE6_START_LUA_PRIMARY_FROM_OWNER",\s*"1"\s*\)' "${main_cc}" ||
   ! rg -Uq 'SetEnvDefault\(\s*"MOCKTAIL_STAGE6_START_LUA_PRIMARY_SLOT8_SOURCE",\s*"0x850"\s*\)' "${main_cc}" ||
   ! rg -Uq 'SetEnvDefault\(\s*"MOCKTAIL_STAGE6_START_LUA_PRIMARY_SLOT10_SOURCE",\s*"0x858"\s*\)' "${main_cc}" ||
   ! rg -Uq 'SetEnvDefault\(\s*"MOCKTAIL_STAGE6_START_LUA_PRIMARY_SLOT18_SOURCE",\s*"0x418"\s*\)' "${main_cc}"; then
  echo "default StartLuaAppDM must seed owner target tables and source primary state from owner+0x850/0x858/0x418 before callbacks run" >&2
  exit 1
fi

if ! rg -Uq 'SetEnvDefault\(\s*"MOCKTAIL_PATCH_STAGE6_START_LUA_BOXED_TARGET_LOOKUP",\s*"1"\s*\)' "${main_cc}" ||
   ! rg -Uq 'SetEnvDefault\(\s*"MOCKTAIL_PATCH_STAGE6_START_LUA_TARGET_CALLBACK_OBJECT",\s*"1"\s*\)' "${main_cc}" ||
   ! rg -Uq 'SetEnvDefault\(\s*"MOCKTAIL_PATCH_STAGE6_START_LUA_TARGET_CALL_RESULT",\s*"1"\s*\)' "${main_cc}" ||
   ! rg -Uq 'SetEnvDefault\(\s*"MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_RESULT20_PAIR_CALLBACK",\s*"1"\s*\)' "${main_cc}" ||
   ! rg -Uq 'SetEnvDefault\(\s*"MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_RESULT20_SPLIT_CALLBACK_ARGS",\s*"1"\s*\)' "${main_cc}" ||
   ! rg -Uq 'SetEnvDefault\(\s*"MOCKTAIL_PATCH_STAGE6_START_LUA_DISPATCHER_SECOND_PAIR_ARGUMENT",\s*"1"\s*\)' "${main_cc}" ||
   ! rg -Uq 'SetEnvDefault\(\s*"MOCKTAIL_PATCH_STAGE6_START_LUA_RESULT20_LOOKUP_LOW_TREE_TARGET_PAIR",\s*"1"\s*\)' "${main_cc}" ||
   ! rg -Uq 'SetEnvDefault\(\s*"MOCKTAIL_PATCH_STAGE6_START_LUA_RESULT20_FALLBACK_NULL_GLOBAL_SLOT",\s*"1"\s*\)' "${main_cc}"; then
  echo "default StartLuaAppDM must enable the verified boxed-target/result20 recovery path that reaches post-StartApp StartLuaAppDM return without the 0x245e4fc lookup crash" >&2
  exit 1
fi

if ! rg -Uq 'SetEnvDefault\(\s*"MOCKTAIL_START_GAME_WITH_PARAM",\s*"0"\s*\)' "${main_cc}" ||
   ! rg -Uq 'SetEnvDefault\(\s*"MOCKTAIL_SYNC_START_APP_WITH_GAME",\s*"1"\s*\)' "${main_cc}" ||
   ! rg -Uq 'SetEnvDefault\(\s*"MOCKTAIL_SEND_GAME_LOADED",\s*"0"\s*\)' "${main_cc}" ||
   ! rg -Uq 'SetEnvDefault\(\s*"MOCKTAIL_SEND_GAME_LOADED_THREAD",\s*"0"\s*\)' "${main_cc}"; then
  echo "default ASMA/V2 startup must remain LuaApp-only; explicit GAME policy owns StartGame/GameLoaded and the initial surface is carried by StartGameParams" >&2
  exit 1
fi

if rg -q 'MOCKTAIL_UPDATE_SURFACE_GAME_BEFORE_START_GAME|MOCKTAIL_RESUME_GAME_WITH_PLATFORM_PARAMS_AFTER_START_GAME' "${main_cc}"; then
  echo "typed GAME startup must not retain pre-Start UpdateSurface or post-Start Resume diagnostic switches" >&2
  exit 1
fi

if rg -q 'RobloxAccountUserIdForStartupParams|RobloxUserIdForStartupParams|LoadRobloxCookies\(\)\.cookies\.empty\(\) \? 0 : 1' "${main_cc}" ||
   ! rg -Uq 'SetLongField\(env, params, "appUserId", identity\.user_id\);' "${main_cc}" ||
   ! rg -Uq 'SetStringField\(env, params, "username", identity\.username\.c_str\(\)\);' "${main_cc}" ||
   ! rg -Uq 'const std::string& username_value\s*=\s*identity\.username;' "${main_cc}" ||
   ! rg -Uq 'const jlong join_target_user_id\s*=\s*GetEnvLong\("MOCKTAIL_GAME_JOIN_USER_ID",\s*0\);' "${main_cc}" ||
   ! rg -Uq 'SetLongField\(env, params, "userId", join_target_user_id\);' "${main_cc}" ||
   ! rg -Uq 'const jint join_request_type\s*=\s*GetEnvInt\("MOCKTAIL_GAME_JOIN_REQUEST_TYPE",\s*-1\);' "${main_cc}"; then
  echo "StartApp and StartGame identity must come from the typed auth result while the join target remains an independent local-GAME default" >&2
  exit 1
fi

if rg -q 'join_request_type_raw' "${main_cc}" ||
   ! rg -Uq 'const std::string game_id_value\s*=\s*GetEnvString\("MOCKTAIL_GAME_ID",\s*""\);' "${main_cc}" ||
   rg -q 'std::to_string\(place_id\)|game_id_value\s*=\s*"0"' "${main_cc}" ||
   ! rg -Uq 'const std::string referral_page_value\s*=\s*GetEnvString\("MOCKTAIL_REFERRAL_PAGE",\s*""\);' "${main_cc}" ||
   ! rg -Uq 'SetObjectField\(env, params, "deviceParams",\s*"Lcom/roblox/engine/jni/model/DeviceParams;",\s*nullptr\);' "${main_cc}"; then
  echo "StartGameParams defaults must match the APK builder: joinRequestType=-1, empty identity/referral/gameId, and null deviceParams" >&2
  exit 1
fi

if ! rg -q 'ResolveRobloxGameSessionSymbols\(capability_lookup\)' "${main_cc}" ||
   ! rg -q 'std::make_unique<mocktail::runtime::RobloxGameSessionRuntime>' "${main_cc}" ||
   ! rg -q 'context->game_session_runtime->InitializeAndStart' "${main_cc}" ||
   ! rg -q 'game_session_runtime->Shutdown\(\)' "${main_cc}" ||
   rg -q 'NativeUpdateSurfaceGameFn|NativeResumeGameWithPlatformParamsFn|context->native_start_game_with_param|native_update_surface_game\(|native_resume_game_with_platform_params\(' "${main_cc}"; then
  echo "production GAME startup and shutdown must cross only the typed RobloxGameSessionRuntime boundary" >&2
  exit 1
fi

if ! rg -q 'TryReturnFromStage6UpdateSurfaceNonCodeCallback' "${main_cc}" ||
   ! rg -q 'skipped Stage6 UpdateSurface non-code callback target' "${main_cc}" ||
   ! rg -q 'mocktail_stage6_start_lua_target_callback_resume_state' "${main_cc}" ||
   ! rg -q 'mocktail_stage6_start_lua_target_callback_resume_graphics' "${main_cc}" ||
   ! rg -q 'mocktail_stage6_start_lua_target_callback_surface_params' "${main_cc}" ||
   ! rg -Fq 'g_stage6_start_lua_target_callback_object_vtable[5]' "${main_cc}" ||
   ! rg -Fq 'g_stage6_start_lua_target_callback_object_vtable[17]' "${main_cc}"; then
  echo "UpdateSurface/ResumeGame recovery must skip non-code callback targets and synthetic target+0x438 must expose the resume-state/resume-graphics slots used before graphics resume" >&2
  exit 1
fi

if ! rg -q 'kSendAppEventGameLoadedReturnOffset\s*=\s*0x2f50db7' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_STAGE6_SEND_APP_EVENT_DISPATCH_GAME_LOADED' "${main_cc}" ||
   ! rg -q 'notification_type = "GAME_LOADED"' "${main_cc}" ||
   ! rg -Fq 'Stage6 SendAppEvent dispatched %s to JNI' "${main_cc}"; then
  echo "Stage6 SendAppEvent fallback must dispatch GAME_LOADED separately from APP_READY instead of reusing the AppReady notification" >&2
  exit 1
fi

if ! rg -Fq 'SeedStage6StartLuaTargetTableFallback(arg0, 0)' "${main_cc}" ||
   ! rg -Fq 'SeedStage6StartLuaTargetTableFallback(arg0, 1)' "${main_cc}"; then
  echo "Stage6 single-surface startLuaApp entry must seed fallback target tables before userDidLogin sees null owner table slots" >&2
  exit 1
fi

if ! rg -q 'PatchStage6StartLuaAppDMGlobalLoadSetup' "${main_cc}" ||
   ! rg -Fq 'PatchStage6StartLuaAppDMGlobalLoadSetup(g_libroblox_base)' "${main_cc}" ||
   ! rg -q 'Stage6 StartLuaAppDM global target-table setup' "${main_cc}" ||
   ! rg -Fq 'SeedStage6StartLuaTargetTableFallback(global, 0)' "${main_cc}" ||
   ! rg -Fq 'SeedStage6StartLuaTargetTableFallback(global, 1)' "${main_cc}"; then
  echo "Stage6 StartLuaAppDM must seed target tables on the native global manager, not only the StartApp owner" >&2
  exit 1
fi

if ! rg -q 'trace_logged_in' "${main_cc}" ||
   ! rg -q 'needs_target_table_hooks' "${main_cc}" ||
   ! rg -Fq '(!trace_gate && !trace_logged_in)' "${main_cc}" ||
   ! rg -Fq 'if (trace_gate)' "${main_cc}" ||
   ! rg -Fq 'if (trace_logged_in)' "${main_cc}" ||
   ! rg -Fq 'if (needs_target_table_hooks)' "${main_cc}"; then
  echo "Stage6 logged-in helper tracing must be armable without enabling the broader StartLua gate trace" >&2
  exit 1
fi

global_seed_line=$(rg -n -F 'SeedStage6StartLuaTargetTableFallback(global, 0)' "${main_cc}" | head -n1 | cut -d: -f1)
global_dispatch_line=$(rg -n -F 'ucontext->uc_mcontext.gregs[REG_RDI] = static_cast<greg_t>(global)' "${main_cc}" | head -n1 | cut -d: -f1)
if [[ -z "${global_seed_line}" || -z "${global_dispatch_line}" ||
      "${global_seed_line}" -gt "${global_dispatch_line}" ]]; then
  echo "Stage6 StartLuaAppDM global target table must be seeded before the global object is passed into native dispatch" >&2
  exit 1
fi

if ! rg -Uq 'SeedStage6StartLuaPrimaryStateFromOwner\(\s*arg0,\s*"single-surface-startLuaApp"\s*\)' "${main_cc}"; then
  echo "Stage6 single-surface startLuaApp entry must seed primary StartLua state before logged-in helper sees null object fields" >&2
  exit 1
fi

target_table_line=$(rg -n -F 'SeedStage6StartLuaTargetTableFallback(arg0, 0)' "${main_cc}" | head -n1 | cut -d: -f1)
primary_state_line=$(rg -n -F 'SeedStage6StartLuaPrimaryStateFromOwner(arg0' "${main_cc}" | head -n1 | cut -d: -f1)
if [[ -z "${target_table_line}" || -z "${primary_state_line}" ||
      "${target_table_line}" -gt "${primary_state_line}" ]]; then
  echo "Stage6 single-surface owner target tables must be seeded before primary StartLua state can source owner+0x850/0x858" >&2
  exit 1
fi

if rg -Uq 'resolve_owner_source[\s\S]{0,500}offset < 0x800' "${main_cc}" ||
   ! rg -Uq 'resolve_owner_source[\s\S]{0,500}offset < 0x1000' "${main_cc}"; then
  echo "Stage6 primary owner source parser must accept target-table offsets such as owner+0x850/0x858" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StartLuaTargetTableDynamicCastTypeReadOffset\s*=\s*0x2bfcedd' "${main_cc}" ||
   ! rg -q 'g_stage6_start_lua_target_table_vtable_storage' "${main_cc}" ||
   ! rg -q 'SeedStage6StartLuaTargetTableScratchVtable' "${main_cc}" ||
   ! rg -Fq 'g_stage6_start_lua_target_table_vtable_storage + 2' "${main_cc}" ||
   ! rg -Uq 'recovered Stage6 StartLua target-table dynamic-cast\s*"[^"]*"\s*type-info' "${main_cc}"; then
  echo "Stage6 synthetic StartLua target table must provide an ABI vtable pre-header and recover the dynamic-cast type-info read" >&2
  exit 1
fi

if ! rg -Fq 'g_stage6_start_lua_target_table_vtable_storage[2 + 6]' "${main_cc}" ||
   ! rg -q 'mocktail_stage6_start_lua_return_self_1a0' "${main_cc}" ||
   ! rg -Fq 'Stage6 StartLua synthetic self+1a0 returner' "${main_cc}" ||
   ! rg -q 'result_looks_like_object' "${main_cc}"; then
  echo "Stage6 synthetic StartLua target table slot 6 must return only valid native-populated target+0x1a0 objects instead of a broad null/no-op" >&2
  exit 1
fi

if ! rg -q 'mocktail_stage6_start_lua_return_size_40000' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_STAGE6_START_LUA_TARGET_TABLE_SLOT6_SOURCE' "${main_cc}"; then
  echo "Stage6 synthetic StartLua target table slot 6 needs an opt-in size-return mode because resolver treats the slot result as a memory-size request" >&2
  exit 1
fi

if ! rg -q 'result20_fields' "${main_cc}"; then
  echo "Stage6 StartLua target-result diagnostics must inspect the nested result+0x20 continuation state" >&2
  exit 1
fi

if ! rg -q 'MOCKTAIL_PATCH_STAGE6_START_LUA_TARGET_CALLBACK_OBJECT' "${main_cc}" ||
   ! rg -q 'InstallStage6StartLuaTargetCallbackObject' "${main_cc}" ||
   ! rg -Fq 'g_stage6_start_lua_target_callback_object_vtable[3]' "${main_cc}" ||
   ! rg -Fq 'g_stage6_start_lua_target_callback_object_vtable[4]' "${main_cc}" ||
   ! rg -q 'target438=%p installed_target438=%p' "${main_cc}"; then
  echo "Stage6 post-apply target-call diagnostics must be able to seed and log target+0x438 callback object slots 0x18/0x20" >&2
  exit 1
fi

if ! rg -q 'MOCKTAIL_PATCH_STAGE6_START_LUA_TARGET_CALL_RESULT' "${main_cc}" ||
   ! rg -q 'patched_target_result=%p' "${main_cc}" ||
   ! rg -Fq 'ReadPointerIfReadable(target + 0x1a0)' "${main_cc}"; then
  echo "Stage6 post-apply target-call must be able to replace invalid wrapper results with target+0x1a0 under an explicit flag" >&2
  exit 1
fi

if ! rg -q 'MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_RESULT20_CALLBACK' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_RESULT20_PAIR_CALLBACK' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_RESULT20_SPLIT_CALLBACK_ARGS' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_RESULT20_PREFER_RESULT_PAIR' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_PATCH_STAGE6_START_LUA_RESOLVER_RESULT20_BACKFILL_OWNER_REF' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaTargetPostApplyTaskThunkCallbackCallOffset\s*=\s*0x26cee6e' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaTargetPostApplyTaskThunkAfterCallbackOffset\s*=\s*0x26cee70' "${main_cc}" ||
   ! rg -q 'g_stage6_start_lua_result20_callback_context_scratch' "${main_cc}" ||
   ! rg -q 'result20_callback_arg=%p result20_callback_in_text=%d' "${main_cc}" ||
   ! rg -q 'prefer_result20_pair_arg=%d' "${main_cc}" ||
   ! rg -q 'backfilled_owner_ref=%d' "${main_cc}" ||
   ! rg -q 'split_args=%d' "${main_cc}" ||
   ! rg -Fq 'Stage6 StartLua post-apply task thunk after callback' "${main_cc}" ||
   ! rg -Fq 'Stage6 StartLua resolver result20 split callback context' "${main_cc}" ||
   ! rg -Fq 'Stage6 StartLua resolver result20 callback materialized' "${main_cc}"; then
  echo "Stage6 resolver diagnostics must be able to materialize result+0x20 callback pairs under an explicit flag and split callback context/source args at the native call site" >&2
  exit 1
fi

if ! rg -q 'kStage6StartLuaResult20LookupTreeReadOffset\s*=\s*0x245e4e3' "${main_cc}" ||
   ! rg -q 'kStage6StartLuaResult20LookupEmptyReturnOffset\s*=\s*0x245e51c' "${main_cc}" ||
   ! rg -q 'kStage6StartLuaResult20FallbackGlobalSlotReadOffset\s*=' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_PATCH_STAGE6_START_LUA_RESULT20_LOOKUP_LOW_TREE_EMPTY' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_PATCH_STAGE6_START_LUA_RESULT20_LOOKUP_LOW_TREE_TARGET_PAIR' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_PATCH_STAGE6_START_LUA_RESULT20_FALLBACK_NULL_GLOBAL_SLOT' "${main_cc}" ||
   ! rg -Fq 'Stage6 StartLua result20 lookup tree-read' "${main_cc}" ||
   ! rg -Fq 'Stage6 StartLua result20 fallback global slot null' "${main_cc}" ||
   ! rg -Fq 'tree_unreadable=%d forced_target_pair=%d' "${main_cc}" ||
   ! rg -q 'owner_pair_readable=%d' "${main_cc}"; then
  echo "Stage6 result20 lookup diagnostics must log and explicitly guard the low/tree-empty/target-pair/fallback-null recovery path" >&2
  exit 1
fi

if ! rg -Uq 'proc_context == selected[\s\S]{0,160}current_proc = selected' "${main_cc}" ||
   ! rg -q 'forced_scheduler_proc=%d' "${main_cc}"; then
  echo "Stage6 resolver scheduler proc recovery must handle proc_context==selected by forcing the register without writing into the selected proc state slot" >&2
  exit 1
fi

if ! rg -q 'kStage6StartLuaResolverTaskCreateOffset\s*=\s*0x2788030' "${main_cc}" ||
   ! rg -Fq 'Stage6 StartLua resolver task create' "${main_cc}"; then
  echo "Stage6 StartLua resolver diagnostics must log the task creation argument pointers that carry target_result into the scheduler" >&2
  exit 1
fi

if ! rg -q 'kStage6StartLuaResolverAfterTaskBuildOffset\s*=\s*0x277ff3c' "${main_cc}" ||
   ! rg -Fq 'Stage6 StartLua resolver after task-build' "${main_cc}" ||
   ! rg -Fq 'caller_out=%p caller_out_fields' "${main_cc}" ||
   ! rg -Fq 'kStage6StartLuaResolverAfterTaskBuildOffset + 4' "${main_cc}"; then
  echo "Stage6 StartLua resolver diagnostics must log the out-slot immediately after task build while emulating the skipped stack unwind instruction" >&2
  exit 1
fi

if ! rg -Fq 'task_arg_fields{0=%p 8=%p 10=%p 18=%p 20=%p 28=%p' "${main_cc}"; then
  echo "Stage6 StartLua resolver closure diagnostics must include task_arg callback capture slots 0x10/0x18 before adding behavioral patches" >&2
  exit 1
fi

if ! rg -q 'MOCKTAIL_PATCH_STAGE6_START_LUA_POST_APPLY_PAIR_ARGUMENT' "${main_cc}" ||
   ! rg -Fq 'force_pair_argument=%d force_null_argument=%d' "${main_cc}"; then
  echo "Stage6 post-apply callback diagnostics must keep pair-argument and null-argument paths explicit in trace logs" >&2
  exit 1
fi

if ! rg -q 'MOCKTAIL_PATCH_STAGE6_START_LUA_DISPATCHER_SECOND_PAIR_ARGUMENT' "${main_cc}" ||
   ! rg -Uq 'kStage6StartLuaDispatcherSecondInvokeCallOffset\s*=\s*0x277c086' "${main_cc}" ||
   ! rg -Fq 'Stage6 StartLua dispatcher second invoke' "${main_cc}" ||
   ! rg -Fq 'force_pair_argument=%d pair_fields' "${main_cc}"; then
  echo "Stage6 dispatcher second invoke must keep pair-argument recovery explicit and jump to the native call site after setting rdi/rsi" >&2
  exit 1
fi

if ! rg -q 'PatchStage6StartLuaUserDidLoginStateLoadRecovery' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_PATCH_STAGE6_START_LUA_USER_DID_LOGIN_STATE_LOAD' "${main_cc}"; then
  echo "Stage6 userDidLogin state-load recovery must be armed independently of deep tracing" >&2
  exit 1
fi

if ! rg -q 'SIG in nativeAppBridgeV2InitWithParams: ' "${main_cc}" ||
   ! rg -q 'r15=%p' "${main_cc}" ||
   ! rg -q 'r14=%p' "${main_cc}" ||
   ! rg -q 'stack0=%p stack0_off=0x%lx' "${main_cc}" ||
   ! rg -q 'frame_ret=%p frame_ret_off=0x%lx' "${main_cc}"; then
  echo "nativeAppBridgeV2InitWithParams recovery must log RIP/off and registers before longjmp so owner-state init crashes can be rooted" >&2
  exit 1
fi

if ! rg -Uq 'kStage6InitSystemDialogNullResultReadOffset\s*=\s*0x2cb74f9' "${main_cc}" ||
   ! rg -Uq 'kStage6InitSystemDialogNullTestOffset\s*=\s*0x2cb74fc' "${main_cc}" ||
   ! rg -q 'Stage6 init system-dialog null result: ' "${main_cc}" ||
   ! rg -q 'taking native null path rip_off=0x%lx' "${main_cc}"; then
  echo "nativeAppBridgeV2InitWithParams must recover its system-dialog null result locally instead of longjmping the whole V2 init" >&2
  exit 1
fi

if ! rg -Uq 'kStage6UnsupportedMessageListHolderNullReadOffset\s*=\s*0x41335bf' "${main_cc}" ||
   ! rg -q 'Stage6 unsupported-message list holder null: ' "${main_cc}" ||
   ! rg -q 'treating as empty rip_off=0x%lx' "${main_cc}"; then
  echo "Stage6 unsupported-message list holder null reads must take the same empty-list path as null message lists" >&2
  exit 1
fi

if ! rg -q 'g_stage6_init_params_holder_scratch' "${main_cc}" ||
   ! rg -Fq '*reinterpret_cast<uintptr_t*>(dest + 0x00) =' "${main_cc}" ||
   ! rg -q 'holder=%p rip_off=0x%lx' "${main_cc}"; then
  echo "Stage6 init-param aggregate null source must seed a writable holder pointer before later init-param writes use dest+0" >&2
  exit 1
fi

if ! rg -q 'MOCKTAIL_PATCH_STAGE6_INIT_NON_CODE_CALLBACK' "${main_cc}" ||
   ! rg -q 'g_init_with_params_recovery_in_progress != 0' "${main_cc}" ||
   ! rg -q 'skipped Stage6 init non-code callback target' "${main_cc}"; then
  echo "Stage6 init must recover non-code callback targets locally instead of longjmping nativeAppBridgeV2InitWithParams" >&2
  exit 1
fi

if ! rg -Uq 'kStage6PostClientSettingsSingletonLockReadOffset\s*=\s*0x23ae827' "${main_cc}" ||
   ! rg -Uq 'kStage6PostClientSettingsSingletonLockGlobalOffset\s*=\s*0x73fabc8' "${main_cc}" ||
   ! rg -q 'g_stage6_post_client_settings_singleton_lock_scratch' "${main_cc}" ||
   ! rg -q 'Stage6 init singleton lock missing: ' "${main_cc}" ||
   ! rg -Fq '*reinterpret_cast<uintptr_t*>(global) = scratch' "${main_cc}" ||
   ! rg -Fq '*reinterpret_cast<uintptr_t*>(saved_rbx_slot) = scratch' "${main_cc}"; then
  echo "Stage6 V2 init must seed the skipped post-client-settings singleton lock global before lazy singleton init dereferences it" >&2
  exit 1
fi

if ! rg -q '0x23a65fb,  // Stage6 post-client-settings singleton constructor tail check.' "${main_cc}" ||
   ! rg -q '0x23a67fb,  // Stage6 post-client-settings inner singleton helper tail check.' "${main_cc}" ||
   ! rg -q '0x23ae7f2,  // Stage6 post-client-settings callback tail check.' "${main_cc}" ||
   ! rg -q '0x233939d,  // Stage6 StartLuaDM dispatcher tail check.' "${main_cc}" ||
   ! rg -q '0x243bff9,  // nativeAppBridgeV2InitWithParams tail check after post-client-settings singleton init.' "${main_cc}" ||
   ! rg -q '0x2311bde,  // Stage6 logging timestamp tail check during StartApp.' "${main_cc}"; then
  echo "Stage6 post-client-settings singleton stack-canary branches must be patched like the other Bionic/libc guard mismatches" >&2
  exit 1
fi

if ! rg -q 'stack check bridge entered caller=' "${main_cc}" ||
   ! rg -q 'parent_ret_off=0x%lx' "${main_cc}" ||
   ! rg -q 'grand_ret_off=0x%lx' "${main_cc}" ||
   ! rg -Fq 'linker::RegisterSymbol("__stack_chk_fail", reinterpret_cast<void*>(mocktail_recover_stack_chk_fail))' "${main_cc}"; then
  echo "Bionic __stack_chk_fail must route through the Mocktail stack-check bridge with caller diagnostics instead of host libc abort" >&2
  exit 1
fi

if ! rg -Uq 'kStage6InitHelperStackFailLandingOffset\s*=\s*0x243c00f' "${main_cc}" ||
   ! rg -Uq 'kStage6InitHelperStackFailCleanupOffset\s*=\s*0x243bffb' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppLoggingStackFailLandingOffset\s*=\s*0x2311bf9' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppLoggingStackFailCleanupOffset\s*=\s*0x2311be0' "${main_cc}" ||
   ! rg -q 'PatchStage6StackCheckExceptionLandings\(g_libroblox_base\)' "${main_cc}" ||
   ! rg -q 'Stage6 stack-check exception landing ' "${main_cc}"; then
  echo "Stage6 stack-check exception landings must jump to native cleanup instead of aborting V2 init/StartApp" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StartAppLoggingHashBucketReadOffset\s*=\s*0x2311e3e' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppLoggingHashEmptyReturnOffset\s*=\s*0x2311f57' "${main_cc}" ||
   ! rg -q 'kStage6StartAppLoggingHashWrapperBucketReadOffset' "${main_cc}" ||
   ! rg -q '0x23113d7' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppLoggingHashWrapperReturnOffset\s*=\s*0x231140e' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppLoggingHashCapacityReadOffset\s*=\s*0x42d4c8e' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppLoggingHashCapacityReturnOffset\s*=\s*0x42d4c9f' "${main_cc}" ||
   ! rg -q 'Stage6 StartApp logging hash table missing: returning' "${main_cc}" ||
   ! rg -q 'Stage6 StartApp logging hash wrapper missing:' "${main_cc}" ||
   ! rg -q 'Stage6 StartApp logging hash capacity missing:' "${main_cc}" ||
   ! rg -q 'gregs\[REG_RBX\] = 0' "${main_cc}" ||
   ! rg -q 'kStage6StartAppLoggingHashEmptyReturnOffset' "${main_cc}"; then
  echo "Stage6 StartApp logging hash helper must recover null backing arrays as empty misses instead of aborting StartApp" >&2
  exit 1
fi

if rg -q 'g_stage6_start_app_map_owner_scratch' "${main_cc}" ||
   rg -Uq 'kStage6MapLookupLowOwnerReadOffset[\s\S]{0,700}Stage6 map lookup low owner: using scratch owner' "${main_cc}" ||
   ! rg -q 'kStage6MapLookupLowOwnerReadOffset' "${main_cc}" ||
   ! rg -q 'kStage6MapLookupUnlockAndReturnOffset' "${main_cc}" ||
   ! rg -q 'Stage6 map lookup low owner: returning null' "${main_cc}"; then
  echo "Stage6 StartApp generic map lookup must return an empty miss for a missing owner instead of creating synthetic owner entries that can escape as callbacks" >&2
  exit 1
fi

if ! rg -q 'g_stage6_string_field_value_scratch' "${main_cc}" ||
   ! rg -q 'SeedStage6StringFieldValueScratch' "${main_cc}" ||
   ! rg -q 'Stage6 string map lookup low owner: using scratch string' "${main_cc}" ||
   ! rg -q 'kStage6StringMapLookupLowOwnerReadOffset' "${main_cc}" ||
   ! rg -q 'g_stage6_string_field_null_current_loop_count = 0' "${main_cc}"; then
  echo "Stage6 StartApp/StartLua string-map lookup must seed a real string holder instead of returning null into the string-field setter loop" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StringFieldNullLoopLimit\s*=\s*256' "${main_cc}" ||
   ! rg -Uq 'kStage6StringFieldLoopReturnOffset\s*=\s*0x233c0b2' "${main_cc}" ||
   ! rg -q 'g_stage6_string_field_null_current_loop_count' "${main_cc}" ||
   ! rg -q 'Stage6 string field null current loop: returning from helper' "${main_cc}" ||
   ! rg -q 'TryReturnFromRepeatedStage6StringFieldLoop' "${main_cc}"; then
  echo "Stage6 repeated string-field null repairs must return from the local helper instead of longjmping all StartApp" >&2
  exit 1
fi

if ! rg -Uq 'kStage6NestedHashLookupLowTableReadOffset\s*=\s*0x2df8c80' "${main_cc}" ||
   ! rg -Uq 'kStage6NestedHashLookupEmptyPathOffset\s*=\s*0x2df8cf9' "${main_cc}" ||
   ! rg -q 'Stage6 nested hash lookup low table: using empty path' "${main_cc}"; then
  echo "Stage6 nested map insertion lookup must treat low table pointers as an empty native miss instead of aborting StartApp" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StringReleaseNullOwnerReadOffset\s*=\s*0x233c13c' "${main_cc}" ||
   ! rg -q 'g_stage6_start_app_release_owner_scratch' "${main_cc}" ||
   ! rg -q 'Stage6 string release null owner: using scratch owner' "${main_cc}" ||
   ! rg -Fq 'gregs[REG_RBX] = static_cast<greg_t>(scratch)' "${main_cc}" ||
   ! rg -Fq 'gregs[REG_R14] = static_cast<greg_t>(scratch + 0x28)' "${main_cc}"; then
  echo "Stage6 StartApp string release cleanup must use a scratch owner when the native owner is null instead of aborting StartApp" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StartAppPayloadMapNullOwnerReadOffset\s*=\s*0x6a9f90d' "${main_cc}" ||
   ! rg -q 'g_stage6_start_app_payload_owner_scratch' "${main_cc}" ||
   ! rg -q 'Stage6 StartApp/StartLua payload map null owner: using scratch owner' "${main_cc}" ||
   ! rg -Fq 'g_start_lua_app_dm_recovery_in_progress != 0' "${main_cc}" ||
   ! rg -Fq 'instruction[0] == 0x48 && instruction[1] == 0x8b &&' "${main_cc}" ||
   ! rg -Fq 'instruction[2] == 0x7b && instruction[3] == 0x28' "${main_cc}"; then
  echo "Stage6 StartApp payload map lookup must continue on a scratch owner instead of aborting when owner is null" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StartAppPayloadHashLowTableReadOffset\s*=\s*0x48ba127' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppPayloadHashEmptyPathOffset\s*=\s*0x48ba179' "${main_cc}" ||
   ! rg -q 'Stage6 StartApp/StartLua payload hash low table: using empty path' "${main_cc}" ||
   ! rg -Fq 'g_start_lua_app_dm_recovery_in_progress != 0' "${main_cc}" ||
   ! rg -Fq 'instruction[0] == 0x44 && instruction[1] == 0x8b &&' "${main_cc}" ||
   ! rg -Fq 'instruction[2] == 0x6f && instruction[3] == 0x10' "${main_cc}"; then
  echo "Stage6 StartApp payload hash lookup must treat low table pointers as empty misses instead of aborting StartApp" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StartAppPayloadLinkLoadOffset\s*=\s*0x48bbb7d' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppPayloadLinkStoreOffset\s*=\s*0x48bbb89' "${main_cc}" ||
   ! rg -q 'g_stage6_start_app_payload_link_slot' "${main_cc}" ||
   ! rg -q 'Stage6 StartApp/StartLua payload link null slot: using scratch slot' "${main_cc}" ||
   ! rg -Fq 'g_start_lua_app_dm_recovery_in_progress != 0' "${main_cc}" ||
   ! rg -Fq 'instruction[0] == 0x48 && instruction[1] == 0x8b &&' "${main_cc}" ||
   ! rg -Fq 'instruction[0] == 0x48 && instruction[1] == 0x89 &&' "${main_cc}"; then
  echo "Stage6 StartApp/StartLua payload link-slot getter must continue on a scratch pointer slot instead of longjmping all StartApp/StartLua" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StartAppPayloadMapLookupLowOwnerReadOffset\s*=\s*0x48b9f2a' "${main_cc}" ||
   ! rg -q 'Stage6 StartApp/StartLua payload map lookup low owner: using scratch owner' "${main_cc}" ||
   ! rg -Fq 'libroblox_offset == kStage6StartAppPayloadMapLookupLowOwnerReadOffset' "${main_cc}" ||
   ! rg -Fq 'g_start_lua_app_dm_recovery_in_progress != 0' "${main_cc}" ||
   ! rg -Fq 'gregs[REG_R14] = static_cast<greg_t>(scratch + 0x28)' "${main_cc}"; then
  echo "Stage6 StartApp payload map insertion must continue with a scratch owner after a low-table miss" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StartAppCollectionManagerNullReadOffset\s*=\s*0x51f2b09' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppCollectionManagerReturnOffset\s*=\s*0x51f2af3' "${main_cc}" ||
   ! rg -q 'Stage6 StartApp/StartLua collection manager null: returning no-op' "${main_cc}" ||
   ! rg -Fq 'g_start_lua_app_dm_recovery_in_progress != 0' "${main_cc}" ||
   ! rg -Fq 'kStage6StartAppCollectionManagerReturnOffset' "${main_cc}"; then
  echo "Stage6 StartApp/StartLua collection helper must return locally when its manager slot is null" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StartAppFallbackHandlerNullReadOffset\s*=\s*0x2460b0d' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppFallbackHandlerAfterCallOffset\s*=\s*0x2460b13' "${main_cc}" ||
   ! rg -q 'Stage6 StartApp fallback handler null: returning empty' "${main_cc}" ||
   ! rg -Fq 'g_start_lua_app_dm_recovery_in_progress != 0' "${main_cc}"; then
  echo "Stage6 StartApp fallback handler must return an empty result when the headless handler slot is null" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StartAppParamsField40AllocReturnOffset\s*=\s*0x244954f' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppParamsField60AllocReturnOffset\s*=\s*0x24495af' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppParamsField0AllocReturnOffset\s*=\s*0x2449645' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppParamsField20AllocReturnOffset\s*=\s*0x24496e0' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppParamsVectorBackingAllocReturnOffset\s*=\s*0x2447eec' "${main_cc}" ||
   ! rg -q 'PatchStage6StartAppParamsAllocationFallback\(g_libroblox_base\)' "${main_cc}" ||
   ! rg -q 'Stage6 StartApp params allocation fallback' "${main_cc}" ||
   ! rg -q 'Stage6 StartApp params vector backing allocation fallback' "${main_cc}" ||
   ! rg -q 'g_stage6_start_app_params_vector_backing_scratch' "${main_cc}" ||
   ! rg -q 'g_stage6_start_app_params_field0_scratch' "${main_cc}" ||
   ! rg -q 'g_stage6_start_app_params_field20_scratch' "${main_cc}" ||
   ! rg -q 'g_stage6_start_app_params_field40_scratch' "${main_cc}" ||
   ! rg -q 'g_stage6_start_app_params_field60_scratch' "${main_cc}"; then
  echo "Stage6 StartApp params allocation must replace null allocator results at exact post-call sites instead of skipping OOM guards" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StartAppInstanceArgProbeOffset\s*=\s*0x25fca9b' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_TRACE_STAGE6_START_APP_INSTANCE_ARG' "${main_cc}" ||
   ! rg -q 'Stage6 StartApp instance-arg cast' "${main_cc}" ||
   ! rg -Fq 'gregs[REG_RAX] = static_cast<greg_t>(vtable)' "${main_cc}" ||
   ! rg -Fq 'kStage6StartAppInstanceArgProbeOffset + 3' "${main_cc}"; then
  echo "Stage6 StartApp Instance-argument cast must have a gated trace point that logs the native callback payload without bypassing the cast" >&2
  exit 1
fi

if ! rg -Uq 'kStage6DataModelPatchHelperInitialReturnProbeOffset\s*=\s*0x2462249' "${main_cc}" ||
   ! rg -Uq 'kStage6DataModelPatchHelperConfigReturnProbeOffset\s*=\s*0x24623bd' "${main_cc}" ||
   ! rg -Uq 'kStage6DataModelPatchHelperProviderReturnProbeOffset\s*=\s*0x2462831' "${main_cc}" ||
   ! rg -Uq 'kStage6DataModelPatchHelperReturnProbeOffset\s*=\s*0x24648a7' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_TRACE_STAGE6_DATAMODEL_PATCH_HELPER' "${main_cc}" ||
   ! rg -q 'PatchStage6DataModelPatchHelperReturnTrace' "${main_cc}" ||
   ! rg -q 'Stage6 DataModel patch helper return' "${main_cc}" ||
   ! rg -Fq 'gregs[REG_RBX] = static_cast<greg_t>(status)' "${main_cc}" ||
   ! rg -Fq 'data_model_patch_helper_return_sites' "${main_cc}" ||
   ! rg -Fq 'probe_offset + 3' "${main_cc}"; then
  echo "Stage6 DataModel patch helper trace must log every native getCachedPatch return and emulate the post-call mov without changing behavior" >&2
  exit 1
fi

if ! rg -Uq 'kStage6DataModelPatchTerminalFlagReadProbeOffset\s*=\s*0x2463bc5' "${main_cc}" ||
   ! rg -Uq 'kStage6ReThrowGetCachedPatchExceptionFlagOffset\s*=\s*0x73cf050' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_TRACE_STAGE6_DATAMODEL_PATCH_TERMINAL' "${main_cc}" ||
   ! rg -q 'PatchStage6DataModelPatchTerminalTrace' "${main_cc}" ||
   ! rg -q 'Stage6 DataModel patch terminal' "${main_cc}" ||
   ! rg -Fq 'flag_read_offset + 6' "${main_cc}" ||
   ! rg -Fq 'gregs[REG_RAX] = static_cast<greg_t>((rax & ~0xffULL) | flag)' "${main_cc}"; then
  echo "Stage6 DataModel patch terminal trace must log the ReThrowGetCachedPatchException gate and emulate the flag-byte load" >&2
  exit 1
fi

if ! rg -Uq 'kStage6DataModelPatchOpenStreamReturnProbeOffset\s*=\s*0x2462aff' "${main_cc}" ||
   ! rg -Uq 'kStage6DataModelPatchInlineLoadReturnProbeOffset\s*=\s*0x2462c19' "${main_cc}" ||
   ! rg -Uq 'kStage6DataModelPatchInlineBuildResultProbeOffset\s*=\s*0x2462dce' "${main_cc}" ||
   ! rg -Uq 'kStage6DataModelPatchInnerLoaderStatusProbeOffset\s*=\s*0x2418e86' "${main_cc}" ||
   ! rg -Uq 'kStage6DataModelPatchInnerLoaderReturnProbeOffset\s*=\s*0x2419015' "${main_cc}" ||
   ! rg -Uq 'kStage6DataModelPatchBuildListEmptyBranchProbeOffset\s*=\s*0x5f9f802' "${main_cc}" ||
   ! rg -Uq 'kStage6DataModelPatchBuildContentNullBranchProbeOffset\s*=\s*0x5f9f812' "${main_cc}" ||
   ! rg -Uq 'kStage6DataModelPatchBuildContentEmptyBranchProbeOffset\s*=\s*0x5f9f81f' "${main_cc}" ||
   ! rg -Uq 'kStage6DataModelPatchBuildFeatureGateBranchProbeOffset\s*=\s*0x5f9f873' "${main_cc}" ||
   ! rg -Uq 'kStage6DataModelPatchBuildFallbackStatusProbeOffset\s*=\s*0x5f9fa94' "${main_cc}" ||
   ! rg -Uq 'kStage6DataModelPatchBuildDeserializeReturnProbeOffset\s*=\s*0x5f9f7b7' "${main_cc}" ||
   ! rg -Uq 'kStage6RbxmDeserializerSummaryProbeOffset\s*=\s*0x2dea942' "${main_cc}" ||
   ! rg -Uq 'kStage6DataModelPatchVerifyBuildStatusProbeOffset\s*=\s*0x5f9f93e' "${main_cc}" ||
   ! rg -Uq 'kStage6DataModelPatchVerifyStatusReturnProbeOffset\s*=\s*0x2462ff2' "${main_cc}" ||
   ! rg -Uq 'kStage6DataModelPatchFinalResultProbeOffset\s*=\s*0x246357c' "${main_cc}" ||
   ! rg -q 'MOCKTAIL_TRACE_STAGE6_DATAMODEL_PATCH_LOAD_STEPS' "${main_cc}" ||
   ! rg -q 'PatchStage6DataModelPatchLoadStepTrace' "${main_cc}" ||
   ! rg -q 'Stage6 DataModel patch load step' "${main_cc}" ||
   ! rg -q 'build-list-empty' "${main_cc}" ||
   ! rg -q 'build-content-null' "${main_cc}" ||
   ! rg -q 'build-content-empty' "${main_cc}" ||
   ! rg -q 'build-feature-gate' "${main_cc}" ||
   ! rg -q 'build-fallback-status' "${main_cc}" ||
   ! rg -q 'build-deserialize-return' "${main_cc}" ||
   ! rg -q 'rbxm-deserialize-summary' "${main_cc}" ||
   ! rg -q 'verify-build-status' "${main_cc}" ||
   ! rg -Fq 'gregs[REG_EFL] & 0x40' "${main_cc}" ||
   ! rg -Fq 'take_branch ? taken_offset : fallthrough_offset' "${main_cc}" ||
   ! rg -Fq 'gregs[REG_RDI] = static_cast<greg_t>(rbp - 0x3d0)' "${main_cc}" ||
   ! rg -Fq 'gregs[REG_RBX] = static_cast<greg_t>(ReadPointerIfReadable(rbp - 0x98))' "${main_cc}" ||
   ! rg -Fq 'gregs[REG_RIP] = static_cast<greg_t>(rbx == 0 ? libroblox_base + 0x2462df6 : libroblox_base + 0x2462dd1)' "${main_cc}" ||
   ! rg -Fq 'gregs[REG_RIP] = static_cast<greg_t>(status == 1 ? libroblox_base + 0x2418e8f : libroblox_base + 0x241902e)' "${main_cc}" ||
   ! rg -Fq 'gregs[REG_RAX] = static_cast<greg_t>(ReadPointerIfReadable(rbp - 0x108))' "${main_cc}" ||
   ! rg -Fq 'gregs[REG_RDI] = static_cast<greg_t>(ReadPointerIfReadable(rbp - 0x3f8))' "${main_cc}" ||
   ! rg -Fq 'gregs[REG_R14] = static_cast<greg_t>(eax & 0xffffffffULL)' "${main_cc}" ||
   ! rg -Fq 'gregs[REG_R12] = static_cast<greg_t>(eax & 0xffffffffULL)' "${main_cc}" ||
   ! rg -Fq 'gregs[REG_RSI] = static_cast<greg_t>(final_result)' "${main_cc}"; then
  echo "Stage6 DataModel patch load-step trace must log stream, verifier/build status, inline fallback, verify status, and final-result slots while emulating replaced instructions" >&2
  exit 1
fi

if ! rg -q 'Stage6 UTF-8 length invalid pointer: returning empty ' "${main_cc}" ||
   ! rg -q 'string rip_off=0x%lx ptr=%p ret=%p scratch=%p seeded=%d' "${main_cc}" ||
   ! rg -q 'gregs\[REG_RAX\] = 0' "${main_cc}"; then
  echo "Stage6 invalid UTF-8 pointer recovery must return an empty string, not a positive copy length" >&2
  exit 1
fi

if ! rg -q 'kStage6VectorInsertLowBackingStoreOffset = 0x2a1febe' "${main_cc}" ||
   ! rg -q 'restored Stage6 vector insert backing' "${main_cc}"; then
  echo "Stage6 low vector backing insert must be redirected to a writable scratch array" >&2
  exit 1
fi

if ! rg -q 'kStage6VectorClearInvalidEntryFlagOffset = 0x2c2f7cf' "${main_cc}" ||
   ! rg -q 'skipped Stage6 vector clear invalid entry' "${main_cc}"; then
  echo "Stage6 invalid vector clear must collapse to an empty vector instead of reading a negative entry" >&2
  exit 1
fi

if ! rg -Uq 'kStage6StartAppInvalidVectorReleaseOffset\s*=\s*0x47159ea' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppInvalidVectorDestructorCallOffset\s*=\s*0x4715a02' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppInvalidVectorDestructorSkipOffset\s*=\s*0x47159f5' "${main_cc}" ||
   ! rg -q 'skipped Stage6 StartApp invalid vector release' "${main_cc}" ||
   ! rg -q 'skipped Stage6 invalid vector destructor' "${main_cc}" ||
   ! rg -q 'synthetic_fallback' "${main_cc}" ||
   ! rg -q 'faulted_refcount' "${main_cc}" ||
   ! rg -Fq 'gregs[REG_RAX] = -1' "${main_cc}" ||
   ! rg -Fq 'instruction[3] == 0xc1' "${main_cc}" ||
   ! rg -Fq 'instruction[0] == 0xff && instruction[1] == 0x50' "${main_cc}"; then
  echo "Stage6 StartApp invalid vector release must skip unreadable refcount atomics and null destructor calls before generic recovery longjmps" >&2
  exit 1
fi

if rg -Fq 'std::ifstream maps("/proc/self/maps")' "${main_cc}" ||
   ! rg -Uq 'void PrintAddressMapForRip\([\s\S]{0,600}open\("/proc/self/maps", O_RDONLY \| O_CLOEXEC\)' "${main_cc}" ||
   ! rg -Uq 'void PrintAddressMapForRip\([\s\S]{0,1800}write\(2, line, static_cast<size_t>\(line_end - line\)\)' "${main_cc}"; then
  echo "Crash logging must not use C++ streams while handling a signal; it must read /proc/self/maps with low-level I/O" >&2
  exit 1
fi

if ! rg -q 'g_stage6_start_lua_callback_target_vtable\[3\]' "${main_cc}" ||
   ! rg -q 'g_stage6_start_lua_callback_target_vtable\[8\]' "${main_cc}" ||
   ! rg -q 'g_stage6_start_lua_callback_target_vtable\[12\]' "${main_cc}" ||
   ! rg -q 'g_stage6_start_lua_callback_target_vtable\[13\]' "${main_cc}" ||
   ! rg -q 'g_stage6_start_lua_callback_target_vtable\[15\]' "${main_cc}" ||
   ! rg -q 'Stage6 StartLua fallback callback noop method' "${main_cc}"; then
  echo "Stage6 StartLua fallback callback target must cover the StartApp vtable slots it is reused through" >&2
  exit 1
fi

if ! rg -q 'g_stage6_start_lua_callback_target_vtable\[17\]' "${main_cc}" ||
   ! rg -q 'mocktail_stage6_start_lua_send_app_event_callback' "${main_cc}" ||
   ! rg -q 'Stage6 StartLua fallback SendAppEvent callback' "${main_cc}"; then
  echo "Stage6 StartLua fallback callback target must cover vtable slot 17 used by SendAppReady/GameLoaded" >&2
  exit 1
fi

if ! rg -q 'g_stage6_start_lua_callback_bucket_scratch' "${main_cc}" ||
   ! rg -Fq '*reinterpret_cast<uintptr_t*>(raw + 0x08) =' "${main_cc}" ||
   ! rg -Fq '*reinterpret_cast<float*>(raw + 0x20) = 1.0f' "${main_cc}"; then
  echo "Stage6 fallback callback table copy must seed valid empty hash buckets instead of a zero bucket count" >&2
  exit 1
fi

if ! rg -q 'parent_return_off=0x%lx' "${main_cc}" ||
   ! rg -Fq 'regs{rsp=%p rbp=%p rax=%p rdi=%p}' "${main_cc}"; then
  echo "Stage6 low-address callback recovery must log parent frame context for StartApp callback-tail triage" >&2
  exit 1
fi

if ! rg -q 'kStage6StartAppHashInsertExceptionFactoryReturnOffset' "${main_cc}" ||
   ! rg -q '0x248f493' "${main_cc}" ||
   ! rg -Uq 'kStage6StartAppHashInsertCallerReturnOffset\s*=\s*0x248e620' "${main_cc}" ||
   ! rg -q 'unwound Stage6 StartApp hash-insert exception' "${main_cc}" ||
   ! rg -Fq 'g_stage5_fallback_region + 0x08' "${main_cc}" ||
   ! rg -Fq 'instruction_address == 0x4' "${main_cc}"; then
  echo "Stage6 StartApp hash-insert exception callback must unwind to the real caller instead of falling into the throw landing" >&2
  exit 1
fi

if ! rg -Uq 'kStage6PlatformHeadersVectorMoveStoreOffset\s*=\s*0x23819d7' "${main_cc}" ||
   ! rg -Uq 'kStage6PlatformHeadersVectorMoveReturnOffset\s*=\s*0x2381a9a' "${main_cc}" ||
   ! rg -q 'g_stage6_platform_headers_vector_scratch' "${main_cc}" ||
   ! rg -q 'rebuilt Stage6 platform-headers vector' "${main_cc}" ||
   ! rg -Fq 'g_start_app_with_params_recovery_in_progress != 0' "${main_cc}" ||
   ! rg -Fq 'instruction[0] == 0x0f && instruction[1] == 0x11' "${main_cc}"; then
  echo "Stage6 platform-header vector move recovery must rebuild the vector into a large scratch buffer before generic StartApp recovery aborts" >&2
  exit 1
fi
