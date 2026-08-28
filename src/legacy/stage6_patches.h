#ifndef MOCKTAIL_LEGACY_STAGE6_PATCHES_H_
#define MOCKTAIL_LEGACY_STAGE6_PATCHES_H_

#include <cstdint>

namespace mocktail::legacy::internal {

bool PatchRobloxSmallAllocator(std::uintptr_t libroblox_base);
bool PatchRobloxAllocatorObject(std::uintptr_t libroblox_base);
bool PatchRobloxServiceHostBuilder(std::uintptr_t libroblox_base);
bool PatchRobloxJniReferenceHighTagMask(std::uintptr_t libroblox_base);
bool RestoreConstructorEmutlsHelpers(std::uintptr_t libroblox_base);
void RestoreKnownRobloxEmutlsKeys(std::uintptr_t libroblox_base);
bool PatchRobloxEmutlsGetBridge(std::uintptr_t libroblox_base);

bool PatchNullSurfaceAppCrash(void* native_start_app_with_params);
bool PatchFontTableClassifierCrash(std::uintptr_t libroblox_base);
bool PatchPostClientSettingsTelemetryCrash(std::uintptr_t libroblox_base);
bool PatchRobloxStackCheckBranches(std::uintptr_t libroblox_base);
bool PatchStage6StackCheckExceptionLandings(std::uintptr_t libroblox_base);
bool PatchEmutlsZeroInitializerMemset(std::uintptr_t libroblox_base);
bool PatchStage6ProtectedLockCmpxchgLoop(std::uintptr_t libroblox_base);
bool PatchStage6UnalignedStackMovaps(std::uintptr_t libroblox_base);
bool PatchStage6MessageBusSelfReferenceCallback(std::uintptr_t libroblox_base);
bool PatchStage6MessagePumpReverseCopy(std::uintptr_t libroblox_base);
bool PatchStage6GlUnsupportedMessageHelpers(std::uintptr_t libroblox_base);
bool PatchStage6PlatformHeadersLookupReturnEmptyEntry(
    std::uintptr_t libroblox_base);
bool PatchStage6StartGameAssetAtIndexClamp(std::uintptr_t libroblox_base);
bool PatchStage6StartLuaOptionalStringLookups(std::uintptr_t libroblox_base);
bool PatchStage6StartLuaNullAppStateGuard(std::uintptr_t libroblox_base);
bool PatchStage6StartLuaForceLoggedInBranch(std::uintptr_t libroblox_base);
bool PatchStage6StartLuaForceAltSetupBranch(std::uintptr_t libroblox_base);
bool PatchStage6StartLuaGateForceDeep(std::uintptr_t libroblox_base);
bool PatchStage6StartLuaDmForceSameThread(std::uintptr_t libroblox_base);
bool PatchStage6StartLuaGateTrace(std::uintptr_t libroblox_base);
bool PatchStage6StartLuaSingleSurfaceEntrySetup(std::uintptr_t libroblox_base);
bool PatchStage6StartLuaAppDMGlobalLoadSetup(std::uintptr_t libroblox_base);
bool PatchStage6StartLuaDeepEntryTrace(std::uintptr_t libroblox_base);
bool PatchStage6StartLuaUserDidLoginStateLoadRecovery(
    std::uintptr_t libroblox_base);
bool PatchStage6StartLuaRefcountReleaseTrace(std::uintptr_t libroblox_base);
bool PatchStage6AppBridgeV2OwnerInitTrace(std::uintptr_t libroblox_base);
bool PatchStage6AsyncAppBridgeHashAllocationFallback(
    std::uintptr_t libroblox_base);
bool PatchStage6AppBridgeVectorAllocationFallback(
    std::uintptr_t libroblox_base);
bool PatchStage6StartAppParamsAllocationFallback(std::uintptr_t libroblox_base);
bool PatchStage6StartAppInstanceArgTrace(std::uintptr_t libroblox_base);
bool PatchStage6DataModelPatchHelperReturnTrace(std::uintptr_t libroblox_base);
bool PatchStage6DataModelPatchTerminalTrace(std::uintptr_t libroblox_base);
bool PatchStage6RbxmNameSlotApplyRepair(std::uintptr_t libroblox_base);
bool PatchStage6DataModelPatchLoadStepTrace(std::uintptr_t libroblox_base);
bool PatchStage6AsyncAppBridgeXmlDeserializeError(
    std::uintptr_t libroblox_base);
bool PatchStage6SystemDialogFormatHelperReturnFalse(
    std::uintptr_t libroblox_base);
bool PatchStage6PlatformHeaderParseStackFailLanding(
    std::uintptr_t libroblox_base);
bool InstallStage6AsyncAppBridgeXmlNameStringFallbacks(
    std::uintptr_t libroblox_base);
bool PatchStage6AsyncAppBridgeOptionalContextFlag(
    std::uintptr_t libroblox_base);
bool PatchNativeUpdateScreenOrientationSetupTrace(
    std::uintptr_t libroblox_base);
bool PatchStage6EnableDmNotificationMonitorFlag(std::uintptr_t libroblox_base);
bool PatchStage6EnableDmNotificationMonitorTrace(std::uintptr_t libroblox_base);
bool InstallStage6StartLuaRegistryFallback(std::uintptr_t libroblox_base);
bool InstallStage6RbxmFileManagerCacheRegistryFallback(
    std::uintptr_t libroblox_base);
bool InstallStage6RbxmFileManagerFeatureRegistryFallback(
    std::uintptr_t libroblox_base);
bool InstallStage6RbxmReflectionDescriptorFallback(
    std::uintptr_t libroblox_base);
bool InstallStage6RbxmCoreClassRegistryFallback(std::uintptr_t libroblox_base);
bool InstallSkippedRobloxHeadlessSingletonFallback(
    std::uintptr_t libroblox_base);
bool InstallStage6SystemDialogSingletonGuardFallback(
    std::uintptr_t libroblox_base);
bool InstallStage6SystemDialogDependencySingletonGuardFallback(
    std::uintptr_t libroblox_base);
bool InstallStage6SystemDialogDescriptorFallbacks(
    std::uintptr_t libroblox_base);
bool InstallStage6IxpDescriptorFallbacks(std::uintptr_t libroblox_base);
bool InstallStage6DataModelPatchAnalyticsDescriptorFallbacks(
    std::uintptr_t libroblox_base);
bool InstallStage6DataModelPatchTelemetryDescriptorFallbacks(
    std::uintptr_t libroblox_base);
bool ForceStage6DeferRbxmSignatureCheckToPostTtiFlag(const char* reason);
bool ForceNativeFlagsLoadedForTaskScheduler(const char* reason);
bool ForceStage6DataModelPatcherForceLocalFlag(const char* reason);
bool ForceStage6StartLuaSelfReferenceCallbackFlag(const char* reason);
bool InstallRobloxUrlStringFallbacks(std::uintptr_t libroblox_base);
bool PatchStage6OpenGLUnsupportedMessageCounter(std::uintptr_t libroblox_base);
bool PatchStage6GlHelperStateSlot(std::uintptr_t libroblox_base);
bool PatchStage6GlQueueTrace(std::uintptr_t libroblox_base);
bool PatchStage6GlPollReturn(std::uintptr_t libroblox_base);
bool PatchStage6GlInfiniteWait(std::uintptr_t libroblox_base);
bool PatchStage6GlWaitReturn(std::uintptr_t libroblox_base);
bool PatchStage6GlTimedWaitReturnFalse(std::uintptr_t libroblox_base);
bool PatchStage6GlConditionWaitWrapperReturnSuccess(
    std::uintptr_t libroblox_base);
bool PatchStage6GlQueuePopReturnEmpty(std::uintptr_t libroblox_base);
bool PatchStage6GlQueueTransferReturnFalse(std::uintptr_t libroblox_base);
bool PatchStage6GlQueueCallbackTailReturnEmpty(std::uintptr_t libroblox_base);
bool PatchStage6GlQueueDrainReturnFalse(std::uintptr_t libroblox_base);
bool PatchStage6FmodRetryCount(std::uintptr_t libroblox_base);
bool PatchStage6FmodInitTrace(std::uintptr_t libroblox_base);
bool PatchStage6FmodCreateGroupTrace(std::uintptr_t libroblox_base);
bool PatchStage6FmodNativeAudioDeviceGroupFailureLog(
    std::uintptr_t libroblox_base);
bool PatchStage6FmodNativeAudioDeviceChangedNoOp(std::uintptr_t libroblox_base);
bool PatchStage6FmodErrorTrace(std::uintptr_t libroblox_base);
bool PatchStage6RslReleaseCountPanic(std::uintptr_t libroblox_base);
bool PatchStage6TextboxSyncNullString(std::uintptr_t libroblox_base);

bool InitializeSystemDialogHandlerFallback(void* native_start_app_with_params);
bool PatchSystemDialogPlatformCalls(void* native_start_app_with_params);
bool PatchShouldDisplayOpenGLUnsupportedMessage(void* should_display_fn);
bool PatchHeadlessUpdateAdapterInit(void* native_start_app_with_params);
bool PatchHeadlessNullIndexBufferWrite(void* native_start_app_with_params);
bool PatchHeadlessMessageBusJavaPublish(void* publish_response_raw);
bool PatchHeadlessNullUtf16CopyWrite(void* native_start_app_with_params);
bool PatchStartAppDebugTrap(void* native_start_app_with_params);

}  // namespace mocktail::legacy::internal

#endif  // MOCKTAIL_LEGACY_STAGE6_PATCHES_H_
