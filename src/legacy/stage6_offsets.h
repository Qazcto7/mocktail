#ifndef MOCKTAIL_LEGACY_STAGE6_OFFSETS_H_
#define MOCKTAIL_LEGACY_STAGE6_OFFSETS_H_

#include <cstddef>
#include <cstdint>

namespace mocktail::legacy::internal {

constexpr uintptr_t kStage5LowAddressThreshold = 0x10000;
constexpr uintptr_t kStage6LikelyHostPointerThreshold = 0x100000000000ULL;
constexpr size_t kStage5FallbackScratchSize = 0x4000;
constexpr size_t kStage6GlScratchSize = 0x20000;
constexpr size_t kStage6GlQueueLaneCount = 16;
constexpr size_t kStage6GlQueueLaneStride = 0x4a140;
constexpr size_t kStage6GlQueueLaneStorageSize =
    kStage6GlQueueLaneCount * kStage6GlQueueLaneStride;
constexpr size_t kStage6AppBridgeHashScratchSize = 0x400000;
constexpr size_t kStartAppManagerScratchSize = 0x400;
constexpr uintptr_t kMaxCanonicalUserPointer = 0x0000800000000000ULL;
constexpr uintptr_t kLibrobloxTextStartOffset = 0x1f235c0;
constexpr uintptr_t kLibrobloxExecutableSegmentEndOffset = 0x6b25450;
constexpr uintptr_t kAppStartSchedulerFaultOffset = 0x29b1878;
constexpr uintptr_t kAppStartCleanupFaultOffset = 0x2980da0;
constexpr uintptr_t kStage6LinkedListLowWriteOffset = 0x23212e2;
constexpr uintptr_t kStage6GlStateReadOffset = 0x277caba;
constexpr uintptr_t kStage6GlStateReadR15Offset = 0x277af95;
constexpr uintptr_t kStage6GlStateReadAltOffset = 0x277e3ea;
constexpr uintptr_t kStage6GlStateReadRdiOffset = 0x277d213;
constexpr uintptr_t kStage6GlQueueReadOffset = 0x277b485;
constexpr uintptr_t kStage6GlStateFlagReadOffset = 0x277b522;
constexpr uintptr_t kStage6GlCounterReadOffset = 0x277b563;
constexpr uintptr_t kStage6GlQueueSelfCompareOffset = 0x277b647;
constexpr uintptr_t kStage6GlHelperReturnOffset = 0x277b991;
constexpr uintptr_t kStage6GlUnsupportedObjectReadStartOffset = 0x277d000;
constexpr uintptr_t kStage6GlUnsupportedObjectReadEndOffset = 0x2780000;
constexpr uintptr_t kStage6GlWaitHelperOffset = 0x2779820;
constexpr uintptr_t kStage6GlTimedWaitHelperOffset = 0x277d0d0;
constexpr uintptr_t kStage6GlConditionWaitWrapperOffset = 0x239408c;
constexpr uintptr_t kStage6GlQueuePopHelperOffset = 0x27802e0;
constexpr uintptr_t kStage6GlQueueTransferHelperOffset = 0x2784750;
constexpr uintptr_t kStage6GlQueueCallbackTailOffset = 0x2784940;
constexpr uintptr_t kStage6GlQueueCallbackTailRetOffset = 0x2784953;
constexpr uintptr_t kStage6GlQueueDrainHelperOffset = 0x2784960;
constexpr uintptr_t kStage6GlWaitBeginCallbackReadOffset = 0x277984b;
constexpr uintptr_t kStage6GlWaitBeginCallbackSkipOffset = 0x2779871;
constexpr uintptr_t kStage6GlInfiniteWaitSyscallOffset = 0x27798ea;
constexpr uintptr_t kStage6GlWaitEndCallbackReadOffset = 0x277990a;
constexpr uintptr_t kStage6GlWaitEndCallbackSkipOffset = 0x2779930;
constexpr uintptr_t kStage6GlTlsQueueNullWriteOffset = 0x2779cc4;
constexpr uintptr_t kStage6GlTlsStateNullReadOffset = 0x2779ce6;
constexpr uintptr_t kStage6GlQueueAtomicLowReadOffset = 0x2779d10;
constexpr uintptr_t kStage6GlTlsReturnedQueueNullOffset = 0x2781db2;
constexpr uintptr_t kStage6GlEventQueueNullReadOffset = 0x2780cc1;
constexpr uintptr_t kStage6GlReturnedQueueAtomicReadOffset = 0x27853e0;
constexpr uintptr_t kStage6GlReturnedQueueAtomicReadNextOffset = 0x2785430;
constexpr uintptr_t kStage6GlReturnedQueueScanStartOffset = 0x27853e0;
constexpr uintptr_t kStage6GlReturnedQueueScanEndOffset = 0x2785828;
constexpr uintptr_t kStage6GlReturnedQueueEmptyReturnOffset = 0x2785975;
constexpr uintptr_t kEmutlsZeroInitializerMemsetCallOffset = 0x2c18f19;
constexpr int kStage6GameGlobalInitEmptyReturnedQueueLimit = 2;
constexpr uintptr_t kStage6ProtectedTableEntryReadOffset = 0x1f263d9;
constexpr uintptr_t kStage6ProtectedLockCmpxchgLoopOffset = 0x1f280fb;
constexpr uintptr_t kStage6MidInstructionMovabsStartOffset = 0x1f23ffc;
constexpr uintptr_t kStage6MidInstructionMovabsOffset = 0x1f24000;
constexpr uintptr_t kStage6MidInstructionMovabsEndOffset = 0x1f24005;
constexpr uintptr_t kStage6MidInstructionEpilogueOffset = 0x3f280fb;
constexpr uintptr_t kStage6AssetPathNativeSetVtableCallOffset = 0x277d527;
constexpr uintptr_t kStage6AssetPathNativeSetVtableReturnOffset =
    kStage6AssetPathNativeSetVtableCallOffset + 0x0d;
constexpr uintptr_t kStage6AssetPathNativeSetVtableCallFallbackOffset =
    0x2efd527;
constexpr uintptr_t kStage6AssetPathNativeSetVtableReturnFallbackOffset =
    kStage6AssetPathNativeSetVtableCallFallbackOffset + 0x0d;
constexpr uintptr_t kV2StartAppNullBucketTableReadOffset = 0x2505d6e;
constexpr uintptr_t kV2StartAppNullBucketTableAllocateOffset = 0x2505dbf;
constexpr uintptr_t kV2StartAppLowBucketKeyReadOffset = 0x2505dd7;
constexpr uintptr_t kStage6StartAppLoggingHashBucketReadOffset = 0x2311e3e;
constexpr uintptr_t kStage6StartAppLoggingHashEmptyReturnOffset = 0x2311f57;
constexpr uintptr_t kStage6StartAppLoggingHashWrapperBucketReadOffset =
    0x23113d7;
constexpr uintptr_t kStage6StartAppLoggingHashWrapperReturnOffset = 0x231140e;
constexpr uintptr_t kStage6StartAppLoggingHashCapacityReadOffset = 0x42d4c8e;
constexpr uintptr_t kStage6StartAppLoggingHashCapacityReturnOffset = 0x42d4c9f;
constexpr uintptr_t kV2StartAppCallbackTailStartOffset = 0x2505d17;
constexpr uintptr_t kV2StartAppCallbackTailEndOffset = 0x2505d22;
constexpr uintptr_t kV2StartAppNullManagerOffset = 0x2506700;
constexpr uintptr_t kV2StartAppManagerOutWriteOffset = 0x6a7cf16;
constexpr uintptr_t kRobloxHeadlessSingletonGlobalOffset = 0x75a8210;
constexpr uintptr_t kRobloxNativeFlagsLoadedByteOffset = 0x75a8250;
constexpr uintptr_t kRobloxChannelPointerOffset = 0x73f8958;
constexpr uintptr_t kRobloxBaseUrlOwnerPointerOffset = 0x73f8960;
constexpr uintptr_t kRobloxBaseUrlGlobalPointerOffset = 0x73f8968;
constexpr uintptr_t kStage6StringAssignNullDestReadOffset = 0x2bc73b8;
constexpr uintptr_t kStage6StringAssignReturnOffset = 0x2bc73d0;
constexpr uintptr_t kStage6InitParamsNullSourceCopyOffset = 0x23f97cb;
constexpr uintptr_t kStage6InitParamsCopyEpilogueOffset = 0x23f9862;
constexpr uintptr_t kStage6HashLookupLowTableReadOffset = 0x233bbb9;
constexpr uintptr_t kStage6HashLookupEmptyPathOffset = 0x233bbf6;
constexpr uintptr_t kStage6NestedHashLookupLowTableReadOffset = 0x2df8c80;
constexpr uintptr_t kStage6NestedHashLookupEmptyPathOffset = 0x2df8cf9;
constexpr uintptr_t kStage6MapLookupLowOwnerReadOffset = 0x2e148b4;
constexpr uintptr_t kStage6MapLookupUnlockAndReturnOffset = 0x2e147fc;
constexpr uintptr_t kStage6StringMapLookupLowOwnerReadOffset = 0x35e6292;
constexpr uintptr_t kStage6StringMapLookupUnlockAndReturnOffset = 0x35e636c;
constexpr uintptr_t kStage6StringFieldNullCurrentReadOffset = 0x233bfd9;
constexpr uintptr_t kStage6StringFieldAssignPathOffset = 0x233c04d;
constexpr uintptr_t kStage6StringFieldNullOldReleaseOffset = 0x35e6067;
constexpr uintptr_t kStage6StringFieldStoreNewOffset = 0x35e607c;
constexpr uintptr_t kStage6StringFieldLoopReturnOffset = 0x233c0b2;
constexpr int kStage6StringFieldNullLoopLimit = 256;
constexpr uintptr_t kStage6StringReleaseNullOwnerReadOffset = 0x233c13c;
constexpr uintptr_t kStage6StartAppPayloadMapNullOwnerReadOffset = 0x6a9f90d;
constexpr uintptr_t kStage6StartAppPayloadHashLowTableReadOffset = 0x48ba127;
constexpr uintptr_t kStage6StartAppPayloadHashEmptyPathOffset = 0x48ba179;
constexpr uintptr_t kStage6StartAppPayloadLinkLoadOffset = 0x48bbb7d;
constexpr uintptr_t kStage6StartAppPayloadLinkStoreOffset = 0x48bbb89;
constexpr uintptr_t kStage6StartAppPayloadMapLookupLowOwnerReadOffset =
    0x48b9f2a;
constexpr uintptr_t kStage6StartAppCollectionManagerNullReadOffset = 0x51f2b09;
constexpr uintptr_t kStage6StartAppCollectionManagerReturnOffset = 0x51f2af3;
constexpr uintptr_t kStage6StartAppFallbackHandlerNullReadOffset = 0x2460b0d;
constexpr uintptr_t kStage6StartAppFallbackHandlerAfterCallOffset = 0x2460b13;
constexpr uintptr_t kStage6StartAppInstanceArgProbeOffset = 0x25fca9b;
constexpr uintptr_t kStage6DataModelPatchHelperInitialReturnProbeOffset =
    0x2462249;
constexpr uintptr_t kStage6DataModelPatchHelperConfigReturnProbeOffset =
    0x24623bd;
constexpr uintptr_t kStage6DataModelPatchHelperProviderReturnProbeOffset =
    0x2462831;
constexpr uintptr_t kStage6DataModelPatchHelperReturnProbeOffset = 0x24648a7;
constexpr uintptr_t kStage6DataModelPatchTerminalFlagReadProbeOffset =
    0x2463bc5;
constexpr uintptr_t kStage6ReThrowGetCachedPatchExceptionFlagOffset = 0x73cf050;
constexpr uintptr_t kStage6DeferRbxmSignatureCheckToPostTtiFlagOffset =
    0x73cf288;
constexpr uintptr_t kStage6DataModelPatcherForceLocalFlagOffset = 0x73cf2d8;
constexpr uintptr_t kStage6DataModelPatchOpenStreamReturnProbeOffset =
    0x2462aff;
constexpr uintptr_t kStage6DataModelPatchInlineLoadReturnProbeOffset =
    0x2462c19;
constexpr uintptr_t kStage6DataModelPatchInlineBuildResultProbeOffset =
    0x2462dce;
constexpr uintptr_t kStage6DataModelPatchInnerLoaderStatusProbeOffset =
    0x2418e86;
constexpr uintptr_t kStage6DataModelPatchInnerLoaderReturnProbeOffset =
    0x2419015;
constexpr uintptr_t kStage6DataModelPatchBuildListEmptyBranchProbeOffset =
    0x5f9f802;
constexpr uintptr_t kStage6DataModelPatchBuildContentNullBranchProbeOffset =
    0x5f9f812;
constexpr uintptr_t kStage6DataModelPatchBuildContentEmptyBranchProbeOffset =
    0x5f9f81f;
constexpr uintptr_t kStage6DataModelPatchBuildFeatureGateBranchProbeOffset =
    0x5f9f873;
constexpr uintptr_t kStage6DataModelPatchBuildFallbackStatusProbeOffset =
    0x5f9fa94;
constexpr uintptr_t kStage6DataModelPatchBuildDeserializeReturnProbeOffset =
    0x5f9f7b7;
constexpr uintptr_t kStage6RbxmDeserializerSummaryProbeOffset = 0x2dea942;
constexpr uintptr_t kStage6RbxmInstIdsReturnProbeOffset = 0x2dea129;
constexpr uintptr_t kStage6RbxmInstModeBranchProbeOffset = 0x2dea25d;
constexpr uintptr_t kStage6RbxmInstProviderReturnProbeOffset = 0x2dea393;
constexpr uintptr_t kStage6RbxmInstFactoryResultProbeOffset = 0x2dea56a;
constexpr uintptr_t kStage6RbxmInstTableInsertReturnProbeOffset = 0x2dea5f1;
constexpr uintptr_t kStage6RbxmInstClassLookupProbeOffset = 0x2de9556;
constexpr uintptr_t kStage6RbxmPropDescriptorLookupProbeOffset = 0x2de9556;
constexpr uintptr_t kStage6RbxmPropApplyCallProbeOffset = 0x2de9bb8;
constexpr uintptr_t kStage6RbxmPropApplyReturnProbeOffset = 0x2de9bbd;
constexpr uintptr_t kStage6RbxmPropertyApplyStreamByteProbeOffset = 0x2deceb5;
constexpr uintptr_t kStage6RbxmPropertyApplyLoopDecisionProbeOffset = 0x2ded059;
constexpr uintptr_t kStage6RbxmPropertyApplyTypeBranchProbeOffset = 0x2ded719;
constexpr uintptr_t kStage6RbxmPropertySetterModeBranchProbeOffset = 0x2ded1c2;
constexpr uintptr_t kStage6RbxmPropertySetterCallProbeOffset = 0x2ded268;
constexpr uintptr_t kStage6RbxmGenericSetterCallProbeOffset = 0x2dedadc;
constexpr uintptr_t kStage6RbxmGenericSetterReturnProbeOffset = 0x2dedae2;
constexpr uintptr_t kStage6RbxmPrntChildIdsReturnProbeOffset = 0x2de949c;
constexpr uintptr_t kStage6RbxmPrntParentIdsReturnProbeOffset = 0x2de9906;
constexpr uintptr_t kStage6RbxmPrntObjectLookupProbeOffset = 0x2de9c73;
constexpr uintptr_t kStage6RbxmPrntParentBranchProbeOffset = 0x2de9c90;
constexpr uintptr_t kStage6RbxmPrntRootAppendReturnProbeOffset = 0x2de9d28;
constexpr uintptr_t kStage6DataModelPatchVerifyBuildStatusProbeOffset =
    0x5f9f93e;
constexpr uintptr_t kStage6DataModelPatchVerifyStatusReturnProbeOffset =
    0x2462ff2;
constexpr uintptr_t kStage6DataModelPatchFinalResultProbeOffset = 0x246357c;
constexpr uintptr_t kStage6RbxmFileManagerEntryProbeOffset = 0x5fa7880;
constexpr uintptr_t kStage6RbxmFileManagerCacheRegistryGlobalOffset = 0x73cf440;
constexpr uintptr_t kStage6RbxmFileManagerCacheRegistryInitOffset = 0x2f38860;
constexpr uintptr_t kStage6RbxmFileManagerFeatureRegistryGlobalOffset =
    0x73cf468;
constexpr uintptr_t kStage6RbxmFileManagerFeatureRegistryMutexGlobalOffset =
    0x73cf490;
constexpr uintptr_t kStage6RbxmFileManagerFeatureRegistryHashOffset = 0x2c20536;
constexpr uintptr_t kStage6RbxmCoreClassRegistryGlobalOffset = 0x73edf90;
constexpr uintptr_t kStage6RbxmInstanceClassInitOffset = 0x1f43205;
constexpr uintptr_t kStage6RbxmFolderClassInitOffset = 0x2098d20;
constexpr uintptr_t kStage6RbxmModuleScriptClassInitOffset = 0x1f587bf;
constexpr uintptr_t kStage6RbxmStringValueClassInitOffset = 0x20e7fbc;
constexpr uintptr_t kStage6RbxmInstanceReflectionInitOffset = 0x1f43796;
constexpr uintptr_t kStage6RbxmInstancePropertyDescriptorInitOffset = 0x2040d80;
constexpr uintptr_t kStage6RbxmFolderReflectionInitOffset = 0x2098b62;
constexpr uintptr_t kStage6RbxmModuleScriptReflectionInitOffset = 0x1f5835f;
constexpr uintptr_t kStage6RbxmStringValueReflectionInitOffset = 0x20e7db3;
constexpr uintptr_t kStage6RbxmInstanceStaticDescriptorInitOffset = 0x22821bb;
constexpr uintptr_t kStage6RbxmClassDescriptorIndexBuildOffset = 0x671e93c;
constexpr uintptr_t kStage6RbxmStringTypeDescriptorInitOffset = 0x1f44c8e;
constexpr uintptr_t kStage6RbxmStringTypeDescriptorStaticOffset = 0x73ee930;
constexpr uintptr_t kStage6RbxmPrimaryDescriptorRegistryHeadGlobalOffset =
    0x75a81c8;
constexpr uintptr_t kStage6RbxmSecondaryDescriptorRegistryHeadGlobalOffset =
    0x75a81d0;
constexpr uintptr_t kStage6RbxmPropertyDescriptorRegistryHeadGlobalOffset =
    0x75a81e0;
constexpr size_t kStage6RbxmDescriptorRegistryPreviewSize = 8192;
constexpr uintptr_t kStage6RbxmInstanceStaticDescriptorGlobalsStartOffset =
    0x73e4600;
constexpr uintptr_t kStage6RbxmInstanceStaticDescriptorGlobalsEndOffset =
    0x73e4c00;
constexpr uintptr_t kStage6RbxmInstanceStaticDescriptorObjectsStartOffset =
    0x71af000;
constexpr uintptr_t kStage6RbxmInstanceStaticDescriptorObjectsEndOffset =
    0x71b000;
constexpr uintptr_t kStage6RbxmChildNameStringReadOffset = 0x65bc0f0;
constexpr uintptr_t kStage6StartAppInitialInstanceNameStringReadOffset =
    0x245919d;
constexpr uintptr_t kStage6StartAppInitialInstanceNameSkipOffset = 0x2459405;
constexpr uintptr_t kStage6StartAppPeerInstanceNameStringReadOffset = 0x24591f9;
constexpr uintptr_t kStage6StartAppPeerInstanceNameSkipOffset = 0x24595f2;
constexpr uintptr_t kStage6StartAppDeepInstanceNameStringReadOffset = 0x247d1c8;
constexpr uintptr_t kStage6StartAppDeepInstanceNameSkipOffset = 0x247d219;
constexpr uintptr_t kStage6StartAppPostHashInstanceNameStringReadOffset =
    0x24981f2;
constexpr uintptr_t kStage6StartAppPostHashInstanceNameSkipOffset = 0x249824f;
constexpr uintptr_t kStage6StartAppInstanceNameStringReadOffset = 0x245e1a0;
constexpr uintptr_t kStage6StartAppInstanceNameSkipOffset = 0x245e1f1;
constexpr uintptr_t kStage6StartAppFallbackInstanceNameStringReadOffset =
    0x245e9cc;
constexpr uintptr_t kStage6StartAppFallbackInstanceNameSkipOffset = 0x245ea1d;
constexpr uintptr_t kStage6StartAppSecondFallbackInstanceNameStringReadOffset =
    0x246ca0a;
constexpr uintptr_t kStage6StartAppSecondFallbackInstanceNameSkipOffset =
    0x246ca5b;
constexpr uintptr_t kStage6StartAppThirdFallbackInstanceNameStringReadOffset =
    0x24705ec;
constexpr uintptr_t kStage6StartAppThirdFallbackInstanceNameSkipOffset =
    0x247063d;
constexpr uintptr_t kStage6DataModelPatchNoVerifiedPatchTrapResumeOffset =
    0x25fcd68;
constexpr uintptr_t kStage6DataModelPatchNoVerifiedPatchEmptyResultOffset =
    0x2464a08;
constexpr uintptr_t kStage6RbxmFileManagerPostCheckStatusProbeOffset =
    0x5fa78eb;
constexpr uintptr_t kStage6RbxmFileManagerLocalStorageUnavailableProbeOffset =
    0x5fa80be;
constexpr uintptr_t kStage6RbxmFileManagerCachingDisabledProbeOffset =
    0x5fa829c;
constexpr uintptr_t kStage6RbxmFileManagerNoLocalStorageStatusProbeOffset =
    0x5fa82d9;
constexpr uintptr_t kStage6RbxmFileManagerPendingStatusProbeOffset = 0x5fa9206;
constexpr uintptr_t kStage6RbxmFileManagerSuccessStatusProbeOffset = 0x5fa875b;
constexpr const char* kStage6UniversalAppRbxmUri =
    "rbxasset://models/UniversalApp/UniversalApp.rbxm";
constexpr uintptr_t kStage6InitWithParamsStaticGuardOffset = 0x70b49f0;
constexpr uintptr_t kStage6InitWithParamsSecondaryStaticGuardOffset = 0x70821d0;
constexpr uintptr_t kStage6LibcxxGuardMutexOffset = 0x707ee60;
constexpr uintptr_t kStage6LibcxxGuardCondOffset = 0x707ee88;
constexpr uintptr_t kStage6UnsupportedMessageSlotDerefOffset = 0x41334fb;
constexpr uintptr_t kStage6UnsupportedMessageSlotStoreReadOffset = 0x413355d;
constexpr uintptr_t kStage6StartLuaUnsupportedMessageSlotDerefOffset =
    0x246cd98;
constexpr uintptr_t kStage6StartLuaUnsupportedMessagePromptSlotDerefOffset =
    0x246ceef;
constexpr uintptr_t kStage6StartLuaUnsupportedMessageEntrySlotDerefOffset =
    0x246cf7d;
constexpr uintptr_t kStage6StartLuaUnsupportedMessageEnumSlotDerefOffset =
    0x246d3f9;
constexpr uintptr_t kStage6StartLuaUnsupportedMessageLoopSlotDerefOffset =
    0x246d97f;
constexpr uintptr_t kStage6StartLuaUnsupportedMessageTailSlotDerefOffset =
    0x246dcb3;
constexpr uintptr_t kStage6StartLuaUnsupportedMessageTail2SlotDerefOffset =
    0x246dd9c;
constexpr uintptr_t kStage6StartLuaUnsupportedMessageTail3SlotDerefOffset =
    0x246de9b;
constexpr uintptr_t kStage6StartLuaUnsupportedMessageTail4SlotDerefOffset =
    0x246e132;
constexpr uintptr_t kStage6StartLuaUnsupportedMessageTail5SlotDerefOffset =
    0x246e25f;
constexpr uintptr_t kStage6StartLuaUnsupportedMessageTail6SlotDerefOffset =
    0x246efc9;
constexpr uintptr_t kStage6StartLuaUnsupportedMessageTail7SlotDerefOffset =
    0x246f141;
constexpr uintptr_t kStage6StartLuaUnsupportedMessageTail8SlotDerefOffset =
    0x246f30e;
constexpr uintptr_t kStage6StartLuaUnsupportedMessageThreadStateReadOffset =
    0x245c4c3;
constexpr uintptr_t kStage6StartLuaUnsupportedMessageThreadStateReturnOffset =
    0x245c4e0;
constexpr uintptr_t
    kStage6StartLuaUnsupportedMessageParentThreadStateReadOffset = 0x233e7c0;
constexpr uintptr_t
    kStage6StartLuaUnsupportedMessageParentThreadStateReturnOffset = 0x233e7dc;
constexpr uintptr_t kStage6StartLuaUnsupportedMessageLeafThreadStateReadOffset =
    0x233eb39;
constexpr uintptr_t
    kStage6StartLuaUnsupportedMessageLeafThreadStateReturnOffset = 0x233eb61;
constexpr uintptr_t kStage6StartLuaPreviousStateFlagReadOffset = 0x233d5e3;
constexpr uintptr_t kStage6StartLuaCurrentStateFlagReadOffset = 0x233d5ff;
constexpr uintptr_t kStage6StartLuaUnsupportedMessageVectorReadOffset =
    0x233c470;
constexpr uintptr_t kStage6StartAppUnsupportedMessageSlotDerefOffset =
    0x245c7a3;
constexpr uintptr_t kStage6StartAppUnsupportedMessageDetailSlotDerefOffset =
    0x245c9fb;
constexpr uintptr_t
    kStage6StartAppUnsupportedMessagePostInstanceSlotDerefOffset = 0x247472c;
constexpr uintptr_t kStage6StartAppUnsupportedMessageProxyObjectReadOffset =
    0x38b4122;
constexpr uintptr_t
    kStage6StartAppUnsupportedMessageProxyObjectStateTestOffset = 0x38b412e;
constexpr uintptr_t kStage6StartAppUnsupportedMessageProxyObjectReturnOffset =
    0x38b427a;
constexpr uintptr_t kStage6StartAppUnsupportedMessageDeepSlotDerefOffset =
    0x38b414b;
constexpr uintptr_t kStage6StartAppUnsupportedMessagePostHashSlotDerefOffset =
    0x249d7c4;
constexpr uintptr_t kStage6StartAppAudioCallbackTableWriteOffset = 0x2fc0788;
constexpr uintptr_t kStage6RslReleaseCountPanicOffset = 0x277ef18;
constexpr uintptr_t kStage6FmodLogHelperOffset = 0x6a9cc20;
constexpr uintptr_t kStage6FmodRetryCountGlobalOffset = 0x702bbf8;
constexpr uintptr_t kStage6FmodSystemCreateReturnOffset = 0x2fbca25;
constexpr uintptr_t kStage6FmodSystemInitOffset = 0x592a50a;
constexpr uintptr_t kStage6FmodSystemInitFunctionReturnOffset = 0x592a6d6;
constexpr uintptr_t kStage6FmodSystemInitReturnOffset = 0x2fbcbbd;
constexpr uintptr_t kStage6FmodNativeAudioDeviceRetryReturnOffset = 0x2fbd312;
constexpr uintptr_t kStage6FmodCreateChannelGroupWrapperReturnOffset =
    0x592bfb5;
constexpr uintptr_t kStage6FmodCreateChannelGroupReturnOffset = 0x59a4921;
constexpr uintptr_t kStage6FmodNativeAudioDeviceGroupFailureLogOffset =
    0x2fba4ea;
constexpr uintptr_t kStage6FmodNativeAudioDeviceChangedOffset = 0x2fad7a8;
constexpr uintptr_t kStage6StartAppNullCallbackOwnerReadOffset = 0x592d5e3;
constexpr uintptr_t kStage6StartAppNullCallbackOwnerFreeReadOffset = 0x592ddf1;
constexpr uintptr_t kStage6StartAppNullCallbackOwnerReturnOffset = 0x592d899;
constexpr uintptr_t kStage6StartAppNullCallbackOwnerTableWriteOffset =
    0x594e22f;
constexpr uintptr_t kStage6StartAppZeroStrideDivisorOffset = 0x592a107;
constexpr uintptr_t kStage6StartAppNullStateObjectReadOffset = 0x594fdde;
constexpr uintptr_t kStage6StartAppNullStateObjectSkipOffset = 0x594fe5f;
constexpr uintptr_t kStage6StartAppReverseStringCopyInvalidDestStoreOffset =
    0x1f76993;
constexpr uintptr_t kStage6StartAppReverseStringCopyDoneOffset = 0x1f7699d;
constexpr uintptr_t kStage6StartLuaDMInvokerReverseStringCopyStoreOffset =
    0x230948b;
constexpr uintptr_t kStage6StartLuaDMInvokerReverseStringCopyDoneOffset =
    0x2309495;
constexpr uintptr_t kStage6StartLuaObserverListCursorReadOffset = 0x59a58af;
constexpr uintptr_t kStage6StartLuaObserverListDoneOffset = 0x59a58eb;
constexpr uintptr_t kStage6StartAppHashInsertExceptionFactoryReturnOffset =
    0x248f493;
constexpr uintptr_t kStage6StartAppHashInsertCallerReturnOffset = 0x248e620;
constexpr uintptr_t kStage6StartGameMapHelperExceptionReturnOffset = 0x243c737;
constexpr uintptr_t kStage6StartGameMapHelperCallerReturnOffset = 0x2543587;
constexpr uintptr_t kStage6StartGameAssetLookupNullReadOffset = 0x25442c0;
constexpr uintptr_t kStage6StartGameAssetLookupNullReturnOffset = 0x25442d3;
constexpr uintptr_t kStage6StartGameAssetLoopNullReadOffset = 0x25446ab;
constexpr uintptr_t kStage6StartGameAssetLoopNullReturnOffset = 0x25446e8;
constexpr uintptr_t kStage6StartGameAssetLookupAtIndexAssertOffset = 0x611e2e3;
constexpr uintptr_t kStage6StartGameAssetLookupAtIndexReturnOffset = 0x611e2f6;
constexpr uintptr_t kStage6StartGameAssetLoopAtIndexAssertOffset = 0x611d6e1;
constexpr uintptr_t kStage6StartGameAssetLoopAtIndexReturnOffset = 0x611d6f4;
constexpr uintptr_t kStage6StartAppInvalidVectorReleaseOffset = 0x47159ea;
constexpr uintptr_t kStage6StartAppInvalidVectorRefcountReadOffset = 0x47159da;
constexpr uintptr_t kStage6StartAppInvalidVectorDestructorCallOffset =
    0x4715a02;
constexpr uintptr_t kStage6StartAppInvalidVectorDestructorSkipOffset =
    0x47159f5;
constexpr uintptr_t kStage6SharedPtrNullAddrefOffset = 0x35f4442;
constexpr uintptr_t kStage6SharedPtrAddrefReturnOffset = 0x35f4446;
constexpr uintptr_t kStage6SharedPtrInvalidAddrefOffset = 0x2bc5990;
constexpr uintptr_t kStage6SharedPtrInvalidAddrefCopyReturnOffset = 0x2c2fb0b;
constexpr uintptr_t kStage6SharedPtrInvalidAddrefCopySuccessReturnOffset =
    0x2c2fb14;
constexpr uintptr_t kStage6SharedPtrCopyNullSourceRefcountOffset = 0x2e1781e;
constexpr uintptr_t kStage6SharedPtrCopyNullSourceReturnOffset = 0x2e17822;
constexpr uintptr_t kStage6SharedPtrReleaseNullSourceRefcountOffset = 0x2df8b40;
constexpr uintptr_t kStage6SharedPtrReleaseNullSourceReturnOffset = 0x2df8b55;
constexpr uintptr_t kStage6PlatformHeaderNullReleaseOffset = 0x2bfc992;
constexpr uintptr_t kStage6PlatformHeaderNullReleaseReturnOffset = 0x2bfc820;
constexpr uintptr_t kStage6LibcxxGuardReleaseNullStoreOffset = 0x2bfc604;
constexpr uintptr_t kStage6LibcxxGuardReleaseReturnOffset = 0x2bfc645;
constexpr uintptr_t kStage6PlatformHeaderValueNullTestOffset = 0x2380195;
constexpr uintptr_t kStage6PlatformHeadersVectorMoveStoreOffset = 0x23819d7;
constexpr uintptr_t kStage6PlatformHeadersVectorMoveReturnOffset = 0x2381a9a;
constexpr uintptr_t kStage6StoullNoConversionThrowOffset = 0x2bc972c;
constexpr uintptr_t kStage6StoullNoConversionCallReturnOffset = 0x2bc8785;
constexpr uintptr_t kStage6SystemDialogSingletonObjectGlobalOffset = 0x71c3da8;
constexpr uintptr_t kStage6SystemDialogSingletonGuardPointerGlobalOffset =
    0x71c3db0;
constexpr uintptr_t kStage6SystemDialogDependencySingletonObjectGlobalOffset =
    0x73d2c78;
constexpr uintptr_t
    kStage6SystemDialogDependencySingletonGuardPointerGlobalOffset = 0x73d2c80;
constexpr uintptr_t kStage6SystemDialogDescriptorChainGlobalOffset = 0x71c3d00;
constexpr uintptr_t kStage6SystemDialogDescriptorPrimaryGlobalOffset =
    0x71c3d08;
constexpr uintptr_t kStage6SystemDialogDescriptorPrimaryNameOffset = 0x4da4c5;
constexpr uintptr_t kStage6SystemDialogDescriptorDefaultNameOffset = 0x3c8a63;
constexpr uintptr_t kStage6SystemDialogDescriptorPrimaryParentGlobalOffset =
    0x71c3cf0;
constexpr uintptr_t kStage6SystemDialogDescriptorSecondaryNameOffset = 0x50e9b9;
constexpr uintptr_t kStage6SystemDialogDescriptorHashNameOffset = 0x4bf9bf;
constexpr uintptr_t kStage6SystemDialogDescriptorCallbackOffset = 0x42f82d7;
constexpr uintptr_t kStage6IxpDescriptorPrimaryGlobalOffset = 0x709e5a8;
constexpr uintptr_t kStage6IxpDescriptorPrimaryNameOffset = 0x3459dd;
constexpr uintptr_t kStage6IxpDescriptorDefaultNameOffset = 0x3c8a63;
constexpr uintptr_t kStage6IxpDescriptorSecondaryGlobalOffset = 0x709e5c0;
constexpr uintptr_t kStage6IxpDescriptorSecondaryNameOffset = 0x2f5cb9;
constexpr uintptr_t kStage6IxpDescriptorTertiaryGlobalOffset = 0x709e5d8;
constexpr uintptr_t kStage6IxpDescriptorTertiaryNameOffset = 0x28f845;
constexpr uintptr_t kStage6IxpDescriptorQuaternaryGlobalOffset = 0x709e5f0;
constexpr uintptr_t kStage6IxpDescriptorQuaternaryNameOffset = 0x345a03;
constexpr uintptr_t kStage6DataModelPatchAnalyticsDescriptorChainGlobalOffset =
    0x73ceb00;
constexpr uintptr_t
    kStage6DataModelPatchAnalyticsDescriptorPrimaryGlobalOffset = 0x73cebb0;
constexpr uintptr_t kStage6DataModelPatchAnalyticsDescriptorPrimaryNameOffset =
    0x3c268e;
constexpr uintptr_t kStage6DataModelPatchAnalyticsDescriptorDefaultNameOffset =
    0x3c8a63;
constexpr uintptr_t
    kStage6DataModelPatchAnalyticsDescriptorPrimaryParentGlobalOffset =
        0x73ceb20;
constexpr uintptr_t
    kStage6DataModelPatchAnalyticsDescriptorSecondaryNameOffset = 0x254176;
constexpr uintptr_t
    kStage6DataModelPatchAnalyticsDescriptorSecondaryStringGlobalOffset =
        0x73cebe0;
constexpr uintptr_t
    kStage6DataModelPatchAnalyticsDescriptorPrimaryStringGlobalOffset =
        0x73cebf8;
constexpr uintptr_t
    kStage6DataModelPatchAnalyticsDescriptorRegistryHeadGlobalOffset =
        0x75a81c8;
constexpr uintptr_t
    kStage6DataModelPatchAnalyticsDescriptorSecondaryRegistryHeadGlobalOffset =
        0x75a81d0;
constexpr uintptr_t kStage6DataModelPatchTelemetryDescriptorChainGlobalOffset =
    0x73cf1d8;
constexpr uintptr_t kStage6DataModelPatchTelemetryDescriptorRootGlobalOffset =
    0x73cf210;
constexpr uintptr_t kStage6DataModelPatchTelemetryDescriptorRootNameOffset =
    0x2875bc;
constexpr uintptr_t kStage6DataModelPatchTelemetryDescriptorDefaultNameOffset =
    0x3c8a63;
constexpr uintptr_t
    kStage6DataModelPatchTelemetryDescriptorRootParentGlobalOffset = 0x73cf1f8;
constexpr uintptr_t kStage6Utf8LengthInvalidPointerOffset = 0x1f28eff;
constexpr uintptr_t kStage6OptionalStringNullReadOffset = 0x233e6fa;
constexpr uintptr_t kStage6OptionalStringLengthTestOffset = 0x233e715;
constexpr uintptr_t kStage6UnsupportedMessageListHolderNullReadOffset =
    0x41335bf;
constexpr uintptr_t kStage6UnsupportedMessageListNullReadOffset = 0x41335c2;
constexpr uintptr_t kStage6UnsupportedMessageListEmptyReturnOffset = 0x413364d;
constexpr uintptr_t kStage6PostClientSettingsSingletonLockReadOffset =
    0x23ae827;
constexpr uintptr_t kStage6PostClientSettingsSingletonLockGlobalOffset =
    0x73fabc8;
constexpr uintptr_t kStage6InitHelperStackFailLandingOffset = 0x243c00f;
constexpr uintptr_t kStage6InitHelperStackFailCleanupOffset = 0x243bffb;
constexpr uintptr_t kStage6StartAppLoggingStackFailLandingOffset = 0x2311bf9;
constexpr uintptr_t kStage6StartAppLoggingStackFailCleanupOffset = 0x2311be0;
constexpr uintptr_t kStage6StartLuaLoggedInBranchOffset = 0x243ec62;
constexpr uintptr_t kStage6StartLuaDirectClosureAltSetupBranchOffset =
    0x243ebba;
constexpr uintptr_t kStage6StartLuaDirectClosureEarlySetupReturnOffset =
    0x243ebdf;
constexpr uintptr_t kStage6StartLuaNullCallbackReadOffset = 0x2f501aa;
constexpr uintptr_t kStage6StartLuaSelfReferenceNullCallbackReadOffset =
    0x2f501d2;
constexpr uintptr_t kStage6StartLuaCallbackCleanupOffset = 0x2f501e2;
constexpr uintptr_t kStage6StartLuaSecondNullCallbackReadOffset = 0x2f5044c;
constexpr uintptr_t kStage6StartLuaSecondCallbackCleanupOffset = 0x2f50455;
constexpr uintptr_t kStage6StartLuaSelfReferenceCallbackFlagOffset = 0x73da4c0;
constexpr uintptr_t kStage6StartLuaGateStateLoadOffset = 0x2f50209;
constexpr uintptr_t kStage6StartLuaGateHelperOffset = 0x24ec7dc;
constexpr uintptr_t kStage6StartLuaGateCheckOffset = 0x24ec821;
constexpr uintptr_t kStage6StartLuaGatePhaseBranchOffset = 0x24ec829;
constexpr uintptr_t kStage6StartLuaGatePayloadBranchOffset = 0x24ec82f;
constexpr uintptr_t kStage6StartLuaGateDeepArgsOffset = 0x24ec831;
constexpr uintptr_t kStage6StartLuaGateReturnOffset = 0x24ec840;
constexpr uintptr_t kStage6StartLuaLoggedInHelperOffset = 0x24ec846;
constexpr uintptr_t kStage6StartLuaLoggedInTargetEntryOffset = 0x2454832;
constexpr uintptr_t kStage6StartLuaTargetApplyOffset = 0x2454ad2;
constexpr uintptr_t kStage6StartLuaTargetPostApplyOffset = 0x2455b2e;
constexpr uintptr_t kStage6StartLuaTargetPostApplyTriggerOffset = 0x2455cbc;
constexpr uintptr_t kStage6StartLuaTargetPostApplyCallbackOffset = 0x2455cf8;
constexpr uintptr_t kStage6StartLuaTargetPostApplyExitOffset = 0x2455d04;
constexpr uintptr_t kStage6StartLuaTargetPostApplyTaskThunkOffset = 0x26ced24;
constexpr uintptr_t kStage6StartLuaTargetPostApplyTaskThunkInitReadyOffset =
    0x26ced78;
constexpr uintptr_t
    kStage6StartLuaTargetPostApplyTaskThunkBeforeTargetCallOffset = 0x26cee1f;
constexpr uintptr_t
    kStage6StartLuaTargetPostApplyTaskThunkAfterTargetCallOffset = 0x26cee2b;
constexpr uintptr_t kStage6StartLuaTargetPostApplyTaskThunkAfterResolveOffset =
    0x26cee58;
constexpr uintptr_t
    kStage6StartLuaTargetPostApplyTaskThunkCallbackInvokeOffset = 0x26cee64;
constexpr uintptr_t kStage6StartLuaTargetPostApplyTaskThunkCallbackCallOffset =
    0x26cee6e;
constexpr uintptr_t kStage6StartLuaTargetPostApplyTaskThunkAfterCallbackOffset =
    0x26cee70;
constexpr uintptr_t kStage6StartLuaTargetPostApplyTaskThunkFastNilOffset =
    0x26cee8d;
constexpr uintptr_t kStage6StartLuaTargetPostApplyTaskThunkReturnOffset =
    0x26cee99;
constexpr uintptr_t kStage6StartLuaDispatcherEmptyInvokeOffset = 0x277c076;
constexpr uintptr_t kStage6StartLuaDispatcherSecondInvokeOffset = 0x277c07f;
constexpr uintptr_t kStage6StartLuaDispatcherSecondInvokeCallOffset = 0x277c086;
constexpr uintptr_t kStage6StartLuaResult20LookupTreeReadOffset = 0x245e4e3;
constexpr uintptr_t kStage6StartLuaResult20LookupEmptyReturnOffset = 0x245e51c;
constexpr uintptr_t kStage6StartLuaResult20FallbackGlobalSlotReadOffset =
    0x2e4de6b;
constexpr uintptr_t kStage6StartLuaResult20FallbackGlobalSlotResumeOffset =
    0x2e4de6e;
constexpr uintptr_t kStage6StartLuaResult20SourceParseReturnOffset = 0x2e4de87;
constexpr uintptr_t kStage6StartLuaResult20SourceBuilderReturnOffset =
    0x25d3e42;
constexpr uintptr_t kStage6StartLuaSyntheticInstanceUpdateCallOffset =
    0x2602703;
constexpr uintptr_t kStage6StartLuaSyntheticInstanceUpdateReturnOffset =
    0x2602708;
constexpr uintptr_t kStage6StartLuaTaskThunkGlobalStringPointerOffset =
    0x759e080;
constexpr uintptr_t kStage6StartLuaTaskThunkResolveGlobalOffset = 0x707faa0;
constexpr uintptr_t kStage6StartLuaResolverBuildOffset = 0x6b1d812;
constexpr uintptr_t kStage6StartLuaResolverAfterTaskBuildOffset = 0x277ff3c;
constexpr uintptr_t kStage6StartLuaResolverQueueBindOffset = 0x277ba43;
constexpr uintptr_t kStage6StartLuaResolverQueuePickOffset = 0x277b060;
constexpr uintptr_t kStage6StartLuaResolverQueuePickNullOffset = 0x277b0d8;
constexpr uintptr_t kStage6StartLuaResolverQueuePickStoreOffset = 0x277b1e0;
constexpr uintptr_t kStage6StartLuaResolverSchedulerEntryOffset = 0x277b3d0;
constexpr uintptr_t kStage6StartLuaResolverSchedulerProcLoadOffset = 0x277b489;
constexpr uintptr_t kStage6StartLuaResolverClosureDispatchOffset = 0x277b509;
constexpr uintptr_t kStage6StartLuaResolverProcMatchBranchOffset = 0x277b257;
constexpr uintptr_t kStage6StartLuaResolverProcMatchTakenOffset = 0x277b3b0;
constexpr uintptr_t kStage6StartLuaResolverScheduleReturnOffset = 0x277bafd;
constexpr uintptr_t kStage6StartLuaResolverCleanupProcExchangeOffset =
    0x277b933;
constexpr uintptr_t kStage6StartLuaResolverClosureRunOffset = 0x27865d9;
constexpr uintptr_t kStage6StartLuaResolverClosureReturnOffset = 0x278660b;
constexpr uintptr_t kStage6StartLuaResolverClosureCoreOffset = 0x2786620;
constexpr uintptr_t kStage6StartLuaResolverClosureCoreAllocResultOffset =
    0x27866a4;
constexpr uintptr_t
    kStage6StartLuaResolverClosureCoreFallbackAllocResultOffset = 0x2786872;
constexpr uintptr_t kStage6StartLuaResolverTaskCreateOffset = 0x2788030;
constexpr uintptr_t kStage6StartLuaLoggedInTargetBoxedLookupFlagOffset =
    0x759df48;
constexpr uintptr_t kStage6StartLuaAppDMGlobalLoadOffset = 0x243eb05;
constexpr uintptr_t kStage6StartLuaAppDMBeforeDispatchOffset = 0x243eb13;
constexpr uintptr_t kStage6StartLuaAppDMAfterDispatchOffset = 0x243eb1a;
constexpr uintptr_t kStage6StartLuaDMDispatchOffset = 0x23392d6;
constexpr uintptr_t kStage6StartLuaDMDispatchSelectedManagerOffset = 0x2339374;
constexpr uintptr_t kStage6StartLuaDMInvokerOffset = 0x2339452;
constexpr uintptr_t kStage6StartLuaDMInvokerSameThreadObjectLoadOffset =
    0x2339484;
constexpr uintptr_t kStage6StartLuaDMInvokerAsyncPathOffset = 0x23394b1;
constexpr uintptr_t kStage6StartLuaDMInvokerNullResultOffset = 0x2339540;
constexpr uintptr_t kStage6StartLuaAppDMGlobalOffset = 0x70807e0;
constexpr uintptr_t kStage6StartLuaDMMainThreadIdGlobalOffset = 0x7081868;
constexpr uintptr_t kStage6StartLuaSingleSurfaceStartLuaAppOffset = 0x2505302;
constexpr uintptr_t kStage6StartLuaUserDidLoginOffset = 0x2690432;
constexpr uintptr_t kStage6StartLuaUserDidLoginDeepCallStateLoadOffset =
    0x26905e3;
constexpr uintptr_t kStage6StartLuaDeepStartOffset = 0x2690666;
constexpr uintptr_t kStage6StartLuaDeepAppStateUpdateOffset = 0x26908aa;
constexpr uintptr_t kStage6StartLuaDeepStateCopyOffset = 0x2690962;
constexpr uintptr_t kStage6StartLuaDeepHeaderLoadOffset = 0x2690ae2;
constexpr uintptr_t kStage6StartLuaDeepHeaderChecksPassedOffset = 0x2690af9;
constexpr uintptr_t kStage6StartLuaDeepCleanupOffset = 0x2690c65;
constexpr uintptr_t kStage6StartLuaReverseStringCopyNullDestStoreOffset =
    0x2491c55;
constexpr uintptr_t kStage6StartLuaReverseStringCopyDoneOffset = 0x2491c5f;
constexpr uintptr_t kStage6StartLuaRegistryGlobalOffset = 0x765a878;
constexpr uintptr_t kStage6AppBridgePrimaryStateOffset = 0x70a3ff0;
constexpr uintptr_t kStage6AppBridgeSecondaryStateOffset = 0x70a4468;
constexpr uintptr_t kStage6AppBridgePrimaryInitGuardOffset = 0x70a4460;
constexpr uintptr_t kStage6AppBridgeSecondaryInitGuardOffset = 0x70a48d8;
constexpr uintptr_t kNativeUpdateScreenOrientationCallbackSetupOffset =
    0x24f1f5a;
constexpr uintptr_t kNativeUpdateScreenOrientationStateSlotLoadOffset =
    0x24f1fe5;
constexpr uintptr_t kStage6EnableDmNotificationMonitorFlagOffset = 0x70b48c0;
constexpr uintptr_t kStage6EnableDmNotificationMonitorBlockOffset = 0x23f0fdf;
constexpr uintptr_t kStage6EnableDmNotificationMonitorBranchOffset = 0x23f0fe7;
constexpr uintptr_t kStage6AppBridgeV2OwnerInitHelperOffset = 0x23f0004;
constexpr uintptr_t kStage6AppBridgeV2OwnerStateStoreOffset = 0x23f09af;
constexpr uintptr_t kStage6InitSystemDialogNullResultReadOffset = 0x2cb74f9;
constexpr uintptr_t kStage6InitSystemDialogNullTestOffset = 0x2cb74fc;
constexpr uintptr_t kStage6AppBridgeVectorAllocationNullCheckOffset = 0x242c63d;
constexpr uintptr_t kStage6StartLuaDeepHashBucketCountReadOffset = 0x2300a52;
constexpr uintptr_t kStage6StartLuaDeepHashLookupMissOffset = 0x2300d93;
constexpr uintptr_t kStage6StartLuaDeepSystemDialogNullResultReadOffset =
    0x2690b0c;
constexpr uintptr_t kStage6StartLuaDeepSystemDialogNullTestOffset = 0x2690b0f;
constexpr uintptr_t kStage6StartLuaNullContinuationAddrefOffset = 0x2f44f83;
constexpr uintptr_t kStage6StartLuaNullContinuationNullRefOffset = 0x2f44f90;
constexpr uintptr_t kStage6StartLuaSharedRefcountReleaseHelperOffset =
    0x233f198;
constexpr uintptr_t kStage6StartLuaRefcountReleaseHelperOffset = 0x2690f86;
constexpr uintptr_t kStage6StartLuaTargetTableDynamicCastTypeReadOffset =
    0x2bfcedd;
constexpr uintptr_t kStage6AsyncAppBridgeHashAllocationStoreOffset = 0x2440b51;
constexpr uintptr_t kStage6StartAppParamsVectorBackingAllocReturnOffset =
    0x2447eec;
constexpr uintptr_t kStage6StartAppParamsField40AllocReturnOffset = 0x244954f;
constexpr uintptr_t kStage6StartAppParamsField60AllocReturnOffset = 0x24495af;
constexpr uintptr_t kStage6StartAppParamsField0AllocReturnOffset = 0x2449645;
constexpr uintptr_t kStage6StartAppParamsField20AllocReturnOffset = 0x24496e0;
constexpr uintptr_t kStage6AsyncAppBridgeXmlDeserializeErrorBranchOffset =
    0x2e01118;
constexpr uintptr_t kStage6AsyncAppBridgeOptionalContextFlagOffset = 0x73f37c8;
constexpr uintptr_t kStage6AsyncAppBridgeXmlNamePrimarySlotOffset = 0x73ee558;
constexpr uintptr_t kStage6AsyncAppBridgeXmlNameSecondarySlotOffset = 0x73ee560;
constexpr uintptr_t kStage6AsyncAppBridgeXmlNameTertiarySlotOffset = 0x73ee570;
constexpr uintptr_t kStage6AsyncAppBridgeXmlNameQuaternarySlotOffset =
    0x73ee478;
constexpr uintptr_t kStage6AsyncAppBridgeXmlNameQuinarySlotOffset = 0x73ee470;
constexpr uintptr_t kStage6AsyncAppBridgeXmlNameSenarySlotOffset = 0x73ee480;
constexpr uintptr_t kStage6AsyncAppBridgeXmlNameSeptenarySlotOffset = 0x73ee3c8;
constexpr uintptr_t kStage6AtomicBitmapMidJumpOffset = 0x1f2892a;
constexpr uintptr_t kStage6AtomicBitmapPostJumpOffset = 0x1f2892c;
constexpr uintptr_t kStage6VectorInsertLowBackingStoreOffset = 0x2a1febe;
constexpr uintptr_t kStage6VectorClearInvalidEntryFlagOffset = 0x2c2f7cf;
constexpr uintptr_t kStage6VectorClearStoreEndOffset = 0x2c2f7e8;
constexpr uintptr_t kStage6SystemDialogMessageNullResultReadOffset = 0x42d4661;
constexpr uintptr_t kStage6SystemDialogFormatHelperOffset = 0x40d2e52;
constexpr uintptr_t kStage6PlatformHeaderParseStackFailCallOffset = 0x23176f2;
constexpr uintptr_t kStage6PlatformHeaderParseErrorLandingOffset = 0x231778d;
constexpr uint64_t kStage6FakeIntrusiveRefcount = 0x100000;

}  // namespace mocktail::legacy::internal

#endif  // MOCKTAIL_LEGACY_STAGE6_OFFSETS_H_
