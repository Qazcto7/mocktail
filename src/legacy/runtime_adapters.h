#ifndef MOCKTAIL_LEGACY_RUNTIME_ADAPTERS_H_
#define MOCKTAIL_LEGACY_RUNTIME_ADAPTERS_H_

#include <jni.h>

#include <cstdint>
#include <memory>
#include <string>

#include "runtime/roblox_experience_composition.h"
#include "runtime/roblox_fresh_game_launch_controller.h"

namespace mocktail::legacy::internal {

struct ExperienceLifecycleTarget {
  std::weak_ptr<runtime::RobloxExperienceComposition> composition;
};

bool RegisterFreshGamePresentObserver(
    void* context, runtime::FreshLaunchPresentObserver observer,
    void* observer_context);
void ClearFreshGamePresentObserver(void* context);

jobject CreateExperienceRawCallback(void* context,
                                    std::shared_ptr<void> callback_context,
                                    void (*run)(void*, JNIEnv*, jstring));
void ClearExperienceRawCallback(void* context, jobject callback);
jobject CreateMessageBusRequestHandler(void* context,
                                       std::shared_ptr<void> callback_context,
                                       std::string (*run)(void*, JNIEnv*,
                                                          jstring));
void ClearMessageBusRequestHandler(void* context, jobject handler);
jobject CreateBrowserServiceMemStorageCallback(
    void* context, std::shared_ptr<void> callback_context,
    void (*on_item_set)(void*, JNIEnv*, jstring));
void ClearBrowserServiceMemStorageCallback(void* context, jobject callback);

void NotifyLuaAppDidReturn(void* context);
runtime::GameSessionUpdateResult ExperienceSurfaceCreated(
    void* context, std::uint64_t generation);
runtime::GameSessionUpdateResult ExperienceSurfaceChanged(
    void* context, runtime::GameSurface surface);
runtime::GameSessionUpdateResult ExperienceSurfaceDestroyed(
    void* context, std::uint64_t generation);

}  // namespace mocktail::legacy::internal

#endif  // MOCKTAIL_LEGACY_RUNTIME_ADAPTERS_H_
