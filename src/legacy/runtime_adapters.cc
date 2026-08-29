#include "legacy/runtime_adapters.h"

#include <utility>

#include "jnivm/jnivm.h"
#include "window/window.h"

namespace mocktail::legacy::internal {

bool RegisterFreshGamePresentObserver(
    void* context, runtime::FreshLaunchPresentObserver observer,
    void* observer_context) {
  if (context == nullptr) {
    return false;
  }
  return static_cast<window::ScopedPresentObserver*>(context)->Register(
      observer, observer_context);
}

void ClearFreshGamePresentObserver(void* context) {
  if (context != nullptr) {
    static_cast<window::ScopedPresentObserver*>(context)->Reset();
  }
}

jobject CreateExperienceRawCallback(void* context,
                                    std::shared_ptr<void> callback_context,
                                    void (*run)(void*, JNIEnv*, jstring)) {
  if (context == nullptr || run == nullptr) {
    return nullptr;
  }
  return static_cast<jnivm::VM*>(context)->CreateMessageBusRawCallback(
      std::move(callback_context), jnivm::MessageBusRawCallbacks{run});
}

void ClearExperienceRawCallback(void* context, jobject callback) {
  if (context != nullptr) {
    static_cast<jnivm::VM*>(context)->ClearMessageBusRawCallback(callback);
  }
}

jobject CreateMessageBusRequestHandler(void* context,
                                       std::shared_ptr<void> callback_context,
                                       std::string (*run)(void*, JNIEnv*,
                                                          jstring)) {
  if (context == nullptr || run == nullptr) {
    return nullptr;
  }
  return static_cast<jnivm::VM*>(context)->CreateMessageBusRequestHandler(
      std::move(callback_context),
      jnivm::MessageBusRequestHandlerCallbacks{run});
}

void ClearMessageBusRequestHandler(void* context, jobject handler) {
  if (context != nullptr) {
    static_cast<jnivm::VM*>(context)->ClearMessageBusRequestHandler(handler);
  }
}

jobject CreateBrowserServiceMemStorageCallback(
    void* context, std::shared_ptr<void> callback_context,
    void (*on_item_set)(void*, JNIEnv*, jstring)) {
  if (context == nullptr || on_item_set == nullptr) {
    return nullptr;
  }
  return static_cast<jnivm::VM*>(context)->CreateMemStorageCallback(
      std::move(callback_context),
      jnivm::MemStorageCallbackCallbacks{on_item_set});
}

void ClearBrowserServiceMemStorageCallback(void* context, jobject callback) {
  if (context != nullptr) {
    static_cast<jnivm::VM*>(context)->ClearMemStorageCallback(callback);
  }
}

void NotifyLuaAppDidReturn(void* context) {
  if (context == nullptr) {
    return;
  }
  const std::shared_ptr<runtime::RobloxExperienceComposition> composition =
      static_cast<ExperienceLifecycleTarget*>(context)->composition.lock();
  if (composition != nullptr) {
    composition->NotifyLuaAppDidReturn();
  }
}

runtime::GameSessionUpdateResult ExperienceSurfaceCreated(
    void* context, std::uint64_t generation) {
  return static_cast<runtime::RobloxExperienceComposition*>(context)
      ->SurfaceCreated(generation);
}

runtime::GameSessionUpdateResult ExperienceSurfaceChanged(
    void* context, runtime::GameSurface surface) {
  return static_cast<runtime::RobloxExperienceComposition*>(context)
      ->SurfaceChanged(std::move(surface));
}

runtime::GameSessionUpdateResult ExperienceSurfaceDestroyed(
    void* context, std::uint64_t generation) {
  return static_cast<runtime::RobloxExperienceComposition*>(context)
      ->SurfaceDestroyed(generation);
}

}  // namespace mocktail::legacy::internal
