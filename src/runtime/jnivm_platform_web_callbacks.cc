// Copyright 2026 Mocktail Project Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "runtime/jnivm_platform_web_callbacks.h"

#include <utility>

#include "jnivm/jnivm.h"

namespace mocktail {
namespace runtime {

bool SetJnivmPlatformWebCallbacks(
    void* context, std::shared_ptr<void> callback_context,
    void (*on_data_model_notification)(void*, JNIEnv*, jstring, jstring),
    void (*on_app_bridge_notification)(void*, JNIEnv*, jstring, jstring),
    void (*on_native_overlay)(void*, JNIEnv*, jstring, jstring),
    void (*on_open_web_activity)(void*, JNIEnv*, jstring, jstring),
    void (*on_sync_cookies)(void*, JNIEnv*, jstring),
    void (*on_set_cookie)(void*, JNIEnv*, jstring, jstring)) {
  if (context == nullptr || callback_context == nullptr ||
      on_data_model_notification == nullptr ||
      on_app_bridge_notification == nullptr || on_native_overlay == nullptr ||
      on_open_web_activity == nullptr || on_sync_cookies == nullptr ||
      on_set_cookie == nullptr) {
    return false;
  }
  static_cast<jnivm::VM*>(context)->SetRobloxDataModelNotificationCallbacks(
      std::move(callback_context),
      jnivm::RobloxDataModelNotificationCallbacks{
          on_data_model_notification, on_app_bridge_notification,
          on_native_overlay, on_open_web_activity, on_sync_cookies,
          on_set_cookie});
  return true;
}

void ClearJnivmPlatformWebCallbacks(void* context) {
  if (context != nullptr) {
    static_cast<jnivm::VM*>(context)
        ->ClearRobloxDataModelNotificationCallbacks();
  }
}

}  // namespace runtime
}  // namespace mocktail
