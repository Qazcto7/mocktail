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

#ifndef MOCKTAIL_RUNTIME_ROBLOX_TEXT_INPUT_JNI_BRIDGE_H_
#define MOCKTAIL_RUNTIME_ROBLOX_TEXT_INPUT_JNI_BRIDGE_H_

#include <cstdint>
#include <memory>
#include <string>

#include "mocktail/status.h"
#include "runtime/roblox_input_native_adapter.h"
#include "window/window.h"

namespace jnivm {
class VM;
}  // namespace jnivm

namespace mocktail {
namespace runtime {

class RobloxWindowInputRuntime;

// Narrow seam between the cross-thread JNI queue and its main-thread owners.
// Production uses RobloxWindowInputRuntime and the SDL window module. Tests
// provide a deterministic implementation without creating an SDL window.
class RobloxTextInputJniBridgeBackend {
 public:
  virtual ~RobloxTextInputJniBridgeBackend() = default;

  virtual Status BeginTextFocusSession(RobloxTextFocusSession session) = 0;
  virtual Status EndTextFocusSession(int64_t textbox_handle,
                                     uint64_t generation,
                                     bool notify_native) = 0;
  virtual Status ReplaceFocusedTextFromEngine(
      uint64_t generation, std::string authoritative_utf8) = 0;
  virtual Status QueryCurrentTextBoxInfo(
      RobloxNativeTextBoxInfoQueryResult* result) = 0;
  virtual Status UpdateTextFocusProperties(
      uint64_t generation, const RobloxTextFocusProperties& properties) = 0;
  virtual bool RegisterMainThreadPump(window::PreTextInputPumpCallback callback,
                                      void* context) = 0;
  virtual void ClearMainThreadPump() = 0;
  virtual void SetTextInputOwnerEnabled(bool enabled) = 0;
  virtual bool RequestShowTextInput(
      uint64_t generation, const window::TextInputArea& area,
      const window::TextInputOptions& options) = 0;
  virtual bool RequestHideTextInput(uint64_t generation) = 0;
};

// Connects pseudo-JVM keyboard callbacks to the input runtime without
// invoking SDL or Roblox native functions from an engine callback thread.
// Guest callbacks enqueue owned commands; the registered window pre-pump
// callback drains them on SDL's main thread.
class RobloxTextInputJniBridge final {
 public:
  static Status Create(jnivm::VM* vm,
                       std::shared_ptr<RobloxWindowInputRuntime> input_runtime,
                       std::unique_ptr<RobloxTextInputJniBridge>* bridge);

  // Deterministic construction seam. The backend is retained through every
  // in-flight VM callback and must obey the same main-thread contract as the
  // production window implementation.
  static Status CreateForTesting(
      jnivm::VM* vm, std::shared_ptr<RobloxTextInputJniBridgeBackend> backend,
      std::unique_ptr<RobloxTextInputJniBridge>* bridge);

  ~RobloxTextInputJniBridge();

  RobloxTextInputJniBridge(const RobloxTextInputJniBridge&) = delete;
  RobloxTextInputJniBridge& operator=(const RobloxTextInputJniBridge&) = delete;

  // Idempotently stops callbacks and clears pending sensitive text before the
  // input runtime and SDL window are destroyed.
  Status Shutdown();

 private:
  struct State;

  RobloxTextInputJniBridge(jnivm::VM* vm, std::shared_ptr<State> state);

  jnivm::VM* vm_ = nullptr;
  std::shared_ptr<State> state_;
  bool installed_ = false;
};

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_ROBLOX_TEXT_INPUT_JNI_BRIDGE_H_
