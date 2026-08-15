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

#ifndef MOCKTAIL_RUNTIME_FAILURE_DIALOG_H_
#define MOCKTAIL_RUNTIME_FAILURE_DIALOG_H_

#include <string_view>

#include "runtime/environment.h"

namespace mocktail {
namespace runtime {

// Canaries and headless sessions remain non-interactive.
bool FailureDialogsEnabled(const Environment& environment);

bool ShowFailureDialog(const Environment& environment,
                       std::string_view message);
bool ShowWarningDialog(const Environment& environment,
                       std::string_view message);

// The helper starts before guest threads, so it can report errors and fatal
// exits even when the main process can no longer show a dialog.
class FailureDialogMonitor final {
 public:
  FailureDialogMonitor() = default;
  ~FailureDialogMonitor();

  FailureDialogMonitor(const FailureDialogMonitor&) = delete;
  FailureDialogMonitor& operator=(const FailureDialogMonitor&) = delete;
  FailureDialogMonitor(FailureDialogMonitor&& other) noexcept;
  FailureDialogMonitor& operator=(FailureDialogMonitor&& other) noexcept;

  static FailureDialogMonitor Start(const Environment& environment,
                                    std::string_view initial_message);

  bool active() const { return socket_ >= 0; }
  void SetMessage(std::string_view message);
  void MarkSuccessful();

 private:
  FailureDialogMonitor(int socket, int helper_pid);
  void Finish(char disposition);

  int socket_ = -1;
  int helper_pid_ = -1;
};

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_FAILURE_DIALOG_H_
