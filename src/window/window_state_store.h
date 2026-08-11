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

#ifndef MOCKTAIL_WINDOW_WINDOW_STATE_STORE_H_
#define MOCKTAIL_WINDOW_WINDOW_STATE_STORE_H_

#include <filesystem>

#include "mocktail/status.h"

namespace mocktail {
namespace window {

// Windowed geometry remains separate from fullscreen/maximized state so a
// compositor transition cannot replace the useful restore rectangle with the
// monitor-sized surface extent.
struct PersistedWindowState {
  int x = 0;
  int y = 0;
  int width = 1280;
  int height = 720;
  bool has_position = false;
  bool fullscreen = false;
  bool maximized = false;
};

struct WindowStateLoadResult {
  bool found = false;
  PersistedWindowState state;
  Status status;

  explicit operator bool() const { return status.ok(); }
};

// Reads and writes the bounded, versioned host window state. The writer uses
// a same-directory temporary file, fsync, and rename so an interrupted launch
// cannot leave a partially written restore record.
WindowStateLoadResult LoadWindowState(const std::filesystem::path& path);
Status StoreWindowState(const std::filesystem::path& path,
                        const PersistedWindowState& state);

}  // namespace window
}  // namespace mocktail

#endif  // MOCKTAIL_WINDOW_WINDOW_STATE_STORE_H_
