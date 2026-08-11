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

#ifndef MOCKTAIL_PLATFORM_TEXT_CLIPBOARD_H_
#define MOCKTAIL_PLATFORM_TEXT_CLIPBOARD_H_

#include <memory>
#include <string>

#include "mocktail/status.h"

namespace mocktail {
namespace platform {

// Main-thread platform boundary for UTF-8 clipboard text. Implementations and
// consumers must not log clipboard contents.
class TextClipboard {
 public:
  virtual ~TextClipboard() = default;

  virtual Status ReadText(std::string* text) = 0;
  virtual Status WriteText(const std::string& text) = 0;
};

// Creates the SDL3 clipboard adapter used by both XWayland and native Wayland.
std::unique_ptr<TextClipboard> CreateSdlTextClipboard();

}  // namespace platform
}  // namespace mocktail

#endif  // MOCKTAIL_PLATFORM_TEXT_CLIPBOARD_H_
