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

#include "mocktail/platform/text_clipboard.h"

#include <SDL3/SDL_clipboard.h>
#include <SDL3/SDL_error.h>
#include <SDL3/SDL_stdinc.h>

#include <memory>
#include <string>
#include <utility>

namespace mocktail {
namespace platform {
namespace {

Status SdlClipboardError(const char* operation) {
  std::string message = operation != nullptr ? operation : "SDL clipboard";
  message += " failed: ";
  const char* error = SDL_GetError();
  message += error != nullptr && error[0] != '\0' ? error : "unknown SDL error";
  return Status::Error(StatusCode::kPlatformError, std::move(message));
}

class SdlTextClipboard final : public TextClipboard {
 public:
  Status ReadText(std::string* text) override {
    if (text == nullptr) {
      return Status::Error(StatusCode::kInvalidArgument,
                           "clipboard text output is required");
    }
    text->clear();
    SDL_ClearError();
    char* clipboard_text = SDL_GetClipboardText();
    if (clipboard_text == nullptr) {
      return SdlClipboardError("SDL_GetClipboardText");
    }
    text->assign(clipboard_text);
    SDL_free(clipboard_text);
    return Status::Ok();
  }

  Status WriteText(const std::string& text) override {
    if (!SDL_SetClipboardText(text.c_str())) {
      return SdlClipboardError("SDL_SetClipboardText");
    }
    return Status::Ok();
  }
};

}  // namespace

std::unique_ptr<TextClipboard> CreateSdlTextClipboard() {
  return std::make_unique<SdlTextClipboard>();
}

}  // namespace platform
}  // namespace mocktail
