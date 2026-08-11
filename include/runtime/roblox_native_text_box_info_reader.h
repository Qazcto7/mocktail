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

#ifndef MOCKTAIL_RUNTIME_ROBLOX_NATIVE_TEXT_BOX_INFO_READER_H_
#define MOCKTAIL_RUNTIME_ROBLOX_NATIVE_TEXT_BOX_INFO_READER_H_

#include <jni.h>

#include "mocktail/status.h"

namespace mocktail {
namespace runtime {

// host copy of the current APK's NativeTextBoxInfo Java value. The copy
// contains no text and remains valid after the JNI local reference is released.
struct RobloxNativeTextBoxInfoSnapshot {
  float x = 0.0F;
  float y = 0.0F;
  float width = 0.0F;
  float height = 0.0F;
  float font_size = 0.0F;
  bool multiline = false;
  int x_alignment = 0;
  int y_alignment = 0;
  int text_color = 0;
  int font = 0;
  int text_input_type = 0;
  int return_key_type = 0;
  bool manual_focus_release = false;
  bool text_wrapped = false;
};

struct RobloxNativeTextBoxInfoQueryResult {
  bool available = false;
  RobloxNativeTextBoxInfoSnapshot info;
};

using RobloxNativeGetTextBoxInfoFn = jobject (*)(JNIEnv*, jclass);

// Calls NativeGLInterface.nativeGetTextBoxInfo and consumes the returned local
// reference. A null result without a JNI exception is a successful
// `available=false` snapshot, matching the Android callback contract when no
// TextBox currently owns focus.
Status QueryRobloxNativeTextBoxInfo(
    JNIEnv* env, jclass native_gl_class,
    RobloxNativeGetTextBoxInfoFn native_get_text_box_info,
    RobloxNativeTextBoxInfoQueryResult* result);

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_ROBLOX_NATIVE_TEXT_BOX_INFO_READER_H_
