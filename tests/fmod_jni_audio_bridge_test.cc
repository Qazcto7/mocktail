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

#include "mocktail/audio/fmod_jni_audio_bridge.h"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "jnivm/jnivm.h"

namespace mocktail::audio {
namespace {

TEST(FmodJniAudioBridgeTest, RunsExactJavaContractThroughSdlSink) {
  unsetenv("MOCKTAIL_AUDIO_OUTPUT_DEVICE");
  jnivm::VM vm;
  const Status install_status = InstallFmodJniAudioBridge(&vm);
  ASSERT_TRUE(install_status.ok()) << install_status.message();

  JNIEnv* env = vm.GetJNIEnv();
  jclass device_class = env->FindClass("org/fmod/AudioDevice");
  ASSERT_NE(device_class, nullptr);
  const jmethodID constructor =
      env->GetMethodID(device_class, "<init>", "()V");
  const jmethodID init =
      env->GetMethodID(device_class, "init", "(IIII)Z");
  const jmethodID write =
      env->GetMethodID(device_class, "write", "([BI)V");
  const jmethodID close = env->GetMethodID(device_class, "close", "()V");
  jobject device = env->NewObject(device_class, constructor);
  ASSERT_NE(device, nullptr);

  ASSERT_EQ(env->CallBooleanMethod(device, init, 2, 48000, 256, 4),
            JNI_TRUE);
  std::vector<jbyte> pcm(256U * 2U * sizeof(std::int16_t), 0);
  jbyteArray array = env->NewByteArray(static_cast<jsize>(pcm.size()));
  ASSERT_NE(array, nullptr);
  env->SetByteArrayRegion(array, 0, static_cast<jsize>(pcm.size()),
                          pcm.data());
  for (int block = 0; block < 4; ++block) {
    env->CallVoidMethod(device, write, array, static_cast<jint>(pcm.size()));
  }

  std::this_thread::sleep_for(std::chrono::milliseconds(150));
  env->CallVoidMethod(device, close);
  const Status shutdown_status = ShutdownFmodJniAudioBridge(&vm);
  EXPECT_TRUE(shutdown_status.ok()) << shutdown_status.message();
}

TEST(FmodJniAudioBridgeTest, RejectsUnavailableConfiguredOutput) {
  ASSERT_EQ(setenv("MOCKTAIL_AUDIO_OUTPUT_DEVICE",
                   "Mocktail device that cannot exist", 1),
            0);
  jnivm::VM vm;
  const Status status = InstallFmodJniAudioBridge(&vm);
  EXPECT_EQ(status.code(), StatusCode::kUnavailable);
  EXPECT_NE(status.message().find("unavailable"), std::string::npos);
  if (status.ok()) {
    EXPECT_TRUE(ShutdownFmodJniAudioBridge(&vm).ok());
  }
  unsetenv("MOCKTAIL_AUDIO_OUTPUT_DEVICE");
}

}  // namespace
}  // namespace mocktail::audio
