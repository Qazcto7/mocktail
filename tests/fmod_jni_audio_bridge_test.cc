#include "mocktail/audio/fmod_jni_audio_bridge.h"
#include "mocktail/audio/sdl_audio_capture.h"
#include "mocktail/audio/webrtc_jni_audio_bridge.h"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "jnivm/jnivm.h"
#include "mocktail/audio/sdl_audio_sink.h"

namespace mocktail::audio {
namespace {

class ScopedEnvironment final {
public:
  ScopedEnvironment(const char *name, const char *value) : name_(name) {
    const char *current = std::getenv(name);
    if (current != nullptr) {
      had_value_ = true;
      previous_ = current;
    }
    setenv(name, value, 1);
  }

  ~ScopedEnvironment() {
    if (had_value_) {
      setenv(name_.c_str(), previous_.c_str(), 1);
    } else {
      unsetenv(name_.c_str());
    }
  }

  ScopedEnvironment(const ScopedEnvironment &) = delete;
  ScopedEnvironment &operator=(const ScopedEnvironment &) = delete;

private:
  std::string name_;
  std::string previous_;
  bool had_value_ = false;
};

class ScopedSdlAudioShutdown final {
public:
  ~ScopedSdlAudioShutdown() { (void)ShutdownSdlAudioSubsystem(); }
};

struct WebRtcCaptureProbe {
  std::mutex mutex;
  std::condition_variable cv;
  void *buffer = nullptr;
  jlong capacity = -1;
  int callbacks = 0;
  int last_size = 0;
};

struct WebRtcPlayoutProbe {
  std::mutex mutex;
  std::condition_variable cv;
  void *buffer = nullptr;
  jlong capacity = -1;
  int callbacks = 0;
  int last_size = 0;
  bool invalid_buffer = false;
};

void JNICALL CacheWebRtcBuffer(JNIEnv *env, jobject, jobject buffer,
                               jlong native_audio_record) {
  auto *probe = reinterpret_cast<WebRtcCaptureProbe *>(native_audio_record);
  std::lock_guard<std::mutex> lock(probe->mutex);
  probe->buffer = env->GetDirectBufferAddress(buffer);
  probe->capacity = env->GetDirectBufferCapacity(buffer);
}

void JNICALL WebRtcDataIsRecorded(JNIEnv *, jobject, jint size,
                                  jlong native_audio_record) {
  auto *probe = reinterpret_cast<WebRtcCaptureProbe *>(native_audio_record);
  {
    std::lock_guard<std::mutex> lock(probe->mutex);
    ++probe->callbacks;
    probe->last_size = size;
  }
  probe->cv.notify_all();
}

void JNICALL CacheWebRtcPlayoutBuffer(JNIEnv *env, jobject, jobject buffer,
                                      jlong native_audio_track) {
  auto *probe = reinterpret_cast<WebRtcPlayoutProbe *>(native_audio_track);
  std::lock_guard<std::mutex> lock(probe->mutex);
  probe->buffer = env->GetDirectBufferAddress(buffer);
  probe->capacity = env->GetDirectBufferCapacity(buffer);
}

void JNICALL WebRtcGetPlayoutData(JNIEnv *, jobject, jint size,
                                  jlong native_audio_track) {
  auto *probe = reinterpret_cast<WebRtcPlayoutProbe *>(native_audio_track);
  {
    std::lock_guard<std::mutex> lock(probe->mutex);
    if (probe->buffer == nullptr || size <= 0 || size > probe->capacity) {
      probe->invalid_buffer = true;
    } else {
      std::memset(probe->buffer, 0x35, static_cast<std::size_t>(size));
    }
    ++probe->callbacks;
    probe->last_size = size;
  }
  probe->cv.notify_all();
}

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

TEST(WebRtcJniAudioBridgeTest, CapturesTenMillisecondFramesThroughExactJni) {
  unsetenv("MOCKTAIL_AUDIO_INPUT_DEVICE");
  ScopedSdlAudioShutdown shutdown;
  jnivm::VM vm;
  const Status install_status = InstallWebRtcJniAudioBridge(&vm);
  ASSERT_TRUE(install_status.ok()) << install_status.message();

  JNIEnv *env = vm.GetJNIEnv();
  jclass recorder_class =
      env->FindClass("org/webrtc/voiceengine/WebRtcAudioRecord");
  ASSERT_NE(recorder_class, nullptr);
  const JNINativeMethod native_methods[] = {
      {const_cast<char *>("nativeCacheDirectBufferAddress"),
       const_cast<char *>("(Ljava/nio/ByteBuffer;J)V"),
       reinterpret_cast<void *>(&CacheWebRtcBuffer)},
      {const_cast<char *>("nativeDataIsRecorded"), const_cast<char *>("(IJ)V"),
       reinterpret_cast<void *>(&WebRtcDataIsRecorded)},
  };
  ASSERT_EQ(env->RegisterNatives(recorder_class, native_methods, 2), JNI_OK);

  const jmethodID constructor =
      env->GetMethodID(recorder_class, "<init>", "(J)V");
  const jmethodID init =
      env->GetMethodID(recorder_class, "initRecording", "(II)I");
  const jmethodID start =
      env->GetMethodID(recorder_class, "startRecording", "()Z");
  const jmethodID stop =
      env->GetMethodID(recorder_class, "stopRecording", "()Z");
  WebRtcCaptureProbe probe;
  jobject recorder = env->NewObject(recorder_class, constructor,
                                    reinterpret_cast<jlong>(&probe));
  ASSERT_NE(recorder, nullptr);

  EXPECT_EQ(env->CallIntMethod(recorder, init, 48000, 1), 480);
  {
    std::lock_guard<std::mutex> lock(probe.mutex);
    EXPECT_NE(probe.buffer, nullptr);
    EXPECT_EQ(probe.capacity, 480 * static_cast<jlong>(sizeof(std::int16_t)));
  }
  ASSERT_EQ(env->CallBooleanMethod(recorder, start), JNI_TRUE);
  {
    std::unique_lock<std::mutex> lock(probe.mutex);
    ASSERT_TRUE(probe.cv.wait_for(lock, std::chrono::seconds(2),
                                  [&probe] { return probe.callbacks > 0; }));
    EXPECT_EQ(probe.last_size, probe.capacity);
  }
  EXPECT_EQ(env->CallBooleanMethod(recorder, stop), JNI_TRUE);

  EXPECT_TRUE(ShutdownWebRtcJniAudioBridge(&vm).ok());
  EXPECT_TRUE(ShutdownSdlAudioSubsystem().ok());
}

TEST(WebRtcJniAudioBridgeTest, DisabledMicrophoneRejectsRecordingInit) {
  ScopedEnvironment input("MOCKTAIL_AUDIO_INPUT_DEVICE", "disabled");
  ScopedSdlAudioShutdown shutdown;
  jnivm::VM vm;
  const Status install_status = InstallWebRtcJniAudioBridge(&vm);
  ASSERT_TRUE(install_status.ok()) << install_status.message();

  JNIEnv *env = vm.GetJNIEnv();
  jclass recorder_class =
      env->FindClass("org/webrtc/voiceengine/WebRtcAudioRecord");
  ASSERT_NE(recorder_class, nullptr);
  const jmethodID constructor =
      env->GetMethodID(recorder_class, "<init>", "(J)V");
  const jmethodID init =
      env->GetMethodID(recorder_class, "initRecording", "(II)I");
  ASSERT_NE(constructor, nullptr);
  ASSERT_NE(init, nullptr);

  jobject recorder = env->NewObject(recorder_class, constructor, 1LL);
  ASSERT_NE(recorder, nullptr);
  EXPECT_EQ(env->CallIntMethod(recorder, init, 48000, 1), -1);
  EXPECT_TRUE(ShutdownWebRtcJniAudioBridge(&vm).ok());
}

TEST(WebRtcJniAudioBridgeTest, PlaysTenMillisecondFramesThroughExactJni) {
  ScopedEnvironment input("MOCKTAIL_AUDIO_INPUT_DEVICE", "disabled");
  ScopedSdlAudioShutdown shutdown;
  jnivm::VM vm;
  const Status install_status = InstallWebRtcJniAudioBridge(&vm);
  ASSERT_TRUE(install_status.ok()) << install_status.message();

  JNIEnv *env = vm.GetJNIEnv();
  jclass track_class =
      env->FindClass("org/webrtc/voiceengine/WebRtcAudioTrack");
  ASSERT_NE(track_class, nullptr);
  const JNINativeMethod native_methods[] = {
      {const_cast<char *>("nativeCacheDirectBufferAddress"),
       const_cast<char *>("(Ljava/nio/ByteBuffer;J)V"),
       reinterpret_cast<void *>(&CacheWebRtcPlayoutBuffer)},
      {const_cast<char *>("nativeGetPlayoutData"), const_cast<char *>("(IJ)V"),
       reinterpret_cast<void *>(&WebRtcGetPlayoutData)},
  };
  ASSERT_EQ(env->RegisterNatives(track_class, native_methods, 2), JNI_OK);

  const jmethodID constructor = env->GetMethodID(track_class, "<init>", "(J)V");
  const jmethodID init = env->GetMethodID(track_class, "initPlayout", "(IID)I");
  const jmethodID buffer_size =
      env->GetMethodID(track_class, "getBufferSizeInFrames", "()I");
  const jmethodID max_volume =
      env->GetMethodID(track_class, "getStreamMaxVolume", "()I");
  const jmethodID volume =
      env->GetMethodID(track_class, "getStreamVolume", "()I");
  const jmethodID set_volume =
      env->GetMethodID(track_class, "setStreamVolume", "(I)Z");
  const jmethodID start = env->GetMethodID(track_class, "startPlayout", "()Z");
  const jmethodID stop = env->GetMethodID(track_class, "stopPlayout", "()Z");
  WebRtcPlayoutProbe probe;
  jobject track =
      env->NewObject(track_class, constructor, reinterpret_cast<jlong>(&probe));
  ASSERT_NE(track, nullptr);

  const jint android_buffer_bytes =
      env->CallIntMethod(track, init, 48000, 2, 1.0);
  EXPECT_GE(android_buffer_bytes,
            480 * 2 * static_cast<jint>(sizeof(std::int16_t)));
  {
    std::lock_guard<std::mutex> lock(probe.mutex);
    EXPECT_NE(probe.buffer, nullptr);
    EXPECT_EQ(probe.capacity,
              480 * 2 * static_cast<jlong>(sizeof(std::int16_t)));
  }
  EXPECT_GE(env->CallIntMethod(track, buffer_size), 480);
  EXPECT_EQ(env->CallIntMethod(track, max_volume), 100);
  EXPECT_EQ(env->CallIntMethod(track, volume), 100);
  EXPECT_EQ(env->CallBooleanMethod(track, set_volume, 50), JNI_TRUE);

  ASSERT_EQ(env->CallBooleanMethod(track, start), JNI_TRUE);
  {
    std::unique_lock<std::mutex> lock(probe.mutex);
    ASSERT_TRUE(probe.cv.wait_for(lock, std::chrono::seconds(2),
                                  [&probe] { return probe.callbacks >= 3; }));
    EXPECT_FALSE(probe.invalid_buffer);
    EXPECT_EQ(probe.last_size, probe.capacity);
  }
  EXPECT_EQ(env->CallBooleanMethod(track, stop), JNI_TRUE);

  EXPECT_TRUE(ShutdownWebRtcJniAudioBridge(&vm).ok());
  EXPECT_TRUE(ShutdownSdlAudioSubsystem().ok());
}

TEST(SdlAudioCaptureTest, ResolvesDefaultIdAndUnambiguousDeviceNames) {
  const std::vector<SdlRecordingDevice> devices = {
      {11, "USB Microphone"},
      {12, "Built-in Microphone"},
      {13, "USB Microphone"},
  };
  std::uint32_t id = 999;
  std::string name;

  EXPECT_TRUE(ResolveSdlRecordingDevice("default", devices, &id, &name).ok());
  EXPECT_EQ(id, 0U);
  EXPECT_EQ(name, "default");

  EXPECT_TRUE(ResolveSdlRecordingDevice("id:12", devices, &id, &name).ok());
  EXPECT_EQ(id, 12U);
  EXPECT_EQ(name, "Built-in Microphone");

  const Status ambiguous =
      ResolveSdlRecordingDevice("USB Microphone", devices, &id, &name);
  EXPECT_EQ(ambiguous.code(), StatusCode::kInvalidArgument);
  const Status unavailable =
      ResolveSdlRecordingDevice("Missing Microphone", devices, &id, &name);
  EXPECT_EQ(unavailable.code(), StatusCode::kUnavailable);
  const Status invalid_id =
      ResolveSdlRecordingDevice("id:0", devices, &id, &name);
  EXPECT_EQ(invalid_id.code(), StatusCode::kInvalidArgument);
}

}  // namespace
}  // namespace mocktail::audio
