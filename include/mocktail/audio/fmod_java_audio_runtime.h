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

#ifndef MOCKTAIL_AUDIO_FMOD_JAVA_AUDIO_RUNTIME_H_
#define MOCKTAIL_AUDIO_FMOD_JAVA_AUDIO_RUNTIME_H_

#include <cstddef>
#include <cstdint>
#include <memory>

#include "mocktail/audio/audio_sink.h"

namespace mocktail::audio {

// org.fmod.AudioDevice is an ordinary Java object. The JNI boundary passes
// its jobject value through this opaque key without making the audio layer
// depend on JNI headers or retain a JNI reference.
using FmodJavaAudioDeviceIdentity = const void*;

// A factory returns a paused sink with exactly source_spec. Production uses
// SDL3; tests can inject a deterministic sink without opening a host device.
// factory_context must remain valid until the runtime is shut down.
using FmodJavaAudioSinkFactory = Status (*)(
    void* factory_context, const PcmSpec& source_spec,
    std::unique_ptr<AudioSink>* sink);

struct FmodJavaAudioRuntimeOptions {
  FmodJavaAudioSinkFactory sink_factory = nullptr;
  void* sink_factory_context = nullptr;

  std::uint32_t max_devices = 8;
  std::uint32_t max_block_count = 256;
  std::size_t max_buffer_bytes_per_device = 64U * 1024U * 1024U;
};

// Content-free counters suitable for readiness logs. They never expose PCM,
// JNI identities, or guest pointers.
struct FmodJavaAudioRuntimeStats {
  std::uint64_t init_attempts = 0;
  std::uint64_t initialized_devices = 0;
  std::uint64_t rejected_init_calls = 0;
  std::uint64_t close_calls = 0;
  std::uint64_t rejected_close_calls = 0;
  std::uint64_t write_attempts = 0;
  std::uint64_t submitted_buffers = 0;
  std::uint64_t submitted_bytes = 0;
  std::uint64_t consumed_buffers = 0;
  std::uint64_t consumed_bytes = 0;
  std::uint64_t discarded_buffers = 0;
  std::uint64_t discarded_bytes = 0;
  std::uint64_t rejected_write_calls = 0;
  std::size_t active_devices = 0;
  std::size_t pending_buffers = 0;
  std::size_t pending_bytes = 0;
};

// Thread-safe implementation of the APK's exact Java playback contract:
//
//   AudioDevice.init(channels, sampleRate, blockSize, blockCount)Z
//   AudioDevice.write(byte[], length)V
//   AudioDevice.close()V
//
// Init() allocates blockCount fixed slots of blockSize frames. Every successful
// Write() copies guest bytes synchronously into one slot, then lends that stable
// storage to AudioSink without a second PCM copy. FmodJavaAudioRuntime performs
// no per-write allocation for buffer storage or release ownership. A producer
// waits with AudioTrack-style blocking backpressure when all slots are borrowed
// instead of growing memory or dropping a block.
class FmodJavaAudioRuntime final {
 public:
  explicit FmodJavaAudioRuntime(
      const FmodJavaAudioRuntimeOptions& options = {});
  ~FmodJavaAudioRuntime();

  FmodJavaAudioRuntime(const FmodJavaAudioRuntime&) = delete;
  FmodJavaAudioRuntime& operator=(const FmodJavaAudioRuntime&) = delete;

  Status Init(FmodJavaAudioDeviceIdentity device_identity, int channels,
              int sample_rate_hz, int block_size_frames, int block_count);
  Status Write(FmodJavaAudioDeviceIdentity device_identity,
               const std::uint8_t* bytes, std::size_t size_bytes);
  Status Close(FmodJavaAudioDeviceIdentity device_identity);

  FmodJavaAudioRuntimeStats GetStats() const;

  // Idempotent. Prevents new devices/writes, shuts down every sink, and waits
  // for every borrowed owned buffer to be released before returning.
  void Shutdown();

 private:
  struct State;
  std::unique_ptr<State> state_;
};

}  // namespace mocktail::audio

#endif  // MOCKTAIL_AUDIO_FMOD_JAVA_AUDIO_RUNTIME_H_
