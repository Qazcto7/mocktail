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

#ifndef MOCKTAIL_AUDIO_AUDIO_SINK_H_
#define MOCKTAIL_AUDIO_AUDIO_SINK_H_

#include <cstddef>
#include <cstdint>

#include "mocktail/status.h"

namespace mocktail::audio {

// Interleaved PCM formats accepted at the host audio boundary. Endianness is
// explicit because Android x86-64 producers use little-endian PCM regardless
// of the host implementation chosen by SDL.
enum class PcmSampleFormat {
  kUnsigned8,
  kSigned16LittleEndian,
  kSigned32LittleEndian,
  kFloat32LittleEndian,
};

struct PcmSpec {
  int sample_rate_hz = 48000;
  std::uint8_t channels = 2;
  PcmSampleFormat format = PcmSampleFormat::kSigned16LittleEndian;
};

using AudioBufferReleaseCallback = void (*)(void* context, const void* data,
                                            std::size_t size_bytes);

// A PCM submission. With no release callback, Enqueue() copies the bytes
// before returning. With a release callback, the sink may borrow the buffer;
// the caller must keep it valid until the callback runs. A successful
// submission invokes the callback exactly once, including when Clear() or
// Shutdown() discards queued audio. A failed submission never invokes it.
struct PcmBuffer {
  const void* data = nullptr;
  std::size_t size_bytes = 0;
  AudioBufferReleaseCallback release_callback = nullptr;
  void* release_context = nullptr;
};

Status ValidatePcmSpec(const PcmSpec& spec);
std::size_t BytesPerSample(PcmSampleFormat format);
std::size_t BytesPerFrame(const PcmSpec& spec);

// Thread-safe PCM playback contract. Implementations perform device format
// conversion and resampling through their host audio library; callers always
// submit data in source_spec().
class AudioSink {
 public:
  virtual ~AudioSink() = default;

  virtual const PcmSpec& source_spec() const = 0;
  virtual Status Enqueue(const PcmBuffer& buffer) = 0;
  virtual Status Pause() = 0;
  virtual Status Resume() = 0;
  // Linear gain is delegated to the host audio library. Zero mutes, one is
  // unity gain, and negative or non-finite values are rejected.
  virtual Status SetGain(float linear_gain) = 0;
  virtual Status Flush() = 0;
  virtual Status Clear() = 0;
  virtual Status GetQueuedBytes(std::size_t* size_bytes) const = 0;

  // Idempotent. It waits for in-flight API calls and releases all borrowed
  // buffers before returning. Calls started after shutdown fail closed.
  virtual void Shutdown() = 0;
};

}  // namespace mocktail::audio

#endif  // MOCKTAIL_AUDIO_AUDIO_SINK_H_
