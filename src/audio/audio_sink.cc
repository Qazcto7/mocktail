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

#include "mocktail/audio/audio_sink.h"

#include <limits>

namespace mocktail::audio {

std::size_t BytesPerSample(PcmSampleFormat format) {
  switch (format) {
    case PcmSampleFormat::kUnsigned8:
      return 1;
    case PcmSampleFormat::kSigned16LittleEndian:
      return 2;
    case PcmSampleFormat::kSigned32LittleEndian:
    case PcmSampleFormat::kFloat32LittleEndian:
      return 4;
  }
  return 0;
}

std::size_t BytesPerFrame(const PcmSpec& spec) {
  const std::size_t bytes_per_sample = BytesPerSample(spec.format);
  if (bytes_per_sample == 0 || spec.channels == 0 ||
      bytes_per_sample >
          std::numeric_limits<std::size_t>::max() / spec.channels) {
    return 0;
  }
  return bytes_per_sample * spec.channels;
}

Status ValidatePcmSpec(const PcmSpec& spec) {
  if (spec.sample_rate_hz < 8000 || spec.sample_rate_hz > 384000) {
    return Status::Error(StatusCode::kInvalidArgument,
                         "PCM sample rate must be between 8000 and 384000 Hz");
  }
  if (spec.channels == 0 || spec.channels > 8) {
    return Status::Error(StatusCode::kInvalidArgument,
                         "PCM channel count must be between 1 and 8");
  }
  if (BytesPerFrame(spec) == 0) {
    return Status::Error(StatusCode::kInvalidArgument,
                         "PCM sample format is unsupported");
  }
  return Status::Ok();
}

}  // namespace mocktail::audio
