#include "mocktail/audio/audio_sink.h"
#include "mocktail/mocktail_rust.h"

namespace mocktail::audio {

namespace {

MocktailRustPcmFormat ToRustPcmFormat(PcmSampleFormat format) {
  switch (format) {
    case PcmSampleFormat::kUnsigned8:
      return kMocktailRustPcmUnsigned8;
    case PcmSampleFormat::kSigned16LittleEndian:
      return kMocktailRustPcmSigned16LittleEndian;
    case PcmSampleFormat::kSigned32LittleEndian:
      return kMocktailRustPcmSigned32LittleEndian;
    case PcmSampleFormat::kFloat32LittleEndian:
      return kMocktailRustPcmFloat32LittleEndian;
  }
  return kMocktailRustPcmUnsigned8;
}

}  // namespace

std::size_t BytesPerSample(PcmSampleFormat format) {
  return mocktail_rust_audio_bytes_per_sample(ToRustPcmFormat(format));
}

std::size_t BytesPerFrame(const PcmSpec& spec) {
  return BytesPerSample(spec.format) * spec.channels;
}

Status ValidatePcmSpec(const PcmSpec& spec) {
  size_t bpf = 0;
  char err_buf[256] = {};
  const int rc = mocktail_rust_audio_validate_pcm(
      spec.sample_rate_hz, spec.channels, ToRustPcmFormat(spec.format),
      &bpf, err_buf, sizeof(err_buf));
  if (rc != 0) {
    return Status::Error(StatusCode::kInvalidArgument,
                         err_buf[0] != '\0' ? err_buf : "invalid PCM spec");
  }
  return Status::Ok();
}

}  // namespace mocktail::audio
