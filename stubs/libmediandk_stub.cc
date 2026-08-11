// Copyright 2026 Mocktail Project Authors
// Apache 2.0 License
//
// stubs/libmediandk_stub.cc — Stub for Android libmediandk.so.
// AMediaCodec / AMediaFormat are no-ops; Roblox uses them for video decoding.

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <cstdio>

struct AMediaCodec {};
struct AMediaFormat {
  char mime[64];
};

// Forward-declared Android media status type.
using media_status_t = int32_t;
static constexpr media_status_t AMEDIA_OK = 0;
static constexpr media_status_t AMEDIA_ERROR_UNKNOWN = -1;

// Keys exported as global const char* symbols (required by Roblox at link time).
extern "C" {

const char* AMEDIAFORMAT_KEY_MIME          = "mime";
const char* AMEDIAFORMAT_KEY_WIDTH         = "width";
const char* AMEDIAFORMAT_KEY_HEIGHT        = "height";
const char* AMEDIAFORMAT_KEY_BIT_RATE      = "bitrate";
const char* AMEDIAFORMAT_KEY_FRAME_RATE    = "frame-rate";
const char* AMEDIAFORMAT_KEY_COLOR_FORMAT  = "color-format";
const char* AMEDIAFORMAT_KEY_CHANNEL_COUNT = "channel-count";
const char* AMEDIAFORMAT_KEY_SAMPLE_RATE   = "sample-rate";
const char* AMEDIAFORMAT_KEY_I_FRAME_INTERVAL = "i-frame-interval";
const char* AMEDIAFORMAT_KEY_STRIDE        = "stride";

// AMediaFormat
AMediaFormat* AMediaFormat_new() {
  return static_cast<AMediaFormat*>(calloc(1, sizeof(AMediaFormat)));
}
void AMediaFormat_delete(AMediaFormat* fmt) { free(fmt); }
bool AMediaFormat_getInt32(AMediaFormat* /*f*/, const char* /*k*/, int32_t* v) {
  if (v) *v = 0;
  return false;
}
bool AMediaFormat_getBuffer(AMediaFormat* /*f*/, const char* /*k*/,
                             void** /*d*/, size_t* /*s*/) { return false; }
void AMediaFormat_setInt32(AMediaFormat* /*f*/, const char* /*k*/,
                            int32_t /*v*/) {}
void AMediaFormat_setFloat(AMediaFormat* /*f*/, const char* /*k*/,
                            float /*v*/) {}
void AMediaFormat_setString(AMediaFormat* /*f*/, const char* k,
                             const char* v) {
  (void)k; (void)v;
}
void AMediaFormat_setBuffer(AMediaFormat* /*f*/, const char* /*k*/,
                             const void* /*d*/, size_t /*s*/) {}
const char* AMediaFormat_toString(AMediaFormat* /*f*/) { return "{}"; }

// AMediaCodec
AMediaCodec* AMediaCodec_createDecoderByType(const char* /*mime*/) {
  return nullptr;
}
AMediaCodec* AMediaCodec_createEncoderByType(const char* /*mime*/) {
  return nullptr;
}
media_status_t AMediaCodec_delete(AMediaCodec* /*codec*/) {
  return AMEDIA_OK;
}
media_status_t AMediaCodec_configure(AMediaCodec* /*codec*/,
                                      const AMediaFormat* /*format*/,
                                      void* /*surface*/, void* /*crypto*/,
                                      uint32_t /*flags*/) {
  return AMEDIA_ERROR_UNKNOWN;
}
media_status_t AMediaCodec_start(AMediaCodec* /*codec*/) {
  return AMEDIA_ERROR_UNKNOWN;
}
media_status_t AMediaCodec_stop(AMediaCodec* /*codec*/) { return AMEDIA_OK; }
media_status_t AMediaCodec_flush(AMediaCodec* /*codec*/) { return AMEDIA_OK; }
uint8_t* AMediaCodec_getInputBuffer(AMediaCodec* /*codec*/, size_t /*idx*/,
                                     size_t* /*sz*/) { return nullptr; }
uint8_t* AMediaCodec_getOutputBuffer(AMediaCodec* /*codec*/, size_t /*idx*/,
                                      size_t* /*sz*/) { return nullptr; }
ssize_t AMediaCodec_dequeueInputBuffer(AMediaCodec* /*codec*/,
                                        int64_t /*timeoutUs*/) { return -1; }
ssize_t AMediaCodec_dequeueOutputBuffer(AMediaCodec* /*codec*/,
                                         void* /*info*/,
                                         int64_t /*timeoutUs*/) { return -1; }
media_status_t AMediaCodec_queueInputBuffer(AMediaCodec* /*codec*/,
                                             size_t /*idx*/, size_t /*offset*/,
                                             size_t /*size*/, uint64_t /*pts*/,
                                             uint32_t /*flags*/) {
  return AMEDIA_ERROR_UNKNOWN;
}
media_status_t AMediaCodec_releaseOutputBuffer(AMediaCodec* /*codec*/,
                                                size_t /*idx*/,
                                                bool /*render*/) {
  return AMEDIA_OK;
}
AMediaFormat* AMediaCodec_getOutputFormat(AMediaCodec* /*codec*/) {
  return AMediaFormat_new();
}

}  // extern "C"
