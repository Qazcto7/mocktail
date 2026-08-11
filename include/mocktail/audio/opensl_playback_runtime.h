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

#ifndef MOCKTAIL_AUDIO_OPENSL_PLAYBACK_RUNTIME_H_
#define MOCKTAIL_AUDIO_OPENSL_PLAYBACK_RUNTIME_H_

#include <cstdint>

#include "mocktail/audio/opensl_runtime_abi.h"

#if defined(__GNUC__) || defined(__clang__)
#define MOCKTAIL_OPENSL_EXPORT __attribute__((visibility("default")))
#else
#define MOCKTAIL_OPENSL_EXPORT
#endif

// Process-wide, content-free evidence from the production OpenSL boundary.
// Counters contain no audio samples, filenames, account data, or device names.
struct MocktailOpenSlRuntimeStats {
  std::uint64_t submitted_buffers;
  std::uint64_t consumed_buffers;
  std::uint64_t clean_player_shutdowns;
};

extern "C" {

#if !defined(MOCKTAIL_USE_SYSTEM_OPENSL_HEADERS)
extern MOCKTAIL_OPENSL_EXPORT const
    mocktail::audio::opensl_abi::InterfaceId SL_IID_ANDROIDCONFIGURATION;
extern MOCKTAIL_OPENSL_EXPORT const
    mocktail::audio::opensl_abi::InterfaceId SL_IID_ANDROIDSIMPLEBUFFERQUEUE;
extern MOCKTAIL_OPENSL_EXPORT const
    mocktail::audio::opensl_abi::InterfaceId SL_IID_BUFFERQUEUE;
extern MOCKTAIL_OPENSL_EXPORT const
    mocktail::audio::opensl_abi::InterfaceId SL_IID_ENGINE;
extern MOCKTAIL_OPENSL_EXPORT const
    mocktail::audio::opensl_abi::InterfaceId SL_IID_PLAY;
extern MOCKTAIL_OPENSL_EXPORT const
    mocktail::audio::opensl_abi::InterfaceId SL_IID_RECORD;
extern MOCKTAIL_OPENSL_EXPORT const
    mocktail::audio::opensl_abi::InterfaceId SL_IID_VOLUME;

MOCKTAIL_OPENSL_EXPORT mocktail::audio::opensl_abi::Result
MOCKTAIL_OPENSL_API_ENTRY slCreateEngine(
    mocktail::audio::opensl_abi::Object* engine,
    mocktail::audio::opensl_abi::Uint32 num_options,
    const mocktail::audio::opensl_abi::EngineOption* options,
    mocktail::audio::opensl_abi::Uint32 num_interfaces,
    const mocktail::audio::opensl_abi::InterfaceId* interface_ids,
    const mocktail::audio::opensl_abi::Boolean* interface_required);
#endif

MOCKTAIL_OPENSL_EXPORT mocktail::audio::opensl_abi::Result
mocktailOpenSlGetRuntimeStats(MocktailOpenSlRuntimeStats* stats,
                              std::uint32_t stats_size);

}  // extern "C"

#endif  // MOCKTAIL_AUDIO_OPENSL_PLAYBACK_RUNTIME_H_
