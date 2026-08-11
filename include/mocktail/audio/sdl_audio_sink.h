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

#ifndef MOCKTAIL_AUDIO_SDL_AUDIO_SINK_H_
#define MOCKTAIL_AUDIO_SDL_AUDIO_SINK_H_

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "mocktail/audio/audio_sink.h"

namespace mocktail::audio {

// SDL documents subsystem initialization and shutdown as main-thread-only.
// The process composition root owns this lifetime; audio workers only create
// streams while the subsystem is active.
Status InitializeSdlAudioSubsystem();
Status ShutdownSdlAudioSubsystem();

struct SdlPlaybackDevice {
  std::uint32_t id = 0;
  std::string name;
};

// Lists physical SDL playback devices. The abstract `default` target is not a
// physical entry and is therefore intentionally absent from this vector.
Status ListSdlPlaybackDevices(std::vector<SdlPlaybackDevice>* devices);

// Resolves `default` or one exact physical device name. This pure selection
// step is separate from SDL enumeration so configuration behavior is directly
// testable.
Status ResolveSdlPlaybackDevice(
    std::string_view requested,
    const std::vector<SdlPlaybackDevice>& available_devices,
    std::uint32_t* playback_device_id, std::string* resolved_name);

// Sets the process playback target used by every subsequently created FMOD
// Java and OpenSL sink. It must run after SDL audio initialization and before
// the first sink is opened.
Status ConfigureSdlPlaybackDevice(
    std::string_view requested,
    std::vector<SdlPlaybackDevice>* available_devices,
    std::string* resolved_name);

// Returns the process playback target currently used by new sinks. The
// physical ID is zero for SDL's system-default route.
Status GetConfiguredSdlPlaybackDevice(std::uint32_t* playback_device_id,
                                      std::string* resolved_name);

// Atomically migrates every live FMOD Java and OpenSL stream to one physical
// SDL device, or to the system default when playback_device_id is zero. New
// sinks inherit the same target. Existing queued PCM stays in its stream.
Status SwitchSdlPlaybackDevice(std::uint32_t playback_device_id,
                               std::string* resolved_name);

struct SdlAudioSinkOptions {
  PcmSpec source_spec;

  // Zero selects the process playback target configured above (the SDL
  // default until explicitly configured). A nonzero ID bypasses that target.
  std::uint32_t playback_device_id = 0;
  bool start_paused = true;
};

// Opens a real SDL 3.4+ playback device and its bound SDL_AudioStream. The SDL
// audio subsystem must already be owned by InitializeSdlAudioSubsystem(). SDL
// owns all format conversion, resampling, and borrowed-buffer consumption.
// On failure, *sink remains null.
Status CreateSdlAudioSink(const SdlAudioSinkOptions& options,
                          std::unique_ptr<AudioSink>* sink);

}  // namespace mocktail::audio

#endif  // MOCKTAIL_AUDIO_SDL_AUDIO_SINK_H_
