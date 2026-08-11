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

#ifndef MOCKTAIL_AUDIO_FMOD_JNI_AUDIO_BRIDGE_H_
#define MOCKTAIL_AUDIO_FMOD_JNI_AUDIO_BRIDGE_H_

#include "mocktail/status.h"

namespace jnivm {
class VM;
}  // namespace jnivm

namespace mocktail::audio {

// Installs the SDL-backed org/fmod/AudioDevice implementation into the
// pseudo-JVM. The VM retains and shuts down the bridge context.
Status InstallFmodJniAudioBridge(jnivm::VM* vm);

// Stops the Java audio runtime and every SDL stream before the window layer
// calls SDL_Quit(). Must run on the main thread after Roblox workers stop.
Status ShutdownFmodJniAudioBridge(jnivm::VM* vm);

}  // namespace mocktail::audio

#endif  // MOCKTAIL_AUDIO_FMOD_JNI_AUDIO_BRIDGE_H_
