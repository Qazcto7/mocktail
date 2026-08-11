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

// src/window/window.h — SDL3 window + real EGL context management.
//
// Provides a real OS window and EGL surface that Roblox can render into.
// EGL calls from libroblox.so are intercepted by libegl_stub and forwarded
// to the handles created here via thread-local / global state.

#ifndef MOCKTAIL_WINDOW_WINDOW_H_
#define MOCKTAIL_WINDOW_WINDOW_H_

#include <cstdint>
#include <filesystem>

#include "mocktail/platform/display_refresh_capabilities.h"
#include "mocktail/status.h"
#include "window/platform_event_observer.h"
#include "window/present_observer.h"
#include "window/window_pointer_capture_owner.h"
#include "window/window_surface_lifecycle.h"
#include "window/window_text_input_owner.h"

namespace mocktail {
namespace window {

using PreTextInputPumpCallback = bool (*)(void* context);
using FullscreenStateSyncCallback = bool (*)(void* context, bool fullscreen);

// Configures the XDG-backed state record used to restore the last windowed
// geometry, maximized state, and F11 fullscreen state. Must be called before
// Init(); readiness runs suppress persistence internally.
Status ConfigureWindowStatePersistence(const std::filesystem::path& path);

// Initialises SDL3, creates the main window and the EGL display.
// Must be called before Stage 6 (before nativeAppBridgeV2InitWithParams).
// Returns true on success.
bool Init(int width, int height, const char* title);

// Pumps pending SDL events.  Call this from a main-loop or keepalive thread.
// Returns false when the user closes the window (quit requested).
bool PumpEvents();

// Paces the next main-thread SDL event drain at 240 Hz. Raw mouse/touch events
// remain unsmoothed; this only prevents the host loop from batching them at
// the old 60 Hz cadence.
void PaceInputPump();

// Accepts GameActivity.setWindowFlags from any guest JNI thread and queues the
// relevant Android fullscreen state for SDL's next main-thread event pump.
// Returns false when the mask contains no supported fullscreen flag.
bool RequestFullscreenFromAndroidWindowFlags(int flags, int mask);

// Recognizes the current Android CoreScript's otherwise-unhandled fullscreen
// menu request and queues one toggle for the SDL thread.
bool RequestFullscreenFromRobloxMenuLog(const char* tag, const char* message);

// Registers the exact-build adapter that mirrors successful SDL fullscreen
// requests into UserGameSettings.InFullScreen().
bool SetFullscreenStateSyncCallback(FullscreenStateSyncCallback callback,
                                    void* context);
void ClearFullscreenStateSyncCallback();

// Returns SDL-derived surface lifetime events from the same polling loop used
// by PumpEvents. The initial mapped surface is generation 1 and is available
// through GetWindowSurfaceSnapshot without a synthetic Created event.
bool PollWindowSurfaceEvent(WindowSurfaceEvent* event);
WindowSurfaceSnapshot GetWindowSurfaceSnapshot();

// Records a compositor-observed event only after the GAME/JNI bridge has
// committed it. The default-off resize readiness gate uses this to distinguish
// a real rebind from an SDL configure notification that native code rejected.
Status RecordResizeReadinessSurfaceCommit(const WindowSurfaceEvent& event);

// Completes the opt-in resize gate after Roblox reaches Stopped. Disabled
// production runs return OK without adding any work to the hot path.
Status StopResizeReadiness();
Status ResizeReadinessCompletionStatus();

struct WindowViewportSnapshot {
  int logical_width = 0;
  int logical_height = 0;
  int pixel_width = 0;
  int pixel_height = 0;

  bool valid() const {
    return logical_width > 0 && logical_height > 0 && pixel_width > 0 &&
           pixel_height > 0;
  }
};

// Input uses logical SDL coordinates while the native surface uses pixels.
// Keep both extents explicit so high-DPI touch normalization cannot mix them.
WindowViewportSnapshot GetWindowViewportSnapshot();

// Returns the immutable SDL display snapshot captured on the window thread.
platform::DisplayRefreshCapabilities GetDisplayRefreshCapabilities();

// Registers the sole consumer of converted SDL input/focus events.
// Surface bookkeeping is internal and does not consume this observer slot.
bool SetPlatformEventObserver(PlatformEventObserver observer, void* context);
void ClearPlatformEventObserver();

// Applies Roblox's exact MouseBehavior.LockCenter state through SDL relative
// mouse mode. The callback is queried only from the SDL main thread.
bool SetMouseLockQueryCallback(MouseLockQueryCallback callback, void* context);
void ClearMouseLockQueryCallback();

// Registers a generic main-thread command drain that runs immediately before
// the SDL text-input owner. Clear waits for any invocation already in flight.
bool SetPreTextInputPumpCallback(PreTextInputPumpCallback callback,
                                 void* context);
void ClearPreTextInputPumpCallback();

// Guest text callbacks only enqueue state. SDL's main-thread-only text-input
// APIs are applied by PumpEvents. The owner remains disabled until the // focused-editor bridge explicitly enables it.
void SetWindowTextInputOwnerEnabled(bool enabled);
bool RequestShowTextInput(uint64_t generation, const TextInputArea& area,
                          const TextInputOptions& options);
bool RequestHideTextInput(uint64_t generation);

// Returns the native EGL display handle (EGLDisplay, opaque void*).
void* GetEGLDisplay();

// Returns the native EGL surface handle (EGLSurface, opaque void*) that
// was created from the SDL3 window.  This is the surface Roblox renders into.
void* GetEGLSurface();

// Returns the native EGL context handle (EGLContext, opaque void*).
void* GetEGLContext();

// Returns the native EGL config handle (EGLConfig, opaque void*).
void* GetEGLConfig();

// Returns the raw ANativeWindow pointer used as the Android surface.
// This is what ANativeWindow_fromSurface() should return.
void* GetNativeWindow();

// Returns the SDL_Window as an opaque pointer for the Vulkan WSI
// adapter. Android guest code must continue to use GetNativeWindow().
void* GetBackendWindow();

// True when the window was created with SDL_WINDOW_VULKAN and no EGL context.
bool UsesDirectVulkan();

// Resolves an OpenGL ES function from SDL's currently loaded GL library.
// Returns nullptr before Init() or when no real GL backend is available.
void* GetGLProcAddress(const char* name);

// Swaps front and back buffers (calls eglSwapBuffers on the real surface).
bool SwapBuffers();

// Returns true once the engine has presented at least one frame.
bool HasPresentedFrame();

// Records a successful host vkQueuePresentKHR. The Vulkan loader adapter is
// the only production caller; tests must not fabricate readiness with it.
void NoteVulkanPresent();

// Records VK_ERROR_OUT_OF_DATE_KHR without invoking SDL or JNI on the render
// thread. PumpEvents coalesces this evidence into surface rebinds.
void NoteVulkanSurfaceOutOfDate();

// Registers one synchronous observer for successful host presentation through
// either vkQueuePresentKHR or SDL_GL_SwapWindow. ClearPresentObserver waits for
// an in-flight callback, allowing its context to be destroyed safely.
bool SetPresentObserver(PresentObserver observer, void* context);
void ClearPresentObserver();

class ScopedPresentObserver final {
 public:
  ScopedPresentObserver() = default;
  ~ScopedPresentObserver();

  ScopedPresentObserver(const ScopedPresentObserver&) = delete;
  ScopedPresentObserver& operator=(const ScopedPresentObserver&) = delete;

  bool Register(PresentObserver observer, void* context);
  void Reset();

 private:
  bool registered_ = false;
};

// Shows the SDL window if it was created hidden for startup.
void ShowIfHidden();

// Binds the EGL context to the calling thread.
// Must be called from the engine rendering thread before any GL calls.
// GLdispatch (Mesa) initialises TLS on the first MakeCurrent per thread.
bool MakeCurrentOnThread();

// Releases the EGL context from the calling thread.
bool ReleaseCurrentOnThread();

// Destroys the window and shuts down SDL3.
void Shutdown();

// Returns true if Init() was called successfully.
bool IsInitialised();

// Returns current window dimensions.
int GetWidth();
int GetHeight();

}  // namespace window
}  // namespace mocktail

#endif  // MOCKTAIL_WINDOW_WINDOW_H_
