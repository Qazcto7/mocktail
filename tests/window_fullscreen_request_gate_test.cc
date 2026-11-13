#include "window/window_fullscreen_request_gate.h"
#include "window/window_fullscreen_state_sync.h"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <thread>

namespace mocktail {
namespace window {
namespace {

TEST(WindowFullscreenRequestGateTest, AppliesAndClearsFullscreenFlag) {
  WindowFullscreenRequestGate gate;
  bool fullscreen = false;

  ASSERT_TRUE(gate.RequestFromAndroidFlags(kAndroidWindowFlagFullscreen,
                                           kAndroidWindowFlagFullscreen));
  ASSERT_TRUE(gate.Take(&fullscreen));
  EXPECT_TRUE(fullscreen);

  ASSERT_TRUE(gate.RequestFromAndroidFlags(0, kAndroidWindowFlagFullscreen));
  ASSERT_TRUE(gate.Take(&fullscreen));
  EXPECT_FALSE(fullscreen);
  EXPECT_FALSE(gate.Take(&fullscreen));
}

TEST(WindowFullscreenRequestGateTest, ForceNotFullscreenOverridesFullscreen) {
  WindowFullscreenRequestGate gate;
  bool fullscreen = false;

  ASSERT_TRUE(gate.RequestFromAndroidFlags(kAndroidWindowFlagFullscreen,
                                           kAndroidWindowFlagFullscreen));
  ASSERT_TRUE(gate.Take(&fullscreen));
  ASSERT_TRUE(fullscreen);

  ASSERT_TRUE(
      gate.RequestFromAndroidFlags(kAndroidWindowFlagForceNotFullscreen,
                                   kAndroidWindowFlagForceNotFullscreen));
  ASSERT_TRUE(gate.Take(&fullscreen));
  EXPECT_FALSE(fullscreen);

  ASSERT_TRUE(
      gate.RequestFromAndroidFlags(0, kAndroidWindowFlagForceNotFullscreen));
  ASSERT_TRUE(gate.Take(&fullscreen));
  EXPECT_TRUE(fullscreen);
}

TEST(WindowFullscreenRequestGateTest, IgnoresUnrelatedFlagsAndCoalesces) {
  WindowFullscreenRequestGate gate;
  bool fullscreen = false;

  EXPECT_FALSE(gate.RequestFromAndroidFlags(0x20, 0x20));
  EXPECT_FALSE(gate.Take(&fullscreen));
  ASSERT_TRUE(gate.RequestFromAndroidFlags(kAndroidWindowFlagFullscreen,
                                           kAndroidWindowFlagFullscreen));
  ASSERT_TRUE(gate.RequestFromAndroidFlags(0, kAndroidWindowFlagFullscreen));
  ASSERT_TRUE(gate.Take(&fullscreen));
  EXPECT_FALSE(fullscreen);

  gate.RequestFromAndroidFlags(kAndroidWindowFlagFullscreen,
                               kAndroidWindowFlagFullscreen);
  gate.Reset();
  EXPECT_FALSE(gate.Take(&fullscreen));
}

struct SyncCallbackState {
  int calls = 0;
  bool last_fullscreen = false;
  bool return_value = true;
};

bool RecordFullscreenSync(void* context, bool fullscreen) {
  auto* state = static_cast<SyncCallbackState*>(context);
  ++state->calls;
  state->last_fullscreen = fullscreen;
  return state->return_value;
}

struct BlockingSyncState {
  std::mutex mutex;
  std::condition_variable cv;
  bool entered = false;
  bool release = false;
  int calls = 0;
  bool last_fullscreen = false;
};

bool BlockingFullscreenSync(void* context, bool fullscreen) {
  auto* state = static_cast<BlockingSyncState*>(context);
  {
    std::unique_lock<std::mutex> lock(state->mutex);
    state->entered = true;
    state->cv.notify_all();
    state->cv.wait(lock, [state] { return state->release; });
    ++state->calls;
    state->last_fullscreen = fullscreen;
  }
  return true;
}

TEST(WindowFullscreenStateSyncTest, EmptyAndRegistrationContracts) {
  WindowFullscreenStateSync sync;
  SyncCallbackState state;

  EXPECT_TRUE(sync.Notify(true));
  EXPECT_FALSE(sync.Register(nullptr, &state));
  EXPECT_FALSE(sync.Register(&RecordFullscreenSync, nullptr));

  ASSERT_TRUE(sync.Register(&RecordFullscreenSync, &state));
  EXPECT_FALSE(sync.Register(&RecordFullscreenSync, &state));

  EXPECT_TRUE(sync.Notify(true));
  EXPECT_EQ(state.calls, 1);
  EXPECT_TRUE(state.last_fullscreen);

  state.return_value = false;
  EXPECT_FALSE(sync.Notify(false));
  EXPECT_EQ(state.calls, 2);
  EXPECT_FALSE(state.last_fullscreen);

  sync.Clear();
  EXPECT_TRUE(sync.Notify(true));
  EXPECT_EQ(state.calls, 2);

  state.return_value = true;
  ASSERT_TRUE(sync.Register(&RecordFullscreenSync, &state));
  EXPECT_TRUE(sync.Notify(true));
  EXPECT_EQ(state.calls, 3);
}

TEST(WindowFullscreenStateSyncTest, ClearWaitsForInFlightNotify) {
  WindowFullscreenStateSync sync;
  BlockingSyncState state;
  ASSERT_TRUE(sync.Register(&BlockingFullscreenSync, &state));

  std::atomic<bool> clear_started{false};
  std::atomic<bool> clear_finished{false};

  std::thread notify_thread([&] { EXPECT_TRUE(sync.Notify(true)); });

  {
    std::unique_lock<std::mutex> lock(state.mutex);
    state.cv.wait(lock, [&] { return state.entered; });
  }

  std::thread clear_thread([&] {
    clear_started.store(true, std::memory_order_release);
    sync.Clear();
    clear_finished.store(true, std::memory_order_release);
  });

  while (!clear_started.load(std::memory_order_acquire)) {
    std::this_thread::yield();
  }
  std::this_thread::sleep_for(std::chrono::milliseconds(20));
  EXPECT_FALSE(clear_finished.load(std::memory_order_acquire));

  {
    std::lock_guard<std::mutex> lock(state.mutex);
    state.release = true;
    state.cv.notify_all();
  }

  notify_thread.join();
  clear_thread.join();

  EXPECT_TRUE(clear_finished.load(std::memory_order_acquire));
  EXPECT_EQ(state.calls, 1);
  EXPECT_TRUE(state.last_fullscreen);
  EXPECT_TRUE(sync.Notify(false));
  EXPECT_EQ(state.calls, 1);
}

}  // namespace
}  // namespace window
}  // namespace mocktail
