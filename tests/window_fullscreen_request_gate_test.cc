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

#include "window/window_fullscreen_request_gate.h"

#include <gtest/gtest.h>

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

}  // namespace
}  // namespace window
}  // namespace mocktail
