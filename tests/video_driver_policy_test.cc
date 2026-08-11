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

#include "window/video_driver_policy.h"

#include <gtest/gtest.h>

namespace mocktail {
namespace window {
namespace {

VideoDriverPolicyInput NvidiaWaylandDirectVulkan() {
  VideoDriverPolicyInput input;
  input.prefer_wayland = true;
  input.has_wayland_session = true;
  input.has_x11_display = true;
  input.uses_direct_vulkan = true;
  input.has_nvidia_kernel_driver = true;
  return input;
}

TEST(VideoDriverPolicyTest, UsesXwaylandForNvidiaDirectVulkanByDefault) {
  EXPECT_EQ(ResolveVideoDriverChoice(NvidiaWaylandDirectVulkan()),
            VideoDriverChoice::kNvidiaDirectVulkanX11);
}

TEST(VideoDriverPolicyTest, ExplicitSdlDriverRemainsAuthoritative) {
  VideoDriverPolicyInput input = NvidiaWaylandDirectVulkan();
  input.has_explicit_sdl_driver = true;

  EXPECT_EQ(ResolveVideoDriverChoice(input), VideoDriverChoice::kSdlDefault);
}

TEST(VideoDriverPolicyTest, ForceWaylandOverridesNvidiaFallback) {
  VideoDriverPolicyInput input = NvidiaWaylandDirectVulkan();
  input.force_wayland = true;

  EXPECT_EQ(ResolveVideoDriverChoice(input), VideoDriverChoice::kWayland);
}

TEST(VideoDriverPolicyTest, ForceX11WinsForAvailableDisplay) {
  VideoDriverPolicyInput input;
  input.force_x11 = true;
  input.prefer_wayland = true;
  input.has_wayland_session = true;
  input.has_x11_display = true;

  EXPECT_EQ(ResolveVideoDriverChoice(input), VideoDriverChoice::kX11);
}

TEST(VideoDriverPolicyTest, KeepsWaylandForNonNvidiaAndNonDirectBackends) {
  VideoDriverPolicyInput input = NvidiaWaylandDirectVulkan();
  input.uses_direct_vulkan = false;

  EXPECT_EQ(ResolveVideoDriverChoice(input), VideoDriverChoice::kWayland);

  input.uses_direct_vulkan = true;
  input.has_nvidia_kernel_driver = false;
  EXPECT_EQ(ResolveVideoDriverChoice(input), VideoDriverChoice::kWayland);
}

TEST(VideoDriverPolicyTest, KeepsWaylandWhenXwaylandIsUnavailable) {
  VideoDriverPolicyInput input = NvidiaWaylandDirectVulkan();
  input.has_x11_display = false;

  EXPECT_EQ(ResolveVideoDriverChoice(input), VideoDriverChoice::kWayland);
}

TEST(VideoDriverPolicyTest, UsesSdlDefaultWhenWaylandPreferenceIsDisabled) {
  VideoDriverPolicyInput input;
  input.prefer_wayland = false;
  input.has_wayland_session = true;
  input.has_x11_display = true;

  EXPECT_EQ(ResolveVideoDriverChoice(input), VideoDriverChoice::kSdlDefault);
}

TEST(VideoDriverPolicyTest, NamesOnlySelectedDrivers) {
  EXPECT_STREQ(VideoDriverChoiceName(VideoDriverChoice::kWayland), "wayland");
  EXPECT_STREQ(VideoDriverChoiceName(VideoDriverChoice::kX11), "x11");
  EXPECT_STREQ(VideoDriverChoiceName(VideoDriverChoice::kNvidiaDirectVulkanX11),
               "x11");
  EXPECT_EQ(VideoDriverChoiceName(VideoDriverChoice::kSdlDefault), nullptr);
}

}  // namespace
}  // namespace window
}  // namespace mocktail
