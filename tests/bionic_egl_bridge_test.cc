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

#include <dlfcn.h>

#include <string>

#include <gtest/gtest.h>

#include "mocktail/graphics/bionic_egl_bridge.h"

namespace mocktail::graphics {
namespace {

TEST(BionicEglBridgeTest, LoadsExactAdapterBesideExecutable) {
  BionicEglBridge bridge;
  ASSERT_TRUE(bridge.Load()) << bridge.error();
  ASSERT_EQ(bridge.exports().size(), 21u);

  const auto create_surface = bridge.exports().find("eglCreateWindowSurface");
  ASSERT_NE(create_surface, bridge.exports().end());

  Dl_info origin = {};
  ASSERT_NE(::dladdr(create_surface->second, &origin), 0);
  ASSERT_NE(origin.dli_fname, nullptr);
  EXPECT_EQ(std::string(origin.dli_fname), bridge.library_path());
}

} // namespace
} // namespace mocktail::graphics
