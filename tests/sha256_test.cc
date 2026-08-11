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

#include "mocktail/sha256.h"

#include <gtest/gtest.h>

#include <string>
#include <string_view>

namespace mocktail {
namespace foundation {
namespace {

TEST(Sha256Test, ComputesStandardVector) {
  EXPECT_EQ(ComputeSha256Hex("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Sha256Test, IncludesEmbeddedNullBytes) {
  const std::string bytes("a\0b", 3);
  EXPECT_EQ(ComputeSha256Hex(bytes),
            "59b271ae1bbcb1d31d41929817f4b16fb439eb4f31520b5ad1d5ce98920a7138");
  EXPECT_NE(ComputeSha256Hex(bytes), ComputeSha256Hex(std::string_view("a")));
}

}  // namespace
}  // namespace foundation
}  // namespace mocktail
