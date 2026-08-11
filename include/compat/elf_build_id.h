// Copyright 2026 Mocktail Project Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

#ifndef MOCKTAIL_COMPAT_ELF_BUILD_ID_H_
#define MOCKTAIL_COMPAT_ELF_BUILD_ID_H_

#include <string>
#include <string_view>

namespace mocktail::compat {

struct BuildIdResult {
  std::string build_id;
  std::string error;

  explicit operator bool() const noexcept { return error.empty(); }
};

// Reads the GNU build ID through elfutils libelf. The returned identifier is
// lowercase hexadecimal and is empty only when an error is reported.
BuildIdResult ReadElfBuildId(const std::string& path);

bool IsValidBuildId(std::string_view build_id) noexcept;

}  // namespace mocktail::compat

#endif  // MOCKTAIL_COMPAT_ELF_BUILD_ID_H_
