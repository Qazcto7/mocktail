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

// Loading by SONAME can select host ANGLE instead of the Bionic adapter. This
// bridge therefore opens the library beside the executable by exact path.

#ifndef MOCKTAIL_GRAPHICS_BIONIC_EGL_BRIDGE_H_
#define MOCKTAIL_GRAPHICS_BIONIC_EGL_BRIDGE_H_

#include <string>
#include <unordered_map>

namespace mocktail::graphics {

using EglExportMap = std::unordered_map<std::string, void *>;

class BionicEglBridge {
public:
  BionicEglBridge() = default;
  BionicEglBridge(const BionicEglBridge &) = delete;
  BionicEglBridge &operator=(const BionicEglBridge &) = delete;

  // The handle stays live because the Bionic linker retains its exports.
  bool Load();

  bool IsLoaded() const { return handle_ != nullptr; }
  void *handle() const { return handle_; }
  const EglExportMap &exports() const { return exports_; }
  const std::string &library_path() const { return library_path_; }
  const std::string &error() const { return error_; }

private:
  void *handle_ = nullptr;
  EglExportMap exports_;
  std::string library_path_;
  std::string error_;
};

} // namespace mocktail::graphics

#endif // MOCKTAIL_GRAPHICS_BIONIC_EGL_BRIDGE_H_
