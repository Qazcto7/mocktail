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

#ifndef MOCKTAIL_RUNTIME_ROBLOX_PLATFORM_WEB_SYMBOLS_H_
#define MOCKTAIL_RUNTIME_ROBLOX_PLATFORM_WEB_SYMBOLS_H_

#include "runtime/roblox_browser_service_bridge.h"
#include "runtime/roblox_web_view_bridge.h"

namespace mocktail {
namespace runtime {

// Exported web-platform entrypoints resolved as one capability. Keeping
// this Build-ID-sensitive symbol inventory outside the research runtime lets
// the composition fail closed when a future payload changes any contract.
struct RobloxPlatformWebSymbols {
  RobloxWebViewMessageBusSymbols web_view;
  RobloxBrowserServiceSymbols browser_service;

  bool complete() const {
    return web_view.complete() && browser_service.complete();
  }
};

RobloxPlatformWebSymbols ResolveRobloxPlatformWebSymbols(
    void* roblox_library, SubscribeWebViewRawFn subscribe_raw,
    DeleteWebViewConnectionFn delete_connection);

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_ROBLOX_PLATFORM_WEB_SYMBOLS_H_
