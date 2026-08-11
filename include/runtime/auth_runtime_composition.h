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

#ifndef MOCKTAIL_RUNTIME_AUTH_RUNTIME_COMPOSITION_H_
#define MOCKTAIL_RUNTIME_AUTH_RUNTIME_COMPOSITION_H_

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "jnivm/jnivm.h"

namespace mocktail {
namespace services {
class AuthService;
class HttpClient;
}  // namespace services

namespace runtime {

class Environment;
class RuntimePaths;

enum class AuthRuntimeStatus {
  kAuthenticated,
  kGuest,
  kInvalidCredentials,
  kUnavailable,
};

// Process-local ownership for the canonical .ROBLOSECURITY header. The class
// is move-only and clears its backing allocation before release.
// Callers must never log the value returned by view() or c_str().
class SecureRobloxCredential final {
 public:
  SecureRobloxCredential() = default;
  explicit SecureRobloxCredential(std::string canonical_header);
  ~SecureRobloxCredential();

  SecureRobloxCredential(const SecureRobloxCredential&) = delete;
  SecureRobloxCredential& operator=(const SecureRobloxCredential&) = delete;
  SecureRobloxCredential(SecureRobloxCredential&& other) noexcept;
  SecureRobloxCredential& operator=(SecureRobloxCredential&& other) noexcept;

  bool empty() const { return bytes_.empty(); }
  size_t size() const { return bytes_.empty() ? 0 : bytes_.size() - 1; }
  const char* c_str() const { return bytes_.empty() ? "" : bytes_.data(); }
  std::string_view view() const { return {c_str(), size()}; }
  void Clear();

 private:
  std::vector<char> bytes_;
};

// Clears a transient string that contained derived credential material.
void SecurelyClearString(std::string* value);

// Binds the production pseudo-VM to the exact credential resolved by the
// authentication preflight. The binding is intentionally non-movable:
// it must be created only after its credential reaches its final address and
// destroyed before that credential or the VM. Guest credentials block legacy
// env/disk fallback until the sink durably accepts a native sign-in value.
class ScopedRobloxCredentialBinding final {
 public:
  ScopedRobloxCredentialBinding(jnivm::VM* jni_vm,
                                const SecureRobloxCredential& credential);
  ~ScopedRobloxCredentialBinding();

  ScopedRobloxCredentialBinding(const ScopedRobloxCredentialBinding&) = delete;
  ScopedRobloxCredentialBinding& operator=(
      const ScopedRobloxCredentialBinding&) = delete;
  ScopedRobloxCredentialBinding(ScopedRobloxCredentialBinding&&) = delete;
  ScopedRobloxCredentialBinding& operator=(
      ScopedRobloxCredentialBinding&&) = delete;

  bool bound() const { return jni_vm_ != nullptr; }

 private:
  static jnivm::RobloxCredentialView ProvideCredential(const void* context);

  jnivm::VM* jni_vm_ = nullptr;
};

// Result of resolving host credentials before the Android runtime starts.
// Credential ownership is retained only so the exact credential validated by
// AuthService can be moved into native startup without reopening its source.
struct AuthRuntimeComposition {
  AuthRuntimeStatus status = AuthRuntimeStatus::kUnavailable;
  std::shared_ptr<jnivm::VM> jni_vm;
  jnivm::RobloxAuthIdentity account_identity;
  SecureRobloxCredential credential;
  long http_status = 0;
  std::string error;

  explicit operator bool() const { return jni_vm != nullptr; }
};

// Resolves the saved Roblox session and constructs the production pseudo-VM.
// A VM is returned only for an authenticated session or when guest startup is
// explicitly enabled with MOCKTAIL_ALLOW_NO_COOKIE_LUA_APP. An exact HTTP 401
// from a managed Mocktail file clears only the rejected .ROBLOSECURITY. A
// rejected default Sober credential is suppressed by a private fingerprint
// without modifying Sober's file. The guest policy then allows native sign-in
// to continue. Explicit overrides, unsafe recovery, other invalid credentials,
// and unavailable authentication still fail closed before native startup.
AuthRuntimeComposition ComposeAuthRuntime(const Environment& environment,
                                          const RuntimePaths& paths,
                                          services::AuthService& auth_service);

// Production overload retaining the HTTP transport for credentials delivered
// by native sign-in after startup. A persisted credential is validated before
// its account identity is promoted into the running pseudo-VM.
AuthRuntimeComposition ComposeAuthRuntime(
    const Environment& environment, const RuntimePaths& paths,
    services::AuthService& auth_service,
    std::shared_ptr<services::HttpClient> live_auth_http_client);

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_AUTH_RUNTIME_COMPOSITION_H_
