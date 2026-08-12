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

// Move-only credential storage that clears its allocation. Never log its view.
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

void SecurelyClearString(std::string* value);

// Must be created after the credential reaches its final address and destroyed
// before the credential or VM. Guest bindings block legacy env/disk fallback.
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

// Retains the validated credential without reopening its source.
struct AuthRuntimeComposition {
  AuthRuntimeStatus status = AuthRuntimeStatus::kUnavailable;
  std::shared_ptr<jnivm::VM> jni_vm;
  jnivm::RobloxAuthIdentity account_identity;
  SecureRobloxCredential credential;
  long http_status = 0;
  std::string error;

  explicit operator bool() const { return jni_vm != nullptr; }
};

// A VM requires authentication or explicit guest mode. HTTP 401 clears only a
// managed credential; rejected Sober credentials are suppressed without
// changing Sober's file.
AuthRuntimeComposition ComposeAuthRuntime(const Environment& environment,
                                          const RuntimePaths& paths,
                                          services::AuthService& auth_service);

// Retains HTTP transport for native sign-in and validates persisted credentials.
AuthRuntimeComposition ComposeAuthRuntime(
    const Environment& environment, const RuntimePaths& paths,
    services::AuthService& auth_service,
    std::shared_ptr<services::HttpClient> live_auth_http_client);

}  // namespace runtime
}  // namespace mocktail

#endif  // MOCKTAIL_RUNTIME_AUTH_RUNTIME_COMPOSITION_H_
