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

#ifndef MOCKTAIL_STATUS_H_
#define MOCKTAIL_STATUS_H_

#include <string>
#include <utility>

namespace mocktail {

enum class StatusCode {
  kOk = 0,
  kInvalidArgument,
  kFailedPrecondition,
  kUnavailable,
  kUnsupported,
  kPlatformError,
};

class Status final {
 public:
  Status() = default;

  static Status Ok() { return Status(); }

  static Status Error(StatusCode code, std::string message) {
    return Status(code, std::move(message));
  }

  bool ok() const { return code_ == StatusCode::kOk; }
  explicit operator bool() const { return ok(); }
  StatusCode code() const { return code_; }
  const std::string& message() const { return message_; }

 private:
  Status(StatusCode code, std::string message)
      : code_(code), message_(std::move(message)) {}

  StatusCode code_ = StatusCode::kOk;
  std::string message_;
};

}  // namespace mocktail

#endif  // MOCKTAIL_STATUS_H_
