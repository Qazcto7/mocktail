#include "runtime/roblox_launch_uri.h"

// [patch.py] RequestFollowUser support
#include "runtime/roblox_presence_resolver.h"
#include "mocktail/mocktail_rust.h"

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace mocktail {
namespace runtime {
namespace {

Status Invalid(std::string message) {
  return Status::Error(StatusCode::kInvalidArgument, std::move(message));
}

}  // namespace

Status ParseRobloxLaunchUri(std::string_view uri,
                            RobloxExperienceLaunchRequest* request) {
  if (request == nullptr) {
    return Invalid("Roblox launch output is null");
  }
  *request = {};
  std::string null_uri(uri);
  std::array<char, 8192> out_json{};
  std::array<char, 256> out_err{};
  int64_t follow_user_id = 0;

  int rc = mocktail_rust_parse_roblox_launch_uri(
      null_uri.c_str(),
      0,
      nullptr,
      out_json.data(),
      out_json.size(),
      out_err.data(),
      out_err.size(),
      &follow_user_id);

  if (rc == 1) {
    ResolvedFollowUserPlace resolved;
    const Status resolve_status = ResolveFollowUserPlace(
        follow_user_id, ReadStoredRoblosecurityCookie(), &resolved);
    if (!resolve_status.ok()) {
      return resolve_status;
    }
    rc = mocktail_rust_parse_roblox_launch_uri(
        null_uri.c_str(),
        resolved.place_id,
        resolved.game_instance_id.c_str(),
        out_json.data(),
        out_json.size(),
        out_err.data(),
        out_err.size(),
        &follow_user_id);
  }

  if (rc != 0) {
    return Invalid(out_err[0] != '\0' ? out_err.data()
                                      : "Roblox launch URI cannot be parsed");
  }

  return ParseRobloxExperienceLaunchJson(out_json.data(), request);
}

Status ParseRobloxWebViewLaunchGame(std::string_view command,
                                    RobloxExperienceLaunchRequest* request) {
  if (request == nullptr) {
    return Invalid("Roblox launchGame output is null");
  }
  *request = {};
  std::string null_cmd(command);
  std::array<char, 8192> out_json{};
  std::array<char, 256> out_err{};
  int64_t follow_user_id = 0;

  int rc = mocktail_rust_parse_webview_launch_game(
      null_cmd.c_str(),
      0,
      nullptr,
      out_json.data(),
      out_json.size(),
      out_err.data(),
      out_err.size(),
      &follow_user_id);

  if (rc == 1) {
    ResolvedFollowUserPlace resolved;
    const Status resolve_status = ResolveFollowUserPlace(
        follow_user_id, ReadStoredRoblosecurityCookie(), &resolved);
    if (!resolve_status.ok()) {
      return resolve_status;
    }
    rc = mocktail_rust_parse_webview_launch_game(
        null_cmd.c_str(),
        resolved.place_id,
        resolved.game_instance_id.c_str(),
        out_json.data(),
        out_json.size(),
        out_err.data(),
        out_err.size(),
        &follow_user_id);
  }

  if (rc != 0) {
    const std::string err_str =
        out_err[0] != '\0' ? out_err.data() : "Roblox launchGame error";
    if (err_str == "WebView command is not launchGame") {
      return Status::Error(StatusCode::kUnsupported, err_str);
    }
    return Invalid(err_str);
  }

  return ParseRobloxExperienceLaunchJson(out_json.data(), request);
}

}  // namespace runtime
}  // namespace mocktail
