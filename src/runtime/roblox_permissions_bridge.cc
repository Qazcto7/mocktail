#include "runtime/roblox_permissions_bridge.h"
#include "mocktail/mocktail_rust.h"

#include <string>
#include <string_view>

namespace mocktail {
namespace runtime {
namespace {
constexpr std::size_t kMaximumJsonBytes = 64 * 1024;

const char* StaticOutcomeLiteral(std::string_view value) {
  if (value == "supported") return "supported";
  if (value == "HIDE") return "HIDE";
  if (value == "AUTHORIZED") return "AUTHORIZED";
  if (value == "DENIED") return "DENIED";
  return "invalid_request";
}

RobloxMessageBusReply Answer(JNIEnv* env, jstring message, std::size_t method,
                             bool microphone_enabled) {
  const bool support = method == 0;
  const bool upsell = method >= 3;
  const char* rejected_body =
      support  ? "{\"permissions\":[]}"
      : upsell ? "{\"hiddenUpsellPermissions\":[\"MICROPHONE_ACCESS\"],\"upsellStatus\":\"HIDE\"}"
               : "{\"missingPermissions\":[\"MICROPHONE_ACCESS\"],\"status\":\"DENIED\"}";
  RobloxMessageBusReply rejected{rejected_body, 13, "invalid_request"};
  if (!message)
    return rejected;
  const jsize size = env->GetStringUTFLength(message);
  if (size <= 0 || static_cast<std::size_t>(size) > kMaximumJsonBytes) {
    return rejected;
  }
  const char* bytes = env->GetStringUTFChars(message, nullptr);
  if (!bytes)
    return rejected;
  const std::string owned(bytes, static_cast<std::size_t>(size));
  env->ReleaseStringUTFChars(message, bytes);

  std::string body(kMaximumJsonBytes, '\0');
  size_t body_len = 0;
  int32_t code = 0;
  char outcome[64] = {};
  if (mocktail_rust_format_permissions_reply(
          method, microphone_enabled ? 1 : 0, owned.c_str(),
          body.data(), body.size(), &body_len,
          &code, outcome, sizeof(outcome)) == 0 &&
      body_len <= body.size()) {
    body.resize(body_len);
    return {std::move(body), code, StaticOutcomeLiteral(outcome)};
  }
  return rejected;
}

}  // namespace

RobloxPermissionsBridge::RobloxPermissionsBridge(
    JniEnvironmentProvider environment,
    RobloxPermissionsMessageBusSymbols symbols,
    RobloxPermissionsMessageBusObjects objects, bool microphone_enabled)
    : bridge_(std::make_unique<RobloxMessageBusRequestBridge>(
          environment, symbols, objects, "PermissionsProtocol",
          std::vector<std::string>{"SupportsPermissions", "HasPermissions",
                                   "PermissionsRequest",
                                   "ShouldShowPermissionUpsell",
                                   "ShouldShowRequestPermissionRationale"},
          [microphone_enabled](JNIEnv* env, jstring message,
                               std::size_t method) {
            return Answer(env, message, method, microphone_enabled);
          })) {}

RobloxPermissionsBridge::~RobloxPermissionsBridge() = default;

Status RobloxPermissionsBridge::Initialize() {
  return bridge_->Initialize();
}

Status RobloxPermissionsBridge::Shutdown() {
  return bridge_->Shutdown();
}
}  // namespace runtime
}  // namespace mocktail
