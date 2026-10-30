#include "runtime/roblox_permissions_bridge.h"
#include "mocktail/mocktail_rust.h"

#include <nlohmann/json.hpp>

namespace mocktail {
namespace runtime {
namespace {
constexpr std::size_t kMaximumJsonBytes = 64 * 1024;
constexpr char kMicrophone[] = "MICROPHONE_ACCESS";
constexpr char kLocalNetwork[] = "LOCAL_NETWORK";

struct Response {
  nlohmann::json body;
  jint code = 0;
  const char* outcome = "DENIED";
};

Response Answer(JNIEnv* env, jstring message, std::size_t method,
                bool microphone_enabled) {
  const bool support = method == 0;
  const bool upsell = method >= 3;
  Response rejected{
      support  ? nlohmann::json{{"permissions", nlohmann::json::array()}}
      : upsell ? nlohmann::json{{"upsellStatus", "HIDE"},
                                {"hiddenUpsellPermissions", {kMicrophone}}}
               : nlohmann::json{{"status", "DENIED"},
                                {"missingPermissions", {kMicrophone}}},
      13, "invalid_request"};
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

  if (support) {
    if (mocktail_rust_validate_json_depth(owned.c_str(), 8) != 1) return rejected;
    return {{{"permissions", {kMicrophone, kLocalNetwork}}}, 0, "supported"};
  }

  int has_missing = 0;
  std::string missing_json(kMaximumJsonBytes, '\0');
  const int status = mocktail_rust_check_permission_request(
      owned.c_str(),
      microphone_enabled ? 1 : 0,
      &has_missing,
      missing_json.data(),
      missing_json.size());

  if (status != 0) {
    return rejected;
  }

  if (upsell) {
    const auto request = nlohmann::json::parse(owned, nullptr, false);
    const auto features = request.is_object() ? request.find("permissions") : request.end();
    return {{{"upsellStatus", "HIDE"},
             {"hiddenUpsellPermissions", features != request.end() ? *features : nlohmann::json::array()}},
            0,
            "HIDE"};
  }

  auto missing_parsed = nlohmann::json::parse(missing_json.c_str(), nullptr, false);
  const char* outcome_status = has_missing == 0 ? "AUTHORIZED" : "DENIED";
  return {{{"status", outcome_status},
           {"missingPermissions", missing_parsed.is_array() ? missing_parsed : nlohmann::json::array()}},
          0,
          outcome_status};
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
            auto response = Answer(env, message, method, microphone_enabled);
            return RobloxMessageBusReply{response.body.dump(), response.code,
                                         response.outcome};
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
