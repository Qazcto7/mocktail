#include "webview/webview_helper_policy.h"

#include "mocktail/mocktail_rust.h"

#include <glib.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>

namespace mocktail {
namespace webview {
namespace {

constexpr char kBridgeSource[] = R"JS(
(() => {
  "use strict";
  const handlers = window.webkit && window.webkit.messageHandlers;
  const handler = handlers && handlers.executeRoblox;
  if (!handler) {
    return;
  }
  const bridge = {};
  Object.defineProperty(bridge, "executeRoblox", {
    value: (query) => handler.postMessage(JSON.parse(query)),
    enumerable: true,
    writable: false,
    configurable: false
  });
  try {
    Object.defineProperty(window, "__globalRobloxAndroidBridge__", {
      value: bridge,
      enumerable: true,
      writable: false,
      configurable: false
    });
  } catch (_) {
    // A page-defined object is never allowed to replace the native bridge.
  }
})();
)JS";

bool ExtractBoundedJscString(JSCValue* value, std::string* text) {
  if (value == nullptr || text == nullptr || !jsc_value_is_string(value)) {
    return false;
  }
  GBytes* bytes = jsc_value_to_string_as_bytes(value);
  if (bytes == nullptr) {
    return false;
  }
  gsize size = 0;
  const auto* data = static_cast<const char*>(g_bytes_get_data(bytes, &size));
  const bool valid =
      data != nullptr && size != 0 && size <= kMaximumHybridCommandBytes;
  if (valid) {
    text->assign(data, size);
  }
  g_bytes_unref(bytes);
  return valid;
}

}  // namespace

bool ShouldDisableWebKitSandbox(std::string_view kernel_version,
                                const char* sandbox_override) {
  const std::string kv_str(kernel_version);
  return mocktail_rust_webview_should_disable_sandbox(kv_str.c_str(),
                                                      sandbox_override) != 0;
}

bool ShouldDisableWebViewHardwareAcceleration(
    bool wayland_display, const char* compositing_override) {
  return mocktail_rust_webview_should_disable_hw_accel(
             wayland_display ? 1 : 0, compositing_override) != 0;
}

const char* AndroidBridgeSource() { return kBridgeSource; }

std::string BuildRobloxAndroidUserAgent() {
  const char* configured_version = std::getenv("MOCKTAIL_ROBLOX_VERSION");
  std::array<char, 256> ua_buf{};
  if (mocktail_rust_webview_build_user_agent(
          configured_version, ua_buf.data(), ua_buf.size()) == 0) {
    return std::string(ua_buf.data());
  }
  return {};
}

bool IsBrowserLoginUrl(std::string_view url) {
  const std::string url_str(url);
  return mocktail_rust_webview_is_browser_login_url(url_str.c_str()) != 0;
}

bool IsEssentialWebResource(const char* uri) {
  return mocktail_rust_webview_is_essential_resource(uri) != 0;
}

std::string BoundedLogToken(const char* value, std::string_view fallback) {
  if (value == nullptr || *value == '\0') {
    return std::string(fallback);
  }
  constexpr std::size_t kMaximumLogTokenBytes = 128;
  std::string token;
  for (const unsigned char character : std::string_view(value)) {
    if (token.size() == kMaximumLogTokenBytes) {
      break;
    }
    token.push_back(character >= 0x21 && character <= 0x7e
                        ? static_cast<char>(character)
                        : '?');
  }
  return token;
}

UriPolicyResult EvaluateNavigationUri(const char* uri) {
  UriPolicyResult result;
  int32_t allowed = 0;
  int32_t privileged = 0;
  std::array<char, 256> scheme_buf{};
  std::array<char, 256> host_buf{};
  (void)mocktail_rust_webview_evaluate_navigation_uri(
      uri, &allowed, &privileged, scheme_buf.data(), scheme_buf.size(),
      host_buf.data(), host_buf.size());
  result.allowed = allowed != 0;
  result.privileged_bridge_allowed = privileged != 0;
  result.scheme = scheme_buf.data();
  result.host = host_buf.data();
  return result;
}

const char* CaptchaEventName(CaptchaEventType type) {
  return mocktail_rust_webview_captcha_event_name_ptr(
      static_cast<int32_t>(type));
}

bool ExtractExecuteRobloxCommand(JSCValue* value, std::string* command) {
  if (value == nullptr || command == nullptr || !jsc_value_is_object(value)) {
    return false;
  }
  char* serialized = jsc_value_to_json(value, 0);
  if (serialized == nullptr) {
    return false;
  }
  const std::size_t size = strnlen(serialized, kMaximumHybridCommandBytes + 1);
  const bool valid = size != 0 && size <= kMaximumHybridCommandBytes;
  if (valid) {
    command->assign(serialized, size);
  }
  g_free(serialized);
  return valid;
}

bool ExtractRobloxWkHybridCommand(JSCValue* value, std::string* command) {
  if (value == nullptr || command == nullptr || !jsc_value_is_object(value)) {
    return false;
  }
  JSCValue* property = jsc_value_object_get_property(value, "command");
  const bool extracted = ExtractBoundedJscString(property, command);
  if (property != nullptr) {
    g_object_unref(property);
  }
  return extracted;
}

bool ParseCaptchaEvent(std::string_view command, CaptchaEvent* event) {
  if (event == nullptr || command.empty() ||
      command.size() > kMaximumHybridCommandBytes) {
    return false;
  }
  int32_t event_type = 0;
  std::array<char, 1025> cb_buf{};
  if (mocktail_rust_webview_parse_captcha_event(
          command.data(), command.size(), &event_type, cb_buf.data(),
          cb_buf.size()) == 0) {
    return false;
  }
  event->type = (event_type == 1) ? CaptchaEventType::kSuccess
                                  : CaptchaEventType::kShown;
  event->callback_id = cb_buf.data();
  return true;
}

std::string BuildCallbackScript(std::string_view callback_id) {
  std::string out(callback_id.size() * 6 + 320, '\0');
  if (mocktail_rust_webview_build_callback_script(
          callback_id.data(), callback_id.size(), out.data(), out.size()) ==
      0) {
    out.resize(std::char_traits<char>::length(out.c_str()));
    return out;
  }
  return {};
}

}  // namespace webview
}  // namespace mocktail
