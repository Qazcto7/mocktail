#include "runtime/webview_helper_launcher.h"

#include <array>
#include <cstdint>
#include <new>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace runtime {

struct WebViewHelperProcess::State {
  MocktailRustWebViewProcess* handle = nullptr;

  ~State() {
    if (handle != nullptr) {
      mocktail_rust_webview_process_release(handle);
      handle = nullptr;
    }
  }
};

WebViewHelperProcess::WebViewHelperProcess(std::shared_ptr<State> state)
    : state_(std::move(state)) {}

bool WebViewHelperProcess::running() const {
  return state_ != nullptr && state_->handle != nullptr &&
         mocktail_rust_webview_process_running(state_->handle) != 0;
}

pid_t WebViewHelperProcess::process_id() const {
  return (state_ != nullptr && state_->handle != nullptr)
             ? static_cast<pid_t>(
                   mocktail_rust_webview_process_pid(state_->handle))
             : -1;
}

namespace {

void AssignBytesCallback(void* ctx, const char* data, size_t len) {
  auto* target = static_cast<std::string*>(ctx);
  if (target != nullptr) {
    if (data != nullptr && len > 0) {
      target->assign(data, len);
    } else {
      target->clear();
    }
  }
}

void AssignControlCommandCallback(void* ctx, uint8_t operation,
                                  const char* payload, size_t payload_len,
                                  int32_t visible) {
  auto* command = static_cast<WebViewHelperControlCommand*>(ctx);
  if (command != nullptr) {
    command->operation = static_cast<WebViewHelperControlOperation>(operation);
    if (payload != nullptr && payload_len > 0) {
      command->payload.assign(payload, payload_len);
    } else {
      command->payload.clear();
    }
    command->visible = (visible != 0);
  }
}

void AssignSingleEventCallback(void* ctx, uint8_t event_type,
                               const char* payload, size_t payload_len) {
  auto* event = static_cast<WebViewHelperEvent*>(ctx);
  if (event != nullptr) {
    event->type = static_cast<WebViewHelperEventType>(event_type);
    if (payload != nullptr && payload_len > 0) {
      event->payload.assign(payload, payload_len);
    } else {
      event->payload.clear();
    }
  }
}

void AppendEventCallback(void* ctx, uint8_t event_type, const char* payload,
                         size_t payload_len) {
  auto* events = static_cast<std::vector<WebViewHelperEvent>*>(ctx);
  if (events != nullptr) {
    WebViewHelperEvent event;
    event.type = static_cast<WebViewHelperEventType>(event_type);
    if (payload != nullptr && payload_len > 0) {
      event.payload.assign(payload, payload_len);
    }
    events->push_back(std::move(event));
  }
}

struct ExitObserverBridge {
  WebViewHelperExitObserver observer;
};

void InvokeExitObserver(void* opaque) {
  auto* bridge = static_cast<ExitObserverBridge*>(opaque);
  if (bridge != nullptr && bridge->observer.valid()) {
    bridge->observer.on_exit(bridge->observer.context.get());
  }
}

void DropExitObserver(void* opaque) {
  delete static_cast<ExitObserverBridge*>(opaque);
}

void CopyOptionalError(std::string* error, const char* buf) {
  if (error != nullptr) {
    *error = buf;
  }
}

}  // namespace

bool ValidateWebViewUrl(std::string_view url, std::string* error) {
  std::array<char, 256> err_buf{};
  const int32_t ok = mocktail_rust_webview_validate_url(
      url.data(), url.size(), err_buf.data(), err_buf.size());
  if (ok == 0) {
    CopyOptionalError(error, err_buf.data());
    return false;
  }
  return true;
}

bool NormalizeWebViewUrl(std::string_view url, std::string* normalized_url,
                         std::string* error) {
  if (normalized_url == nullptr) {
    CopyOptionalError(error, "webview URL has no output destination");
    return false;
  }
  std::array<char, 256> err_buf{};
  const int32_t ok = mocktail_rust_webview_normalize_url(
      url.data(), url.size(), &AssignBytesCallback, normalized_url,
      err_buf.data(), err_buf.size());
  if (ok == 0) {
    normalized_url->clear();
    CopyOptionalError(error, err_buf.data());
    return false;
  }
  return true;
}

bool DecodeWebViewRequest(std::string_view request, std::string* url,
                          std::string* error) {
  if (url == nullptr) {
    CopyOptionalError(error, "webview request has no output destination");
    return false;
  }
  std::array<char, 256> err_buf{};
  const int32_t ok = mocktail_rust_webview_decode_request(
      request.data(), request.size(), &AssignBytesCallback, url, err_buf.data(),
      err_buf.size());
  if (ok == 0) {
    CopyOptionalError(error, err_buf.data());
    return false;
  }
  return true;
}

bool DecodeWebViewHelperControlPacket(std::string_view packet,
                                      WebViewHelperControlCommand* command,
                                      std::string* error) {
  if (error != nullptr) {
    error->clear();
  }
  if (command == nullptr) {
    CopyOptionalError(error, "webview control command has no output destination");
    return false;
  }
  std::array<char, 256> err_buf{};
  const int32_t ok = mocktail_rust_webview_decode_control_packet(
      packet.data(), packet.size(), &AssignControlCommandCallback, command,
      err_buf.data(), err_buf.size());
  if (ok == 0) {
    command->operation = WebViewHelperControlOperation::kClose;
    command->payload.clear();
    command->visible = false;
    CopyOptionalError(error, err_buf.data());
    return false;
  }
  return true;
}

bool EncodeWebViewHelperEventPacket(WebViewHelperEventType type,
                                    std::string_view payload,
                                    std::string* packet) {
  if (packet == nullptr) {
    return false;
  }
  return mocktail_rust_webview_encode_event_packet(
             static_cast<uint8_t>(type), payload.data(), payload.size(),
             &AssignBytesCallback, packet) != 0;
}

bool DecodeWebViewHelperEventPacket(std::string_view packet,
                                    WebViewHelperEvent* event,
                                    std::string* error) {
  if (error != nullptr) {
    error->clear();
  }
  if (event == nullptr) {
    CopyOptionalError(error, "webview event has no output destination");
    return false;
  }
  std::array<char, 256> err_buf{};
  const int32_t ok = mocktail_rust_webview_decode_event_packet(
      packet.data(), packet.size(), &AssignSingleEventCallback, event,
      err_buf.data(), err_buf.size());
  if (ok == 0) {
    event->type = WebViewHelperEventType::kExecuteRoblox;
    event->payload.clear();
    CopyOptionalError(error, err_buf.data());
    return false;
  }
  return true;
}

bool WebViewHelperProcess::LoadUrl(std::string_view url) const {
  return state_ != nullptr && state_->handle != nullptr &&
         mocktail_rust_webview_process_load_url(state_->handle, url.data(),
                                                url.size()) != 0;
}

bool WebViewHelperProcess::SetTitle(std::string_view title) const {
  return state_ != nullptr && state_->handle != nullptr &&
         mocktail_rust_webview_process_set_title(state_->handle, title.data(),
                                                 title.size()) != 0;
}

bool WebViewHelperProcess::SetVisible(bool visible) const {
  return state_ != nullptr && state_->handle != nullptr &&
         mocktail_rust_webview_process_set_visible(state_->handle,
                                                   visible ? 1 : 0) != 0;
}

bool WebViewHelperProcess::EvaluateJavaScript(std::string_view script) const {
  return state_ != nullptr && state_->handle != nullptr &&
         mocktail_rust_webview_process_evaluate_javascript(
             state_->handle, script.data(), script.size()) != 0;
}

bool WebViewHelperProcess::SetBackNavigationDisabled(bool disabled) const {
  return state_ != nullptr && state_->handle != nullptr &&
         mocktail_rust_webview_process_set_back_navigation_disabled(
             state_->handle, disabled ? 1 : 0) != 0;
}

bool WebViewHelperProcess::SetShowDomainAsTitle(bool enabled) const {
  return state_ != nullptr && state_->handle != nullptr &&
         mocktail_rust_webview_process_set_show_domain_as_title(
             state_->handle, enabled ? 1 : 0) != 0;
}

bool WebViewHelperProcess::SetRobloxCookie(std::string_view value) const {
  return state_ != nullptr && state_->handle != nullptr &&
         mocktail_rust_webview_process_set_roblox_cookie(
             state_->handle, value.data(), value.size()) != 0;
}

bool WebViewHelperProcess::ClearRobloxCookie() const {
  return state_ != nullptr && state_->handle != nullptr &&
         mocktail_rust_webview_process_clear_roblox_cookie(state_->handle) != 0;
}

bool WebViewHelperProcess::WaitUntilReady(
    std::chrono::milliseconds timeout) const {
  if (state_ == nullptr || state_->handle == nullptr || timeout.count() < 0) {
    return false;
  }
  return mocktail_rust_webview_process_wait_until_ready(state_->handle,
                                                        timeout.count()) != 0;
}

bool WebViewHelperProcess::DrainEvents(
    std::vector<WebViewHelperEvent>* events) const {
  if (state_ == nullptr || state_->handle == nullptr || events == nullptr) {
    return false;
  }
  return mocktail_rust_webview_process_drain_events(
             state_->handle, &AppendEventCallback, events) != 0;
}

bool WebViewHelperProcess::RequestClose() const {
  if (state_ == nullptr || state_->handle == nullptr) {
    return false;
  }
  return mocktail_rust_webview_process_request_close(state_->handle) != 0;
}

WebViewHelperLaunchResult LaunchWebViewHelper(
    const std::filesystem::path& helper, std::string_view url,
    WebViewHelperExitObserver exit_observer) {
  WebViewHelperLaunchResult result;
  auto* bridge =
      new (std::nothrow) ExitObserverBridge{std::move(exit_observer)};
  if (bridge == nullptr) {
    result.error = "cannot allocate webview helper exit observer";
    return result;
  }

  const std::string helper_str = helper.string();
  MocktailRustWebViewProcess* rust_handle = nullptr;
  int32_t pid = -1;
  std::array<char, 256> err_buf{};
  const int32_t rc = mocktail_rust_webview_launch(
      helper_str.data(), helper_str.size(), url.data(), url.size(), bridge,
      &InvokeExitObserver, &DropExitObserver, &rust_handle, &pid,
      err_buf.data(), err_buf.size());
  if (rc != 0 || rust_handle == nullptr) {
    result.error = err_buf.data();
    return result;
  }

  auto state = std::make_shared<WebViewHelperProcess::State>();
  state->handle = rust_handle;
  result.spawned = true;
  result.process_id = static_cast<pid_t>(pid);
  result.process = std::shared_ptr<WebViewHelperProcess>(
      new WebViewHelperProcess(std::move(state)));
  return result;
}

}  // namespace runtime
}  // namespace mocktail
