#include "runtime/external_launch_broker.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <utility>

#include "mocktail/mocktail_rust.h"
#include "runtime/single_instance_lock.h"

namespace mocktail {
namespace runtime {
namespace {

std::mutex g_active_broker_mutex;
std::weak_ptr<ExternalLaunchBroker> g_active_broker;

StatusCode StatusCodeFromRust(int32_t raw_code) {
  switch (raw_code) {
    case 0:
      return StatusCode::kOk;
    case 1:
      return StatusCode::kInvalidArgument;
    case 2:
      return StatusCode::kFailedPrecondition;
    case 3:
      return StatusCode::kUnavailable;
    case 4:
      return StatusCode::kUnsupported;
    default:
      return StatusCode::kPlatformError;
  }
}

Status StatusFromRust(int32_t status_code, const char* err_buf,
                      const char* fallback_message) {
  const StatusCode code = StatusCodeFromRust(status_code);
  if (code == StatusCode::kOk) {
    return Status::Ok();
  }
  const std::string message =
      (err_buf != nullptr && err_buf[0] != '\0') ? err_buf : fallback_message;
  return Status::Error(code, message);
}

struct DrainDispatchContext {
  const ExternalLaunchSink* sink = nullptr;
};

void CopyErrorBuffer(char* dst, size_t cap, const std::string& message) {
  if (dst == nullptr || cap == 0) {
    return;
  }
  const size_t copy_len = std::min(message.size(), cap - 1);
  if (copy_len > 0) {
    std::char_traits<char>::copy(dst, message.data(), copy_len);
  }
  dst[copy_len] = '\0';
}

int32_t DispatchToExternalLaunchSink(void* ctx, const char* canonical_json_ptr,
                                     size_t canonical_json_len,
                                     int32_t* out_status_code, char* out_err,
                                     size_t err_cap) {
  auto* adapter = static_cast<DrainDispatchContext*>(ctx);
  if (adapter == nullptr || adapter->sink == nullptr ||
      !adapter->sink->valid() || canonical_json_ptr == nullptr) {
    if (out_status_code != nullptr) {
      *out_status_code = static_cast<int32_t>(StatusCode::kInvalidArgument);
    }
    CopyErrorBuffer(out_err, err_cap, "external-launch sink is incomplete");
    return -1;
  }

  RobloxExperienceLaunchRequest request;
  const std::string canonical_json(canonical_json_ptr, canonical_json_len);
  Status status = ParseRobloxExperienceLaunchJson(canonical_json, &request);
  if (!status.ok()) {
    if (out_status_code != nullptr) {
      *out_status_code = static_cast<int32_t>(StatusCode::kInvalidArgument);
    }
    CopyErrorBuffer(out_err, err_cap, "external-launch canonical JSON is invalid");
    return -1;
  }

  status = adapter->sink->dispatch(adapter->sink->context, request);
  if (!status.ok()) {
    if (out_status_code != nullptr) {
      *out_status_code = static_cast<int32_t>(status.code());
    }
    CopyErrorBuffer(out_err, err_cap, status.message());
    return -1;
  }

  if (out_status_code != nullptr) {
    *out_status_code = static_cast<int32_t>(StatusCode::kOk);
  }
  return 0;
}

}  // namespace

Status ResolveExternalLaunchSocketPath(bool owner,
                                       std::filesystem::path* socket_path) {
  if (socket_path == nullptr) {
    return Status::Error(StatusCode::kInvalidArgument,
                         "external-launch socket output is null");
  }
  socket_path->clear();
  const std::string instance_key = CurrentExecutableInstanceKey();
  std::array<char, 512> path_buf{};
  std::array<char, 256> err_buf{};
  int32_t status_code = static_cast<int32_t>(StatusCode::kPlatformError);

  if (mocktail_rust_external_launch_resolve_socket_path(
          owner, instance_key.data(), instance_key.size(), path_buf.data(),
          path_buf.size(), &status_code, err_buf.data(), err_buf.size()) != 0) {
    return StatusFromRust(status_code, err_buf.data(),
                          "cannot resolve external-launch socket path");
  }
  *socket_path = std::filesystem::path(path_buf.data());
  return Status::Ok();
}

class ExternalLaunchBroker::Impl final {
 public:
  explicit Impl(ExternalLaunchBrokerOptions options)
      : options_(std::move(options)) {}

  ~Impl() {
    if (rust_broker_ != nullptr) {
      mocktail_rust_external_launch_broker_destroy(rust_broker_);
      rust_broker_ = nullptr;
    }
  }

  Status Start(const RobloxExperienceLaunchRequest* initial_request) {
    const std::string requested_socket = options_.socket_path.string();
    const std::string instance_key = CurrentExecutableInstanceKey();
    std::array<char, 256> err_buf{};
    int32_t status_code = static_cast<int32_t>(StatusCode::kPlatformError);
    MocktailRustExternalLaunchBroker* rust_broker = nullptr;

    const char* init_ptr = initial_request != nullptr
                               ? initial_request->canonical_json.data()
                               : nullptr;
    const size_t init_len = initial_request != nullptr
                                ? initial_request->canonical_json.size()
                                : 0;

    if (mocktail_rust_external_launch_broker_start(
            requested_socket.data(), requested_socket.size(),
            instance_key.data(), instance_key.size(),
            options_.maximum_pending_launches, options_.forwarding_timeout_ms,
            initial_request != nullptr, init_ptr, init_len, &rust_broker,
            &status_code, err_buf.data(), err_buf.size()) != 0 ||
        rust_broker == nullptr) {
      return StatusFromRust(status_code, err_buf.data(),
                            "cannot start external-launch broker");
    }

    rust_broker_ = rust_broker;
    std::array<char, 512> path_buf{};
    if (mocktail_rust_external_launch_broker_socket_path(
            rust_broker_, path_buf.data(), path_buf.size()) == 0) {
      socket_path_ = std::filesystem::path(path_buf.data());
    }
    return Status::Ok();
  }

  Status QueueInitial(RobloxExperienceLaunchRequest request) {
    std::array<char, 256> err_buf{};
    int32_t status_code = static_cast<int32_t>(StatusCode::kPlatformError);
    if (mocktail_rust_external_launch_broker_queue_initial(
            rust_broker_, request.canonical_json.data(),
            request.canonical_json.size(), &status_code, err_buf.data(),
            err_buf.size()) != 0) {
      return StatusFromRust(status_code, err_buf.data(),
                            "cannot queue initial external-launch request");
    }
    return Status::Ok();
  }

  Status Drain(const ExternalLaunchSink& sink, std::size_t maximum_requests) {
    if (!sink.valid()) {
      return Status::Error(StatusCode::kInvalidArgument,
                           "external-launch sink is incomplete");
    }
    DrainDispatchContext adapter{&sink};
    std::array<char, 256> err_buf{};
    int32_t status_code = static_cast<int32_t>(StatusCode::kPlatformError);
    if (mocktail_rust_external_launch_broker_drain(
            rust_broker_, maximum_requests, &DispatchToExternalLaunchSink,
            &adapter, &status_code, err_buf.data(), err_buf.size()) != 0) {
      return StatusFromRust(status_code, err_buf.data(),
                            "external-launch drain failed");
    }
    return Status::Ok();
  }

  Status Shutdown() {
    if (rust_broker_ == nullptr) {
      return Status::Ok();
    }
    std::array<char, 256> err_buf{};
    int32_t status_code = static_cast<int32_t>(StatusCode::kPlatformError);
    if (mocktail_rust_external_launch_broker_shutdown(
            rust_broker_, &status_code, err_buf.data(), err_buf.size()) != 0) {
      return StatusFromRust(status_code, err_buf.data(),
                            "cannot shut down external-launch broker");
    }
    return Status::Ok();
  }

  std::size_t pending_launch_count() const {
    return mocktail_rust_external_launch_broker_pending_count(rust_broker_);
  }

  const std::filesystem::path& socket_path() const { return socket_path_; }

 private:
  const ExternalLaunchBrokerOptions options_;
  MocktailRustExternalLaunchBroker* rust_broker_ = nullptr;
  std::filesystem::path socket_path_;
};

ExternalLaunchBroker::ExternalLaunchBroker(std::unique_ptr<Impl> impl)
    : impl_(std::move(impl)) {}

ExternalLaunchBroker::~ExternalLaunchBroker() { (void)impl_->Shutdown(); }

Status ExternalLaunchBroker::StartOwnerAfterLockAcquired(
    ExternalLaunchBrokerOptions options,
    std::shared_ptr<ExternalLaunchBroker>* broker,
    const RobloxExperienceLaunchRequest* initial_request) {
  if (broker == nullptr) {
    return Status::Error(StatusCode::kInvalidArgument,
                         "external-launch broker output is null");
  }
  broker->reset();
  auto impl = std::make_unique<Impl>(std::move(options));
  Status status = impl->Start(initial_request);
  if (!status.ok()) {
    return status;
  }
  *broker = std::shared_ptr<ExternalLaunchBroker>(
      new ExternalLaunchBroker(std::move(impl)));
  return Status::Ok();
}

Status ExternalLaunchBroker::ForwardToOwner(
    const ExternalLaunchBrokerOptions& options,
    const RobloxExperienceLaunchRequest& request) {
  const std::string requested_socket = options.socket_path.string();
  const std::string instance_key = CurrentExecutableInstanceKey();
  std::array<char, 256> err_buf{};
  int32_t status_code = static_cast<int32_t>(StatusCode::kPlatformError);

  if (mocktail_rust_external_launch_forward_to_owner(
          requested_socket.data(), requested_socket.size(),
          instance_key.data(), instance_key.size(),
          options.forwarding_timeout_ms, request.canonical_json.data(),
          request.canonical_json.size(), &status_code, err_buf.data(),
          err_buf.size()) != 0) {
    return StatusFromRust(status_code, err_buf.data(),
                          "external-launch forwarding failed");
  }
  return Status::Ok();
}

Status ExternalLaunchBroker::QueueInitialRequest(
    RobloxExperienceLaunchRequest request) {
  return impl_->QueueInitial(std::move(request));
}

Status ExternalLaunchBroker::Drain(const ExternalLaunchSink& sink,
                                   std::size_t maximum_requests) {
  return impl_->Drain(sink, maximum_requests);
}

Status ExternalLaunchBroker::Shutdown() { return impl_->Shutdown(); }

std::size_t ExternalLaunchBroker::pending_launch_count() const {
  return impl_->pending_launch_count();
}

const std::filesystem::path& ExternalLaunchBroker::socket_path() const {
  return impl_->socket_path();
}

Status InstallActiveExternalLaunchBroker(
    const std::shared_ptr<ExternalLaunchBroker>& broker) {
  if (broker == nullptr) {
    return Status::Error(StatusCode::kInvalidArgument,
                         "active external-launch broker is null");
  }
  std::lock_guard<std::mutex> lock(g_active_broker_mutex);
  if (!g_active_broker.expired()) {
    return Status::Error(StatusCode::kFailedPrecondition,
                         "an active external-launch broker is already installed");
  }
  g_active_broker = broker;
  return Status::Ok();
}

void ClearActiveExternalLaunchBroker(const ExternalLaunchBroker* broker) {
  std::lock_guard<std::mutex> lock(g_active_broker_mutex);
  const std::shared_ptr<ExternalLaunchBroker> active = g_active_broker.lock();
  if (active.get() == broker) {
    g_active_broker.reset();
  }
}

std::shared_ptr<ExternalLaunchBroker> GetActiveExternalLaunchBroker() {
  std::lock_guard<std::mutex> lock(g_active_broker_mutex);
  return g_active_broker.lock();
}

Status DrainActiveExternalLaunchRequests(const ExternalLaunchSink& sink,
                                         std::size_t maximum_requests) {
  const std::shared_ptr<ExternalLaunchBroker> broker =
      GetActiveExternalLaunchBroker();
  return broker != nullptr ? broker->Drain(sink, maximum_requests)
                           : Status::Ok();
}

}  // namespace runtime
}  // namespace mocktail
