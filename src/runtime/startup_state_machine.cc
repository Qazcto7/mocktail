#include "runtime/startup_state_machine.h"

#include <array>
#include <utility>

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace runtime {
namespace {

StartupUpdateResult MakeResult(int status, MocktailRustStartupState state,
                               const char* msg) {
  StartupUpdateResult result;
  switch (status) {
    case 0:
      result.status = StartupUpdateStatus::kApplied;
      break;
    case 1:
      result.status = StartupUpdateStatus::kDuplicate;
      break;
    default:
      result.status = StartupUpdateStatus::kRejected;
      break;
  }
  result.state = static_cast<StartupState>(state);
  result.message = msg != nullptr ? msg : "";
  return result;
}

}  // namespace

StartupStateMachine::StartupStateMachine(StartupRequirements requirements) {
  MocktailRustStartupRequirements req = {
      requirements.windowed ? 1 : 0,
      requirements.require_input_ready ? 1 : 0,
      requirements.require_audio_ready ? 1 : 0,
  };
  sm_ = mocktail_rust_startup_sm_create(req);
}

StartupStateMachine::~StartupStateMachine() {
  if (sm_ != nullptr) {
    mocktail_rust_startup_sm_destroy(
        reinterpret_cast<MocktailRustStartupSm*>(sm_));
    sm_ = nullptr;
  }
}

StartupUpdateResult StartupStateMachine::RecordEvidence(
    StartupEvidence evidence) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (sm_ == nullptr) {
    return {StartupUpdateStatus::kRejected, StartupState::kFailure,
            "state machine uninitialized"};
  }
  MocktailRustStartupState out_state = kRustStartupCreated;
  int out_status = 2;
  std::array<char, 512> msg{};
  mocktail_rust_startup_sm_record_evidence(
      reinterpret_cast<MocktailRustStartupSm*>(sm_),
      static_cast<int>(evidence), &out_state, &out_status, msg.data(),
      msg.size());
  return MakeResult(out_status, out_state, msg.data());
}

StartupUpdateResult StartupStateMachine::Fail(std::string reason) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (sm_ == nullptr) {
    return {StartupUpdateStatus::kRejected, StartupState::kFailure,
            "state machine uninitialized"};
  }
  MocktailRustStartupState out_state = kRustStartupCreated;
  int out_status = 2;
  std::array<char, 512> msg{};
  mocktail_rust_startup_sm_fail(reinterpret_cast<MocktailRustStartupSm*>(sm_),
                                reason.c_str(), &out_state, &out_status,
                                msg.data(), msg.size());
  return MakeResult(out_status, out_state, msg.data());
}

StartupUpdateResult StartupStateMachine::BeginStopping() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (sm_ == nullptr) {
    return {StartupUpdateStatus::kRejected, StartupState::kFailure,
            "state machine uninitialized"};
  }
  MocktailRustStartupState out_state = kRustStartupCreated;
  int out_status = 2;
  std::array<char, 512> msg{};
  mocktail_rust_startup_sm_begin_stopping(
      reinterpret_cast<MocktailRustStartupSm*>(sm_), &out_state, &out_status,
      msg.data(), msg.size());
  return MakeResult(out_status, out_state, msg.data());
}

StartupUpdateResult StartupStateMachine::MarkStopped() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (sm_ == nullptr) {
    return {StartupUpdateStatus::kRejected, StartupState::kFailure,
            "state machine uninitialized"};
  }
  MocktailRustStartupState out_state = kRustStartupCreated;
  int out_status = 2;
  std::array<char, 512> msg{};
  mocktail_rust_startup_sm_mark_stopped(
      reinterpret_cast<MocktailRustStartupSm*>(sm_), &out_state, &out_status,
      msg.data(), msg.size());
  return MakeResult(out_status, out_state, msg.data());
}

StartupSnapshot StartupStateMachine::Snapshot() const {
  std::lock_guard<std::mutex> lock(mutex_);
  StartupSnapshot snapshot;
  if (sm_ == nullptr) {
    return snapshot;
  }
  MocktailRustStartupSnapshot raw{};
  std::array<char, 512> reason{};
  mocktail_rust_startup_sm_snapshot(
      reinterpret_cast<const MocktailRustStartupSm*>(sm_), &raw, reason.data(),
      reason.size());

  snapshot.state = static_cast<StartupState>(raw.state);
  snapshot.requirements.windowed = raw.requirements.windowed != 0;
  snapshot.requirements.require_input_ready =
      raw.requirements.require_input_ready != 0;
  snapshot.requirements.require_audio_ready =
      raw.requirements.require_audio_ready != 0;
  snapshot.configured = raw.configured != 0;
  snapshot.jni_runtime_ready = raw.jni_runtime_ready != 0;
  snapshot.libraries_loaded = raw.libraries_loaded != 0;
  snapshot.jni_on_load_complete = raw.jni_on_load_complete != 0;
  snapshot.engine_started = raw.engine_started != 0;
  snapshot.data_model_loading = raw.data_model_loading != 0;
  snapshot.lua_app_ready = raw.lua_app_ready != 0;
  snapshot.real_frame_presented = raw.real_frame_presented != 0;
  snapshot.input_ready = raw.input_ready != 0;
  snapshot.audio_ready = raw.audio_ready != 0;
  snapshot.revision = raw.revision;
  snapshot.failure_reason = reason.data();
  return snapshot;
}

const char* StartupStateName(StartupState state) {
  switch (state) {
    case StartupState::kCreated:
      return "Created";
    case StartupState::kConfigured:
      return "Configured";
    case StartupState::kJniRuntimeReady:
      return "JniRuntimeReady";
    case StartupState::kLibrariesLoaded:
      return "LibrariesLoaded";
    case StartupState::kJniOnLoadComplete:
      return "JniOnLoadComplete";
    case StartupState::kEngineStarted:
      return "EngineStarted";
    case StartupState::kDataModelLoading:
      return "DataModelLoading";
    case StartupState::kLuaAppReady:
      return "LuaAppReady";
    case StartupState::kReady:
      return "Ready";
    case StartupState::kFailure:
      return "Failure";
    case StartupState::kStopping:
      return "Stopping";
    case StartupState::kStopped:
      return "Stopped";
  }
  return "Unknown";
}

const char* StartupEvidenceName(StartupEvidence evidence) {
  switch (evidence) {
    case StartupEvidence::kConfigured:
      return "Configured";
    case StartupEvidence::kJniRuntimeReady:
      return "JniRuntimeReady";
    case StartupEvidence::kLibrariesLoaded:
      return "LibrariesLoaded";
    case StartupEvidence::kJniOnLoadComplete:
      return "JniOnLoadComplete";
    case StartupEvidence::kEngineStarted:
      return "EngineStarted";
    case StartupEvidence::kDataModelLoading:
      return "DataModelLoading";
    case StartupEvidence::kLuaAppReady:
      return "LuaAppReady";
    case StartupEvidence::kRealFramePresented:
      return "RealFramePresented";
    case StartupEvidence::kInputReady:
      return "InputReady";
    case StartupEvidence::kAudioReady:
      return "AudioReady";
  }
  return "Unknown";
}

}  // namespace runtime
}  // namespace mocktail
