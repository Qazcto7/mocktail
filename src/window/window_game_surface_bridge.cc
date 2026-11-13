#include "window/window_game_surface_bridge.h"

#include <array>
#include <utility>

#include "mocktail/mocktail_rust.h"
#include "runtime/roblox_game_session_native_adapter.h"
#include "window/window.h"

namespace mocktail {
namespace window {
namespace {

MocktailRustSurfaceEvent ToRustSurfaceEvent(const WindowSurfaceEvent& event) {
  MocktailRustSurfaceEvent rust_event{};
  rust_event.event_type = static_cast<int32_t>(event.type);
  rust_event.surface.generation = event.surface.generation;
  rust_event.surface.native_window =
      static_cast<uintptr_t>(event.surface.native_window);
  rust_event.surface.width = event.surface.width;
  rust_event.surface.height = event.surface.height;
  rust_event.surface.available = event.surface.available ? 1 : 0;
  rust_event.surface.dpi_scale = event.surface.dpi_scale;
  return rust_event;
}

Status InvalidArgument(std::string message) {
  return Status::Error(StatusCode::kInvalidArgument, std::move(message));
}

Status FailedPrecondition(std::string message) {
  return Status::Error(StatusCode::kFailedPrecondition, std::move(message));
}

runtime::GameSessionUpdateResult RuntimeCreated(void* context,
                                                uint64_t generation) {
  return static_cast<runtime::RobloxGameSessionRuntime*>(context)
      ->SurfaceCreated(generation);
}

runtime::GameSessionUpdateResult RuntimeChanged(void* context,
                                                runtime::GameSurface surface) {
  return static_cast<runtime::RobloxGameSessionRuntime*>(context)
      ->RebindSurface(surface);
}

runtime::GameSessionUpdateResult RuntimeDestroyed(void* context,
                                                  uint64_t generation) {
  return static_cast<runtime::RobloxGameSessionRuntime*>(context)
      ->SurfaceDestroyed(generation);
}

bool PollProductionWindowSurfaceEvent(void*, WindowSurfaceEvent* event) {
  return PollWindowSurfaceEvent(event);
}

Status RecordProductionResizeCommit(void*, const WindowSurfaceEvent& event) {
  return RecordResizeReadinessSurfaceCommit(event);
}

}  // namespace

WindowGameSurfaceConsumer MakeWindowGameSurfaceConsumer(
    runtime::RobloxGameSessionRuntime* runtime) {
  if (runtime == nullptr) {
    return {};
  }
  return {runtime, &RuntimeCreated, &RuntimeChanged, &RuntimeDestroyed};
}

WindowGameSurfaceEventSource MakeWindowGameSurfaceEventSource() {
  return {nullptr, &PollProductionWindowSurfaceEvent};
}

WindowGameSurfaceCommitObserver MakeWindowResizeReadinessCommitObserver() {
  return {nullptr, &RecordProductionResizeCommit};
}

WindowGameSurfaceBridge::WindowGameSurfaceBridge(
    WindowGameSurfaceEventSource source, WindowGameSurfaceConsumer consumer,
    WindowGameSurfaceCommitObserver observer)
    : source_(source), consumer_(consumer), observer_(observer) {
  if (!source_.complete()) {
    terminal_status_ =
        InvalidArgument("window game-surface event source is incomplete");
    snapshot_.failed = true;
  } else if (!consumer_.complete()) {
    terminal_status_ =
        InvalidArgument("window game-surface consumer is incomplete");
    snapshot_.failed = true;
  }
}

WindowGameSurfaceDrainResult WindowGameSurfaceBridge::Drain() {
  if (!terminal_status_.ok()) {
    return {terminal_status_, 0};
  }

  std::size_t drained_events = 0;
  WindowSurfaceEvent event;
  while (source_.poll(source_.context, &event)) {
    ++drained_events;
    Status validation = ValidateEvent(event);
    if (!validation.ok()) {
      return Fail(std::move(validation), drained_events);
    }

    const runtime::GameSessionUpdateResult update = Dispatch(event);
    if (!update.ok()) {
      const std::string detail = update.cause.ok()
                                     ? "GAME lifecycle rejected surface event"
                                     : update.cause.message();
      return Fail(FailedPrecondition(detail), drained_events);
    }
    if (observer_.complete()) {
      Status observe_status = observer_.committed(observer_.context, event);
      if (!observe_status.ok()) {
        return Fail(std::move(observe_status), drained_events);
      }
    }

    const MocktailRustSurfaceEvent rust_event = ToRustSurfaceEvent(event);
    MocktailRustGameSurfaceBridgeSnapshot rust_snapshot{
        snapshot_.accepted_events,
        snapshot_.duplicate_events,
        snapshot_.last_generation,
        static_cast<int32_t>(snapshot_.last_event_type),
        snapshot_.failed,
    };
    mocktail_rust_game_surface_bridge_record_event(
        &rust_event, update.changed(), &rust_snapshot);
    snapshot_.accepted_events = rust_snapshot.accepted_events;
    snapshot_.duplicate_events = rust_snapshot.duplicate_events;
    snapshot_.last_generation = rust_snapshot.last_generation;
    snapshot_.last_event_type =
        static_cast<WindowSurfaceEventType>(rust_snapshot.last_event_type);
    snapshot_.failed = rust_snapshot.failed;
  }
  return {Status::Ok(), drained_events};
}

WindowGameSurfaceBridgeSnapshot WindowGameSurfaceBridge::Snapshot() const {
  return snapshot_;
}

Status WindowGameSurfaceBridge::ValidateEvent(
    const WindowSurfaceEvent& event) const {
  const MocktailRustSurfaceEvent rust_event = ToRustSurfaceEvent(event);
  std::array<char, 256> err_buf{};
  if (mocktail_rust_game_surface_bridge_validate_event(
          &rust_event, err_buf.data(), err_buf.size()) != 0) {
    return InvalidArgument(err_buf[0] != '\0'
                               ? std::string(err_buf.data())
                               : "window surface event is invalid");
  }
  return Status::Ok();
}

runtime::GameSessionUpdateResult WindowGameSurfaceBridge::Dispatch(
    const WindowSurfaceEvent& event) const {
  switch (event.type) {
    case WindowSurfaceEventType::kCreated:
      return consumer_.created(consumer_.context, event.surface.generation);
    case WindowSurfaceEventType::kChanged:
      return consumer_.changed(
          consumer_.context,
          {event.surface.generation, event.surface.native_window,
           event.surface.width, event.surface.height,
           event.surface.dpi_scale});
    case WindowSurfaceEventType::kDestroyed:
      return consumer_.destroyed(consumer_.context, event.surface.generation);
  }
  runtime::GameSessionUpdateResult rejected;
  rejected.cause = InvalidArgument("window surface event type is invalid");
  return rejected;
}

WindowGameSurfaceDrainResult WindowGameSurfaceBridge::Fail(
    Status status, std::size_t drained_events) {
  terminal_status_ = std::move(status);
  snapshot_.failed = true;
  return {terminal_status_, drained_events};
}

}  // namespace window
}  // namespace mocktail
