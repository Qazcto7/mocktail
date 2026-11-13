#include "runtime/roblox_text_display_state.h"
#include "mocktail/mocktail_rust.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

namespace mocktail {
namespace runtime {
namespace {

void SecureClear(std::string* value) {
  if (value == nullptr) {
    return;
  }
  if (!value->empty()) {
    mocktail_rust_secure_zero(&(*value)[0], value->size());
  }
  value->clear();
}

}  // namespace

int RobloxTextOverlayViewport::coordinate_width() const {
  return valid() ? mocktail_rust_text_overlay_viewport_coordinate_size(
                       width, density_scale)
                 : 0;
}

int RobloxTextOverlayViewport::coordinate_height() const {
  return valid() ? mocktail_rust_text_overlay_viewport_coordinate_size(
                       height, density_scale)
                 : 0;
}

RobloxTextOverlayPresentation::~RobloxTextOverlayPresentation() {
  ClearSensitive();
}

RobloxTextOverlayPresentation::RobloxTextOverlayPresentation(
    RobloxTextOverlayPresentation&& other)
    : visible(other.visible),
      generation(other.generation),
      geometry(other.geometry),
      font_size(other.font_size),
      multiline(other.multiline),
      x_alignment(other.x_alignment),
      y_alignment(other.y_alignment),
      text_color(other.text_color),
      font(other.font),
      text_input_type(other.text_input_type),
      text_wrapped(other.text_wrapped),
      display_utf8(other.display_utf8),
      caret_utf8_byte(other.caret_utf8_byte),
      selection_begin_utf8_byte(other.selection_begin_utf8_byte),
      selection_end_utf8_byte(other.selection_end_utf8_byte) {
  other.ClearSensitive();
}

RobloxTextOverlayPresentation& RobloxTextOverlayPresentation::operator=(
    RobloxTextOverlayPresentation&& other) {
  if (this == &other) {
    return *this;
  }
  ClearSensitive();
  visible = other.visible;
  generation = other.generation;
  geometry = other.geometry;
  font_size = other.font_size;
  multiline = other.multiline;
  x_alignment = other.x_alignment;
  y_alignment = other.y_alignment;
  text_color = other.text_color;
  font = other.font;
  text_input_type = other.text_input_type;
  text_wrapped = other.text_wrapped;
  display_utf8 = other.display_utf8;
  caret_utf8_byte = other.caret_utf8_byte;
  selection_begin_utf8_byte = other.selection_begin_utf8_byte;
  selection_end_utf8_byte = other.selection_end_utf8_byte;
  other.ClearSensitive();
  return *this;
}

void RobloxTextOverlayPresentation::ClearSensitive() {
  SecureClear(&display_utf8);
  visible = false;
  generation = 0;
  geometry = {};
  font_size = 0.0F;
  multiline = false;
  x_alignment = 0;
  y_alignment = 1;
  text_color = 0;
  font = 0;
  text_input_type = 0;
  text_wrapped = false;
  caret_utf8_byte = 0;
  selection_begin_utf8_byte = 0;
  selection_end_utf8_byte = 0;
}

bool IsRobloxPasswordTextInputType(int32_t text_input_type) {
  return mocktail_rust_text_is_password_input(text_input_type) != 0;
}

RobloxTextOverlayGeometry ResolveRobloxTextOverlayGeometry(
    const RobloxTextDisplayUpdate& update,
    const RobloxTextOverlayViewport& viewport) {
  MocktailRustTextOverlayGeometryResult resolved{};
  if (!mocktail_rust_text_overlay_resolve_geometry(
          update.area_x, update.area_y, update.area_width, update.area_height,
          viewport.width, viewport.height, viewport.density_scale, &resolved)) {
    // A guessed bottom-screen editor is visibly detached from Roblox's
    // TextBox. Missing native geometry stays fail-closed until a later focus
    // snapshot supplies a real rectangle.
    return {};
  }

  // Keep the native rectangle intact. The compositor clips its destination
  // against the swapchain and advances the source rectangle by the matching
  // amount. Cropping here would shrink the layout box and incorrectly
  // re-align text that is only partially outside the viewport.
  return {resolved.x, resolved.y, resolved.width, resolved.height,
          resolved.used_fallback};
}

Status BuildRobloxTextOverlayPresentation(
    const RobloxTextDisplayUpdate& update,
    const RobloxTextOverlayViewport& viewport,
    RobloxTextOverlayPresentation* presentation) {
  if (presentation == nullptr) {
    return Status::Error(StatusCode::kInvalidArgument,
                         "text overlay presentation output is required");
  }
  MocktailRustTextPresentationMetrics metrics{};
  const int32_t prep_status = mocktail_rust_text_display_prepare_presentation(
      update.generation, viewport.width, viewport.height,
      viewport.density_scale, update.text_input_type, update.utf8,
      update.utf8_size, update.cursor_utf16, update.selection_begin_utf16,
      update.selection_end_utf16, &metrics);
  switch (prep_status) {
    case MOCKTAIL_RUST_TEXT_DISPLAY_BUILD_OK:
      break;
    case MOCKTAIL_RUST_TEXT_DISPLAY_BUILD_INVALID_GENERATION:
      return Status::Error(StatusCode::kInvalidArgument,
                           "text overlay generation must be nonzero");
    case MOCKTAIL_RUST_TEXT_DISPLAY_BUILD_INVALID_VIEWPORT:
      return Status::Error(StatusCode::kInvalidArgument,
                           "text overlay viewport must be positive");
    case MOCKTAIL_RUST_TEXT_DISPLAY_BUILD_INVALID_UTF8_PTR:
      return Status::Error(StatusCode::kInvalidArgument,
                           "text overlay UTF-8 buffer is unavailable");
    case MOCKTAIL_RUST_TEXT_DISPLAY_BUILD_INVALID_UTF8:
      return Status::Error(StatusCode::kInvalidArgument,
                           "text overlay received invalid UTF-8");
    case MOCKTAIL_RUST_TEXT_DISPLAY_BUILD_PASSWORD_OVERFLOW:
      return Status::Error(StatusCode::kUnavailable,
                           "text overlay password mask is too large");
    default:
      return Status::Error(StatusCode::kInvalidArgument,
                           "text overlay presentation preparation failed");
  }

  RobloxTextOverlayPresentation candidate;
  candidate.visible = true;
  candidate.generation = update.generation;
  candidate.geometry = ResolveRobloxTextOverlayGeometry(update, viewport);
  candidate.font_size = update.font_size;
  candidate.multiline = update.multiline;
  candidate.x_alignment = update.x_alignment;
  candidate.y_alignment = update.y_alignment;
  candidate.text_color = update.text_color;
  candidate.font = update.font;
  candidate.text_input_type = update.text_input_type;
  candidate.text_wrapped = update.text_wrapped;
  candidate.caret_utf8_byte = metrics.caret_utf8_byte;
  candidate.selection_begin_utf8_byte = metrics.selection_begin_utf8_byte;
  candidate.selection_end_utf8_byte = metrics.selection_end_utf8_byte;

  if (metrics.is_password) {
    candidate.display_utf8.resize(metrics.display_bytes, '\0');
    if (metrics.codepoint_count > 0 &&
        mocktail_rust_text_display_write_password_bullets(
            metrics.codepoint_count,
            reinterpret_cast<uint8_t*>(&candidate.display_utf8[0]),
            candidate.display_utf8.size()) !=
            MOCKTAIL_RUST_TEXT_DISPLAY_BUILD_OK) {
      return Status::Error(StatusCode::kUnavailable,
                           "text overlay password mask is too large");
    }
  } else if (update.utf8_size > 0 && update.utf8 != nullptr) {
    candidate.display_utf8.assign(update.utf8, update.utf8_size);
  }

  *presentation = std::move(candidate);
  return Status::Ok();
}

Status RobloxTextDisplayState::Apply(const RobloxTextDisplayUpdate& update,
                                     const RobloxTextOverlayViewport& viewport,
                                     bool* changed) {
  if (changed == nullptr) {
    return Status::Error(StatusCode::kInvalidArgument,
                         "text overlay changed output is required");
  }
  *changed = false;

  const int32_t action = mocktail_rust_text_display_decide_apply(
      static_cast<int32_t>(update.event), update.generation,
      presentation_.visible, presentation_.generation);
  switch (action) {
    case MOCKTAIL_RUST_TEXT_DISPLAY_APPLY_NOOP:
      return Status::Ok();
    case MOCKTAIL_RUST_TEXT_DISPLAY_APPLY_HIDE_CLEAR:
      presentation_.ClearSensitive();
      *changed = true;
      return Status::Ok();
    case MOCKTAIL_RUST_TEXT_DISPLAY_APPLY_BUILD_PRESENTATION: {
      RobloxTextOverlayPresentation candidate;
      Status status =
          BuildRobloxTextOverlayPresentation(update, viewport, &candidate);
      if (!status.ok()) {
        return status;
      }
      presentation_ = std::move(candidate);
      *changed = true;
      return Status::Ok();
    }
    default:
      return Status::Error(StatusCode::kInvalidArgument,
                           "text overlay event is invalid");
  }
}

void RobloxTextDisplayState::Reset() { presentation_.ClearSensitive(); }

}  // namespace runtime
}  // namespace mocktail
