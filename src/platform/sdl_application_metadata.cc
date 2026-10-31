#include "mocktail/platform/sdl_application_metadata.h"

#include <SDL3/SDL.h>

#include <string>
#include <utility>

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace platform {
namespace {

Status MetadataError(const char* operation) {
  std::string message = operation;
  message += " failed: ";
  const char* error = SDL_GetError();
  message += error != nullptr && error[0] != '\0' ? error : "unknown SDL error";
  return Status::Error(StatusCode::kPlatformError, std::move(message));
}

}  // namespace

Status ConfigureSdlApplicationMetadata() {
  char app_name[64];
  char app_id[128];
  char app_type[32];
  if (mocktail_rust_platform_metadata_identity(
          app_name, sizeof(app_name),
          app_id, sizeof(app_id),
          app_type, sizeof(app_type)) != 0) {
    return Status::Error(StatusCode::kPlatformError, "Failed to resolve app metadata from Rust");
  }
  if (!SDL_SetAppMetadata(app_name, MOCKTAIL_PROJECT_VERSION,
                          app_id)) {
    return MetadataError("SDL_SetAppMetadata");
  }
  if (!SDL_SetAppMetadataProperty(SDL_PROP_APP_METADATA_TYPE_STRING, app_type)) {
    return MetadataError("SDL_SetAppMetadataProperty(type)");
  }
  return Status::Ok();
}

}  // namespace platform
}  // namespace mocktail
