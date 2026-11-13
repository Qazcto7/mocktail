#include "runtime/roblox_text_font_resolver.h"

#include <array>
#include <string>

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace runtime {

RobloxTextFontSelection ResolveRobloxTextFont(
    int32_t font, const std::string& asset_content_root) {
  RobloxTextFontSelection selection;
  if (asset_content_root.empty()) {
    return selection;
  }
  std::array<char, 4096> primary_buf{};
  float scale = selection.size_scale;
  bool exact = false;
  const int32_t rc = mocktail_rust_resolve_roblox_text_font(
      font, asset_content_root.data(), asset_content_root.size(),
      primary_buf.data(), primary_buf.size(), &scale, &exact);
  if (rc == 0) {
    selection.primary_file = std::string(primary_buf.data());
    selection.size_scale = scale;
    selection.exact_mapping = exact;
  }
  return selection;
}

RobloxTextFontSelection ResolveRobloxTextFont(int32_t font) {
  RobloxTextFontSelection selection;
  std::array<char, 4096> primary_buf{};
  float scale = selection.size_scale;
  bool exact = false;
  const int32_t rc = mocktail_rust_resolve_roblox_text_font(
      font, nullptr, 0, primary_buf.data(), primary_buf.size(), &scale, &exact);
  if (rc == 0) {
    selection.primary_file = std::string(primary_buf.data());
    selection.size_scale = scale;
    selection.exact_mapping = exact;
  }
  return selection;
}

}  // namespace runtime
}  // namespace mocktail
