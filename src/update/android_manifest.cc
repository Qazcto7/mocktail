#include "update/android_manifest.h"
#include "mocktail/mocktail_rust.h"

#include <cstdint>
#include <string>

namespace mocktail::update {

AndroidManifestIdentity ParseAndroidManifest(std::string_view binary_xml) {
  AndroidManifestIdentity result;
  if (binary_xml.empty()) {
    result.error = "AndroidManifest.xml is not valid binary XML";
    return result;
  }
  MocktailRustManifestResult rust_result = {};
  const int status = mocktail_rust_parse_android_manifest(
      reinterpret_cast<const uint8_t*>(binary_xml.data()),
      binary_xml.size(),
      &rust_result);
  if (status >= 0) {
    result.package_name = rust_result.package_name;
    result.version_name = rust_result.version_name;
    result.split_name = rust_result.split_name;
    result.version_code = rust_result.version_code;
    result.error = rust_result.error;
    return result;
  }
  result.error = "failed to parse Android binary XML via mocktail-core (Rust)";
  return result;
}

}  // namespace mocktail::update
