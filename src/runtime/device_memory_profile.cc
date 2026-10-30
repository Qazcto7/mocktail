#include "runtime/device_memory_profile.h"
#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace runtime {

DeviceMemoryProfile BuildDeviceMemoryProfile(std::uint64_t host_memory_bytes) {
  MocktailRustDeviceMemoryProfile rust_profile = {};
  mocktail_rust_build_device_memory_profile(host_memory_bytes, &rust_profile);

  DeviceMemoryProfile profile;
  profile.total_memory_mb = rust_profile.total_memory_mb;
  profile.memory_class_mb = rust_profile.memory_class_mb;
  profile.large_memory_class_mb = rust_profile.large_memory_class_mb;
  profile.low_memory_killer_background_threshold =
      rust_profile.low_memory_killer_background_threshold;
  profile.low_memory_killer_foreground_threshold =
      rust_profile.low_memory_killer_foreground_threshold;
  profile.low_ram_device = rust_profile.low_ram_device != 0;
  return profile;
}

}  // namespace runtime
}  // namespace mocktail
