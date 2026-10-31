#include "runtime/process_launch_policy.h"

#include <string>
#include <vector>

#include "mocktail/mocktail_rust.h"

namespace mocktail::runtime {

std::string ApplyInteractiveProcessLaunchPolicy() {
  std::vector<char> buffer(4096, '\0');
  size_t written = 0;
  if (mocktail_rust_apply_interactive_process_launch_policy(
          buffer.data(), buffer.size(), &written) == 0) {
    return std::string(buffer.data(), written);
  }
  if (written > 0) {
    buffer.resize(written + 1, '\0');
    if (mocktail_rust_apply_interactive_process_launch_policy(
            buffer.data(), buffer.size(), &written) == 0) {
      return std::string(buffer.data(), written);
    }
  }
  return {};
}

}  // namespace mocktail::runtime
