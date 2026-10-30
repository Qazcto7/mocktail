#include "runtime/system_proxy.h"

#include <gio/gio.h>

#include <string>
#include <vector>

#include "mocktail/mocktail_rust.h"

namespace mocktail {
namespace runtime {
namespace {

constexpr char kSystemProxyProbeUrl[] = "https://www.roblox.com/";

}  // namespace

SystemProxyResult SelectSystemProxy(
    const std::vector<std::string>& candidates) {
  SystemProxyResult result;
  if (candidates.empty()) {
    result.error = "system proxy resolver returned no connection method";
    return result;
  }

  const std::string& candidate = candidates.front();
  char scheme_buf[64] = {0};
  char host_buf[256] = {0};
  uint16_t port = 0;
  int is_direct = 0;
  int has_auth = 0;

  const int rc = mocktail_rust_parse_proxy_uri(
      candidate.c_str(),
      scheme_buf,
      sizeof(scheme_buf),
      host_buf,
      sizeof(host_buf),
      &port,
      &is_direct,
      &has_auth);

  if (rc != 0) {
    result.error = "system proxy resolver returned an invalid proxy URI";
    return result;
  }
  if (is_direct != 0) {
    return result;
  }
  if (has_auth != 0) {
    result.error = "authenticated system proxies are not supported";
    return result;
  }
  if (host_buf[0] == '\0' || port == 0) {
    result.error = "system proxy has no valid host and port";
    return result;
  }

  result.proxy = ParseNetworkProxyConfig(
      host_buf, std::to_string(port), scheme_buf);
  if (!result.proxy.has_value()) {
    result.error = "system proxy must use HTTP, HTTPS, or SOCKS5";
  }
  return result;
}

SystemProxyResult ResolveSystemProxy() {
  SystemProxyResult result;
  GProxyResolver* resolver = g_proxy_resolver_get_default();
  if (resolver == nullptr || !g_proxy_resolver_is_supported(resolver)) {
    result.error = "system proxy resolver is unavailable";
    return result;
  }

  GError* lookup_error = nullptr;
  gchar** resolved = g_proxy_resolver_lookup(
      resolver, kSystemProxyProbeUrl, nullptr, &lookup_error);
  if (resolved == nullptr) {
    result.error = lookup_error != nullptr && lookup_error->message != nullptr
                       ? std::string("could not resolve system proxy: ") +
                             lookup_error->message
                       : "could not resolve system proxy";
    if (lookup_error != nullptr) g_error_free(lookup_error);
    return result;
  }

  std::vector<std::string> candidates;
  for (gchar** candidate = resolved; *candidate != nullptr; ++candidate) {
    candidates.emplace_back(*candidate);
  }
  g_strfreev(resolved);
  return SelectSystemProxy(candidates);
}

}  // namespace runtime
}  // namespace mocktail
