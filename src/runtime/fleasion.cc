#include "runtime/fleasion.h"

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include <array>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>

#include "mocktail/mocktail_rust.h"

namespace mocktail::runtime {
namespace {

using Bio = std::unique_ptr<BIO, decltype(&BIO_free)>;
using Certificate = std::unique_ptr<X509, decltype(&X509_free)>;

bool ReadFile(const std::filesystem::path& path, std::string* contents) {
  std::error_code error;
  if (!path.is_absolute() || !std::filesystem::is_regular_file(path, error))
    return false;
  const auto size = std::filesystem::file_size(path, error);
  if (error || size == 0 || size > 4 * 1024 * 1024) return false;
  std::ifstream input(path, std::ios::binary);
  contents->resize(static_cast<std::size_t>(size));
  return static_cast<bool>(input.read(contents->data(), contents->size()));
}

std::filesystem::path DefaultCertificate(const Environment& environment,
                                         const RuntimePaths& paths) {
  std::filesystem::path root = environment.GetOr("XDG_CONFIG_HOME", "");
  if (!root.is_absolute()) root = paths.home() / ".config";
  return root / "Fleasion/proxy_ca/ca.crt";
}

}  // namespace

FleasionPreparation PrepareFleasion(const RuntimeConfig& config,
                                   const Environment& environment,
                                   const RuntimePaths& paths) {
  FleasionPreparation result;
  if (!config.fleasion_enabled()) return result;
  if (!config.fleasion_valid()) {
    result.error = "invalid Fleasion configuration";
    return result;
  }
  result.certificate = config.fleasion_ca_certificate().value_or(
      DefaultCertificate(environment, paths));
  result.bundle = paths.cache_root() / "fleasion/cacert.pem";
  result.base_bundle = config.ca_bundle().value_or(std::filesystem::path{});
  // Re-exec and updater canaries inherit the generated bundle. Rebuild from
  // the original roots so a rotated Fleasion CA does not accumulate forever.
  if (result.base_bundle == result.bundle ||
      result.base_bundle == environment.GetOr("MOCKTAIL_FLEASION_GENERATED_BUNDLE", "")) {
    result.base_bundle = environment.GetOr("MOCKTAIL_FLEASION_BASE_CA_BUNDLE", "");
  }
  if (result.base_bundle.empty()) {
    for (const char* candidate : {"/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"}) {
      std::error_code error;
      if (std::filesystem::is_regular_file(candidate, error)) {
        result.base_bundle = candidate;
        break;
      }
    }
  }
  std::error_code equivalent_error;
  const bool certificate_is_output = std::filesystem::equivalent(
      result.certificate, result.bundle, equivalent_error);
  equivalent_error.clear();
  const bool base_is_output = std::filesystem::equivalent(
      result.base_bundle, result.bundle, equivalent_error);
  if (result.certificate == result.bundle || result.base_bundle == result.bundle ||
      certificate_is_output || base_is_output) {
    result.error = "Fleasion source certificates must be outside its generated bundle";
    return result;
  }

  std::string ca_pem;
  if (!ReadFile(result.certificate, &ca_pem)) {
    result.error = "cannot read Fleasion CA certificate at " + result.certificate.string() +
                   "; start Fleasion first or set integrations.fleasion.ca_certificate";
    return result;
  }
  Bio ca_input(BIO_new_mem_buf(ca_pem.data(), static_cast<int>(ca_pem.size())), BIO_free);
  Certificate ca(ca_input ? PEM_read_bio_X509(ca_input.get(), nullptr, nullptr, nullptr)
                         : nullptr, X509_free);
  if (!ca || X509_check_ca(ca.get()) <= 0 ||
      X509_cmp_current_time(X509_get0_notBefore(ca.get())) >= 0 ||
      X509_cmp_current_time(X509_get0_notAfter(ca.get())) <= 0) {
    ERR_clear_error();
    result.error = "Fleasion CA must be a currently valid PEM CA certificate";
    return result;
  }

  std::array<char, 512> out_err{};
  const int rc = mocktail_rust_fleasion_prepare_bundle(
      result.certificate.c_str(), result.base_bundle.c_str(),
      result.bundle.c_str(), out_err.data(), out_err.size());
  if (rc != 0) {
    if (rc == -5) {
      result.error = "cannot read Fleasion CA certificate at " +
                     result.certificate.string() +
                     "; start Fleasion first or set integrations.fleasion.ca_certificate";
    } else {
      result.error = out_err[0] != '\0' ? out_err.data()
                                        : "failed to prepare Fleasion CA bundle";
    }
  }
  return result;
}

}  // namespace mocktail::runtime
