#include "update/apk_signature.h"

#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "mocktail/mocktail_rust.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <limits>
#include <memory>
#include <string>
#include <vector>

namespace mocktail::update {
namespace {

struct Mapping final {
  int descriptor = -1;
  const unsigned char* bytes = nullptr;
  std::size_t size = 0;

  ~Mapping() {
    if (bytes != nullptr) munmap(const_cast<unsigned char*>(bytes), size);
    if (descriptor >= 0) close(descriptor);
  }

  Mapping(const Mapping&) = delete;
  Mapping& operator=(const Mapping&) = delete;
  Mapping() = default;
};

template <typename T, void (*Free)(T*)>
struct OpenSslDeleter {
  void operator()(T* value) const {
    if (value != nullptr) Free(value);
  }
};

using EvpKey =
    std::unique_ptr<EVP_PKEY, OpenSslDeleter<EVP_PKEY, EVP_PKEY_free>>;
using X509Certificate = std::unique_ptr<X509, OpenSslDeleter<X509, X509_free>>;
using DigestContext =
    std::unique_ptr<EVP_MD_CTX, OpenSslDeleter<EVP_MD_CTX, EVP_MD_CTX_free>>;

bool MapFile(const std::filesystem::path& path, Mapping* mapping,
             std::string* error) {
  mapping->descriptor = open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (mapping->descriptor < 0) {
    *error = "cannot open APK for signature verification";
    return false;
  }
  struct stat metadata = {};
  if (fstat(mapping->descriptor, &metadata) != 0 ||
      !S_ISREG(metadata.st_mode) || metadata.st_size < 32 ||
      static_cast<std::uintmax_t>(metadata.st_size) >
          std::numeric_limits<std::size_t>::max()) {
    *error = "APK is not a bounded regular file";
    return false;
  }
  mapping->size = static_cast<std::size_t>(metadata.st_size);
  void* bytes = mmap(nullptr, mapping->size, PROT_READ, MAP_PRIVATE,
                     mapping->descriptor, 0);
  if (bytes == MAP_FAILED) {
    *error = "cannot map APK for signature verification";
    mapping->bytes = nullptr;
    return false;
  }
  mapping->bytes = static_cast<const unsigned char*>(bytes);
  return true;
}

void WriteErr(char* err_buf, size_t err_cap, const char* msg) {
  if (err_buf != nullptr && err_cap > 0) {
    std::snprintf(err_buf, err_cap, "%s", msg);
  }
}

struct OpenSslVerifyState {
  EvpKey current_pubkey;
  std::vector<std::string> certificates;
};

int32_t VerifySignatureCallback(
    void* ctx, const uint8_t* pubkey, size_t pubkey_len,
    const uint8_t* signed_data, size_t signed_data_len,
    const uint8_t* signature, size_t signature_len, int32_t digest_kind,
    int32_t is_pss, char* err_buf, size_t err_cap) {
  auto* state = static_cast<OpenSslVerifyState*>(ctx);
  const unsigned char* public_cursor = pubkey;
  EvpKey key(d2i_PUBKEY(nullptr, &public_cursor, static_cast<long>(pubkey_len)));
  if (!key || public_cursor != pubkey + pubkey_len) {
    WriteErr(err_buf, err_cap, "APK signer public key is malformed");
    return -1;
  }

  const EVP_MD* md = digest_kind == 1 ? EVP_sha512() : EVP_sha256();
  DigestContext context(EVP_MD_CTX_new());
  EVP_PKEY_CTX* key_context = nullptr;
  if (!context || EVP_DigestVerifyInit(context.get(), &key_context, md, nullptr,
                                       key.get()) != 1) {
    WriteErr(err_buf, err_cap, "cannot initialise APK signer verification");
    return -1;
  }
  if (is_pss != 0 &&
      (EVP_PKEY_CTX_set_rsa_padding(key_context, RSA_PKCS1_PSS_PADDING) <= 0 ||
       EVP_PKEY_CTX_set_rsa_pss_saltlen(key_context, EVP_MD_get_size(md)) <=
           0 ||
       EVP_PKEY_CTX_set_rsa_mgf1_md(key_context, md) <= 0)) {
    WriteErr(err_buf, err_cap, "cannot configure APK RSA-PSS verification");
    return -1;
  }
  if (EVP_DigestVerify(context.get(), signature, signature_len, signed_data,
                       signed_data_len) != 1) {
    WriteErr(err_buf, err_cap, "APK signer signature verification failed");
    return -1;
  }

  state->current_pubkey = std::move(key);
  return 0;
}

int32_t VerifyCertificateCallback(void* ctx, const uint8_t* encoded_cert,
                                  size_t encoded_cert_len, int32_t is_leaf,
                                  char* err_buf, size_t err_cap) {
  auto* state = static_cast<OpenSslVerifyState*>(ctx);
  const unsigned char* cert_cursor = encoded_cert;
  X509Certificate certificate(
      d2i_X509(nullptr, &cert_cursor, static_cast<long>(encoded_cert_len)));
  if (!certificate || cert_cursor != encoded_cert + encoded_cert_len) {
    WriteErr(err_buf, err_cap, "APK signer certificate is malformed");
    return -1;
  }
  if (is_leaf != 0) {
    EvpKey certificate_key(X509_get_pubkey(certificate.get()));
    if (!certificate_key ||
        EVP_PKEY_eq(certificate_key.get(), state->current_pubkey.get()) != 1) {
      WriteErr(err_buf, err_cap,
               "APK signer public key does not match its certificate");
      return -1;
    }
  }
  return 0;
}

void EmitFingerprintCallback(void* ctx, const char* hex_ptr, size_t hex_len) {
  auto* state = static_cast<OpenSslVerifyState*>(ctx);
  if (state != nullptr && hex_ptr != nullptr) {
    state->certificates.emplace_back(hex_ptr, hex_len);
  }
}

}  // namespace

ApkSignatureResult VerifyApkSignature(const std::filesystem::path& apk_path) {
  ApkSignatureResult result;
  Mapping mapping;
  if (!MapFile(apk_path, &mapping, &result.error)) return result;

  OpenSslVerifyState state;
  std::array<char, 256> err_buf{};
  const int32_t rc = mocktail_rust_verify_apk_signature_container(
      mapping.bytes, mapping.size, &state, &VerifySignatureCallback,
      &VerifyCertificateCallback, &EmitFingerprintCallback, err_buf.data(),
      err_buf.size());
  if (rc != 0) {
    result.error = err_buf[0] != '\0' ? err_buf.data()
                                      : "APK signature verification failed";
    return result;
  }
  result.certificate_sha256 = std::move(state.certificates);
  return result;
}

}  // namespace mocktail::update
