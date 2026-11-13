#include "compat/host_abi_profile_loader.h"
#include "mocktail/mocktail_rust.h"

#include <elf.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "compat/elf_build_id.h"
#include "compat/guest_abi.h"

namespace mocktail::compat {
namespace {

static_assert(static_cast<int>(HostBridgeKind::kAllocate) == 0);
static_assert(static_cast<int>(HostBridgeKind::kReallocate) == 1);
static_assert(static_cast<int>(HostBridgeKind::kAlignedAllocate) == 2);
static_assert(static_cast<int>(HostBridgeKind::kFree) == 3);
static_assert(static_cast<int>(HostBridgeKind::kUsableSize) == 4);
static_assert(static_cast<int>(HostAllocatorStrategy::kNativeMimalloc) == 1);
static_assert(kMaxHostBridgeEntries == 8);
static_assert(kMaxConstructorRunRanges == 26);

std::string ComputeSha256Hex(std::string_view bytes,
                             std::size_t max_chars = 0) {
  char hex_buf[65] = {};
  if (mocktail_rust_host_abi_sha256_hex(
          reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size(),
          max_chars, hex_buf, sizeof(hex_buf)) != 0) {
    return {};
  }
  return std::string(hex_buf);
}

constexpr std::size_t kMaximumProfileBytes = 1024 * 1024;
constexpr std::size_t kMaximumReceiptBytes = 64 * 1024;

class FileDescriptor {
 public:
  explicit FileDescriptor(int value) noexcept : value_(value) {}
  ~FileDescriptor() {
    if (value_ >= 0) {
      close(value_);
    }
  }
  FileDescriptor(const FileDescriptor&) = delete;
  FileDescriptor& operator=(const FileDescriptor&) = delete;
  int get() const noexcept { return value_; }

 private:
  int value_;
};

struct ElfDeleter {
  void operator()(Elf* elf) const noexcept {
    if (elf != nullptr) {
      elf_end(elf);
    }
  }
};

struct LoadSegment {
  std::uint64_t begin = 0;
  std::uint64_t end = 0;
  unsigned int flags = 0;
};

struct OwnedHostAbiProfile {
  HostAbiProfile profile;
  std::string build_id;
  std::array<std::string, kMaxHostBridgeEntries> labels;
  std::string canonical_payload_path;
  std::string payload_sha256;
  std::string profile_sha256;
  std::string reference_build_id;
  std::string reference_payload_sha256;
  std::vector<uintptr_t> derivation_code_rvas;

  void BindViews() {
    profile.elf_build_id = build_id;
    for (std::size_t index = 0; index < profile.bridge_entry_count; ++index) {
      profile.bridge_entries[index].label = labels[index];
    }
  }
};

std::mutex g_external_profiles_mutex;
std::vector<std::unique_ptr<OwnedHostAbiProfile>> g_external_profiles;

ExternalHostAbiProfileResult Failure(std::string error) {
  ExternalHostAbiProfileResult result;
  result.error = std::move(error);
  return result;
}

bool ReadSmallRegularFile(const std::string& path, std::size_t maximum_bytes,
                          bool require_immutable, std::string* contents,
                          std::string* error) {
  struct stat status{};
  if (lstat(path.c_str(), &status) != 0) {
    *error = "lstat(" + path + "): " + std::strerror(errno);
    return false;
  }
  if (!S_ISREG(status.st_mode)) {
    *error = "not a regular non-symlink file: " + path;
    return false;
  }
  if (status.st_uid != geteuid()) {
    *error = "file is not owned by the current user: " + path;
    return false;
  }
  if ((status.st_mode & (S_IWGRP | S_IWOTH)) != 0) {
    *error = "file is group- or world-writable: " + path;
    return false;
  }
  if (require_immutable && (status.st_mode & S_IWUSR) != 0) {
    *error = "approval evidence is owner-writable: " + path;
    return false;
  }
  if (status.st_size < 0 ||
      static_cast<std::uint64_t>(status.st_size) > maximum_bytes) {
    *error = "file exceeds the accepted size limit: " + path;
    return false;
  }
  std::ifstream input(path, std::ios::binary);
  if (!input) {
    *error = "cannot open file: " + path;
    return false;
  }
  contents->assign(std::istreambuf_iterator<char>(input),
                   std::istreambuf_iterator<char>());
  if (input.bad()) {
    *error = "cannot read file: " + path;
    return false;
  }
  return true;
}

std::optional<std::string> CanonicalRegularPath(const std::string& path,
                                                std::string* error) {
  if (path.empty() || !std::filesystem::path(path).is_absolute()) {
    *error = "path must be absolute: " + path;
    return std::nullopt;
  }
  struct stat link_status{};
  if (lstat(path.c_str(), &link_status) != 0) {
    *error = "lstat(" + path + "): " + std::strerror(errno);
    return std::nullopt;
  }
  if (S_ISLNK(link_status.st_mode)) {
    *error = "symlink paths are not accepted: " + path;
    return std::nullopt;
  }
  std::error_code code;
  const std::filesystem::path canonical =
      std::filesystem::canonical(path, code);
  if (code) {
    *error = "cannot canonicalize " + path + ": " + code.message();
    return std::nullopt;
  }
  const std::filesystem::file_status status =
      std::filesystem::status(canonical, code);
  if (code || !std::filesystem::is_regular_file(status)) {
    *error = "canonical path is not a regular file: " + canonical.string();
    return std::nullopt;
  }
  return canonical.string();
}

std::unique_ptr<OwnedHostAbiProfile> ParseProfileBytes(
    const std::string& path, std::string_view bytes, std::string* error) {
  MocktailRustParsedHostAbiProfile parsed{};
  char err_buf[256] = {};
  const int rc = mocktail_rust_host_abi_parse_profile_json(
      bytes.data(), bytes.size(), kGuestElfMachine == EM_X86_64,
      alignof(void*), std::numeric_limits<std::uintptr_t>::max(), &parsed,
      err_buf, sizeof(err_buf));
  if (rc == -2) {
    *error = "invalid JSON object: " + path;
    return nullptr;
  }
  if (rc != 0) {
    *error = err_buf[0] != '\0' ? err_buf
                                : "unsupported external host ABI profile schema";
    return nullptr;
  }

  auto owned = std::make_unique<OwnedHostAbiProfile>();
  owned->build_id = parsed.build_id;
  owned->reference_build_id = parsed.reference_build_id;
  owned->reference_payload_sha256 = parsed.reference_payload_sha256;
  owned->profile.bridge_entry_count = parsed.bridge_entry_count;
  for (std::size_t i = 0; i < parsed.bridge_entry_count; ++i) {
    owned->labels[i] = parsed.bridge_entries[i].label;
    owned->profile.bridge_entries[i].rva =
        static_cast<uintptr_t>(parsed.bridge_entries[i].rva);
    owned->profile.bridge_entries[i].kind =
        static_cast<HostBridgeKind>(parsed.bridge_entries[i].kind);
    owned->profile.bridge_entries[i].label = {};
  }
  owned->profile.data_seeds.allocator_object_slot =
      static_cast<uintptr_t>(parsed.allocator_object_slot);
  owned->profile.data_seeds.empty_string_slot =
      static_cast<uintptr_t>(parsed.empty_string_slot);
  owned->profile.data_seeds.jni_singleton_slot =
      static_cast<uintptr_t>(parsed.jni_singleton_slot);
  owned->profile.data_seeds.jni_singleton_bytes = parsed.jni_singleton_bytes;
  owned->profile.data_seeds.arena_initializer =
      static_cast<uintptr_t>(parsed.arena_initializer);
  owned->profile.data_seeds.allocator_thread_initializer =
      static_cast<uintptr_t>(parsed.allocator_thread_initializer);
  owned->profile.data_seeds.arena_guard_slot =
      static_cast<uintptr_t>(parsed.arena_guard_slot);
  owned->profile.data_seeds.arena_table_slot =
      static_cast<uintptr_t>(parsed.arena_table_slot);
  owned->profile.data_seeds.arena_table_slot_count =
      parsed.arena_table_slot_count;
  owned->profile.native_allocator.allocate =
      static_cast<uintptr_t>(parsed.native_allocator_allocate);
  owned->profile.native_allocator.deallocate =
      static_cast<uintptr_t>(parsed.native_allocator_deallocate);
  owned->profile.init_array_offset =
      static_cast<uintptr_t>(parsed.init_array_offset);
  owned->profile.init_array_count = parsed.init_array_count;
  owned->profile.constructor_run_range_count =
      parsed.constructor_run_range_count;
  for (std::size_t i = 0; i < parsed.constructor_run_range_count; ++i) {
    owned->profile.constructor_run_ranges[i] = {
        parsed.constructor_run_ranges[i].begin,
        parsed.constructor_run_ranges[i].end_exclusive};
  }
  owned->profile.native_mimalloc_constructor_run_range_count =
      parsed.native_mimalloc_constructor_run_range_count;
  for (std::size_t i = 0;
       i < parsed.native_mimalloc_constructor_run_range_count; ++i) {
    owned->profile.native_mimalloc_constructor_run_ranges[i] = {
        parsed.native_mimalloc_constructor_run_ranges[i].begin,
        parsed.native_mimalloc_constructor_run_ranges[i].end_exclusive};
  }
  owned->profile.native_mimalloc_thread_initializer_after_constructor =
      parsed.native_mimalloc_thread_initializer_after_constructor;
  owned->profile.native_pre_jni_bootstrap.registry_initializer =
      static_cast<uintptr_t>(parsed.native_pre_jni_registry_initializer);
  owned->profile.native_pre_jni_bootstrap.registry_slot =
      static_cast<uintptr_t>(parsed.native_pre_jni_registry_slot);
  owned->profile.host_allocator_bridges_supported =
      parsed.host_allocator_bridges_supported != 0;
  owned->profile.default_allocator_strategy =
      static_cast<HostAllocatorStrategy>(parsed.default_allocator_strategy);
  owned->derivation_code_rvas.assign(
      parsed.derivation_code_rvas,
      parsed.derivation_code_rvas + parsed.derivation_code_rva_count);
  owned->BindViews();
  return owned;
}

bool RangeInSegment(const std::vector<LoadSegment>& segments,
                    std::uint64_t begin, std::uint64_t size,
                    unsigned int required_flags, unsigned int forbidden_flags) {
  if (size == 0 || begin > std::numeric_limits<std::uint64_t>::max() - size) {
    return false;
  }
  const std::uint64_t end = begin + size;
  return std::any_of(segments.begin(), segments.end(),
                     [begin, end, required_flags,
                      forbidden_flags](const LoadSegment& segment) {
                       return (segment.flags & required_flags) ==
                                  required_flags &&
                              (segment.flags & forbidden_flags) == 0 &&
                              segment.begin <= begin && end <= segment.end;
                     });
}

bool ValidateProfileAgainstElf(const std::string& payload_path,
                               const HostAbiProfile& profile,
                               const std::vector<uintptr_t>& derivation_rvas,
                               std::string* error) {
  if (elf_version(EV_CURRENT) == EV_NONE) {
    *error = "libelf initialization failed";
    return false;
  }
  FileDescriptor descriptor(open(payload_path.c_str(), O_RDONLY | O_CLOEXEC));
  if (descriptor.get() < 0) {
    *error = "cannot open payload ELF: " + std::string(std::strerror(errno));
    return false;
  }
  std::unique_ptr<Elf, ElfDeleter> elf(
      elf_begin(descriptor.get(), ELF_C_READ, nullptr));
  if (!elf || elf_kind(elf.get()) != ELF_K_ELF) {
    *error = "payload is not a readable ELF object";
    return false;
  }
  GElf_Ehdr header{};
  if (gelf_getehdr(elf.get(), &header) == nullptr ||
      gelf_getclass(elf.get()) != ELFCLASS64 ||
      header.e_machine != kGuestElfMachine || header.e_type != ET_DYN) {
    *error = "payload must be a " + std::string(kGuestAbi) +
             " ET_DYN ELF object";
    return false;
  }

  std::size_t program_count = 0;
  if (elf_getphdrnum(elf.get(), &program_count) != 0) {
    *error = "cannot enumerate payload ELF program headers";
    return false;
  }
  std::vector<LoadSegment> segments;
  for (std::size_t index = 0; index < program_count; ++index) {
    GElf_Phdr program{};
    if (gelf_getphdr(elf.get(), static_cast<int>(index), &program) == nullptr) {
      *error = "cannot read payload ELF program header";
      return false;
    }
    if (program.p_type == PT_LOAD && program.p_memsz > 0 &&
        program.p_vaddr <=
            std::numeric_limits<std::uint64_t>::max() - program.p_memsz) {
      segments.push_back({program.p_vaddr, program.p_vaddr + program.p_memsz,
                          program.p_flags});
    }
  }

  std::vector<uintptr_t> code_rvas = {
      profile.data_seeds.arena_initializer,
      profile.data_seeds.allocator_thread_initializer,
      profile.native_allocator.allocate,
      profile.native_allocator.deallocate,
      profile.native_pre_jni_bootstrap.registry_initializer,
  };
  for (std::size_t index = 0; index < profile.bridge_entry_count; ++index) {
    code_rvas.push_back(profile.bridge_entries[index].rva);
  }
  code_rvas.insert(code_rvas.end(), derivation_rvas.begin(),
                   derivation_rvas.end());
  for (const uintptr_t rva : code_rvas) {
    if (!RangeInSegment(segments, rva, 1, PF_R | PF_X, PF_W)) {
      *error =
          "host ABI profile contains a code RVA outside executable ELF "
          "segments";
      return false;
    }
  }

  const std::array<uintptr_t, 6> data_rvas = {
      profile.data_seeds.allocator_object_slot,
      profile.data_seeds.empty_string_slot,
      profile.data_seeds.jni_singleton_slot,
      profile.data_seeds.arena_guard_slot,
      profile.data_seeds.arena_table_slot,
      profile.native_pre_jni_bootstrap.registry_slot,
  };
  for (const uintptr_t rva : data_rvas) {
    if (!RangeInSegment(segments, rva, sizeof(void*), PF_R | PF_W, PF_X)) {
      *error =
          "host ABI profile contains a data RVA outside writable ELF segments";
      return false;
    }
  }

  std::size_t section_count = 0;
  if (elf_getshdrnum(elf.get(), &section_count) != 0) {
    *error = "cannot enumerate payload ELF sections";
    return false;
  }
  bool exact_init_array = false;
  for (std::size_t index = 0; index < section_count; ++index) {
    Elf_Scn* section = elf_getscn(elf.get(), index);
    GElf_Shdr section_header{};
    if (section == nullptr ||
        gelf_getshdr(section, &section_header) == nullptr) {
      *error = "cannot read payload ELF section";
      return false;
    }
    if (section_header.sh_type == SHT_INIT_ARRAY &&
        section_header.sh_addr == profile.init_array_offset &&
        (section_header.sh_entsize == 0 ||
         section_header.sh_entsize == sizeof(std::uint64_t)) &&
        section_header.sh_size ==
            profile.init_array_count * sizeof(std::uint64_t) &&
        (section_header.sh_flags & (SHF_ALLOC | SHF_WRITE)) ==
            (SHF_ALLOC | SHF_WRITE) &&
        (section_header.sh_flags & SHF_EXECINSTR) == 0) {
      exact_init_array = true;
      break;
    }
  }
  if (!exact_init_array) {
    *error = "host ABI profile does not match the payload .init_array";
    return false;
  }
  return true;
}

void AssignHostAbiString(void* raw_ctx, const char* ptr, size_t len) {
  auto* out = static_cast<std::string*>(raw_ctx);
  out->assign(ptr, len);
}

struct CanaryEvidence {
  std::string sha256;
  std::string run_id;
};

bool ValidateCanaryAttestation(const std::string& attestation_path,
                               std::size_t expected_run,
                               std::string_view payload_id,
                               std::string_view payload_fingerprint,
                               std::string_view profile_sha256,
                               std::string_view compatibility_manifest_sha256,
                               std::string_view runtime_sha256,
                               std::string_view runtime_build_id,
                               CanaryEvidence* evidence, std::string* error) {
  std::string attestation_bytes;
  if (!ReadSmallRegularFile(attestation_path, kMaximumReceiptBytes, true,
                            &attestation_bytes, error)) {
    return false;
  }
  char sha_buf[65] = {};
  char err_buf[256] = {};
  std::string run_id;
  const int rc = mocktail_rust_host_abi_validate_canary_attestation_json(
      attestation_bytes.data(), attestation_bytes.size(), expected_run,
      std::string(payload_id).c_str(), std::string(payload_fingerprint).c_str(),
      std::string(profile_sha256).c_str(),
      std::string(compatibility_manifest_sha256).c_str(),
      std::string(runtime_sha256).c_str(), std::string(runtime_build_id).c_str(),
      sha_buf, sizeof(sha_buf), AssignHostAbiString, &run_id, err_buf,
      sizeof(err_buf));
  if (rc == -2) {
    *error = "invalid JSON object: " + attestation_path;
    return false;
  }
  if (rc != 0) {
    *error = err_buf[0] != '\0'
                 ? err_buf
                 : "canary attestation does not match the exact approval evidence";
    return false;
  }
  evidence->sha256 = sha_buf;
  evidence->run_id = std::move(run_id);
  return true;
}

bool ValidateReceipt(const std::string& receipt_path,
                     const std::string& canonical_payload_path,
                     const std::string& payload_sha256,
                     const std::string& profile_sha256,
                     const std::string& payload_id, const std::string& build_id,
                     const std::string& compatibility_manifest_path,
                     std::string* error) {
  std::string receipt_bytes;
  if (!ReadSmallRegularFile(receipt_path, kMaximumReceiptBytes, true,
                            &receipt_bytes, error)) {
    return false;
  }
  MocktailRustParsedApprovalReceipt parsed{};
  char err_buf[256] = {};
  const int parse_rc = mocktail_rust_host_abi_parse_receipt_json(
      receipt_bytes.data(), receipt_bytes.size(), receipt_path.c_str(),
      canonical_payload_path.c_str(), payload_sha256.c_str(),
      profile_sha256.c_str(), payload_id.c_str(), build_id.c_str(), &parsed,
      err_buf, sizeof(err_buf));
  if (parse_rc == -2) {
    *error = "invalid JSON object: " + receipt_path;
    return false;
  }
  if (parse_rc != 0) {
    *error = err_buf[0] != '\0'
                 ? err_buf
                 : "approval receipt does not authorize the exact ABI profile and payload";
    return false;
  }

  const FileSha256Result manifest_hash =
      ComputeFileSha256(compatibility_manifest_path);
  if (!manifest_hash) {
    *error = "cannot hash compatibility manifest for approval receipt";
    return false;
  }
  if (std::string_view(parsed.compatibility_manifest_sha256) !=
      manifest_hash.sha256) {
    *error = "approval receipt belongs to different compatibility bytes";
    return false;
  }

  const std::filesystem::path receipt_file(receipt_path);
  const std::string evidence_prefix = payload_id + "-" + parsed.generation;
  std::array<CanaryEvidence, 2> canary_evidence;
  for (std::size_t index = 0; index < canary_evidence.size(); ++index) {
    const std::string filename =
        evidence_prefix + ".canary-" + std::to_string(index + 1) + ".json";
    const std::filesystem::path candidate =
        receipt_file.parent_path() / filename;
    std::string path_error;
    const std::optional<std::string> canonical_attestation =
        CanonicalRegularPath(candidate.string(), &path_error);
    if (!canonical_attestation.has_value() ||
        std::filesystem::path(*canonical_attestation).parent_path() !=
            receipt_file.parent_path() ||
        std::filesystem::path(*canonical_attestation).filename() != filename) {
      *error = "approval receipt is missing an adjacent canary attestation";
      return false;
    }
    if (!ValidateCanaryAttestation(
            *canonical_attestation, index + 1, payload_id,
            parsed.payload_fingerprint, profile_sha256, manifest_hash.sha256,
            parsed.canary_runtime_sha256, parsed.runtime_build_id,
            &canary_evidence[index], error)) {
      return false;
    }
  }

  if (mocktail_rust_host_abi_verify_receipt_evidence(
          &parsed, profile_sha256.c_str(), manifest_hash.sha256.c_str(),
          canary_evidence[0].sha256.c_str(), canary_evidence[0].run_id.c_str(),
          canary_evidence[1].sha256.c_str(), canary_evidence[1].run_id.c_str(),
          err_buf, sizeof(err_buf)) != 0) {
    *error = err_buf[0] != '\0'
                 ? err_buf
                 : "approval receipt evidence generation does not match";
    return false;
  }
  return true;
}

const OwnedHostAbiProfile* FindLoadedProfile(std::string_view build_id) {
  std::lock_guard<std::mutex> lock(g_external_profiles_mutex);
  for (const std::unique_ptr<OwnedHostAbiProfile>& profile :
       g_external_profiles) {
    if (profile->build_id == build_id) {
      return profile.get();
    }
  }
  return nullptr;
}

ExternalHostAbiProfileResult RegisterProfile(
    std::unique_ptr<OwnedHostAbiProfile> profile) {
  std::lock_guard<std::mutex> lock(g_external_profiles_mutex);
  for (const std::unique_ptr<OwnedHostAbiProfile>& existing :
       g_external_profiles) {
    if (existing->build_id != profile->build_id) {
      continue;
    }
    if (existing->canonical_payload_path == profile->canonical_payload_path &&
        existing->payload_sha256 == profile->payload_sha256 &&
        existing->profile_sha256 == profile->profile_sha256) {
      return {&existing->profile,
              existing->payload_sha256,
              existing->profile_sha256,
              {}};
    }
    return Failure(
        "a different external ABI profile is already loaded for this Build ID");
  }
  profile->BindViews();
  const HostAbiProfile* registered = &profile->profile;
  const std::string payload_sha256 = profile->payload_sha256;
  const std::string profile_sha256 = profile->profile_sha256;
  g_external_profiles.push_back(std::move(profile));
  return {registered, payload_sha256, profile_sha256, {}};
}

}  // namespace

FileSha256Result ComputeFileSha256(const std::string& path) {
  char hex_buf[65] = {};
  char err_buf[512] = {};
  int rc = mocktail_rust_compute_file_sha256(
      path.c_str(), hex_buf, sizeof(hex_buf), err_buf, sizeof(err_buf));
  if (rc != 0) {
    return {{}, err_buf[0] != '\0' ? err_buf : "cannot hash file: " + path};
  }
  return {std::string(hex_buf), {}};
}

const HostAbiProfile* FindLoadedExternalHostAbiProfile(
    std::string_view build_id) noexcept {
  const OwnedHostAbiProfile* loaded = FindLoadedProfile(build_id);
  return loaded != nullptr ? &loaded->profile : nullptr;
}

ExternalHostAbiProfileResult LoadExternalHostAbiProfile(
    const ExternalHostAbiProfileRequest& request) {
  if (request.profile_file.empty() || request.payload_path.empty() ||
      request.expected_build_id.empty()) {
    return Failure("external host ABI profile request is incomplete");
  }
  if (request.candidate_canary) {
    if (!request.candidate_process_authorization ||
        !request.explicit_unverified_authorization ||
        !request.approval_receipt_path.empty()) {
      return Failure(
          "candidate ABI profile requires isolated canary authorization");
    }
  } else if (request.candidate_process_authorization ||
             request.approval_receipt_path.empty()) {
    return Failure("normal ABI profile loading requires an approval receipt");
  }

  std::string path_error;
  const std::optional<std::string> canonical_profile =
      CanonicalRegularPath(request.profile_file, &path_error);
  if (!canonical_profile.has_value()) {
    return Failure(path_error);
  }
  const std::optional<std::string> canonical_payload =
      CanonicalRegularPath(request.payload_path, &path_error);
  if (!canonical_payload.has_value()) {
    return Failure(path_error);
  }
  const std::optional<std::string> canonical_manifest =
      CanonicalRegularPath(request.compatibility_manifest_path, &path_error);
  if (!canonical_manifest.has_value()) {
    return Failure(path_error);
  }

  std::string profile_bytes;
  if (!ReadSmallRegularFile(*canonical_profile, kMaximumProfileBytes, false,
                            &profile_bytes, &path_error)) {
    return Failure(path_error);
  }
  std::unique_ptr<OwnedHostAbiProfile> profile =
      ParseProfileBytes(*canonical_profile, profile_bytes, &path_error);
  if (!profile) {
    return Failure(path_error);
  }

  char encoded_payload_sha256_buf[65] = {};
  char payload_id_buf[128] = {};
  if (mocktail_rust_host_abi_validate_profile_identity(
          profile_bytes.data(), profile_bytes.size(), profile->build_id.c_str(),
          profile->reference_build_id.c_str(),
          profile->reference_payload_sha256.c_str(), canonical_payload->c_str(),
          request.expected_build_id.c_str(), encoded_payload_sha256_buf,
          sizeof(encoded_payload_sha256_buf), payload_id_buf,
          sizeof(payload_id_buf)) != 0) {
    return Failure(
        "external host ABI profile payload identity does not match the launch");
  }
  const std::string encoded_payload_sha256(encoded_payload_sha256_buf);
  const std::string payload_id(payload_id_buf);
  const BuildIdResult actual_build_id = ReadElfBuildId(*canonical_payload);
  if (!actual_build_id || actual_build_id.build_id != profile->build_id) {
    return Failure(
        "external host ABI profile Build ID does not match payload ELF");
  }

  const FileSha256Result payload_hash = ComputeFileSha256(*canonical_payload);
  if (!payload_hash || payload_hash.sha256 != encoded_payload_sha256) {
    return Failure(
        "external host ABI profile SHA-256 does not match payload bytes");
  }
  const std::string profile_sha256 = ComputeSha256Hex(profile_bytes);
  if (profile_sha256.empty()) {
    return Failure("cannot compute external host ABI profile SHA-256");
  }
  if (!ValidateProfileAgainstElf(*canonical_payload, profile->profile,
                                 profile->derivation_code_rvas, &path_error)) {
    return Failure(path_error);
  }

  profile->canonical_payload_path = *canonical_payload;
  profile->payload_sha256 = payload_hash.sha256;
  profile->profile_sha256 = profile_sha256;

  if (FindHostAbiProfile(profile->build_id) != nullptr) {
    const OwnedHostAbiProfile* loaded = FindLoadedProfile(profile->build_id);
    if (loaded == nullptr) {
      return Failure(
          "external host ABI profile cannot override a built-in Build ID");
    }
  }

  if (!request.candidate_canary) {
    const std::optional<std::string> canonical_receipt =
        CanonicalRegularPath(request.approval_receipt_path, &path_error);
    if (!canonical_receipt.has_value() ||
        !ValidateReceipt(*canonical_receipt, *canonical_payload,
                         payload_hash.sha256, profile_sha256, payload_id,
                         profile->build_id, *canonical_manifest, &path_error)) {
      return Failure(path_error);
    }
  }
  return RegisterProfile(std::move(profile));
}

ExternalHostAbiProfileResult InitializeHostAbiProfileFromEnvironment(
    const std::string& payload_path,
    const std::string& compatibility_manifest_path,
    const std::string& expected_build_id,
    bool explicit_unverified_authorization) {
  const char* profile_file = std::getenv("MOCKTAIL_HOST_ABI_PROFILE_FILE");
  const char* canary = std::getenv("MOCKTAIL_HOST_ABI_CANARY");
  const char* candidate_process =
      std::getenv("MOCKTAIL_ALLOW_CANDIDATE_HOST_ABI");
  const char* receipt = std::getenv("MOCKTAIL_HOST_ABI_APPROVAL_RECEIPT");
  const bool has_profile = profile_file != nullptr && profile_file[0] != '\0';
  const bool has_canary_marker = canary != nullptr && canary[0] != '\0';
  const bool candidate_canary =
      has_canary_marker && std::string_view(canary) == "1";
  const bool has_candidate_process_marker =
      candidate_process != nullptr && candidate_process[0] != '\0';
  const bool candidate_process_authorization =
      has_candidate_process_marker &&
      std::string_view(candidate_process) == "1";
  const bool has_receipt = receipt != nullptr && receipt[0] != '\0';
  if (!has_profile) {
    if (has_canary_marker || has_candidate_process_marker || has_receipt) {
      return Failure("host ABI authorization was set without a profile file");
    }
    return {};
  }
  if (has_canary_marker != candidate_canary ||
      has_candidate_process_marker != candidate_process_authorization) {
    return Failure("host ABI canary markers must use the exact value 1");
  }
  if (candidate_canary == has_receipt ||
      candidate_canary != candidate_process_authorization) {
    return Failure(
        "external host ABI profile requires exactly one authorization mode");
  }
  ExternalHostAbiProfileRequest request;
  request.profile_file = profile_file;
  request.payload_path = payload_path;
  request.compatibility_manifest_path = compatibility_manifest_path;
  request.expected_build_id = expected_build_id;
  request.approval_receipt_path = has_receipt ? receipt : "";
  request.candidate_canary = candidate_canary;
  request.candidate_process_authorization = candidate_process_authorization;
  request.explicit_unverified_authorization = explicit_unverified_authorization;
  return LoadExternalHostAbiProfile(request);
}

void SetHostAbiProfileHashingFaultForTesting(bool enabled) noexcept {
  mocktail_rust_host_abi_set_hashing_fault_for_testing(enabled);
}

}  // namespace mocktail::compat
