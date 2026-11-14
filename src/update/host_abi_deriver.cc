#include "update/host_abi_deriver.h"

#include <capstone.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "mocktail/mocktail_rust.h"

namespace mocktail::update {

namespace {

MocktailRustStrSlice ToSlice(std::string_view value) noexcept {
  return MocktailRustStrSlice{value.data(), value.size()};
}

MocktailRustStrSlice CStrToSlice(const char* value) noexcept {
  if (value == nullptr) {
    return MocktailRustStrSlice{nullptr, 0};
  }
  return ToSlice(std::string_view(value));
}

std::string FromSlice(MocktailRustStrSlice slice) {
  if (slice.ptr == nullptr || slice.len == 0) {
    return {};
  }
  return std::string(slice.ptr, slice.len);
}

struct CapstoneDisasmState {
  csh handle = 0;

  ~CapstoneDisasmState() {
    if (handle != 0) {
      cs_close(&handle);
    }
  }
};

int32_t OpenX86Callback(void* ctx) {
  auto* state = static_cast<CapstoneDisasmState*>(ctx);
  if (state == nullptr) {
    return -1;
  }
  if (state->handle != 0) {
    return 0;
  }
  int major = 0;
  int minor = 0;
  cs_version(&major, &minor);
  if (major != 5 || cs_open(CS_ARCH_X86, CS_MODE_64, &state->handle) != CS_ERR_OK ||
      cs_option(state->handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) {
    if (state->handle != 0) {
      cs_close(&state->handle);
      state->handle = 0;
    }
    return -1;
  }
  return 0;
}

int32_t DecodeX86Callback(void* disasm_ctx, uint64_t rva,
                          const uint8_t* bytes_ptr, size_t bytes_len,
                          size_t count, MocktailDeriverOnInsnFn on_insn,
                          void* recv_ctx) {
  auto* state = static_cast<CapstoneDisasmState*>(disasm_ctx);
  if (state == nullptr || state->handle == 0) {
    return 1;
  }
  if (on_insn == nullptr) {
    return 2;
  }

  cs_insn* decoded = nullptr;
  const std::size_t decoded_count =
      cs_disasm(state->handle, bytes_ptr, bytes_len, rva, count, &decoded);
  if (decoded_count != count || decoded == nullptr) {
    if (decoded != nullptr) {
      cs_free(decoded, decoded_count);
    }
    return 2;
  }

  std::vector<MocktailRustDecodedOperandView> operands;
  for (std::size_t index = 0; index < count; ++index) {
    const cs_insn& source = decoded[index];
    if (source.size == 0 || source.detail == nullptr) {
      cs_free(decoded, decoded_count);
      return 3;
    }

    const cs_x86& x86 = source.detail->x86;
    operands.clear();
    operands.reserve(x86.op_count);
    for (std::uint8_t op_idx = 0; op_idx < x86.op_count; ++op_idx) {
      const cs_x86_op& src_op = x86.operands[op_idx];
      MocktailRustDecodedOperandView op{};
      op.size = src_op.size;
      if (src_op.type == X86_OP_REG) {
        op.kind = 0;
        op.reg_name = CStrToSlice(cs_reg_name(state->handle, src_op.reg));
      } else if (src_op.type == X86_OP_IMM) {
        op.kind = 1;
        op.value = src_op.imm;
      } else if (src_op.type == X86_OP_MEM) {
        op.kind = 2;
        const x86_op_mem& mem = src_op.mem;
        op.seg_name = CStrToSlice(cs_reg_name(state->handle, mem.segment));
        op.base_name = CStrToSlice(cs_reg_name(state->handle, mem.base));
        op.index_name = CStrToSlice(cs_reg_name(state->handle, mem.index));
        op.scale = mem.scale;
        op.value = mem.disp;
        op.rip_relative = mem.base == X86_REG_RIP;
      } else {
        cs_free(decoded, decoded_count);
        return 4;
      }
      operands.push_back(op);
    }

    MocktailRustDecodedInsnView insn_view{};
    insn_view.address = source.address;
    insn_view.size = source.size;
    insn_view.imm_offset = x86.encoding.imm_offset;
    insn_view.imm_size = x86.encoding.imm_size;
    insn_view.disp_offset = x86.encoding.disp_offset;
    insn_view.disp_size = x86.encoding.disp_size;
    insn_view.control_flow =
        cs_insn_group(state->handle, &source, CS_GRP_CALL) ||
        cs_insn_group(state->handle, &source, CS_GRP_JUMP);
    insn_view.returns = cs_insn_group(state->handle, &source, CS_GRP_RET);
    insn_view.mnemonic = CStrToSlice(source.mnemonic);
    insn_view.operands_ptr = operands.empty() ? nullptr : operands.data();
    insn_view.operand_count = operands.size();
    if (!on_insn(recv_ctx, &insn_view)) {
      cs_free(decoded, decoded_count);
      return 2;
    }
  }

  cs_free(decoded, decoded_count);
  return 0;
}

void OnSidecarIdentity(void* ctx, MocktailRustStrSlice elf_build_id,
                       MocktailRustStrSlice payload_id) {
  auto* out = static_cast<HostAbiSidecarIdentity*>(ctx);
  if (out == nullptr) {
    return;
  }
  out->elf_build_id = FromSlice(elf_build_id);
  out->payload_id = FromSlice(payload_id);
}

void OnSidecarError(void* ctx, MocktailRustStrSlice error) {
  auto* out = static_cast<HostAbiSidecarIdentity*>(ctx);
  if (out == nullptr) {
    return;
  }
  out->error = FromSlice(error);
}

void OnDeriveResult(void* ctx, MocktailRustStrSlice profile_path,
                    MocktailRustStrSlice compatibility_path) {
  auto* out = static_cast<HostAbiDerivationResult*>(ctx);
  if (out == nullptr) {
    return;
  }
  out->profile = FromSlice(profile_path);
  out->compatibility_manifest = FromSlice(compatibility_path);
}

void OnDeriveError(void* ctx, MocktailRustStrSlice error) {
  auto* out = static_cast<HostAbiDerivationResult*>(ctx);
  if (out == nullptr) {
    return;
  }
  out->error = FromSlice(error);
}

}  // namespace

HostAbiSidecarIdentity ReadHostAbiSidecarIdentity(
    const std::filesystem::path& sidecar) {
  HostAbiSidecarIdentity identity;
  const std::string sidecar_path = sidecar.string();
  const int32_t rc = mocktail_rust_deriver_read_sidecar_identity_file(
      ToSlice(sidecar_path), &OnSidecarIdentity, &OnSidecarError, &identity);
  if (rc != 0 && identity.error.empty()) {
    identity.error = "cannot read HostAbi sidecar identity";
  }
  return identity;
}

HostAbiDerivationResult DeriveHostAbiProfile(
    const HostAbiDerivationOptions& options) {
  const std::string ref_lib = options.reference_library.string();
  const std::string ref_profile = options.reference_profile.string();
  const std::string cand_dir = options.candidate_payload_directory.string();
  const std::string out_dir = options.output_directory.string();

  std::vector<std::string> manifest_strings;
  manifest_strings.reserve(options.reference_compatibility_manifests.size());
  for (const auto& path : options.reference_compatibility_manifests) {
    manifest_strings.push_back(path.string());
  }
  std::vector<MocktailRustStrSlice> manifest_slices;
  manifest_slices.reserve(manifest_strings.size());
  for (const auto& str : manifest_strings) {
    manifest_slices.push_back(ToSlice(str));
  }

  const MocktailRustDeriverOptionsView opts_view{
      ToSlice(ref_lib),
      ToSlice(ref_profile),
      manifest_slices.empty() ? nullptr : manifest_slices.data(),
      manifest_slices.size(),
      ToSlice(cand_dir),
      ToSlice(out_dir),
  };

  CapstoneDisasmState disasm_state;
  HostAbiDerivationResult result;
  const int32_t rc = mocktail_rust_deriver_derive_host_abi_profile(
      &opts_view, &OpenX86Callback, &DecodeX86Callback, &disasm_state,
      &OnDeriveResult, &OnDeriveError, &result);
  if (rc != 0 && result.error.empty()) {
    result.error = "HostAbi profile derivation failed";
  }
  return result;
}

}  // namespace mocktail::update
