#include "update/update_coordinator.h"

#include <sys/socket.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "mocktail/mocktail_rust.h"
#include "update/apk_bundle.h"
#include "update/apk_provider.h"
#include "update/apkpure_provider.h"
#include "update/host_abi_deriver.h"
#include "update/payload_store.h"
#include "update/pinned_apk_provider.h"

namespace mocktail::update {
namespace {

MocktailRustStrSlice ToSlice(std::string_view value) {
  return {value.data(), value.size()};
}

std::string_view ToStringView(MocktailRustStrSlice slice) {
  if (slice.ptr == nullptr || slice.len == 0) {
    return {};
  }
  return {slice.ptr, slice.len};
}

std::filesystem::path ToPath(MocktailRustStrSlice slice) {
  const std::string_view sv = ToStringView(slice);
  return std::filesystem::path(sv);
}

MocktailRustSupportedProfileView ToProfileView(
    const SupportedPayloadProfile& profile) {
  MocktailRustSupportedProfileView view{};
  view.version_name = ToSlice(profile.version_name);
  view.version_code = profile.version_code;
  view.elf_build_id = ToSlice(profile.elf_build_id);
  return view;
}

std::vector<MocktailRustSupportedProfileView> ToProfileViews(
    const std::vector<SupportedPayloadProfile>& profiles) {
  std::vector<MocktailRustSupportedProfileView> views;
  views.reserve(profiles.size());
  for (const SupportedPayloadProfile& profile : profiles) {
    views.push_back(ToProfileView(profile));
  }
  return views;
}

struct StoreResultStrings {
  bool valid = false;
  std::string payload_id;
  std::string payload_directory;
  std::string host_abi_profile;
  std::string compatibility_manifest;
  std::string version_name;
  std::uint64_t version_code = 0;
  std::string build_id;
  std::string error;

  explicit StoreResultStrings(const PayloadStoreResult& r)
      : valid(static_cast<bool>(r)),
        payload_id(r.payload_id),
        payload_directory(r.payload_directory.string()),
        host_abi_profile(r.host_abi_profile.string()),
        compatibility_manifest(r.compatibility_manifest.string()),
        version_name(r.version_name),
        version_code(r.version_code),
        build_id(r.build_id),
        error(r.error) {}

  MocktailRustCoordinatorStoreResultView view() const {
    MocktailRustCoordinatorStoreResultView v{};
    v.valid = valid;
    v.payload_id = ToSlice(payload_id);
    v.payload_directory = ToSlice(payload_directory);
    v.host_abi_profile = ToSlice(host_abi_profile);
    v.compatibility_manifest = ToSlice(compatibility_manifest);
    v.version_name = ToSlice(version_name);
    v.version_code = version_code;
    v.build_id = ToSlice(build_id);
    v.error = ToSlice(error);
    return v;
  }
};

void EmitStoreResult(
    const PayloadStoreResult& result, void* receiver_ctx,
    void (*on_result)(void*, const MocktailRustCoordinatorStoreResultView*)) {
  if (on_result == nullptr) return;
  const StoreResultStrings backing(result);
  const MocktailRustCoordinatorStoreResultView view = backing.view();
  on_result(receiver_ctx, &view);
}

void ProgressPacket(int descriptor, std::string_view message) {
  if (descriptor < 0) return;
  const std::string packet = "P" + std::string(message);
  (void)send(descriptor, packet.data(), packet.size(), MSG_NOSIGNAL);
}

ProviderChain BuildProviderChain(const UpdatePaths& paths) {
  ProviderChain chain;
  if (!paths.download_sources_manifest.empty()) {
    chain.Add(
        std::make_unique<PinnedApkProvider>(paths.download_sources_manifest));
  }
  chain.Add(std::make_unique<ApkPureProvider>());
  return chain;
}

struct CoordinatorContext {
  const UpdatePaths& paths;
  PayloadStore store;
  ProviderChain default_providers;
  const ApkProvider& provider;

  CoordinatorContext(const UpdatePaths& update_paths,
                     const ApkProvider* source)
      : paths(update_paths),
        store(update_paths.data_root, update_paths.compatibility_manifest,
              update_paths.runtime_binary),
        default_providers(BuildProviderChain(update_paths)),
        provider(source != nullptr ? *source : default_providers) {}
};

void OpCheckLatest(void* ctx, void* receiver_ctx,
                   void (*on_result)(void*, MocktailRustStrSlice, uint64_t,
                                     MocktailRustStrSlice)) {
  auto* context = static_cast<CoordinatorContext*>(ctx);
  const ProviderVersion latest = context->provider.CheckLatest();
  if (on_result != nullptr) {
    on_result(receiver_ctx, ToSlice(latest.version_name), latest.version_code,
              ToSlice(latest.error));
  }
}

void OpDownloadAndPrepare(
    void* ctx, MocktailRustStrSlice version_name, uint64_t version_code,
    bool has_exact_build_id, MocktailRustStrSlice exact_build_id,
    MocktailRustStrSlice download_directory,
    MocktailRustStrSlice prepare_prefix,
    MocktailRustStrSlice signing_trust_manifest, int32_t progress_fd,
    void* receiver_ctx,
    void (*on_result)(void*, MocktailRustStrSlice, MocktailRustStrSlice)) {
  auto* context = static_cast<CoordinatorContext*>(ctx);
  ExpectedPayloadIdentity identity;
  identity.version_name = std::string(ToStringView(version_name));
  identity.version_code = version_code;
  if (has_exact_build_id) {
    identity.exact_build_id = std::string(ToStringView(exact_build_id));
  }

  const std::filesystem::path download_dir = ToPath(download_directory);
  const std::filesystem::path prep_prefix = ToPath(prepare_prefix);
  const std::filesystem::path trust_manifest = ToPath(signing_trust_manifest);

  PreparedPayload prepared;
  std::size_t preparation = 0;
  const ProviderDownloadResult downloaded = context->provider.DownloadVerified(
      ProviderVersion{identity.version_name, identity.version_code, {}},
      download_dir, progress_fd,
      [&](const ProviderDownloadResult& archives) {
        ProgressPacket(progress_fd, "Verifying Roblox...");
        prepared = PreparePayloadFromArchives(
            archives.archives, identity, trust_manifest,
            prep_prefix / ("prepare-" + std::to_string(++preparation)),
            archives.source + "-native");
        return prepared.error;
      });
  if (on_result == nullptr) return;
  if (!downloaded) {
    on_result(receiver_ctx, {}, ToSlice(downloaded.error));
    return;
  }
  const std::string dir_str = prepared.directory.string();
  on_result(receiver_ctx, ToSlice(dir_str), {});
}

void OpDeriveHostAbi(
    void* /*ctx*/, MocktailRustStrSlice reference_library,
    MocktailRustStrSlice reference_profile,
    const MocktailRustStrSlice* reference_manifests,
    size_t reference_manifests_count,
    MocktailRustStrSlice candidate_payload_directory,
    MocktailRustStrSlice output_directory, void* receiver_ctx,
    void (*on_result)(void*, MocktailRustStrSlice, MocktailRustStrSlice,
                      MocktailRustStrSlice)) {
  HostAbiDerivationOptions options;
  options.reference_library = ToPath(reference_library);
  options.reference_profile = ToPath(reference_profile);
  if (reference_manifests != nullptr) {
    options.reference_compatibility_manifests.reserve(
        reference_manifests_count);
    for (std::size_t i = 0; i < reference_manifests_count; ++i) {
      options.reference_compatibility_manifests.push_back(
          ToPath(reference_manifests[i]));
    }
  }
  options.candidate_payload_directory = ToPath(candidate_payload_directory);
  options.output_directory = ToPath(output_directory);

  const HostAbiDerivationResult derived = DeriveHostAbiProfile(options);
  if (on_result == nullptr) return;
  const std::string profile_str = derived.profile.string();
  const std::string compat_str = derived.compatibility_manifest.string();
  on_result(receiver_ctx, ToSlice(profile_str), ToSlice(compat_str),
            ToSlice(derived.error));
}

void OpStoreInspectCurrent(
    void* ctx, void* receiver_ctx,
    void (*on_result)(void*, const MocktailRustCoordinatorStoreResultView*)) {
  auto* context = static_cast<CoordinatorContext*>(ctx);
  EmitStoreResult(context->store.InspectCurrent(), receiver_ctx, on_result);
}

void OpStoreVerifyCurrent(
    void* ctx, void* receiver_ctx,
    void (*on_result)(void*, const MocktailRustCoordinatorStoreResultView*)) {
  auto* context = static_cast<CoordinatorContext*>(ctx);
  EmitStoreResult(context->store.VerifyCurrent(), receiver_ctx, on_result);
}

void OpStoreStage(
    void* ctx, MocktailRustStrSlice prepared_directory, void* receiver_ctx,
    void (*on_result)(void*, const MocktailRustCoordinatorStoreResultView*)) {
  auto* context = static_cast<CoordinatorContext*>(ctx);
  EmitStoreResult(context->store.Stage(ToPath(prepared_directory)),
                  receiver_ctx, on_result);
}

void OpStorePromote(
    void* ctx, MocktailRustStrSlice payload_id, void* receiver_ctx,
    void (*on_result)(void*, const MocktailRustCoordinatorStoreResultView*)) {
  auto* context = static_cast<CoordinatorContext*>(ctx);
  EmitStoreResult(context->store.Promote(ToStringView(payload_id)),
                  receiver_ctx, on_result);
}

void OpStorePromoteProbation(
    void* ctx, MocktailRustStrSlice payload_id,
    MocktailRustStrSlice candidate_profile,
    MocktailRustStrSlice candidate_compatibility,
    MocktailRustStrSlice canary_log_0, MocktailRustStrSlice canary_log_1,
    void* receiver_ctx,
    void (*on_result)(void*, const MocktailRustCoordinatorStoreResultView*)) {
  auto* context = static_cast<CoordinatorContext*>(ctx);
  EmitStoreResult(
      context->store.PromoteProbation(
          ToStringView(payload_id), ToPath(candidate_profile),
          ToPath(candidate_compatibility),
          {ToPath(canary_log_0), ToPath(canary_log_1)}),
      receiver_ctx, on_result);
}

void OpStoreCollectGarbage(
    void* ctx, const MocktailRustStrSlice* keep, size_t keep_count,
    void* receiver_ctx,
    void (*on_result)(void*, size_t, uint64_t, MocktailRustStrSlice)) {
  auto* context = static_cast<CoordinatorContext*>(ctx);
  std::vector<std::string> keep_ids;
  if (keep != nullptr) {
    keep_ids.reserve(keep_count);
    for (std::size_t i = 0; i < keep_count; ++i) {
      keep_ids.emplace_back(ToStringView(keep[i]));
    }
  }
  const PayloadGarbageResult collected =
      context->store.CollectGarbage(keep_ids);
  if (on_result != nullptr) {
    on_result(receiver_ctx, collected.removed.size(),
              static_cast<uint64_t>(collected.freed_bytes),
              ToSlice(collected.error));
  }
}

struct UpdatePathsStrings {
  std::string config_file;
  std::string data_root;
  std::string cache_root;
  std::string state_root;
  std::string compatibility_manifest;
  std::string signing_trust_manifest;
  std::string download_sources_manifest;
  std::string host_abi_reference_profile;
  std::string runtime_binary;
  std::string runtime_launcher;

  explicit UpdatePathsStrings(const UpdatePaths& p)
      : config_file(p.config_file.string()),
        data_root(p.data_root.string()),
        cache_root(p.cache_root.string()),
        state_root(p.state_root.string()),
        compatibility_manifest(p.compatibility_manifest.string()),
        signing_trust_manifest(p.signing_trust_manifest.string()),
        download_sources_manifest(p.download_sources_manifest.string()),
        host_abi_reference_profile(p.host_abi_reference_profile.string()),
        runtime_binary(p.runtime_binary.string()),
        runtime_launcher(p.runtime_launcher.string()) {}

  MocktailRustUpdatePathsView view() const {
    MocktailRustUpdatePathsView v{};
    v.config_file = ToSlice(config_file);
    v.data_root = ToSlice(data_root);
    v.cache_root = ToSlice(cache_root);
    v.state_root = ToSlice(state_root);
    v.compatibility_manifest = ToSlice(compatibility_manifest);
    v.signing_trust_manifest = ToSlice(signing_trust_manifest);
    v.download_sources_manifest = ToSlice(download_sources_manifest);
    v.host_abi_reference_profile = ToSlice(host_abi_reference_profile);
    v.runtime_binary = ToSlice(runtime_binary);
    v.runtime_launcher = ToSlice(runtime_launcher);
    return v;
  }
};

}  // namespace

std::optional<SupportedPayloadProfile> ResolveReferenceProfile(
    const std::filesystem::path& location,
    const std::vector<SupportedPayloadProfile>& profiles,
    std::filesystem::path* sidecar) {
  const std::string loc_str = location.string();
  const std::vector<MocktailRustSupportedProfileView> views =
      ToProfileViews(profiles);
  struct MatchState {
    const std::vector<SupportedPayloadProfile>& profiles;
    std::filesystem::path* sidecar;
    std::optional<SupportedPayloadProfile> selected;
  } state{profiles, sidecar, std::nullopt};

  const bool found = mocktail_rust_resolve_reference_profile(
      ToSlice(loc_str), views.empty() ? nullptr : views.data(), views.size(),
      [](void* ctx, size_t profile_index, MocktailRustStrSlice sidecar_path) {
        auto* s = static_cast<MatchState*>(ctx);
        if (profile_index < s->profiles.size()) {
          s->selected = s->profiles[profile_index];
          if (s->sidecar != nullptr) {
            *s->sidecar = ToPath(sidecar_path);
          }
        }
      },
      &state);
  return found ? state.selected : std::nullopt;
}

std::vector<UpdateCandidatePlan> PlanUpdateCandidates(
    const std::vector<SupportedPayloadProfile>& profiles,
    const SupportedPayloadProfile& preferred, const ProviderVersion* latest,
    const PayloadStoreResult& current, const PayloadStoreResult& installed) {
  const std::vector<MocktailRustSupportedProfileView> profile_views =
      ToProfileViews(profiles);
  const MocktailRustSupportedProfileView preferred_view =
      ToProfileView(preferred);
  const bool has_latest = latest != nullptr && static_cast<bool>(*latest);
  const MocktailRustStrSlice latest_name =
      has_latest ? ToSlice(latest->version_name) : MocktailRustStrSlice{};
  const uint64_t latest_code = has_latest ? latest->version_code : 0;

  const StoreResultStrings current_strings(current);
  const StoreResultStrings installed_strings(installed);
  const MocktailRustCoordinatorStoreResultView current_view =
      current_strings.view();
  const MocktailRustCoordinatorStoreResultView installed_view =
      installed_strings.view();

  std::vector<UpdateCandidatePlan> plans;
  mocktail_rust_plan_update_candidates(
      profile_views.empty() ? nullptr : profile_views.data(),
      profile_views.size(), &preferred_view, has_latest, latest_name,
      latest_code, &current_view, &installed_view,
      [](void* ctx, const MocktailRustUpdateCandidatePlanView* plan) {
        auto* out = static_cast<std::vector<UpdateCandidatePlan>*>(ctx);
        UpdateCandidatePlan item;
        item.identity.version_name =
            std::string(ToStringView(plan->version_name));
        item.identity.version_code = plan->version_code;
        if (plan->has_exact_build_id) {
          item.identity.exact_build_id =
              std::string(ToStringView(plan->exact_build_id));
        }
        item.exact_supported = plan->exact_supported;
        item.reuse_installed = plan->reuse_installed;
        item.origin = std::string(ToStringView(plan->origin));
        out->push_back(std::move(item));
      },
      &plans);
  return plans;
}

UpdateResult RunUpdate(const UpdatePaths& paths, const UpdateRequest& request,
                       const ApkProvider* source) {
  CoordinatorContext context(paths, source);
  const UpdatePathsStrings path_strings(paths);
  const MocktailRustUpdatePathsView paths_view = path_strings.view();

  MocktailRustUpdateRequestView request_view{};
  request_view.startup_preflight = request.startup_preflight;
  request_view.check_latest = request.check_latest;
  request_view.run_canary = request.run_canary;
  request_view.download_only = request.download_only;
  request_view.force_run_latest = request.force_run_latest;
  request_view.canary_graphics_backend =
      static_cast<int32_t>(request.canary_graphics_backend);
  request_view.progress_fd = request.progress_fd;

  MocktailRustUpdateCoordinatorOps ops{};
  ops.ctx = &context;
  ops.provider_check_latest = OpCheckLatest;
  ops.download_and_prepare = OpDownloadAndPrepare;
  ops.derive_host_abi_profile = OpDeriveHostAbi;
  ops.store_inspect_current = OpStoreInspectCurrent;
  ops.store_verify_current = OpStoreVerifyCurrent;
  ops.store_stage = OpStoreStage;
  ops.store_promote = OpStorePromote;
  ops.store_promote_probation = OpStorePromoteProbation;
  ops.store_collect_garbage = OpStoreCollectGarbage;

  UpdateResult result;
  mocktail_rust_run_update(
      &paths_view, &request_view, &ops,
      [](void* ctx, const MocktailRustUpdateResultView* view) {
        auto* out = static_cast<UpdateResult*>(ctx);
        out->changed = view->changed;
        out->stale = view->stale;
        out->payload_id.assign(ToStringView(view->payload_id));
        out->message.assign(ToStringView(view->message));
        out->error.assign(ToStringView(view->error));
        if (view->warnings != nullptr) {
          out->warnings.reserve(view->warning_count);
          for (std::size_t i = 0; i < view->warning_count; ++i) {
            out->warnings.emplace_back(ToStringView(view->warnings[i]));
          }
        }
      },
      &result);
  return result;
}

}  // namespace mocktail::update
