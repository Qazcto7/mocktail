#!/usr/bin/env bash
# Copyright 2026 Mocktail Project Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

set -euo pipefail

# The test doubles as a fake native runtime when the fixture selector is set.

EmitNetworkFixture() {
  local join_place=424242
  local loaded_place=424242
  if [[ "${MOCKTAIL_NETWORK_VALIDATOR_FIXTURE}" == "mismatched-join-place" ]]; then
    join_place=999999
  fi
  if [[ "${MOCKTAIL_NETWORK_VALIDATOR_FIXTURE}" == "mismatched-loaded-place" ]]; then
    loaded_place=999999
  fi

  printf '%s\n' \
    '  [auth] typed Roblox identity resolved for production VM' \
    '  [compat] Roblox 9.999.1 Build ID aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa (supported)' \
    '  [compat] legacy binary patches: disabled' \
    '  [compat] signal-recovery handler disabled for this Build ID' \
    '  [compat] native allocator retained; host allocator bridges disabled' \
    '  [engine] nativeAppBridgeV2StartGameWithParam'

  if [[ "${MOCKTAIL_NETWORK_VALIDATOR_FIXTURE}" == "bad-order" ]]; then
    printf '%s\n' \
      '  [window] first Roblox Vulkan frame presented' \
      '  [window] vkQueuePresentKHR #1 window=0x1234'
  fi

  printf '%s\n' \
    '[I/Roblox] [FLog::SingleSurfaceApp] setStage: (stage:UGCGame)'

  if [[ "${MOCKTAIL_NETWORK_VALIDATOR_FIXTURE}" != "legacy-owner" ]]; then
    printf '%s\n' \
      '  [game-session] typed lifecycle startup completed: Running'
  fi

  printf '%s\n' \
    "[I/Roblox] [FLog::Output] ! Joining game 'SENSITIVE-GAME-ID' place ${join_place} at 192.0.2.10:53640" \
    '[I/Roblox] [FLog::GameJoinLoadTime] diagnostic userid=SENSITIVE-USER-ID placeid=424242'

  if [[ "${MOCKTAIL_NETWORK_VALIDATOR_FIXTURE}" != "bad-order" &&
        "${MOCKTAIL_NETWORK_VALIDATOR_FIXTURE}" != "late-graphics" ]]; then
    printf '%s\n' \
      '  [window] first Roblox Vulkan frame presented' \
      '  [window] vkQueuePresentKHR #1 window=0x1234'
  fi

  printf '%s\n' \
    '[I/Roblox] [DFLog::NetworkClient] Connection accepted from 192.0.2.10|53640'

  if [[ "${MOCKTAIL_NETWORK_VALIDATOR_FIXTURE}" == "bad-network-order" ]]; then
    printf '%s\n' \
      '[I/Roblox] [FLog::Network] Time taken to initialize schema = 12.5 ms' \
      '[I/Roblox] [FLog::Network] Replicator created for player 192.0.2.10|53640'
  else
    printf '%s\n' \
      '[I/Roblox] [FLog::Network] Replicator created for player 192.0.2.10|53640' \
      '[I/Roblox] [FLog::Network] Time taken to initialize schema = 12.5 ms'
  fi

  if [[ "${MOCKTAIL_NETWORK_VALIDATOR_FIXTURE}" == "terminal-failure" ]]; then
    printf '%s\n' '[I/Roblox] ClientJoinFail'
  fi
  if [[ "${MOCKTAIL_NETWORK_VALIDATOR_FIXTURE}" == "credential-leak" ]]; then
    printf '%s\n' '.ROBLOSECURITY=SENSITIVE-COOKIE-VALUE'
  fi
  if [[ "${MOCKTAIL_NETWORK_VALIDATOR_FIXTURE}" == "value-only-credential-leak" ]]; then
    printf '%s\n' \
      '_|WARNING:-DO-NOT-SHARE-THIS.SYNTHETIC-CREDENTIAL-CANARY'
  fi

  if [[ "${MOCKTAIL_NETWORK_VALIDATOR_FIXTURE}" == "wrong-loaded-contract" ]]; then
    printf '%s\n' \
      "[D/rbx.jni] onGameLoaded() SessionReporterState_GameLoaded placeId=${loaded_place}"
  else
    printf '%s\n' \
      "[D/rbx.jni] onGameLoaded() SessionReporterState_GameLoaded placeId:${loaded_place}"
  fi

  if [[ "${MOCKTAIL_NETWORK_VALIDATOR_FIXTURE}" == "attestation-timeout" ]]; then
    printf '%s\n' \
      '[I/Roblox] [DFLog::NetworkClient] Disconnect reason received: 319'
  fi
  if [[ "${MOCKTAIL_NETWORK_VALIDATOR_FIXTURE}" == "attestation-rejection" ]]; then
    printf '%s\n' \
      '[I/Roblox] Roblox was not able to verify the integrity of the game due to a network issue. Please reconnect.'
  fi

  if [[ "${MOCKTAIL_NETWORK_VALIDATOR_FIXTURE}" == "late-graphics" ]]; then
    printf '%s\n' \
      '  [window] first Roblox Vulkan frame presented' \
      '  [window] vkQueuePresentKHR #1 window=0x1234'
  fi

  printf '%s\n' \
    '[I/Roblox] [FLog::Graphics] RenderView destroyed[1]' \
    '[I/Roblox] [FLog::Graphics] Vulkan: Saved pipeline cache' \
    '  [vulkan] SDL WSI adapter shut down' \
    '[I/Roblox] [DFLog::NetworkClient] Client:Disconnect' \
    '[I/Roblox] [FLog::Network] Time to disconnect replication data: 0.5' \
    '[I/Roblox] [FLog::Network] NetworkClient:Remove' \
    '[I/Roblox] [DFLog::MegaReplicatorLogDisconnectCleanUpLog] Destroying MegaReplicator.' \
    '[I/Roblox] [FLog::UgcExperienceController] UgcExperienceController: finalized' \
    '[I/Roblox] [FLog::Network] Replicator destroyed: 0x1234' \
    '[I/Roblox] [FLog::SingleSurfaceApp] setStage: (stage:None)' \
    '  [main] Roblox lifecycle shutdown: Stopped (completed)'
}

if [[ -n "${MOCKTAIL_NETWORK_VALIDATOR_FIXTURE:-}" ]]; then
  EmitNetworkFixture
  exit 0
fi

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 /path/to/real_bringup_smoke.sh" >&2
  exit 2
fi

SMOKE_SCRIPT="$1"
TEST_SCRIPT="$(realpath "$0")"
TEST_ROOT="$(mktemp -d)"
trap 'rm -rf "${TEST_ROOT}"' EXIT

COOKIE_FILE="${TEST_ROOT}/cookie"
printf '%s\n' 'synthetic-cookie-not-a-credential' >"${COOKIE_FILE}"
chmod 600 "${COOKIE_FILE}"

RunFixture() {
  local fixture="$1"
  local expected_result="$2"
  local run_root="${TEST_ROOT}/${fixture}"
  local output="${run_root}/validator-output.log"
  mkdir -p "${run_root}/logs"

  set +e
  env -i \
    PATH="${PATH}" \
    HOME="${HOME}" \
    MOCKTAIL_NETWORK_VALIDATOR_FIXTURE="${fixture}" \
    MOCKTAIL_BIN="${TEST_SCRIPT}" \
    MOCKTAIL_LOG_DIR="${run_root}/logs" \
    MOCKTAIL_DISABLE_SUPPORT_BUNDLE=1 \
    MOCKTAIL_SKIP_UPDATE_CHECK=1 \
    MOCKTAIL_COOKIE_FILE="${COOKIE_FILE}" \
    MOCKTAIL_PLACE_ID=424242 \
    MOCKTAIL_AUTO_EXIT_AFTER_PRESENT_MS=20000 \
    MOCKTAIL_SMOKE_TIMEOUT_S=90 \
    bash "${SMOKE_SCRIPT}" NETWORK >"${output}" 2>&1
  local result=$?
  set -e

  if [[ "${expected_result}" == "pass" && "${result}" -ne 0 ]]; then
    echo "NETWORK validator rejected the ordered synthetic fixture" >&2
    return 1
  fi
  if [[ "${expected_result}" == "fail" && "${result}" -eq 0 ]]; then
    echo "NETWORK validator accepted an invalid synthetic fixture" >&2
    return 1
  fi

  local raw_log
  raw_log="$(find "${run_root}/logs" -maxdepth 1 -type f \
    -name 'tierNETWORK_*.log' -print -quit)"
  if [[ -z "${raw_log}" || "$(stat -c '%a' -- "${raw_log}")" != "600" ]]; then
    echo "NETWORK validator did not retain its raw log as mode 0600" >&2
    return 1
  fi
  if ! rg --fixed-strings --quiet 'SENSITIVE-GAME-ID' "${raw_log}"; then
    echo "NETWORK synthetic fixture did not exercise sensitive raw output" >&2
    return 1
  fi
  if rg --quiet \
    'SENSITIVE-GAME-ID|SENSITIVE-USER-ID|424242|999999|192\.0\.2\.10|53640|SENSITIVE-COOKIE-VALUE|SYNTHETIC-CREDENTIAL-CANARY' \
    "${output}"; then
    echo "NETWORK validator exposed sensitive native output" >&2
    return 1
  fi
}

RunContractFailure() {
  local label="$1"
  local forbidden_output="$2"
  shift 2
  local run_root="${TEST_ROOT}/contract-${label}"
  local output="${run_root}/validator-output.log"
  mkdir -p "${run_root}/logs"

  set +e
  env -i \
    PATH="${PATH}" \
    HOME="${HOME}" \
    MOCKTAIL_NETWORK_VALIDATOR_FIXTURE=good \
    MOCKTAIL_BIN="${TEST_SCRIPT}" \
    MOCKTAIL_LOG_DIR="${run_root}/logs" \
    MOCKTAIL_DISABLE_SUPPORT_BUNDLE=1 \
    MOCKTAIL_SKIP_UPDATE_CHECK=1 \
    MOCKTAIL_COOKIE_FILE="${COOKIE_FILE}" \
    MOCKTAIL_PLACE_ID=424242 \
    MOCKTAIL_AUTO_EXIT_AFTER_PRESENT_MS=20000 \
    MOCKTAIL_SMOKE_TIMEOUT_S=90 \
    "$@" \
    bash "${SMOKE_SCRIPT}" NETWORK >"${output}" 2>&1
  local result=$?
  set -e
  if [[ "${result}" -eq 0 ]]; then
    echo "NETWORK validator accepted an invalid environment contract" >&2
    return 1
  fi
  if [[ -n "${forbidden_output}" ]] &&
     rg --fixed-strings --quiet "${forbidden_output}" "${output}"; then
    echo "NETWORK contract failure exposed a protected value" >&2
    return 1
  fi
}

RunFixture good pass
RunFixture late-graphics pass
RunFixture bad-order fail
RunFixture bad-network-order fail
RunFixture legacy-owner fail
RunFixture mismatched-join-place fail
RunFixture mismatched-loaded-place fail
RunFixture wrong-loaded-contract fail
RunFixture terminal-failure fail
RunFixture attestation-timeout fail
RunFixture attestation-rejection fail
RunFixture credential-leak fail
RunFixture value-only-credential-leak fail
RunContractFailure zero-place '' MOCKTAIL_PLACE_ID=0
RunContractFailure short-present '' MOCKTAIL_AUTO_EXIT_AFTER_PRESENT_MS=19999
RunContractFailure short-timeout '' MOCKTAIL_SMOKE_TIMEOUT_S=89
RunContractFailure special-selector 'SENSITIVE-ACCESS-CODE' \
  MOCKTAIL_GAME_ACCESS_CODE=SENSITIVE-ACCESS-CODE

echo "NETWORK readiness validator synthetic tests passed"
