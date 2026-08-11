#!/usr/bin/env bash
# Copyright 2026 Mocktail Project Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

readonly main_source="${1:?main source is required}"

LineOf() {
  local pattern="$1"
  local line
  line="$(rg -n -m1 --fixed-strings "${pattern}" "${main_source}" | cut -d: -f1)"
  [[ -n "${line}" ]] || {
    printf 'missing startup marker: %s\n' "${pattern}" >&2
    exit 1
  }
  printf '%s\n' "${line}"
}

readonly normalize_line="$(LineOf 'BuildCommandLineReexecArguments')"
readonly scrub_line="$(LineOf 'ScrubCommandLineLaunchArguments')"
readonly canary_policy_line="$(LineOf 'const bool isolated_canary =')"
readonly lock_line="$(LineOf 'SingleInstanceLock::AcquireForLaunch')"
readonly reexec_line="$(LineOf 'MaybeReexecWithCgroupMemoryLimit')"
readonly preflight_line="$(LineOf 'RunPayloadUpdatePreflight')"
readonly broker_canary_guard_line="$(LineOf '!isolated_canary) {')"
readonly broker_line="$(LineOf 'ExternalLaunchBroker::StartOwnerAfterLockAcquired')"

if ! (( normalize_line < scrub_line &&
        scrub_line < canary_policy_line &&
        canary_policy_line < lock_line &&
        lock_line < reexec_line &&
        reexec_line < preflight_line &&
        preflight_line < broker_canary_guard_line &&
        broker_canary_guard_line < broker_line )); then
  printf '%s\n' \
    'external-launch startup must normalize and scrub browser input, acquire' \
    'the lock, cross every exec boundary, skip isolated canaries, and only' \
    'then ACK launch requests' \
    >&2
  exit 1
fi

printf 'External launch lifecycle ordering checks passed\n'
