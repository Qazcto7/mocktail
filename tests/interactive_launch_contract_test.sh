#!/usr/bin/env bash

# Copyright 2026 Mocktail Project Authors
# Licensed under the Apache License, Version 2.0.

set -euo pipefail

if [[ "${MOCKTAIL_LAUNCH_CONTRACT_FIXTURE:-0}" == "1" ]]; then
  parent_command="$(<"/proc/${PPID}/comm")"
  printf 'fixture_parent_command=%s\n' "${parent_command}"
  printf 'fixture_present_timer_ms=%s\n' \
    "${MOCKTAIL_AUTO_EXIT_AFTER_PRESENT_MS:-unset}"
  printf '%s\n' \
    '[compat] legacy binary patches: disabled' \
    '[compat] signal-recovery handler disabled' \
    '[compat] native allocator retained; host allocator bridges disabled' \
    '[window] vkQueuePresentKHR #1 window=0x1234' \
    '[window] first Roblox Vulkan frame presented' \
    '[vulkan] SDL WSI adapter shut down' \
    '[main] Roblox lifecycle shutdown: Stopped'
  exit 0
fi

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 /path/to/real_bringup_smoke.sh" >&2
  exit 2
fi

readonly smoke_script="$1"
readonly test_script="$(realpath "$0")"
readonly test_root="$(mktemp -d)"
trap 'rm -rf "${test_root}"' EXIT

RunCase() {
  local -r name="$1"
  local -r present_timer_ms="$2"
  local -r expected_timeout_parent="$3"
  local -r case_root="${test_root}/${name}"
  local -r output="${case_root}/output.log"
  mkdir -p "${case_root}/logs"

  if ! env -i \
    PATH="${PATH}" \
    HOME="${HOME}" \
    MOCKTAIL_LAUNCH_CONTRACT_FIXTURE=1 \
    MOCKTAIL_BIN="${test_script}" \
    MOCKTAIL_LOG_DIR="${case_root}/logs" \
    MOCKTAIL_SKIP_UPDATE_CHECK=1 \
    MOCKTAIL_AUTO_EXIT_AFTER_PRESENT_MS="${present_timer_ms}" \
    MOCKTAIL_SMOKE_TIMEOUT_S=5 \
    bash "${smoke_script}" C >"${output}" 2>&1; then
    echo "${name} Tier C launch contract was rejected" >&2
    return 1
  fi

  if ! rg --fixed-strings --quiet \
    "fixture_present_timer_ms=${present_timer_ms}" "${output}"; then
    echo "${name} Tier C launch lost its present-timer contract" >&2
    return 1
  fi

  if [[ "${expected_timeout_parent}" == "yes" ]]; then
    if ! rg --fixed-strings --quiet 'fixture_parent_command=timeout' \
      "${output}"; then
      echo "${name} Tier C smoke launch lost its watchdog" >&2
      return 1
    fi
  elif rg --fixed-strings --quiet 'fixture_parent_command=timeout' \
    "${output}"; then
    echo "${name} Tier C interactive launch retained a hidden watchdog" >&2
    return 1
  fi
}

RunCase interactive 0 no
RunCase smoke 3000 yes

echo "interactive and smoke launch lifetime contracts passed"
