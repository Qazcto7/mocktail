#!/usr/bin/env bash
# Copyright 2026 Mocktail Project Authors
# Licensed under the Apache License, Version 2.0.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROJECT_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
CONFIG_ROOT="${XDG_CONFIG_HOME:-${HOME}/.config}/mocktail"
UNIT_ROOT="${XDG_CONFIG_HOME:-${HOME}/.config}/systemd/user"
CANARY_BINARY="${MOCKTAIL_UPDATE_CANARY_BIN:-}"
UPDATE_HELPER="${MOCKTAIL_UPDATE_HELPER:-}"

if [[ -z "${CANARY_BINARY}" ]]; then
  for candidate in "${PROJECT_ROOT}/build/mocktail" \
      /usr/lib/mocktail/mocktail; do
    if [[ -f "${candidate}" && ! -L "${candidate}" && -x "${candidate}" ]]; then
      CANARY_BINARY="${candidate}"
      break
    fi
  done
fi
if [[ -z "${UPDATE_HELPER}" ]]; then
  for candidate in "${PROJECT_ROOT}/build/mocktail_updater" \
      /usr/lib/mocktail/mocktail_updater; do
    if [[ -f "${candidate}" && ! -L "${candidate}" && -x "${candidate}" ]]; then
      UPDATE_HELPER="${candidate}"
      break
    fi
  done
fi
[[ "${CANARY_BINARY}" == /* && -f "${CANARY_BINARY}" &&
   ! -L "${CANARY_BINARY}" && -x "${CANARY_BINARY}" ]] || {
  echo "build or install Mocktail before enabling its update timer" >&2
  exit 1
}
[[ "${UPDATE_HELPER}" == /* && -f "${UPDATE_HELPER}" &&
   ! -L "${UPDATE_HELPER}" && -x "${UPDATE_HELPER}" ]] || {
  echo "build or install the native Mocktail updater before enabling its timer" >&2
  exit 1
}

[[ "${PROJECT_ROOT}" != *$'\n'* && "${PROJECT_ROOT}" != *'%'* ]] || {
  echo "unsupported project path for systemd environment file" >&2
  exit 1
}
mkdir -p "${CONFIG_ROOT}" "${UNIT_ROOT}"
install -m 0644 "${PROJECT_ROOT}/config/systemd/mocktail-update.service" \
  "${UNIT_ROOT}/mocktail-update.service"
install -m 0644 "${PROJECT_ROOT}/config/systemd/mocktail-update.timer" \
  "${UNIT_ROOT}/mocktail-update.timer"
if [[ ! -e "${CONFIG_ROOT}/config.yaml" ]]; then
  install -m 0600 "${PROJECT_ROOT}/config/mocktail.example.yaml" \
    "${CONFIG_ROOT}/config.yaml"
fi
temporary="$(mktemp "${CONFIG_ROOT}/.updater.env.XXXXXX")"
trap 'rm -f -- "${temporary}"' EXIT
printf 'MOCKTAIL_UPDATE_HELPER=%q\n' "${UPDATE_HELPER}" > "${temporary}"
printf 'MOCKTAIL_UPDATE_CANARY_BIN=%q\n' "${CANARY_BINARY}" >> "${temporary}"
chmod 0600 "${temporary}"
mv -f -- "${temporary}" "${CONFIG_ROOT}/updater.env"
trap - EXIT

systemctl --user daemon-reload
systemctl --user enable --now mocktail-update.timer
systemctl --user list-timers mocktail-update.timer --no-pager
