#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VALIDATOR="${ROOT}/scripts/input_readiness_gate.sh"
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

write_fixture() {
  local path="$1"
  local variant="$2"
  {
    echo "  [input] typed production input ready: mouse=1 touch=1 keyboard=1 text=0"
    if [[ "${variant}" == "bad-order" ]]; then
      echo "  [input] SDL readiness pointer sequence queued"
    fi
    echo "  [window] first Roblox Vulkan frame presented"
    if [[ "${variant}" != "bad-order" ]]; then
      echo "  [input] SDL readiness pointer sequence queued"
    fi
    if [[ "${variant}" != "missing-native" ]]; then
      echo "  [input] first mouse button reached Roblox native input"
    fi
    if [[ "${variant}" != "missing-touch" ]]; then
      echo "  [input] first touch event reached Roblox native input"
    fi
    if [[ "${variant}" == "jni-error" ]]; then
      echo "nativePassMouseButton raised a JNI exception"
    elif [[ "${variant}" == "touch-jni-error" ]]; then
      echo "nativePassInput raised a JNI exception"
    fi
    echo "  [main] Roblox lifecycle shutdown: Stopped"
  } >"${path}"
}

good="${TMP}/good.log"
write_fixture "${good}" good
"${VALIDATOR}" validate "${good}" >/dev/null

for variant in bad-order missing-native missing-touch jni-error touch-jni-error; do
  fixture="${TMP}/${variant}.log"
  write_fixture "${fixture}" "${variant}"
  if "${VALIDATOR}" validate "${fixture}" >/dev/null 2>&1; then
    echo "INPUT validator accepted invalid fixture: ${variant}" >&2
    exit 1
  fi
done

echo "INPUT readiness validator synthetic tests passed"
