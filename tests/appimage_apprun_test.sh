#!/usr/bin/env bash
# Copyright 2026 Mocktail Project Authors
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

readonly app_run="${1:?usage: appimage_apprun_test.sh /path/to/AppRun}"
app_dir="$(mktemp -d)"
trap 'rm -rf -- "${app_dir}"' EXIT

mkdir -p -- "${app_dir}/usr/share/mocktail-bundle"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'printf "bundle=%s argc=%s first=%s second=%s\\n" "$0" "$#" "$1" "$2"' \
  >"${app_dir}/usr/share/mocktail-bundle/run.sh"
chmod 0755 "${app_dir}/usr/share/mocktail-bundle/run.sh"
ln -s share/mocktail-bundle/run.sh "${app_dir}/usr/mocktail"

readonly launch_uri='roblox://experiences/start?placeId=1&gameInstanceId=a%2Bb'
output="$(APPDIR="${app_dir}" "${app_run}" --launch-uri "${launch_uri}")"
grep -Fq "bundle=${app_dir}/usr/share/mocktail-bundle/run.sh" <<<"${output}"
grep -Fq 'argc=2' <<<"${output}"
grep -Fq 'first=--launch-uri' <<<"${output}"
grep -Fq "second=${launch_uri}" <<<"${output}"

printf 'AppImage AppRun test passed\n'
