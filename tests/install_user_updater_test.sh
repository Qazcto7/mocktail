#!/usr/bin/env bash
# Copyright 2026 Mocktail Project Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

readonly installer="${1:?user updater installer is required}"
readonly project_root="${2:?project root is required}"
test_root="$(mktemp -d)"
trap 'rm -rf -- "${test_root}"' EXIT

mkdir -p "${test_root}/bin" "${test_root}/home"
canary="${test_root}/mocktail"
printf '#!/usr/bin/env bash\nexit 0\n' >"${canary}"
chmod 0755 "${canary}"
cat >"${test_root}/bin/systemctl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"${SYSTEMCTL_CALLS:?}"
EOF
chmod 0755 "${test_root}/bin/systemctl"

export HOME="${test_root}/home"
export XDG_CONFIG_HOME="${test_root}/config"
export MOCKTAIL_UPDATE_CANARY_BIN="${canary}"
export SYSTEMCTL_CALLS="${test_root}/systemctl-calls"
export PATH="${test_root}/bin:${PATH}"
"${installer}" >/dev/null

readonly config_root="${XDG_CONFIG_HOME}/mocktail"
readonly unit_root="${XDG_CONFIG_HOME}/systemd/user"
[[ -f "${config_root}/config.yaml" ]]
[[ -f "${unit_root}/mocktail-update.service" ]]
[[ -f "${unit_root}/mocktail-update.timer" ]]
grep -Fxq "MOCKTAIL_PROJECT_ROOT=${project_root}" \
  "${config_root}/updater.env"
grep -Fxq "MOCKTAIL_UPDATE_CANARY_BIN=${canary}" \
  "${config_root}/updater.env"
grep -Fq \
  'auto_update_roblox.sh --skip-build --no-launch --scheduled' \
  "${unit_root}/mocktail-update.service"
grep -Fxq -- '--user daemon-reload' "${SYSTEMCTL_CALLS}"
grep -Fxq -- '--user enable --now mocktail-update.timer' "${SYSTEMCTL_CALLS}"
grep -Fxq -- '--user list-timers mocktail-update.timer --no-pager' \
  "${SYSTEMCTL_CALLS}"

# A source-tree timer must follow the runtime built from that same tree. An
# older system installation may coexist, but it cannot safely approve or
# reject payloads on behalf of the development binary.
fixture_project="${test_root}/fixture-project"
mkdir -p "${fixture_project}/scripts" "${fixture_project}/build" \
  "${fixture_project}/config/systemd"
cp -- "${installer}" "${fixture_project}/scripts/install_user_updater.sh"
cp -- "${project_root}/config/systemd/mocktail-update.service" \
  "${fixture_project}/config/systemd/mocktail-update.service"
cp -- "${project_root}/config/systemd/mocktail-update.timer" \
  "${fixture_project}/config/systemd/mocktail-update.timer"
cp -- "${project_root}/config/mocktail.example.yaml" \
  "${fixture_project}/config/mocktail.example.yaml"
printf '#!/usr/bin/env bash\nexit 0\n' > \
  "${fixture_project}/build/mocktail"
chmod 0755 "${fixture_project}/build/mocktail"
unset MOCKTAIL_UPDATE_CANARY_BIN
"${fixture_project}/scripts/install_user_updater.sh" >/dev/null
grep -Fxq \
  "MOCKTAIL_UPDATE_CANARY_BIN=${fixture_project}/build/mocktail" \
  "${config_root}/updater.env"

echo "user updater installation checks passed"
