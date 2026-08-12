#!/usr/bin/env bash
# Copyright 2026 Mocktail Project Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
umask 022

readonly REPOSITORY="${1:?Flatpak repository path is required}"
readonly BUNDLE="${2:?Flatpak bundle path is required}"
readonly PUBLIC_KEY="${3:?GPG public key path is required}"
readonly OUTPUT="${4:?Pages output path is required}"
readonly BASE_URL="https://mocktail.bigrat.space"

[[ -d "${REPOSITORY}" && ! -L "${REPOSITORY}" ]] || {
  printf 'Flatpak repository is missing or unsafe: %s\n' "${REPOSITORY}" >&2
  exit 1
}
[[ -f "${BUNDLE}" && ! -L "${BUNDLE}" ]] || {
  printf 'Flatpak bundle is missing or unsafe: %s\n' "${BUNDLE}" >&2
  exit 1
}
[[ -s "${PUBLIC_KEY}" && ! -L "${PUBLIC_KEY}" ]] || {
  printf 'Flatpak public key is missing or unsafe: %s\n' "${PUBLIC_KEY}" >&2
  exit 1
}
[[ ! -e "${OUTPUT}" ]] || {
  printf 'Pages output already exists: %s\n' "${OUTPUT}" >&2
  exit 1
}

mkdir -p -- "${OUTPUT}"
cp -a -- "${REPOSITORY}" "${OUTPUT}/repo"
install -m 0644 -- "${BUNDLE}" "${OUTPUT}/Mocktail-x86_64.flatpak"
install -m 0644 -- "${PUBLIC_KEY}" "${OUTPUT}/mocktail-flatpak.gpg"
install -m 0644 -- \
  "$(dirname -- "${BASH_SOURCE[0]}")/../packaging/space.bigrat.mocktail.svg" \
  "${OUTPUT}/mocktail.svg"
install -m 0644 -- \
  "$(dirname -- "${BASH_SOURCE[0]}")/../packaging/discord-join.html" \
  "${OUTPUT}/join.html"

readonly GPG_KEY="$(base64 --wrap=0 "${PUBLIC_KEY}")"

cat >"${OUTPUT}/mocktail.flatpakrepo" <<EOF
[Flatpak Repo]
Title=Mocktail
Url=${BASE_URL}/repo/
Homepage=https://github.com/komaruworld/mocktail
Comment=Development builds of Mocktail
Description=Signed x86_64 Flatpak builds published from Mocktail main
Icon=${BASE_URL}/mocktail.svg
GPGKey=${GPG_KEY}
EOF

cat >"${OUTPUT}/mocktail.flatpakref" <<EOF
[Flatpak Ref]
Title=Mocktail
Name=space.bigrat.mocktail
Branch=stable
Url=${BASE_URL}/repo/
RuntimeRepo=https://dl.flathub.org/repo/flathub.flatpakrepo
Homepage=https://github.com/komaruworld/mocktail
Comment=Play Roblox on Linux
Icon=${BASE_URL}/mocktail.svg
GPGKey=${GPG_KEY}
IsRuntime=false
EOF

cat >"${OUTPUT}/index.html" <<'EOF'
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark light">
  <title>Mocktail for Linux</title>
  <style>
    :root { font: 17px/1.55 system-ui, sans-serif; color-scheme: dark; }
    body { margin: 0; background: #0d1117; color: #e6edf3; }
    main { max-width: 680px; margin: 12vh auto; padding: 32px; }
    img { width: 88px; height: 88px; }
    h1 { font-size: clamp(2.5rem, 8vw, 4.5rem); margin: .2rem 0; }
    p { color: #9da7b3; }
    a.button { display: inline-block; margin: 16px 8px 16px 0; padding: 12px 18px;
      border-radius: 9px; background: #238636; color: white; text-decoration: none;
      font-weight: 700; }
    a.secondary { background: #21262d; }
    code { background: #161b22; border: 1px solid #30363d; border-radius: 6px;
      display: block; padding: 14px; overflow-wrap: anywhere; }
  </style>
</head>
<body><main>
  <img src="mocktail.svg" alt="Mocktail logo">
  <h1>Mocktail</h1>
  <p>Signed development Flatpak builds for Linux x86_64.</p>
  <a class="button" href="mocktail.flatpakref">Install with Flatpak</a>
  <a class="button secondary" href="https://github.com/komaruworld/mocktail">Source</a>
  <code>flatpak install --user https://mocktail.bigrat.space/mocktail.flatpakref</code>
  <p>Mocktail is an independent community project and is not affiliated with Roblox Corporation.</p>
</main></body>
</html>
EOF
