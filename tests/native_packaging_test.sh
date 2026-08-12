#!/usr/bin/env bash
# Copyright 2026 Mocktail Project Authors
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

readonly ROOT="${1:?source root is required}"
readonly CMAKE_FILE="${ROOT}/CMakeLists.txt"
readonly PKGBUILD="${ROOT}/packaging/arch/PKGBUILD"
readonly AUR_STABLE_PKGBUILD="${ROOT}/packaging/aur/mocktail/PKGBUILD"
readonly AUR_STABLE_SRCINFO="${ROOT}/packaging/aur/mocktail/.SRCINFO"
readonly AUR_BIN_PKGBUILD="${ROOT}/packaging/aur/mocktail-bin/PKGBUILD"
readonly AUR_BIN_SRCINFO="${ROOT}/packaging/aur/mocktail-bin/.SRCINFO"
readonly AUR_PKGBUILD="${ROOT}/packaging/aur/mocktail-git/PKGBUILD"
readonly AUR_SRCINFO="${ROOT}/packaging/aur/mocktail-git/.SRCINFO"
readonly WORKFLOW="${ROOT}/.github/workflows/packages.yml"
readonly README="${ROOT}/README.md"
readonly STUB_CMAKE="${ROOT}/stubs/CMakeLists.txt"
readonly ANDROID_STUB="${ROOT}/stubs/libandroid_stub.cc"

Fail() {
  printf 'Native packaging test failed: %s\n' "$*" >&2
  exit 1
}

bash -n "${PKGBUILD}"
bash -n "${AUR_STABLE_PKGBUILD}"
bash -n "${AUR_BIN_PKGBUILD}"
bash -n "${AUR_PKGBUILD}"

grep -Fq 'include(CPack)' "${CMAKE_FILE}" ||
  Fail 'CMake does not enable CPack'
grep -Fq 'CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON' "${CMAKE_FILE}" ||
  Fail 'DEB packages do not derive shared-library dependencies'
grep -Fq 'CPACK_RPM_PACKAGE_AUTOREQPROV ON' "${CMAKE_FILE}" ||
  Fail 'RPM packages do not derive runtime requirements'
grep -Fq 'pkgname=mocktail' "${PKGBUILD}" ||
  Fail 'Arch package name is not stable'
grep -Fq "'sdl3>=3.4'" "${PKGBUILD}" ||
  Fail 'Arch package does not enforce the SDL minimum'
grep -Fq "'libplacebo'" "${PKGBUILD}" ||
  Fail 'Arch package does not declare the graphics composition dependency'
grep -Fq 'pkgname=mocktail-git' "${AUR_PKGBUILD}" ||
  Fail 'AUR VCS package name is not stable'
grep -Fq 'pkgname=mocktail' "${AUR_STABLE_PKGBUILD}" ||
  Fail 'AUR source package name is not stable'
grep -Fq '#tag=${pkgver}' "${AUR_STABLE_PKGBUILD}" ||
  Fail 'AUR source package does not pin its Git tag'
grep -Fq 'pkgbase = mocktail' "${AUR_STABLE_SRCINFO}" ||
  Fail 'AUR source package has no generated .SRCINFO metadata'
grep -Fq 'pkgname=mocktail-bin' "${AUR_BIN_PKGBUILD}" ||
  Fail 'AUR binary package name is not stable'
grep -Fq 'pkgbase = mocktail-bin' "${AUR_BIN_SRCINFO}" ||
  Fail 'AUR binary package has no generated .SRCINFO metadata'
grep -Fq -- \
  "'mocktail::git+https://github.com/komaruworld/mocktail.git#branch=main'" \
  "${AUR_PKGBUILD}" ||
  Fail 'AUR package does not build from the upstream Git repository'
grep -Fq "provides=('mocktail')" "${AUR_PKGBUILD}" ||
  Fail 'AUR VCS package does not provide the stable package name'
grep -Fq -- \
  '-DMOCKTAIL_DEFAULT_COMPATIBILITY_MANIFEST=/usr/share/mocktail/metadata/' \
  "${AUR_PKGBUILD}" ||
  Fail 'AUR package embeds a build-tree compatibility manifest path'
grep -Fq 'pkgbase = mocktail-git' "${AUR_SRCINFO}" ||
  Fail 'AUR package has no generated .SRCINFO metadata'
grep -Fq 'paru -S mocktail-git' "${README}" ||
  Fail 'README has no AUR installation instructions'
grep -Fq 'yay -S mocktail-git' "${README}" ||
  Fail 'README has no alternative AUR helper command'
grep -Fq 'LINKER:--no-as-needed' "${STUB_CMAKE}" ||
  Fail 'system shims can lose their host libc dependencies'
grep -Fq 'MOCKTAIL_MINIZIP_HAS_STREAM_TELL' "${STUB_CMAKE}" ||
  Fail 'CMake does not detect the minizip-ng offset API'
grep -Fq 'mz_stream_tell(unzGetStream(archive))' "${ANDROID_STUB}" ||
  Fail 'Android assets do not support the minizip-ng offset API'

for expected in \
    'ubuntu:26.04' \
    'fedora:44' \
    'archlinux:base-devel' \
    'minizip-ng-compat-devel' \
    'libgif7' \
    '-G DEB' \
    '-G RPM' \
    'makepkg --dir' \
    'Mocktail-x86_64.AppImage' \
    'gh release upload continuous'; do
  grep -Fq -- "${expected}" "${WORKFLOW}" ||
    Fail "native package workflow is missing: ${expected}"
done

grep -Fq 'sudo pacman -U ./mocktail-*-x86_64.pkg.tar.zst' "${README}" ||
  Fail 'README has no direct pacman installation command'
grep -Fq 'Ubuntu 26.04+' "${README}" ||
  Fail 'README has no Ubuntu source dependency guide'
grep -Fq 'Arch Linux' "${README}" ||
  Fail 'README has no Arch source dependency guide'
grep -Fq 'Fedora 44+' "${README}" ||
  Fail 'README has no Fedora source dependency guide'

printf 'Native packaging contract test passed\n'
