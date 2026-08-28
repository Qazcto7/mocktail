#!/usr/bin/env bash
# Copyright 2026 Mocktail Project Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -Eeuo pipefail
umask 022

RUNTIME_ROOT=""
TARGET_LIBC=""
STAGING_ROOT=""
SUPPORT_RUNTIME=""

readonly -a REQUIRED_COMMANDS=(
  bash
  bwrap
  xdg-dbus-proxy
  jq
  unzip
  file
  flock
  timeout
  readelf
  sha256sum
  curl
  tar
  gzip
  find
  sed
  grep
  awk
  sort
  comm
  stat
  id
  mktemp
  dirname
  uname
)

readonly -a PYTHON_DISTRIBUTIONS=(
  capstone
  PyYAML
  requests
  urllib3
  certifi
  charset-normalizer
  idna
)

Usage() {
  cat <<'EOF'
Usage: scripts/package_standalone_support.sh --runtime-root DIR --libc ABI

Populate DIR/runtime with the native command, Python, Java, and CA support
needed by the standalone Mocktail scripts. ABI must be glibc or musl and must
match the build host. ELF dependency closure is intentionally left to the
parent packager.
EOF
}

Log() {
  printf '[standalone-support] %s\n' "$*" >&2
}

Die() {
  Log "error: $*"
  exit 1
}

Cleanup() {
  if [[ -n "${STAGING_ROOT}" && -d "${STAGING_ROOT}" &&
        ! -L "${STAGING_ROOT}" ]]; then
    rm -rf -- "${STAGING_ROOT}"
  fi
}

trap Cleanup EXIT

ParseArguments() {
  while (( $# > 0 )); do
    case "$1" in
      --runtime-root)
        (( $# >= 2 )) || Die "--runtime-root requires a directory"
        RUNTIME_ROOT="$2"
        shift 2
        ;;
      --runtime-root=*)
        RUNTIME_ROOT="${1#*=}"
        shift
        ;;
      --libc)
        (( $# >= 2 )) || Die "--libc requires glibc or musl"
        TARGET_LIBC="$2"
        shift 2
        ;;
      --libc=*)
        TARGET_LIBC="${1#*=}"
        shift
        ;;
      -h|--help)
        Usage
        exit 0
        ;;
      *)
        Die "unknown option: $1"
        ;;
    esac
  done

  [[ -n "${RUNTIME_ROOT}" ]] || Die "--runtime-root is required"
  [[ "${TARGET_LIBC}" == glibc || "${TARGET_LIBC}" == musl ]] ||
    Die "--libc must be glibc or musl"
}

RequireBuildCommands() {
  local command_name
  for command_name in cp cmp install java jlink ldd ln mkdir mv python3 \
      readlink realpath rm rmdir; do
    command -v "${command_name}" >/dev/null 2>&1 ||
      Die "required build command is unavailable: ${command_name}"
  done
}

RejectUnsafeText() {
  local -r value="$1"
  local -r description="$2"
  [[ -n "${value}" && "${value}" != *$'\n'* && "${value}" != *$'\r'* &&
     "${value}" != *$'\t'* ]] || Die "${description} is empty or unsafe"
}

ValidateRuntimeRoot() {
  RejectUnsafeText "${RUNTIME_ROOT}" "runtime root"
  [[ "${RUNTIME_ROOT}" == /* ]] || Die "runtime root must be absolute"
  [[ -d "${RUNTIME_ROOT}" && ! -L "${RUNTIME_ROOT}" ]] ||
    Die "runtime root must be an existing non-symlink directory"

  local canonical_root
  canonical_root="$(realpath -e -- "${RUNTIME_ROOT}")" ||
    Die "cannot canonicalize runtime root"
  canonical_root="${canonical_root%/}"
  [[ -n "${canonical_root}" && "${canonical_root}" != / ]] ||
    Die "refusing unsafe runtime root"
  [[ "${RUNTIME_ROOT%/}" == "${canonical_root}" ]] ||
    Die "runtime root must be canonical and contain no symlink components"
  RUNTIME_ROOT="${canonical_root}"

  local -r destination="${RUNTIME_ROOT}/runtime"
  if [[ -e "${destination}" || -L "${destination}" ]]; then
    [[ -d "${destination}" && ! -L "${destination}" ]] ||
      Die "runtime destination must not be a symlink or non-directory"
    if find "${destination}" -mindepth 1 -maxdepth 1 -print -quit |
        grep -q .; then
      Die "runtime destination is not empty: ${destination}"
    fi
  fi
}

DetectHostLibc() {
  local output=""
  output="$(getconf GNU_LIBC_VERSION 2>/dev/null || true)"
  if [[ "${output}" == glibc\ * ]]; then
    printf 'glibc\n'
    return
  fi
  output="$(ldd --version 2>&1 || true)"
  if grep -qi musl <<<"${output}"; then
    printf 'musl\n'
    return
  fi

  local interpreter=""
  interpreter="$(LC_ALL=C readelf -l /proc/$$/exe 2>/dev/null |
    sed -n 's/.*Requesting program interpreter: \([^]]*\).*/\1/p')"
  case "${interpreter}" in
    *ld-linux*.so.*) printf 'glibc\n' ;;
    *ld-musl-*.so.1) printf 'musl\n' ;;
    *) printf 'unknown\n' ;;
  esac
}

ValidateNativeHost() {
  local host_libc
  host_libc="$(DetectHostLibc)"
  [[ "${host_libc}" != unknown ]] || Die "cannot determine host libc"
  [[ "${host_libc}" == "${TARGET_LIBC}" ]] ||
    Die "requested ${TARGET_LIBC} support on a ${host_libc} host; cross-packaging is unsupported"
}

ValidateRelativePath() {
  local -r path="$1"
  RejectUnsafeText "${path}" "relative path"
  [[ "${path}" != /* && "${path}" != . && "${path}" != .. &&
     "${path}" != ../* && "${path}" != */../* &&
     "${path}" != */.. && "${path}" != ./* &&
     "${path}" != */./* && "${path}" != */. &&
     "${path}" != *//* ]] || Die "unsafe relative path: ${path}"
}

PathIsInside() {
  local -r path="$1"
  local -r root="$2"
  [[ "${path}" == "${root}" || "${path}" == "${root}/"* ]]
}

InstallRegularFile() {
  local -r source="$1"
  local -r destination="$2"
  [[ -f "${source}" && ! -L "${source}" ]] ||
    Die "source is not a regular file: ${source}"
  mkdir -p -- "$(dirname -- "${destination}")"
  if [[ -e "${destination}" || -L "${destination}" ]]; then
    [[ -f "${destination}" && ! -L "${destination}" ]] ||
      Die "support file collision: ${destination}"
    cmp -s -- "${source}" "${destination}" ||
      Die "different support files collide at ${destination}"
    return
  fi
  cp -p -- "${source}" "${destination}"
}

CopySafeLink() {
  local -r source="$1"
  local -r source_root="$2"
  local -r destination="$3"
  local -r destination_root="$4"
  local target resolved relative_target destination_target
  target="$(readlink -- "${source}")" || Die "cannot read symlink: ${source}"
  RejectUnsafeText "${target}" "symlink target"
  resolved="$(realpath -e -- "${source}")" ||
    Die "dangling symlink is not permitted: ${source}"
  if ! PathIsInside "${resolved}" "${source_root}"; then
    # Host packages sometimes point a data file (not code) at a canonical
    # system copy, for example certifi/cacert.pem. Materialize that file so
    # the packaged tree does not retain an absolute or escaping link.
    [[ -f "${resolved}" && ! -L "${resolved}" ]] ||
      Die "symlink escapes its copied tree: ${source} -> ${target}"
    InstallRegularFile "${resolved}" "${destination}"
    return
  fi

  relative_target="$(realpath --relative-to="$(dirname -- "${source}")" -- \
    "${resolved}")" || Die "cannot normalize symlink: ${source}"
  ValidateRelativePath "${relative_target}"
  destination_target="$(realpath -m -- \
    "$(dirname -- "${destination}")/${relative_target}")"
  PathIsInside "${destination_target}" "${destination_root}" ||
    Die "rewritten symlink escapes destination: ${destination}"
  mkdir -p -- "$(dirname -- "${destination}")"
  if [[ -e "${destination}" || -L "${destination}" ]]; then
    [[ -L "${destination}" &&
       "$(readlink -- "${destination}")" == "${relative_target}" ]] ||
      Die "support symlink collision: ${destination}"
    return
  fi
  ln -s -- "${relative_target}" "${destination}"
}

CopyTree() {
  local -r source_input="$1"
  local -r destination_root="$2"
  local -r prune_python_packages="${3:-false}"
  local source_root
  source_root="$(realpath -e -- "${source_input}")" ||
    Die "cannot resolve source tree: ${source_input}"
  [[ -d "${source_root}" && ! -L "${source_root}" ]] ||
    Die "source tree must resolve to a directory: ${source_input}"
  mkdir -p -- "${destination_root}"

  local entry relative destination
  while IFS= read -r -d '' entry; do
    relative="${entry#"${source_root}"/}"
    ValidateRelativePath "${relative}"
    destination="${destination_root}/${relative}"
    if [[ -L "${entry}" ]]; then
      CopySafeLink "${entry}" "${source_root}" "${destination}" \
        "${destination_root}"
    elif [[ -d "${entry}" ]]; then
      if [[ -e "${destination}" && ! -d "${destination}" ]]; then
        Die "support directory collision: ${destination}"
      fi
      mkdir -p -- "${destination}"
      chmod --reference="${entry}" "${destination}"
    elif [[ -f "${entry}" ]]; then
      InstallRegularFile "${entry}" "${destination}"
    else
      Die "unsupported special file in source tree: ${entry}"
    fi
  done < <(
    if [[ "${prune_python_packages}" == true ]]; then
      # Tk is an optional Python GUI stack and is not used by Mocktail's
      # support scripts. Keeping _tkinter in the copied standard library
      # makes the later ELF closure require Tcl/Tk even when the build image
      # intentionally does not install those libraries.
      find -P "${source_root}" -mindepth 1 \
        \( -type d \( -name site-packages -o -name dist-packages -o \
                       -name __pycache__ -o -name tkinter -o \
                       -name idlelib -o -name turtledemo \) -prune \) -o \
        \( -type f \( -name '*.pyc' -o -name '_tkinter*.so' \) \
           -prune \) -o -print0
    else
      find -P "${source_root}" -mindepth 1 \
        \( -type d -name __pycache__ -prune \) -o \
        \( -type f -name '*.pyc' -prune \) -o -print0
    fi
  )
}

CopyCommand() {
  local -r name="$1"
  local source resolved target_name
  source="$(type -P -- "${name}" || true)"
  [[ -n "${source}" ]] || Die "required runtime command is unavailable: ${name}"
  RejectUnsafeText "${source}" "command path"
  [[ "${source}" == /* ]] || Die "command path is not absolute: ${source}"
  resolved="$(realpath -e -- "${source}")" ||
    Die "cannot resolve runtime command: ${source}"
  [[ -f "${resolved}" && -x "${resolved}" ]] ||
    Die "runtime command is not an executable regular file: ${resolved}"
  target_name="$(basename -- "${resolved}")"
  [[ "${target_name}" =~ ^[A-Za-z0-9._+-]+$ ]] ||
    Die "runtime command has an unsafe target name: ${resolved}"

  InstallRegularFile "${resolved}" "${SUPPORT_RUNTIME}/bin/${target_name}"
  if [[ "${name}" != "${target_name}" ]]; then
    if [[ -e "${SUPPORT_RUNTIME}/bin/${name}" ||
          -L "${SUPPORT_RUNTIME}/bin/${name}" ]]; then
      Die "runtime command name collision: ${name}"
    fi
    ln -s -- "${target_name}" "${SUPPORT_RUNTIME}/bin/${name}"
  fi
}

CopyRuntimeCommands() {
  local command_name
  for command_name in "${REQUIRED_COMMANDS[@]}"; do
    CopyCommand "${command_name}"
  done
  if type -P -- rg >/dev/null 2>&1; then
    CopyCommand rg
  fi
}

PythonValue() {
  local -r expression="$1"
  python3 -c "import sys, sysconfig; print(${expression})"
}

PythonDistributionFiles() {
  local -r distribution="$1"
  python3 - "${distribution}" <<'PY'
import importlib.metadata
import importlib.util
import os
import pathlib
import sys


def find_import_root(source):
    candidates = []
    for entry in sys.path:
        if not entry:
            continue
        try:
            root = pathlib.Path(entry).resolve(strict=True)
            source.relative_to(root)
        except (OSError, ValueError):
            continue
        candidates.append(root)
    if not candidates:
        raise SystemExit(1)
    return max(candidates, key=lambda path: len(path.parts))

name = sys.argv[1]
try:
    installed_distribution = importlib.metadata.distribution(name)
except importlib.metadata.PackageNotFoundError:
    installed_distribution = None

entries = []
if installed_distribution is not None and installed_distribution.files:
    root = pathlib.Path(
        installed_distribution.locate_file("")
    ).resolve(strict=True)
    for entry in installed_distribution.files:
        entries.append((
            root,
            pathlib.Path(installed_distribution.locate_file(entry)),
            pathlib.PurePath(entry),
        ))
else:
    fallback_modules = {
        "capstone": ("capstone",),
        "pyyaml": ("yaml", "_yaml"),
        "requests": ("requests",),
        "urllib3": ("urllib3",),
        "certifi": ("certifi",),
        "charset-normalizer": ("charset_normalizer",),
        "idna": ("idna",),
    }.get(name.lower(), ())
    discovered = []
    for module in fallback_modules:
        spec = importlib.util.find_spec(module)
        if spec is None:
            raise SystemExit(1)
        if spec.submodule_search_locations is not None:
            module_root = pathlib.Path(
                next(iter(spec.submodule_search_locations))
            ).resolve(strict=True)
            discovered.extend(
                path for path in module_root.rglob("*")
                if path.is_file() or path.is_symlink()
            )
        elif spec.origin:
            discovered.append(pathlib.Path(spec.origin).resolve(strict=True))
    for source in discovered:
        root = find_import_root(source)
        entries.append((root, source, source.relative_to(root)))
written = 0
for root, source, relative in entries:
    relative = pathlib.PurePath(relative)
    if relative.is_absolute() or ".." in relative.parts:
        continue
    if "__pycache__" in relative.parts or relative.suffix == ".pyc":
        continue
    if not source.exists() and not source.is_symlink():
        raise SystemExit(1)
    os.write(1, os.fsencode(root) + b"\0")
    os.write(1, os.fsencode(source) + b"\0")
    os.write(1, os.fsencode(relative) + b"\0")
    written += 1
if written == 0:
    raise SystemExit(1)
PY
}

CopyPythonRuntime() {
  local python_executable python_resolved python_version stdlib platstdlib
  python_executable="$(type -P -- python3 || true)"
  [[ -n "${python_executable}" ]] || Die "python3 is required to build support"
  python_resolved="$(realpath -e -- "${python_executable}")" ||
    Die "cannot resolve python3"
  [[ -f "${python_resolved}" && -x "${python_resolved}" ]] ||
    Die "python3 does not resolve to an executable regular file"
  python_version="$(PythonValue 'f"{sys.version_info.major}.{sys.version_info.minor}"')"
  [[ "${python_version}" =~ ^[0-9]+\.[0-9]+$ ]] ||
    Die "cannot determine Python version"
  stdlib="$(PythonValue 'sysconfig.get_path("stdlib")')"
  platstdlib="$(PythonValue 'sysconfig.get_path("platstdlib")')"
  RejectUnsafeText "${stdlib}" "Python stdlib path"
  RejectUnsafeText "${platstdlib}" "Python platform stdlib path"

  local -r python_bin="${SUPPORT_RUNTIME}/python/bin"
  local -r python_library="${SUPPORT_RUNTIME}/python/lib/python${python_version}"
  mkdir -p -- "${python_bin}" "${python_library}"
  local python_binary_name
  python_binary_name="$(basename -- "${python_resolved}")"
  InstallRegularFile "${python_resolved}" \
    "${python_bin}/${python_binary_name}"
  if [[ "${python_binary_name}" != python3 ]]; then
    ln -s -- "${python_binary_name}" "${python_bin}/python3"
  fi
  ln -s -- "../python/bin/python3" "${SUPPORT_RUNTIME}/bin/python3"

  CopyTree "${stdlib}" "${python_library}" true
  local canonical_stdlib canonical_platstdlib
  canonical_stdlib="$(realpath -e -- "${stdlib}")"
  canonical_platstdlib="$(realpath -e -- "${platstdlib}")"
  if [[ "${canonical_platstdlib}" != "${canonical_stdlib}" ]]; then
    CopyTree "${platstdlib}" "${python_library}" true
  fi

  local distribution distribution_root source relative destination
  for distribution in "${PYTHON_DISTRIBUTIONS[@]}"; do
    local copied=0
    while IFS= read -r -d '' distribution_root &&
          IFS= read -r -d '' source &&
          IFS= read -r -d '' relative; do
      ValidateRelativePath "${relative}"
      distribution_root="$(realpath -e -- "${distribution_root}")" ||
        Die "cannot resolve Python distribution root: ${distribution}"
      destination="${python_library}/${relative}"
      if [[ -L "${source}" ]]; then
        CopySafeLink "${source}" "${distribution_root}" "${destination}" \
          "${python_library}"
      elif [[ -f "${source}" ]]; then
        InstallRegularFile "${source}" "${destination}"
      elif [[ ! -d "${source}" ]]; then
        Die "unsupported Python distribution entry: ${source}"
      fi
      ((copied += 1))
    done < <(PythonDistributionFiles "${distribution}")
    (( copied > 0 )) ||
      Die "required Python distribution is unavailable: ${distribution}"
  done

}

CopyCaBundle() {
  local -a candidates=()
  if [[ -n "${SSL_CERT_FILE:-}" ]]; then
    candidates+=("${SSL_CERT_FILE}")
  fi
  candidates+=(
    /etc/ssl/certs/ca-certificates.crt
    /etc/pki/tls/certs/ca-bundle.crt
    /etc/ssl/ca-bundle.pem
    /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
  )
  local candidate resolved=""
  for candidate in "${candidates[@]}"; do
    [[ "${candidate}" == /* && -r "${candidate}" ]] || continue
    resolved="$(realpath -e -- "${candidate}" 2>/dev/null || true)"
    if [[ -n "${resolved}" && -f "${resolved}" && -s "${resolved}" ]]; then
      break
    fi
    resolved=""
  done
  [[ -n "${resolved}" ]] || Die "cannot find a readable host CA bundle"
  mkdir -p -- "${SUPPORT_RUNTIME}/share/ca-certificates"
  install -m 0644 -- "${resolved}" \
    "${SUPPORT_RUNTIME}/share/ca-certificates/ca-bundle.crt"
}

BuildJlinkRuntime() {
  local jlink_executable jlink_resolved java_home module_path
  jlink_executable="$(type -P -- jlink || true)"
  [[ -n "${jlink_executable}" ]] || Die "jlink is required to build support"
  jlink_resolved="$(realpath -e -- "${jlink_executable}")" ||
    Die "cannot resolve jlink"
  java_home="$(dirname -- "$(dirname -- "${jlink_resolved}")")"
  module_path="${java_home}/jmods"
  [[ -f "${module_path}/java.base.jmod" &&
     -f "${module_path}/java.logging.jmod" &&
     -f "${module_path}/java.desktop.jmod" &&
     -f "${module_path}/jdk.zipfs.jmod" ]] ||
    Die "jlink JMOD files are unavailable under ${java_home}"

  local compression=2
  if "${jlink_resolved}" --help 2>&1 | grep -q 'zip-{0-9}'; then
    compression=zip-6
  fi
  "${jlink_resolved}" --module-path "${module_path}" \
    --add-modules java.base,java.logging,java.desktop,jdk.zipfs \
    --strip-debug --no-man-pages \
    --no-header-files --compress="${compression}" \
    --output "${SUPPORT_RUNTIME}/jre"
  [[ -x "${SUPPORT_RUNTIME}/jre/bin/java" ]] ||
    Die "jlink did not produce a Java launcher"
  ln -s -- "../jre/bin/java" "${SUPPORT_RUNTIME}/bin/java"

  local modules
  modules="$("${SUPPORT_RUNTIME}/jre/bin/java" --list-modules |
    sed 's/@.*//' | LC_ALL=C sort)"
  [[ "${modules}" == \
     $'java.base\njava.datatransfer\njava.desktop\njava.logging\njava.prefs\njava.xml\njdk.zipfs' ]] ||
    Die "jlink image contains unexpected modules"
}

ValidateCopiedSymlinks() {
  local -r root="$1"
  local link resolved
  while IFS= read -r -d '' link; do
    resolved="$(realpath -e -- "${link}")" ||
      Die "packaged support contains a dangling symlink: ${link}"
    PathIsInside "${resolved}" "${root}" ||
      Die "packaged support symlink escapes its root: ${link}"
  done < <(find -P "${root}" -type l -print0)
}

VerifySupportRuntime() {
  local -r python="${SUPPORT_RUNTIME}/bin/python3"
  local -r ca_bundle="${SUPPORT_RUNTIME}/share/ca-certificates/ca-bundle.crt"
  [[ -x "${python}" && -s "${ca_bundle}" ]] ||
    Die "packaged Python or CA support is incomplete"
  PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1 "${python}" -s -c '
import pathlib
import sys
import capstone
import yaml
import certifi
import charset_normalizer
import idna
import requests
import urllib3
if capstone.cs_version()[0] != 5:
    raise SystemExit("bundled capstone major version is not 5")
prefix = pathlib.Path(sys.prefix).resolve()
expected = pathlib.Path(sys.executable).resolve().parents[1]
if prefix != expected:
    raise SystemExit(f"Python prefix escaped support runtime: {prefix}")
' || Die "relocated Python dependency verification failed"
  ValidateCopiedSymlinks "${SUPPORT_RUNTIME}"
}

PublishRuntime() {
  local -r destination="${RUNTIME_ROOT}/runtime"
  if [[ -d "${destination}" && ! -L "${destination}" ]]; then
    rmdir -- "${destination}" || Die "runtime destination changed during build"
  elif [[ -e "${destination}" || -L "${destination}" ]]; then
    Die "runtime destination changed during build"
  fi
  mv -T -- "${SUPPORT_RUNTIME}" "${destination}"
  rmdir -- "${STAGING_ROOT}" ||
    Die "standalone support staging root is not empty after publish"
  STAGING_ROOT=""
  Log "native ${TARGET_LIBC} support populated at ${destination}"
}

Main() {
  ParseArguments "$@"
  RequireBuildCommands
  ValidateRuntimeRoot
  ValidateNativeHost

  STAGING_ROOT="$(mktemp -d -- \
    "${RUNTIME_ROOT}/.mocktail-standalone-support.XXXXXX")" ||
    Die "cannot create support staging directory"
  SUPPORT_RUNTIME="${STAGING_ROOT}/runtime"
  mkdir -p -- "${SUPPORT_RUNTIME}/bin" "${SUPPORT_RUNTIME}/python" \
    "${SUPPORT_RUNTIME}/jre" "${SUPPORT_RUNTIME}/share"
  rmdir -- "${SUPPORT_RUNTIME}/jre"

  CopyRuntimeCommands
  CopyPythonRuntime
  CopyCaBundle
  BuildJlinkRuntime
  VerifySupportRuntime
  PublishRuntime
}

Main "$@"
