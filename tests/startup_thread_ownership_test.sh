#!/usr/bin/env bash
# Copyright 2026 Mocktail Project Authors
#
# Licensed under the Apache License, Version 2.0 (the "License")

set -euo pipefail

legacy_runtime="${1:?usage: startup_thread_ownership_test.sh legacy_runtime.cc owned_pthread.h}"
owned_pthread_header="${2:?usage: startup_thread_ownership_test.sh legacy_runtime.cc owned_pthread.h}"

if ! rg -q 'mocktail::runtime::OwnedPthread startup_thread' "${legacy_runtime}" ||
   ! rg -q 'startup_thread\.CancelAndJoinFor\(' "${legacy_runtime}" ||
   ! rg -q 'std::_Exit\(EXIT_FAILURE\)' "${legacy_runtime}"; then
  echo "startup timeout must use the typed owned pthread and fail closed before RAII unwind" >&2
  exit 1
fi

if rg -Uq 'startup thread timed out[\s\S]{0,2400}pthread_detach' "${legacy_runtime}" ||
   rg -q 'Detach|pthread_detach' "${owned_pthread_header}"; then
  echo "a timed-out owned startup worker must never be detached" >&2
  exit 1
fi

startup_cancel_line="$(rg -n -m1 'startup_thread\.CancelAndJoinFor\(' "${legacy_runtime}" | cut -d: -f1)"
startup_exit_line="$(rg -n 'std::_Exit\(EXIT_FAILURE\)' "${legacy_runtime}" | tail -1 | cut -d: -f1)"
if [[ -z "${startup_cancel_line}" || -z "${startup_exit_line}" ]] ||
   ! ((startup_cancel_line < startup_exit_line)) ||
   sed -n "${startup_cancel_line},${startup_exit_line}p" "${legacy_runtime}" |
     rg -q 'return EXIT_FAILURE'; then
  echo "unrecoverable cancellation must exhaust bounded join grace before _Exit" >&2
  exit 1
fi

if ! rg -q 'mocktail::runtime::OwnedPthread onload_thread' "${legacy_runtime}" ||
   ! rg -q 'onload_thread\.WaitFor\(jni_timeout_ms' "${legacy_runtime}" ||
   ! rg -q 'onload_thread\.CancelAndJoinFor\(' "${legacy_runtime}" ||
   rg -q 'pthread_detach\(onload_thread\)|async_context->finished|volatile sig_atomic_t finished' "${legacy_runtime}"; then
  echo "JNI_OnLoad timeout must use joined ownership without racy completion state" >&2
  exit 1
fi

onload_cancel_line="$(rg -n -m1 'onload_thread\.CancelAndJoinFor\(' "${legacy_runtime}" | cut -d: -f1)"
onload_exit_line="$(rg -n -m1 'std::_Exit\(EXIT_FAILURE\)' "${legacy_runtime}" | cut -d: -f1)"
if [[ -z "${onload_cancel_line}" || -z "${onload_exit_line}" ]] ||
   ! ((onload_cancel_line < onload_exit_line)) ||
   sed -n "${onload_cancel_line},${onload_exit_line}p" "${legacy_runtime}" |
     rg -q 'return EXIT_FAILURE'; then
  echo "JNI_OnLoad timeout must terminate before VM or async context unwind" >&2
  exit 1
fi
