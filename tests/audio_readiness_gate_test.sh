#!/usr/bin/env bash

# Copyright 2026 Mocktail Project Authors
# Licensed under the Apache License, Version 2.0.

set -euo pipefail

readonly gate="$1"
readonly temp_dir="$(mktemp -d)"
trap 'rm -rf "${temp_dir}"' EXIT

not_emitted_log="${temp_dir}/not_emitted.log"
printf '%s\n' '[mocktail][audio] OpenSL player realized: rate_hz=48000 channels=2 format=s16le queue_capacity=4' >"${not_emitted_log}"
if [[ "$("${gate}" "${not_emitted_log}")" != 'audio_status=not_emitted' ]]; then
  echo "no-buffer runs must keep audio optional" >&2
  exit 1
fi

submitted_only_log="${temp_dir}/submitted_only.log"
printf '%s\n' '[mocktail][audio] OpenSL playback activity: submitted_buffers=1' >"${submitted_only_log}"
if "${gate}" "${submitted_only_log}" >/dev/null 2>&1; then
  echo "submitted audio without SDL consumption must fail" >&2
  exit 1
fi

complete_log="${temp_dir}/complete.log"
printf '%s\n' \
  '[mocktail][audio] OpenSL playback activity: submitted_buffers=1' \
  '[mocktail][audio] OpenSL playback evidence: consumed_buffers=1' \
  '[mocktail][audio] OpenSL player shutdown: submitted=2 consumed=1 discarded=1 clean=true' \
  >"${complete_log}"
if [[ "$("${gate}" "${complete_log}")" != \
      'audio_status=consumed_and_shutdown_cleanly' ]]; then
  echo "consumed audio with clean shutdown must pass" >&2
  exit 1
fi

unclean_log="${temp_dir}/unclean.log"
printf '%s\n' \
  '[mocktail][audio] OpenSL playback activity: submitted_buffers=1' \
  '[mocktail][audio] OpenSL playback evidence: consumed_buffers=1' \
  '[mocktail][audio] OpenSL player shutdown: submitted=2 consumed=1 discarded=1 clean=false' \
  >"${unclean_log}"
if "${gate}" "${unclean_log}" >/dev/null 2>&1; then
  echo "unclean audio shutdown must fail" >&2
  exit 1
fi

fmod_complete_log="${temp_dir}/fmod_complete.log"
printf '%s\n' \
  '[mocktail][audio] fmod_java initialized channels=2 sample_rate_hz=48000 block_size_frames=512 block_count=4' \
  '[mocktail][audio] fmod_java first_submission submitted_buffers=1 submitted_bytes=2048 consumed_buffers=0 consumed_bytes=0 discarded_buffers=0 discarded_bytes=0 pending_buffers=1' \
  '[mocktail][audio] fmod_java closed submitted_buffers=8 submitted_bytes=16384 consumed_buffers=7 consumed_bytes=14336 discarded_buffers=1 discarded_bytes=2048 pending_buffers=0' \
  '[mocktail][audio] fmod_java shutdown submitted_buffers=8 submitted_bytes=16384 consumed_buffers=7 consumed_bytes=14336 discarded_buffers=1 discarded_bytes=2048 pending_buffers=0' \
  '[window] Shutdown window=0x1 context=(nil) surface=(nil)' \
  >"${fmod_complete_log}"
if [[ "$("${gate}" "${fmod_complete_log}")" != \
      'audio_status=consumed_and_shutdown_cleanly' ]]; then
  echo "consumed FMOD Java audio with clean shutdown must pass" >&2
  exit 1
fi

fmod_rejected_log="${temp_dir}/fmod_rejected.log"
cp "${fmod_complete_log}" "${fmod_rejected_log}"
printf '%s\n' \
  '[mocktail][audio] fmod_java write_failed reason=bounded queue full' \
  >>"${fmod_rejected_log}"
if "${gate}" "${fmod_rejected_log}" >/dev/null 2>&1; then
  echo "rejected FMOD Java PCM writes must fail readiness" >&2
  exit 1
fi

fmod_init_failed_log="${temp_dir}/fmod_init_failed.log"
printf '%s\n' \
  '[mocktail][audio] fmod_java init_failed reason=playback unavailable' \
  >"${fmod_init_failed_log}"
if "${gate}" "${fmod_init_failed_log}" >/dev/null 2>&1; then
  echo "FMOD Java init failure without submission must fail readiness" >&2
  exit 1
fi

fmod_bad_order_log="${temp_dir}/fmod_bad_order.log"
printf '%s\n' \
  '[mocktail][audio] fmod_java first_submission submitted_buffers=1 submitted_bytes=2048 consumed_buffers=0 consumed_bytes=0 discarded_buffers=0 discarded_bytes=0 pending_buffers=1' \
  '[window] Shutdown window=0x1 context=(nil) surface=(nil)' \
  '[mocktail][audio] fmod_java shutdown submitted_buffers=8 submitted_bytes=16384 consumed_buffers=7 consumed_bytes=14336 discarded_buffers=1 discarded_bytes=2048 pending_buffers=0' \
  >"${fmod_bad_order_log}"
if "${gate}" "${fmod_bad_order_log}" >/dev/null 2>&1; then
  echo "FMOD shutdown after SDL window teardown must fail readiness" >&2
  exit 1
fi
