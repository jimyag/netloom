#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
lock_dir="${repo_root}/.netloom-e2e.lock"
pid_file="${lock_dir}/pid"

cleanup() {
  rm -rf "${lock_dir}"
}

acquire_lock() {
  while true; do
    if mkdir "${lock_dir}" 2>/dev/null; then
      printf '%s\n' "$$" >"${pid_file}"
      trap cleanup EXIT INT TERM
      return 0
    fi

    if [[ -f "${pid_file}" ]]; then
      holder_pid=$(cat "${pid_file}" 2>/dev/null || true)
      if [[ -n "${holder_pid}" ]] && kill -0 "${holder_pid}" 2>/dev/null; then
        echo "[netloom] waiting for e2e lock held by pid ${holder_pid}" >&2
        sleep 1
        continue
      fi
    fi

    rm -rf "${lock_dir}"
  done
}

acquire_lock
"$@"
