#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
compose_file="${repo_root}/tests/e2e/docker-compose.yaml"
bin_dir="${repo_root}/bin"
compose_project=$(basename "$(dirname "${compose_file}")")

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

need_cmd go
need_cmd docker

if ! docker compose version >/dev/null 2>&1; then
  echo "docker compose is not available" >&2
  exit 1
fi

wait_for_project_removal() {
  local deadline=$((SECONDS + 45))
  while (( SECONDS < deadline )); do
    if [[ -z "$(docker ps -a --filter "label=com.docker.compose.project=${compose_project}" --format '{{.Names}}')" ]]; then
      return 0
    fi
    sleep 1
  done
  echo "docker compose project ${compose_project} did not finish removing containers" >&2
  docker ps -a --filter "label=com.docker.compose.project=${compose_project}" --format 'table {{.Names}}\t{{.Status}}' >&2 || true
  exit 1
}

echo "[netloom] building local binaries"
mkdir -p "${bin_dir}"
CGO_ENABLED=0 go build -trimpath -o "${bin_dir}/" "${repo_root}/cmd/..."

echo "[netloom] resetting docker e2e lab"
docker compose -f "${compose_file}" down -v --remove-orphans >/dev/null 2>&1 || true
wait_for_project_removal
docker compose -f "${compose_file}" up -d --quiet-pull --force-recreate --remove-orphans

echo "[netloom] waiting for services"
deadline=$((SECONDS + 45))
while (( SECONDS < deadline )); do
  if docker compose -f "${compose_file}" exec -T ovn-central \
    ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock show >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

if ! docker compose -f "${compose_file}" exec -T ovn-central \
  ovn-nbctl --db=unix:/var/run/ovn/ovnnb_db.sock show >/dev/null 2>&1; then
  echo "ovn northbound database did not become ready" >&2
  docker compose -f "${compose_file}" logs --no-color ovn-central >&2 || true
  exit 1
fi

for service in node-a node-b node-c; do
  running=$(docker compose -f "${compose_file}" ps -q "${service}")
  if [[ -z "${running}" ]]; then
    echo "service ${service} is not running" >&2
    docker compose -f "${compose_file}" ps >&2
    exit 1
  fi
done

echo "[netloom] verifying privileged datapath prerequisites"
for service in node-a node-b node-c; do
  echo "[netloom] preparing ${service}"
  docker compose -f "${compose_file}" exec -T "${service}" sh -ceu '
    if ! command -v ip >/dev/null 2>&1 || ! ip -V 2>&1 | grep -q iproute2; then
      apk add --no-cache iproute2 >/dev/null
    fi
    ip -V | grep -q iproute2
    ip link show >/dev/null
    ip netns list >/dev/null
    test -d /sys/fs/bpf || mkdir -p /sys/fs/bpf
    test -d /netloom/bin
    test -x /netloom/bin/netloom-agent
    test -x /netloom/bin/netloom-controller
  '
done

echo "[netloom] environment is ready"
docker compose -f "${compose_file}" ps
