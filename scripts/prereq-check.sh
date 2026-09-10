#!/usr/bin/env bash
set -euo pipefail

mode="${1:-}"
provider="${POC_PROVIDER:-docker}"
if [[ "$mode" != "rootful" && "$mode" != "rootless" ]]; then
  echo "usage: $0 <rootful|rootless>" >&2
  exit 2
fi

failed=0
if [[ "$provider" != "docker" && "$provider" != "podman" ]]; then
  echo "unsupported POC_PROVIDER=$provider (expected docker or podman)" >&2
  exit 2
fi

for cmd in "$provider" kind kubectl python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "MISSING  $cmd"
    failed=1
  else
    echo "OK       $cmd=$(command -v "$cmd")"
  fi
done

if [[ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null || true)" == "cgroup2fs" ]]; then
  echo "OK       cgroup=v2"
else
  echo "MISSING  cgroup=v2"
  failed=1
fi

if [[ "$provider" == "docker" ]] && command -v docker >/dev/null 2>&1; then
  security_options="$(docker info --format '{{json .SecurityOptions}}' 2>/dev/null || true)"
  echo "INFO     docker_security_options=$security_options"
  if [[ "$mode" == "rootless" && "$security_options" != *rootless* ]]; then
    echo "MISMATCH requested=rootless detected=rootful-or-unavailable"
    failed=1
  fi
  if [[ "$mode" == "rootful" && "$security_options" == *rootless* ]]; then
    echo "MISMATCH requested=rootful detected=rootless"
    failed=1
  fi
fi

if [[ "$provider" == "podman" ]] && command -v podman >/dev/null 2>&1; then
  rootless_detected="$(podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null || true)"
  echo "INFO     podman_rootless=$rootless_detected"
  if [[ "$mode" == "rootless" && "$rootless_detected" != "true" ]]; then
    echo "MISMATCH requested=rootless detected=rootful-or-unavailable"
    failed=1
  fi
  if [[ "$mode" == "rootful" && "$rootless_detected" == "true" ]]; then
    echo "MISMATCH requested=rootful detected=rootless"
    failed=1
  fi
fi

if [[ "$failed" -ne 0 ]]; then
  exit 1
fi

echo "READY    mode=$mode provider=$provider"
