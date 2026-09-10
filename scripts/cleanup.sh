#!/usr/bin/env bash
set -euo pipefail

mode="${1:-}"
if [[ "$mode" != "rootful" && "$mode" != "rootless" ]]; then
  echo "usage: $0 <rootful|rootless>" >&2
  exit 2
fi

kind delete cluster --name "rootless-poc-${mode}"
echo "Canary retained at /var/tmp/rootless-k8s-poc-${mode} for manual inspection."

