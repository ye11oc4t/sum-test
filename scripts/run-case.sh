#!/usr/bin/env bash
set -euo pipefail

mode="${1:-}"
provider="${POC_PROVIDER:-docker}"
if [[ "$mode" != "rootful" && "$mode" != "rootless" ]]; then
  echo "usage: $0 <rootful|rootless>" >&2
  exit 2
fi
if [[ "$provider" != "docker" && "$provider" != "podman" ]]; then
  echo "unsupported POC_PROVIDER=$provider (expected docker or podman)" >&2
  exit 2
fi
if [[ "$provider" == "podman" ]]; then
  export KIND_EXPERIMENTAL_PROVIDER=podman
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
project_dir="$(cd "$script_dir/.." && pwd)"
cluster_name="rootless-poc-${mode}"
node_name="${cluster_name}-control-plane"
node_image="${POC_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"
canary_dir="/var/tmp/rootless-k8s-poc-${mode}"
result_file="$project_dir/results/${mode}.tsv"
metadata_file="$project_dir/results/${mode}-metadata.txt"

bash "$script_dir/prereq-check.sh" "$mode"
mkdir -p "$project_dir/results"

sudo install -d -o root -g root -m 0755 "$canary_dir"
sudo touch "$canary_dir/root-owned-canary"
sudo chown root:root "$canary_dir/root-owned-canary"
sudo chmod 0644 "$canary_dir/root-owned-canary"
printf '%s\n' 'POC_ROOT_ONLY_SYNTHETIC' | sudo tee "$canary_dir/root-only-synthetic" >/dev/null
sudo chown root:root "$canary_dir/root-only-synthetic"
sudo chmod 0600 "$canary_dir/root-only-synthetic"

config_file="$(mktemp)"
cleanup_config() {
  rm -f "$config_file"
}
trap cleanup_config EXIT

cat >"$config_file" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    extraMounts:
      - hostPath: $canary_dir
        containerPath: /poc-host
EOF

kind delete cluster --name "$cluster_name" >/dev/null 2>&1 || true
kind create cluster --name "$cluster_name" --image "$node_image" --config "$config_file" --wait 180s

kubectl --context "kind-${cluster_name}" apply -f "$project_dir/manifests/victims.yaml"
kubectl --context "kind-${cluster_name}" wait --for=condition=Ready pod/victim-a -n tenant-a --timeout=180s
kubectl --context "kind-${cluster_name}" wait --for=condition=Ready pod/victim-b -n tenant-b --timeout=180s

"$provider" cp "$script_dir/probe-node.sh" "$node_name:/tmp/probe-node.sh"
"$provider" exec "$node_name" chmod 0755 /tmp/probe-node.sh
"$provider" exec "$node_name" bash /tmp/probe-node.sh "$mode" >"$result_file"

{
  echo "timestamp_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "mode=$mode"
  echo "provider=$provider"
  echo "node_image=$node_image"
  echo "kind_version=$(kind version)"
  echo "kubectl_version=$(kubectl version --client=true -o yaml 2>/dev/null | tr '\n' ' ')"
  echo "provider_version=$($provider version 2>/dev/null | tr '\n' ' ')"
  echo "provider_info=$($provider info 2>/dev/null | tr '\n' ' ' | cut -c1-2000)"
  echo "node_running_in_userns=$(kubectl --context "kind-${cluster_name}" get node "$node_name" -o jsonpath='{.status.features.supplementalFeatures.node.runningInUserNamespace}' 2>/dev/null || true)"
  echo "node_pid1_uid_map=$($provider exec "$node_name" cat /proc/1/uid_map | tr '\n' ';')"
  echo "canary_sha256=$(sha256sum "$canary_dir/root-owned-canary" | awk '{print $1}')"
} >"$metadata_file"

echo "RESULT   $result_file"
echo "META     $metadata_file"
