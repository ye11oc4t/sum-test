#!/usr/bin/env bash
set -Eeuo pipefail

ARTIFACT_DIR="${ARTIFACT_DIR:-artifacts}"
NAMESPACE="userns-causal"
PSA_NAMESPACE="userns-psa"
HOST_SENTINEL_DIR="/var/lib/userns-causal-poc"
NODE_NAME="$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')"

mkdir -p "$ARTIFACT_DIR"
RESULTS="$ARTIFACT_DIR/results.tsv"
ENVIRONMENT="$ARTIFACT_DIR/environment.txt"

printf 'phase\tpod\thostUsers\tinside_uid\tuid_map\tcontainer_userns\thost_uid\thost_userns\tsentinel_read\tsentinel_write\tnegative_network\timage_id\n' > "$RESULTS"

{
  printf 'date_utc='; date -u +%FT%TZ
  printf 'kernel='; uname -r
  printf 'kubernetes='; kubectl version -o json | jq -c .
  printf 'node='; kubectl get node "$NODE_NAME" -o json | jq -c '{name:.metadata.name,kernel:.status.nodeInfo.kernelVersion,containerRuntime:.status.nodeInfo.containerRuntimeVersion,kubelet:.status.nodeInfo.kubeletVersion,osImage:.status.nodeInfo.osImage}'
  printf 'mounts='; findmnt -J / /var/lib/rancher 2>/dev/null || true
  printf 'k3s='; sudo k3s --version || true
  printf 'crictl='; sudo k3s crictl --version || true
  printf 'runc='; sudo find /var/lib/rancher/k3s/data -type f -name runc -perm -111 -print -quit | xargs -r sudo sh -c '"$1" --version' sh || true
} > "$ENVIRONMENT" 2>&1

sudo install -d -m 0755 "$HOST_SENTINEL_DIR"
printf 'host-root-only\n' | sudo tee "$HOST_SENTINEL_DIR/sentinel" >/dev/null
sudo chown 0:0 "$HOST_SENTINEL_DIR/sentinel"
sudo chmod 0600 "$HOST_SENTINEL_DIR/sentinel"

kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -

cat <<EOF | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo
  namespace: ${NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: echo
  template:
    metadata:
      labels:
        app: echo
    spec:
      containers:
      - name: echo
        image: hashicorp/http-echo:1.0
        args: ["-text=negative-control-ok"]
        ports:
        - containerPort: 5678
---
apiVersion: v1
kind: Service
metadata:
  name: echo
  namespace: ${NAMESPACE}
spec:
  selector:
    app: echo
  ports:
  - port: 5678
    targetPort: 5678
EOF
kubectl -n "$NAMESPACE" rollout status deployment/echo --timeout=120s

cleanup_pod() {
  kubectl -n "$NAMESPACE" delete pod userns-probe --ignore-not-found --wait=true >/dev/null
}
trap cleanup_pod EXIT

run_phase() {
  local phase="$1"
  local host_users="$2"

  cleanup_pod
  cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: userns-probe
  namespace: ${NAMESPACE}
  labels:
    experiment: userns-causal
    phase: ${phase}
spec:
  nodeName: ${NODE_NAME}
  hostUsers: ${host_users}
  restartPolicy: Never
  containers:
  - name: probe
    image: busybox:1.36.1
    command: ["sh", "-c", "sleep 3600"]
    securityContext:
      runAsUser: 0
      runAsGroup: 0
    volumeMounts:
    - name: host-sentinel
      mountPath: /host-sentinel
  volumes:
  - name: host-sentinel
    hostPath:
      path: ${HOST_SENTINEL_DIR}
      type: Directory
EOF

  if ! kubectl -n "$NAMESPACE" wait --for=condition=Ready pod/userns-probe --timeout=120s; then
    kubectl -n "$NAMESPACE" describe pod userns-probe > "$ARTIFACT_DIR/${phase}-describe.txt" || true
    kubectl -n "$NAMESPACE" get events --sort-by=.lastTimestamp > "$ARTIFACT_DIR/${phase}-events.txt" || true
    printf '%s\tuserns-probe\t%s\tPOD_NOT_READY\n' "$phase" "$host_users" >> "$RESULTS"
    return 0
  fi

  local cid pid inside_uid uid_map container_userns host_uid host_userns sentinel_read sentinel_write negative_network image_id
  cid="$(sudo k3s crictl ps --name userns-probe -q | head -n1)"
  pid="$(sudo k3s crictl inspect "$cid" | jq -r '.info.pid // .status.pid // empty')"
  inside_uid="$(kubectl -n "$NAMESPACE" exec userns-probe -- id -u | tr -d '\r')"
  uid_map="$(kubectl -n "$NAMESPACE" exec userns-probe -- cat /proc/self/uid_map | awk '{$1=$1};1' | paste -sd ';' -)"
  container_userns="$(kubectl -n "$NAMESPACE" exec userns-probe -- readlink /proc/self/ns/user | tr -d '\r')"
  host_uid="$(sudo awk '/^Uid:/{print $2}' "/proc/${pid}/status")"
  host_userns="$(sudo readlink "/proc/${pid}/ns/user")"
  image_id="$(kubectl -n "$NAMESPACE" get pod userns-probe -o jsonpath='{.status.containerStatuses[0].imageID}')"

  if kubectl -n "$NAMESPACE" exec userns-probe -- sh -c 'test "$(cat /host-sentinel/sentinel)" = host-root-only'; then
    sentinel_read=success
  else
    sentinel_read=blocked
  fi
  if kubectl -n "$NAMESPACE" exec userns-probe -- sh -c 'printf x >> /host-sentinel/sentinel'; then
    sentinel_write=success
  else
    sentinel_write=blocked
  fi
  if kubectl -n "$NAMESPACE" exec userns-probe -- wget -qO- --timeout=5 "http://echo.${NAMESPACE}.svc.cluster.local:5678" | grep -q negative-control-ok; then
    negative_network=success
  else
    negative_network=failed
  fi

  printf '%s\tuserns-probe\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$phase" "$host_users" "$inside_uid" "$uid_map" "$container_userns" "$host_uid" "$host_userns" \
    "$sentinel_read" "$sentinel_write" "$negative_network" "$image_id" >> "$RESULTS"
}

# Reversal design: the only intended treatment change is hostUsers.
run_phase control_before true
run_phase treatment false
run_phase control_after true

kubectl create namespace "$PSA_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace "$PSA_NAMESPACE" pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/enforce-version=v1.36 --overwrite

psa_probe() {
  local name="$1"
  local host_users="$2"
  local output rc
  set +e
  output="$(cat <<EOF | kubectl apply -f - 2>&1
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  namespace: ${PSA_NAMESPACE}
spec:
  hostUsers: ${host_users}
  restartPolicy: Never
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: probe
    image: busybox:1.36.1
    command: ["sh", "-c", "id && sleep 30"]
    securityContext:
      runAsUser: 0
      runAsNonRoot: false
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
EOF
)"
  rc=$?
  set -e
  jq -n --arg name "$name" --argjson hostUsers "$host_users" --argjson rc "$rc" --arg output "$output" \
    '{pod:$name,hostUsers:$hostUsers,admitted:($rc==0),kubectlOutput:$output}' >> "$ARTIFACT_DIR/psa-results.jsonl"
}

psa_probe psa-control true
psa_probe psa-treatment false

python3 - "$RESULTS" "$ARTIFACT_DIR/summary.json" <<'PY'
import csv, json, sys

rows = list(csv.DictReader(open(sys.argv[1], encoding="utf-8"), delimiter="\t"))
normal = [r for r in rows if r.get("inside_uid") != "POD_NOT_READY"]
by_phase = {r["phase"]: r for r in normal}

def changed(field):
    before = by_phase.get("control_before", {}).get(field)
    treatment = by_phase.get("treatment", {}).get(field)
    after = by_phase.get("control_after", {}).get(field)
    return before == after and treatment != before

summary = {
    "complete_triplet": len(normal) == 3,
    "uid_map_reversal": changed("uid_map"),
    "host_uid_reversal": changed("host_uid"),
    "userns_inode_reversal": changed("container_userns"),
    "sentinel_read_reversal": changed("sentinel_read"),
    "sentinel_write_reversal": changed("sentinel_write"),
    "negative_network_stable": len({r.get("negative_network") for r in normal}) == 1,
    "image_digest_stable": len({r.get("image_id") for r in normal}) == 1,
    "rows": rows,
}
with open(sys.argv[2], "w", encoding="utf-8") as f:
    json.dump(summary, f, ensure_ascii=False, indent=2)
print(json.dumps(summary, ensure_ascii=False, indent=2))
PY

kubectl get pods -A -o wide > "$ARTIFACT_DIR/pods.txt"
kubectl get events -A --sort-by=.lastTimestamp > "$ARTIFACT_DIR/events.txt"

