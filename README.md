# Rootless Kubernetes Residual-Authority PoC

이 PoC는 Kubernetes 노드 런타임이 침해된 뒤의 권한을 두 층으로 나눠 측정합니다.

1. **호스트 격리:** 실제 호스트의 root 소유 파일을 변경할 수 있는가?
2. **잔존 오케스트레이션 권한:** 호스트 root를 얻지 못해도 CRI, kubelet 자격증명, Pod 데이터에 접근할 수 있는가?

실제 CVE exploit은 실행하지 않습니다. 공격자가 kubelet/containerd와 같은 노드 구성요소의 실행 문맥을 획득한 **post-compromise 상태**를 `docker exec`로 안전하게 모사합니다. 인터넷에 노출된 클러스터나 운영 환경에서 실행하지 마세요.

## 연구 가설

- H1: Rootless 환경에서는 노드 내부 UID 0이 호스트의 실제 UID 0으로 매핑되지 않으므로 root 소유 canary 쓰기가 차단된다.
- H2: 그러나 노드 내부에서 containerd socket과 kubelet 파일에 접근할 수 있으므로 동일 노드의 workload와 해당 workload가 참조하는 Secret은 여전히 침해될 수 있다.
- H3: 따라서 `host containment`와 `workload/orchestration containment`는 동일한 보안 속성이 아니다.

## 실험 설계의 한계

이 번들은 재현성이 높은 kind 기반 Go/No-Go 실험입니다. kind 노드는 Docker 컨테이너이므로, 최종 논문에는 다음 보강이 필요합니다.

- 핵심 결과를 직접 실행한 rootless kubelet 또는 별도 worker node에서 재현
- 단일 control-plane kind 노드의 `/etc/kubernetes/admin.conf` 결과는 논문 주장에 사용하지 않음
- Kubelet client credential 결과와 CRI 결과를 분리하여 해석
- 임의 명령 목록이 아니라 공개된 kubelet/containerd/runc/CRI-O CVE의 post-condition으로 probe 집합을 확장

## 요구사항

- 전용 Ubuntu 24.04 실험 VM 2대 권장
- cgroup v2
- Docker Engine 20.10+
- 또는 Rootless Podman 3.0+
- 한 VM은 rootful Docker, 다른 VM은 rootless Docker
- `kind`, `kubectl`, `python3`
- 실험 VM의 sudo 권한

Kubernetes v1.37 공식 kind node image가 준비되어 있다면 `POC_NODE_IMAGE`로 지정하세요. 기본값은 공개 검증된 `kindest/node:v1.36.1`입니다. Rootless 노드 구성 원리는 동일하며, 논문 결과를 주장할 때는 반드시 실제 사용 버전과 이미지 digest를 기록해야 합니다.

## 실행

### 1. 두 VM에서 사전 점검

```bash
./scripts/prereq-check.sh rootful
./scripts/prereq-check.sh rootless
```

Rootless VM에서는 일반 사용자로 실행하고 Docker rootless context 또는 socket을 선택해야 합니다.

```bash
export DOCKER_HOST="unix:///run/user/$(id -u)/docker.sock"
docker info
```

Rootless Podman을 쓰는 경우:

```bash
export POC_PROVIDER=podman
podman info --format '{{.Host.Security.Rootless}}'
```

### 2. 각 VM에서 실험 실행

Rootful VM:

```bash
./scripts/run-case.sh rootful
```

Rootless VM:

```bash
export DOCKER_HOST="unix:///run/user/$(id -u)/docker.sock"
./scripts/run-case.sh rootless
```

또는 Rootless Podman:

```bash
POC_PROVIDER=podman ./scripts/run-case.sh rootless
```

결과는 각각 `results/rootful.tsv`, `results/rootless.tsv`에 저장됩니다. 두 파일을 한 VM으로 모은 뒤 비교합니다.

```bash
python3 scripts/compare.py results/rootful.tsv results/rootless.tsv \
  --output results/comparison.md
```

### 3. 정리

```bash
./scripts/cleanup.sh rootful
./scripts/cleanup.sh rootless
```

## Go/No-Go 판정

`compare.py`는 아래 조건으로 예비 판정을 냅니다.

- **GO:** Rootful만 host canary를 변경할 수 있고, Rootless에서도 CRI를 통해 다른 Pod의 합성 Secret을 읽을 수 있음
- **NO-GO:** Rootless의 호스트 보호 차이가 없거나, 잔존 workload 권한이 확인되지 않음
- **INDETERMINATE:** 도구 누락, Pod 미기동, kubelet kubeconfig 위치 차이 등으로 probe가 완료되지 않음

GO가 나와도 곧바로 논문 결론은 아닙니다. 이는 “연구할 만한 보안 경계 차이가 존재한다”는 사전 증거입니다.
