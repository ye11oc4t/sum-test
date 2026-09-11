# Kubernetes UserNS causal PoC

This harness tests whether a security-relevant runtime outcome can be attributed
to pod-level Kubernetes User Namespaces (`spec.hostUsers: false`). It uses a
reversal design: `true -> false -> true` while pinning the same image, node,
security context, host sentinel, and network target.

The initial Go/No-Go evidence is:

1. treatment receipt: UID map, host-observed UID, and user namespace inode;
2. host-impact proxy: `CAP_SYS_MODULE` authority, tested using a deliberately
   invalid module. A host-authorized call reaches module-format validation,
   whereas a capability scoped to a child UserNS should fail at permission
   checking. No valid module is loaded;
3. negative controls: explicitly mounted `hostPath` access and service network
   reachability should remain stable;
4. native-policy control: Pod Security Admission behavior for UID 0 with and
   without pod UserNS.

The sentinel is created only on the disposable GitHub-hosted runner. The test
does not exploit a CVE or target any external system.
