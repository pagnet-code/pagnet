# Pagnet client in Kubernetes

The client image is `ghcr.io/pagnet-code/pagnet`. It runs the outbound-only
Pagnet daemon, not the control plane. The chart creates no Service or Ingress.
Use a Linux cluster and select a published image tag or set `image.digest` to a
`sha256:` manifest digest. The first install below uses `latest` explicitly;
production deployments should select a tested release tag.

New GHCR packages may require registry authentication. If the image is private,
create a Kubernetes image pull Secret in the `pagnet` namespace using a protected
Docker config file, and pass its name with `--set-string
image.pullSecrets[0]=ghcr-auth` to the Helm command below. Do not place registry
tokens in Helm values. Once the package is public, this option can be omitted.

From the repository root, create an external Secret using a file containing
only the one-time enrollment token, then install:

```bash
kubectl create namespace pagnet
kubectl -n pagnet create secret generic pagnet-enrollment \
  --from-file=token=/secure/path/pagnet-enrollment-token
helm upgrade --install pagnet ./helm/pagnet-client \
  --namespace pagnet \
  --set-string image.tag=latest \
  --set-string enrollment.existingSecret=pagnet-enrollment \
  --set-string enrollment.server=https://app.pagnet.dev \
  --set-string enrollment.name=kubernetes-client
```

Replace the server URL if your control plane is elsewhere. In Pagnet, open
**Hosts → Add host** and create a one-time enrollment token before installing.
The Secret
must use the key `token`; the chart neither creates a Secret nor accepts a
plaintext token value. The token is exposed only to the init container through
`PAGNET_ENROLL_TOKEN`, never to the daemon. Do not put tokens in Helm values,
command arguments, Git, or deployment logs.

The init container enrolls account `default` only when the state directory is
empty, with `/workspace` as the sole allowed root (`allow_list`). An existing
nonempty account config skips enrollment; an empty/nonregular config or partial
state without that config fails closed. The daemon validates the existing
account and uses `--require-enrolled --non-interactive --no-auto-update`, so
invalid or incomplete enrollment cannot silently mint a replacement identity.
Investigate and restore damaged state from a trusted backup rather than deleting
it to trigger enrollment. Changing the server or name values does not reenroll
an existing account.

After successful enrollment, the one-time token can be revoked and the Secret
removed. Its reference is optional at pod startup so an enrolled pod can restart
without it; a fresh state directory still requires the Secret. Keep
`enrollment.existingSecret` set to the same reference in Helm values.

The chart runs one replica with a `Recreate` strategy and a ReadWriteOnce PVC.
It retains a chart-created PVC on uninstall (`helm.sh/resource-policy: keep`);
back up the state securely because it contains host credentials and identity.
Reinstalling with a retained PVC may require setting `persistence.existingClaim`
to its name. Select an existing state PVC with:

```bash
helm upgrade --install pagnet ./helm/pagnet-client --namespace pagnet \
  --set-string enrollment.existingSecret=pagnet-enrollment \
  --set-string persistence.existingClaim=pagnet-state
```

`persistence.size` defaults to `1Gi`; `persistence.storageClass` uses the cluster
default unless set. Existing storage must permit UID/GID `10001` to write;
`fsGroup: 10001` requests group access where the storage driver supports it.
Do not share a state volume between independent clients or scale replicas.

`/workspace` defaults to an ephemeral `emptyDir`. Set
`workspace.existingClaim` for persistent workspace files. No host directories
are mounted. Automatic workspace scanning is disabled with
`PAGNET_SCAN_WORKSPACES=0`. Both containers run without root, privileges, added
capabilities, service-account credentials, or a writable root filesystem;
`/tmp` is writable ephemeral storage. `HOME=/var/lib/pagnet/home` is a private
mode-0700 directory on the state PVC, separate from the enrollment state. Image updates are performed through Helm,
not by daemon self-update.

The base image contains the daemon only. Runtime CLIs such as Codex, Claude,
Gemini, or Qwen, their authentication, and their dependencies must be supplied
separately before runtime execution will work. A derived image must preserve
the nonroot user, writable-path assumptions, and the shell used by enrollment.
Native worker containment relies on Linux Landlock support and the cluster's
seccomp policy allowing the required Landlock syscalls. A cluster that blocks
these syscalls, or a kernel lacking the required Landlock ABI, can run into
runtime execution failures; validate runtime containment on the actual cluster.
Do not weaken confinement to work around an unsupported runtime environment.

Check rollout with `kubectl -n pagnet rollout status deployment/pagnet-pagnet-client`
and inspect daemon logs with `kubectl -n pagnet logs deployment/pagnet-pagnet-client`.
Enrollment failures are in the `enroll` init container logs. No live cluster
installation is required for chart checks (Helm 3+, Python 3, and PyYAML):

```bash
python3 helm/pagnet-client/tests/check.py
```
