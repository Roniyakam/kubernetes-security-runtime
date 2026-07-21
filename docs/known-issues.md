# Known issues and trade-offs — S1

## Falcosidekick version is pinned by the Falco chart, not chosen independently

`falcosecurity/falco` 9.1.0 bundles Falcosidekick as a subchart
(`condition: falcosidekick.enabled`) pinned to `0.12.*`
(app version 2.x, exact patch resolved at `helm dependency` time) —
**not** the `0.14.0` chart / `2.31.1` app version available standalone
in the same `falcosecurity/charts` repo. This repo intentionally uses
the bundled subchart (one Helm release, one ArgoCD Application, and
`falco.http_output` auto-wired to it — see
`gitops/falco/values.yaml`) rather than deploying Falcosidekick as a
second, independently-versioned Application. Trade-off: Falcosidekick's
version is a step behind whatever the standalone chart offers until
the falco chart's own `Chart.yaml` dependency constraint is bumped
upstream.

## Grafana Explore validation query is `{source="syscall"}`, not `{job="falco"}`

Falcosidekick's Loki output sets exactly these labels by default:
`rule`, `source`, `priority`, plus `k8s_ns_name`/`k8s_pod_name` when
present (verified against `falcosidekick` 2.31.1
`outputs/loki.go`). There is no `job` label unless explicitly added —
Falcosidekick has no config knob for a static custom label, only
`extralabels` (promotes existing *event* fields, and Falco events
don't carry a field named `job`). `source` is Falco's own event source
field, which is `"syscall"` for every rule in
`gitops/falco/custom-rules.yaml` (all are kernel/syscall-based, not
k8s audit). Correct validation query:
`{source="syscall"}`, optionally narrowed with
`{source="syscall", rule="Terminal shell in container"}`.

## grpc_output confirmed absent

Verified against `helm show values falcosecurity/falco --version
9.1.0` (2026-07-21): no `grpc_output` key anywhere in the chart's
values schema, and `helm template` output contains no gRPC-related
resources. `falco.http_output` (auto-wired to Falcosidekick, see
`gitops/falco/values.yaml`) is the only output configured.

## `fd.rip` rejects CIDR notation — use `fd.rnet`

`fd.rip` only accepts literal IP addresses; the CIDR list
(`10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8`) in
"Custom - Unexpected Outbound Connection"
(`gitops/falco/custom-rules.yaml`) made Falco 0.44.1 fail rule
compilation with `LOAD_ERR_COMPILE_CONDITION`, crash-looping the
`falco` container on every node. Root cause: `fd.rip` is a
single-address field; `fd.rnet` is the dedicated network/CIDR-matching
field. Fix: replaced `fd.rip in (...)` with `fd.rnet in (...)`.
Verified with `falco --validate` against the running 0.44.1 image
(commit `b2baa0f`).

## `fullnameOverride` doesn't cascade into the bundled `falcosidekick` subchart

`falco.falcosidekickConfig` computes `http_output.url` as
`http://<falco-fullname>-falcosidekick` (`http://falco-falcosidekick`,
from `gitops/falco/values.yaml`'s `fullnameOverride: "falco"`) but
never reads the `falcosidekick` subchart's own values. Root cause:
without a matching `fullnameOverride` in
`gitops/falcosidekick/values.yaml`, the subchart's Service defaulted
to the release-name-derived
`kubernetes-security-runtime-falcosidekick` — an NXDOMAIN target from
Falco's point of view, so every alert was silently dropped before
reaching Falcosidekick/Loki (no error logged by either side). Fix:
pinned `falcosidekick.fullnameOverride: "falco-falcosidekick"`
explicitly in `gitops/falcosidekick/values.yaml` to match what
`falco.falcosidekickConfig` computes. Verified with `helm template`
that this produces a Service name matching the computed
`http_output.url` (commit `0f15f77`).

## Loki reachability from the K3s cluster (fixed in `devops-saas-platform`)

Falcosidekick's Loki output requires reaching `vm-monitoring:3100`
from pods running on `vm-k8s-master`/`vm-k8s-worker`. As of
2026-07-21, `vm-monitoring`'s Docker Compose stack published Loki's
port as `127.0.0.1:3100:3100` — loopback-only — so the existing UFW
rule allowing the K8s hosts on port 3100 was a no-op (nothing
listened on the external interface). Fixed in `devops-saas-platform`
(`ansible/roles/monitoring/templates/docker-compose.yml.j2`, bound to
`0.0.0.0` instead, same pattern already used there for Grafana/
Patroni/PgBouncer — UFW remains the actual access control).
Reachability re-verified from a pod on the K3s cluster after the fix
(`curl http://<vm-monitoring-ip>:3100/ready` → `200`).

## Real IP address committed in `gitops/falcosidekick/values.yaml`

`falcosidekick.config.loki.hostport` hardcodes `vm-monitoring`'s
public IP. This is a deliberate S1 trade-off for a portfolio project
(the endpoint is only reachable from `vm-k8s-master`/
`vm-k8s-worker` per UFW regardless of who reads this public repo), not
a pattern to copy onto non-portfolio infrastructure. Follow-up before
reuse elsewhere: internal DNS, or a Kubernetes `ExternalName` Service
in the `falco` namespace so the real address lives in one place and
isn't duplicated across every consumer.

## Rule "Unexpected Outbound Connection" (T1048) will be noisy

No per-workload egress allowlist exists yet — see
`docs/threat-model.md` "Known false-positive sources". Acceptable for
S1 (log-only); would need tuning before any automated response is
attached to it in S2.

## Falco's default ruleset is not pinned by this repo

Falco 0.44.x fetches its default rules (including the stock
`"Terminal shell in container"` rule referenced in the validation
sequence) at pod startup via `falcoctl artifact install`/`follow`
init/sidecar containers, from the `falcosecurity` OCI index — not
from a version baked into the `falco` container image or this chart.
`gitops/falco/custom-rules.yaml`'s 6 rules are self-contained (no
dependency on macros from that default ruleset) specifically to avoid
breaking if the fetched ruleset's macro names change between
`falcoctl` pulls.
