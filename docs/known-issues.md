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

## S2 — webhook circuit breaker is in-memory, not persisted

`webhook/app.py`'s circuit breaker (decision 4,
`docs/cadrage-s2-webhook-response.md`) keeps its 5-minute sliding
window of real isolations as a plain in-process `deque`, not backed by
Redis/etcd/a K8s resource. A restart of the `webhook` pod (crash,
`kubectl rollout restart`, node eviction, `replicas: 1` reschedule)
silently resets the count to zero. This is a deliberate scope
trade-off for a portfolio project, not an oversight — the circuit
breaker's job is bounding a burst of real actions during the pod's
current lifetime, not serving as a durable audit trail (that's what
the structured incident logs shipped to Loki are for). Do not treat
"3 isolations since last restart" as "3 isolations in the last 5
minutes, ever" when reading `circuit_breaker_trips_total`.

## S2 — `/release` shares the same token as `/webhook`

No separate analyst-only credential exists (decision 8,
`docs/cadrage-s2-webhook-response.md`) — whoever holds the shared
webhook token (Falcosidekick's config, or a human calling `/release`
directly) can do both. Acceptable for a single-operator portfolio
cluster; would need a second, narrower-scoped token before this
pattern is reused where multiple people/services hold the token.

## S2 — webhook `/metrics` is served on two ports, only one NodePort-exposed

`vm-monitoring`'s Prometheus (Docker Compose stack, outside the K3s
cluster — see the Loki reachability entry above) has no route to the
K3s pod network (`10.42.0.0/24`) or `*.svc.cluster.local` DNS; every
other scrape target in `devops-saas-platform`'s
`prometheus.yml.j2` is node-level (`node_exporter`/`patroni` run
directly on VMs), not a K8s `ClusterIP` Service — there was no
existing pattern to copy for this. Resolved by giving the webhook a
second, dedicated metrics-only port: `webhook/app.py`'s `main()` (the
container's actual entrypoint, see `Dockerfile`) starts
`prometheus_client`'s own standalone HTTP server on `:9090` in
addition to the FastAPI app's own `/metrics` route on `:8080`. Only
`:9090` is `NodePort`-exposed (`gitops/webhook/service.yaml`,
`webhook-metrics` Service, `nodePort: 30090`) — it can only ever serve
`/metrics`, nothing else, so exposing it outside the cluster doesn't
widen the isolation-endpoint attack surface. `:8080` (`/webhook`,
`/release`, `/healthz`, and its own `/metrics`) stays on the
`ClusterIP`-only `falco-webhook` Service, matching the validation
sequence's `curl http://webhook:8080/metrics` step. `main()` only runs
as the container entrypoint (`if __name__ == "__main__":`), never on
`import app` — `webhook/tests/` never binds either port.

## S2 — pod-controller behavior under isolation: observed result (live validation, 2026-07-22)

Decision 12 (`docs/cadrage-s2-webhook-response.md`): the webhook never
deletes the isolated pod, only labels it and creates a deny-all
`NetworkPolicy` (Ingress + Egress). The open question was whether the
pod's own controller (Deployment/ReplicaSet) would replace it
independently once its liveness/readiness probe started failing under
isolation.

**Live validation performed** against `DRY_RUN=false` (temporarily
flipped via GitOps, reverted after): a disposable `nginx:1.27`
Deployment (`test-real-controlled`, namespace `default`, 1 replica,
liveness probe `httpGet :80/`, `periodSeconds=5`, `failureThreshold=1`)
was created, a real shell spawned inside it via `kubectl exec ... sh`
at `2026-07-22T12:36:28.046Z`. The webhook's structured incident log
confirmed real isolation (`action="isolated"`) and the deny-all
`NetworkPolicy` (`quarantine-test-real-controlled-78bf7747f6-8lpd4`)
existed by `2026-07-22T12:36:28.5Z` (sub-second, consistent with the
bare-pod case below).

**Observed result: the pod was never killed or replaced.** Polled
every 5s for 4.5 minutes immediately after isolation, then confirmed
again via `kubectl describe pod` ~20 minutes after creation:
`Restart Count: 0` throughout, same pod name/UID the entire time, no
`Unhealthy`/`Killing`/`BackOff` event ever appeared in
`kubectl get events -n default` for this pod — only the normal
`Scheduled`/`Pulled`/`Created`/`Started` events from initial creation.

**Root cause, verified directly, not assumed**: the `NetworkPolicy`
*is* enforced for pod-to-pod traffic — a separate test pod on the same
node, issuing `curl` directly at the isolated pod's IP, got
`Connection refused` in ~1ms. But the isolated nginx pod's own access
log showed `kube-probe/1.29` succeeding with `200` responses every 5
seconds, continuously, for the entire isolation window (12+ minutes
observed) — the kubelet's own liveness/readiness probe traffic was
never blocked. This cluster runs vanilla k3s (`v1.29.4+k3s1`) with its
embedded flannel + kube-router-based `NetworkPolicy` enforcement (no
separate CNI controller pod visible in `kube-system` — enforcement is
built into the k3s agent/server binary). On this stack, kubelet health
probes are same-node, locally-routed traffic that bypasses the
overlay-network path the netpol rules actually filter, while
cross-node/cross-pod traffic over the overlay is correctly blocked.

**Practical consequence for this project**: decision 12's assumed
failure mode (isolation triggers a probe failure → controller restarts
the pod → investigation window destroyed) **does not manifest on this
cluster**, for any Deployment-backed workload, because kubelet probes
are always node-local by construction. The manual mitigation described
in decision 12 (remove probes / scale down before a prolonged
investigation) is not required in practice here — but this is a
property of k3s's specific `NetworkPolicy` enforcement implementation,
not a general Kubernetes guarantee. A cluster running Calico, Cilium,
or another CNI with a different (and more complete) `NetworkPolicy`
enforcement path could behave differently, i.e. actually block kubelet
probe traffic and hit the original decision-12 concern. This finding
is scoped to this cluster's actual CNI, not a universal claim about
Kubernetes `NetworkPolicy` behavior.

## S2 — image tag bootstrap in `gitops/webhook/deployment.yaml` (resolved)

`.github/workflows/ci.yml`'s `build-push-webhook` job only publishes
an image once a commit lands on `main` (tag = that commit's SHA, never
`latest`). The Deployment manifest that references this image was
necessarily committed *before* that first image existed, so
`gitops/webhook/deployment.yaml` briefly shipped with a placeholder
tag (`PENDING_FIRST_BUILD`), replaced with the real SHA
(`c84b02bb637d60391d5115f6e608c02033c00315`) in a follow-up commit
once CI confirmed (`gh run watch`) that first image was published. A
one-time bootstrap ordering issue, not a recurring one: every commit
after this one has its image built before (or in the same push as)
any manifest change referencing it, so no future commit needs this
two-step dance — a normal image tag bump is a single commit.

## S2 — `celery`/`rabbitmq` have zero automated isolation coverage (security trade-off, not blast-radius)

Live S2 validation (2026-07-22) found that `celery` and `rabbitmq`'s
exec-based liveness/readiness probes invoke a shell every 5-15s, which
trips rule 1 ("Shell Spawned in Container") continuously — the rule as
currently written cannot distinguish a kubelet-issued probe exec from
an attacker's interactive shell. The initial fix added both namespaces
to the same protected-namespace list as `argocd`/`vault`/`kube-system`/
`falco` (decision 11), which conflated two different things:

- Decision 11's original four are a **blast-radius** exception:
  isolating them would break the platform's own control plane, and
  that stays true no matter how good the detection is. Permanent by
  design.
- `celery`/`rabbitmq` are a **security trade-off**: the webhook refuses
  to isolate them purely because rule 1 can't tell probe noise from a
  real shell yet. This is not a statement that compromise in these
  namespaces is lower-risk — it means genuine shell-based compromise in
  either namespace currently gets **zero automated isolation
  coverage**, identical to a false positive from a health check.
  Falco still logs the alert (S1 detection is unaffected), but S2's
  automated response takes no action either way.

`webhook/app.py` now tracks these as two separate sets
(`CRITICAL_NAMESPACES`, `NOISY_PROBE_NAMESPACES`) with distinct
`log_incident` actions (`refused_protected_namespace` vs
`refused_noisy_probe_namespace`) so the two reasons stay
distinguishable in the structured incident logs (decision 6) instead
of collapsing into one indistinguishable category.

**Not yet implemented** — the actual fix, to close this coverage gap
without reintroducing the probe noise:

- Tune rule 1 to exclude the exact probe command patterns from each
  deployment's spec (the probe command is known and static per
  Deployment), or
- Use process lineage (parent process from a kubelet exec vs. an
  interactive shell) to distinguish legitimate health checks from real
  compromise at the Falco rule level, rather than at the webhook.

Once either is in place and validated against both namespaces, remove
`celery`/`rabbitmq` from `NOISY_PROBE_NAMESPACES` — this list is a
temporary mitigation, not a permanent design choice like
`CRITICAL_NAMESPACES`.

**Systemic observation (2026-07-22, live traffic)**: the same
exec-probe false-positive pattern is also observed live against
`vault` (`vault-0`, protected via `CRITICAL_NAMESPACES` for blast-radius
reasons, independent of this trade-off) — rule 1 is tripping on
kubelet-issued probe execs in at least three namespaces now
(`vault`, `celery`, `rabbitmq`), not just the two patched here. This
confirms the false-positive rate is a property of rule 1 itself, not
an artifact specific to celery/rabbitmq's workload — the eventual fix
(probe-aware exclusion or process-lineage detection) noted above
applies cluster-wide, not just to these two namespaces.

## S2 — same-pod event deduplication (decision 7): confirmed working, live validation, 2026-07-22

Distinct from the circuit-breaker test above (which used 4 different
pods to trip the threshold). This tested decision 7's dedup path
specifically: one disposable pod (`dedup-test-1`, `nginx:1.27`,
namespace `default`), `DRY_RUN=false` temporarily via GitOps
(`test(s2): activation réelle temporaire... gaps 1-2`, reverted in
`test(s2): retour DRY_RUN=true... gaps 1-2`), a real shell spawned on
it three times within ~3 seconds via `kubectl exec ... sh`.

**Result**: first exec → `action="isolated"`, `result="isolated"`,
`latency_ms=81.67`. Second and third execs (14:39:08.85Z and
14:39:10.24Z) → `action="deduplicated"`, `result="skipped"` both
times, no `latency_ms` (short-circuited before the timed section, per
`webhook/app.py`). `kubectl get networkpolicy -n default` showed
exactly one `NetworkPolicy` (`quarantine-dedup-test-1`) throughout, and
`/metrics` after the run read `isolations_total=1`,
`circuit_breaker_trips_total=0` — confirming the second/third triggers
never reached the isolation code path or the circuit breaker counter,
exactly as decision 7 specifies. Test pod and its `NetworkPolicy`
deleted after validation.

## S2 — Loki incident visibility (decision 6): fixed, direct push to Loki's HTTP API

**Fixed 2026-07-24** (superseding the "label guess was wrong" entry
below, kept for the diagnostic history): `webhook/app.py`'s
`log_incident()` now pushes each structured incident directly to
Loki's push API (`POST /loki/api/v1/push`), in addition to the
existing stdout JSON, using `job="webhook-incidents"` as a single
static label (decision 6) -- the JSON detail stays in the log line
body, never promoted to per-field labels, to avoid a high-cardinality
label explosion (a distinct series per `pod_name`/`namespace`/etc.).
Same vm-monitoring Loki instance and hostport Falcosidekick already
uses (`gitops/falcosidekick/values.yaml`'s `config.loki.hostport`,
`gitops/webhook/deployment.yaml`'s `LOKI_PUSH_URL` env var) -- no new
UFW rule, same reachability path already established for S1. Format
verified directly against the running Loki 3.0.0
(`/loki/api/v1/status/buildinfo`) before writing any code: a manual
`curl -X POST .../loki/api/v1/push` with a
`{"streams": [{"stream": {...}, "values": [[<ns>, <line>]]}]}` body
returned `204`, and a follow-up `query_range` read it back.

Fire-and-forget with a 2-second timeout: a Loki outage only logs a
stdout warning, never blocks or fails the isolation/release action
itself (fail-open, decision 5) -- covered by
`test_loki_push_failure_does_not_fail_the_request`
(`webhook/tests/test_app.py`).

**Live validation, 2026-07-24**: disposable pod `loki-gap2-clean`
(`nginx:1.27`, namespace `default`), real shell via `kubectl exec`,
`DRY_RUN=false` temporarily via GitOps (reverted immediately after).
`{job="webhook-incidents"} |= "loki-gap2-clean"` returned exactly one
entry: `action="isolated"`, `result="isolated"`, `latency_ms=96.79`,
`falco_rule`, `mitre_technique`, `namespace`, `pod_name` all populated
-- every field decision 6 asks for, queryable in Loki for real, closing
the gap this entry originally documented as open.

**A real bug was found and fixed during this same live validation**,
not just the expected happy path -- see the next entry
("self-triggering feedback loop") for what it was and how it was
caught.

## S2 — Loki push created a self-triggering feedback loop on the webhook's own pod (found and fixed, 2026-07-24)

The first implementation of the Loki push above (see previous entry)
used `urllib.request.urlopen()`, which opens a brand-new TCP connection
for every single push -- no connection reuse. Live-validated
consequence: the webhook pod's own egress to Loki (an external IP, see
"Real IP address committed" entry below) is itself traffic that Falco
monitors from that pod's network namespace. `webhook` lives in the
`falco` namespace (`CRITICAL_NAMESPACES`, decision 11), so every one of
these self-triggered "Custom - Unexpected Outbound Connection" alerts
was correctly refused (`action="refused_protected_namespace"`, never a
real isolation) -- but refusing still calls `log_incident()`, which
pushed to Loki again, opening another new connection, tripping another
alert, refused again, pushed again... a self-sustaining loop entirely
contained within the webhook's own request-handling path.

**Observed live** (`DRY_RUN=false` validation window, before the fix):
a sustained stream of `refused_protected_namespace` entries for
`pod_name="webhook-<hash>"`, roughly 1/second sustained (some bursts
tighter), webhook pod CPU at 112m of its 200m limit (vs. 4m at rest
after the fix), confirmed via `kubectl top pod` and direct Loki queries
returning over a thousand matching lines for a few minutes of window.
Not a runaway explosion (bounded by request-handling throughput, and
namespace=falco means never a real isolation or circuit-breaker
increment either way) but a real, self-inflicted noise source and
wasted egress against `vm-monitoring`, not something to ship.

**Root cause, verified directly**: Falcosidekick's own Loki output
does *not* show up as a repeating source of this same alert on its own
pod (also in the protected `falco` namespace) because it reuses one
persistent HTTP connection across pushes -- the TCP handshake, which is
what the Falco rule actually detects as a "new" connection, happens
once, not once per push.

**Fix**: `webhook/app.py`'s `_push_incident_to_loki()` now uses one
module-level `http.client.HTTPConnection`, created lazily and reused
across pushes (`_loki_connection()`), only reconnecting after a failed
request. This matches Falcosidekick's actual behavior instead of the
initially-assumed equivalence between "same pattern" and "same
library call" -- fire-and-forget with a short timeout was correct;
opening a fresh connection per call was the actual bug. Covered by
`test_loki_connection_is_reused_across_pushes`
(`webhook/tests/test_app.py`): two pushes, one `HTTPConnection`
constructed, `.request()` called twice on it.

**Re-validated after the fix**: same live window, webhook pod CPU back
to 4m, zero `pod_name="webhook-<hash>"` entries in a 35-second window
post-rollout (only the pre-existing, already-documented noisy-probe
events from `celery`/`rabbitmq`/`vault` remained) -- see the previous
entry for the clean re-run of the actual gap-2 validation once this was
fixed.

**Practical lesson for this project**: "mirror Falcosidekick's pattern"
was correct at the level of transport choice (direct HTTP push, no
log-shipping agent) but the first implementation copied the *shape* of
that pattern (fire-and-forget POST) without verifying the specific
mechanic (connection reuse) that made it safe for a pod Falco itself
monitors. Any future direct network call made *from* a pod running
inside a Falco-monitored namespace needs this same check: does the
call reuse a connection, or does it manufacture a new "unexpected
outbound connection" event every time it fires.

## S2 — Loki incident visibility (decision 6): label guess was wrong, and the underlying transport doesn't exist (superseded, fixed 2026-07-24)

**Superseded**: this entry documents the original diagnosis of the
gap; the fix and its live validation are recorded above under
"Loki incident visibility (decision 6): fixed, direct push to Loki's
HTTP API". Kept here for the diagnostic history.

Decision 6 (`docs/cadrage-s2-webhook-response.md`) assumed the
webhook's structured `log_incident()` JSON (stdout, `"log_type":
"webhook_incident"`) would reach Loki as `{job="webhook-incidents"}`
via "the same stdout-scrape mechanism Falcosidekick's own Loki output
relies on" (see `webhook/app.py`'s module docstring, written before
this was verified). This assumption does not hold on this cluster.

**Verified directly, live validation 2026-07-22 (same test window as
the dedup test above)**: `curl` against Loki's label API
(`$LOKI/loki/api/v1/labels`) returns exactly `hostname`, `k8s_ns_name`,
`k8s_pod_name`, `priority`, `rule`, `service_name`, `source`, `tags` —
**no `job` label exists in Loki at all**, and
`{job="webhook-incidents"}` returns zero results for the test window.
Meanwhile `{source="syscall"} |= "dedup-test-1"` returns the expected
three raw Falco events for the same test (confirming Loki itself and
the query path both work fine).

**Root cause**: Falcosidekick's Loki output (`gitops/falcosidekick/values.yaml`,
`loki.hostport`) is a direct HTTP push made by the Falcosidekick pod
itself, driven by the Falco alert it already received in-process — it
is not a generic log-shipping agent and never touches any other pod's
stdout. There is no Promtail/Fluent Bit/Vector/Grafana Agent — or any
other log-shipping DaemonSet — anywhere in this K3s cluster (`kubectl
get daemonset -A` shows only the `falco` DaemonSet itself; `kubectl get
deployment,statefulset -A` shows no such workload in any namespace;
`helm list -A` shows only `vault` besides what ArgoCD manages). The
webhook's own stdout is only visible via `kubectl logs`, ordinary
container-runtime log files on the node — it never reaches Loki under
any label, `job="webhook-incidents"` or otherwise.

**Practical consequence**: decision 6's audit trail exists (the JSON is
written, structured, and correct — verified via `kubectl logs` during
this same test, showing `falco_rule`, `mitre_technique`, `namespace`,
`pod_name`, `action`, `result` all populated correctly), but it is not
centrally queryable in Loki as designed, and does not survive the
webhook pod's log retention/rotation on the node the way S1's Falco
alerts survive in Loki for 15 days. This is a real, unclosed gap, not
a documentation-only correction. Closing it for real would need either:
a log-shipping DaemonSet added to the cluster (disproportionate
operational surface for one pod's structured logs, mirrors the
CRD-controller trade-off already declined in the SOAR maturity note),
or the webhook pushing directly to Loki's push API
(`/loki/api/v1/push`) itself, the same pattern Falcosidekick already
uses for its own output. Neither is implemented; `docs/cadrage-s2-webhook-response.md`'s
checklist item for this is intentionally left unchecked rather than
marked done against a query that returns nothing.

## S2 — RBAC `list` on pods was unused, removed (least-privilege tightening, 2026-07-22)

`gitops/webhook/clusterrole.yaml`'s `webhook-isolator` `ClusterRole`
originally granted `["get", "list", "patch"]` on `pods`. Checked
directly against `webhook/app.py`: the only pod calls anywhere in the
code are `read_namespaced_pod` (`get`, used for decision 7's dedup
check) and `patch_namespaced_pod` (label patch, both the isolate and
`/release` paths) — `list_namespaced_pod` is never called. `list` on
`networkpolicies`, by contrast, **is** used
(`list_namespaced_network_policy` in `/release`, to find the
quarantine `NetworkPolicy` by label selector before deleting it), so
that verb stays.

Tightened `pods` to `["get", "patch"]` (`gitops/webhook/clusterrole.yaml`,
commit `fix(s2): retire 'list' inutilisé sur pods...`). Re-verified
live after the GitOps change synced:
`kubectl auth can-i --list --as=system:serviceaccount:falco:webhook`
now reads `pods [get patch]` / `networkpolicies.networking.k8s.io [get
list create delete patch]` — matching exactly what the code calls, one
verb narrower than the RBAC audit originally recorded in
`docs/cadrage-s2-webhook-response.md`. A correction to an already-live
RBAC grant, not a change in behavior: nothing in `webhook/app.py` ever
relied on listing pods.
