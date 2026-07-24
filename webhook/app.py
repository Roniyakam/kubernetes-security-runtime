"""S2 automated-response webhook.

Receives Falcosidekick's forwarded Falco alerts (POST /webhook) and, for
priority=Critical events outside the protected namespaces, isolates the
targeted pod's network access. DRY_RUN=true by default: no Kubernetes API
call is made until this is flipped via GitOps (decision 13,
docs/cadrage-s2-webhook-response.md).

Structured incident logs are written to stdout as JSON with a
"log_type": "webhook_incident" marker (decision 6), and additionally
pushed directly to Loki's HTTP push API (job="webhook-incidents") --
the same direct-push pattern Falcosidekick's own Loki output already
uses for Falco's alerts, since there is no log-shipping agent anywhere
in this cluster to scrape this pod's stdout (see docs/known-issues.md,
"Loki incident visibility" gap). The push is fire-and-forget with a
short timeout: a Loki outage never blocks or fails the underlying
isolation/release action (fail-open, consistent with decision 5).

The push reuses one persistent http.client.HTTPConnection (module-level
_loki_conn) instead of opening a new connection per push. This isn't an
optimization -- a fresh connection per call was live-validated to make
this pod's own egress to Loki repeatedly re-trip Falco's "Unexpected
Outbound Connection" rule on itself (namespace=falco is protected, so
never a real isolation, but every refusal's log_incident() call opened
another new connection, tripping another alert, in a self-sustaining
loop). Reusing one connection means the TCP handshake -- the thing the
rule actually detects -- happens once per pod lifetime, matching how
Falcosidekick's own long-lived Loki output connection behaves. See
docs/known-issues.md.

/metrics is served twice, deliberately: once on the main FastAPI app
(port 8080, ClusterIP-only, alongside /webhook and /release) and once via
prometheus_client's own standalone server (port 9090, main() below). Only
the second is NodePort-exposed for the external Prometheus on
vm-monitoring to scrape -- /webhook and /release never need to leave the
cluster network, so only a metrics-only port does. See
docs/known-issues.md.

Decision 6 addendum: with DRY_RUN=true as the permanent resting state
(decision 13) and GAP 2's fix making every refusal reach Loki, vault's
and celery/rabbitmq's probe-driven refusals (decision 11's protected
namespaces, NOISY_PROBE_NAMESPACES) fire continuously and forever --
expected, low-signal noise that would otherwise flood Loki and bury
real signal on the same namespaces. Only the Loki push for these two
refusal actions is rate-limited, one push per (namespace, action)
combination per 5-minute rolling window, reusing decision 4's
sliding-window pattern keyed per-pair instead of globally
(_loki_refusal_push_allowed()). The Prometheus counters
(refused_protected_namespace_total, refused_noisy_probe_namespace_total)
and the stdout JSON log are never throttled -- only what reaches Loki
changes. See docs/known-issues.md.
"""

import http.client
import json
import logging
import os
import sys
import time
from collections import deque
from datetime import UTC, datetime
from urllib.parse import urlsplit

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    generate_latest,
    start_http_server,
)
from starlette.responses import Response

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger("webhook")

WEBHOOK_TOKEN = os.environ["WEBHOOK_TOKEN"]
DRY_RUN = os.environ.get("DRY_RUN", "true").strip().lower() == "true"

# Same vm-monitoring Loki instance, same hostport Falcosidekick already
# pushes to (gitops/falcosidekick/values.yaml's config.loki.hostport) --
# reachable from the falco namespace via the same UFW-scoped path, no new
# network rule needed. Default matches that committed value; overridable
# via GitOps like every other env var here.
LOKI_PUSH_URL = os.environ.get("LOKI_PUSH_URL", "http://51.15.199.56:3100")
LOKI_PUSH_TIMEOUT_SECONDS = 2
_loki_push_host = urlsplit(LOKI_PUSH_URL)

# Reused across pushes -- see module docstring for why a fresh connection
# per push is not just wasteful but actively harmful here.
_loki_conn: http.client.HTTPConnection | None = None

# Decision 11: blast-radius critical infrastructure, isolating these would
# break the platform itself, permanent by design.
CRITICAL_NAMESPACES = {"argocd", "vault", "kube-system", "falco"}

# Known false-positive source: exec-based liveness/readiness probes trigger
# "Shell Spawned in Container" every 5-15s, indistinguishable from a real
# shell by rule 1 as currently written. This is a SECURITY TRADE-OFF, not a
# blast-radius exception: these namespaces lose real isolation coverage for
# genuine shell-based compromise, not just for probe noise. Temporary
# mitigation, not a permanent design choice. Better fix (not implemented
# yet, tracked in known-issues.md): tune rule 1 to exclude the exact probe
# command patterns from each deployment's spec, or use process lineage
# (parent process from kubelet exec vs interactive shell) to distinguish
# legitimate health checks from real compromise, then remove these
# namespaces from this list once done.
NOISY_PROBE_NAMESPACES = {"celery", "rabbitmq"}

QUARANTINE_LABEL = "security.internal/quarantine-target"

# Decision 4: 5-minute sliding window, trip at 3 real isolations. In-memory
# only -- resets on webhook pod restart, see docs/known-issues.md.
CIRCUIT_BREAKER_WINDOW_SECONDS = 300
CIRCUIT_BREAKER_THRESHOLD = 3

# Decision 5: copied verbatim from docs/threat-model.md's "6 rules -- MITRE
# ATT&CK mapping" table rather than duplicated/redefined independently.
MITRE_MAP = {
    "Custom - Shell Spawned in Container": "T1059",
    "Custom - New User Created in Container": "T1136",
    "Custom - Sudo Usage in Pod": "T1068",
    "Custom - Unexpected Outbound Connection": "T1048",
    "Custom - Write to Sensitive Account File": "T1098",
    "Custom - Unexpected Binary Execution From Writable Path": "T1610",
}

app = FastAPI()

auth_failures_total = Counter(
    "auth_failures_total", "Requests rejected for a missing or invalid Authorization header"
)
isolations_total = Counter("isolations_total", "Real (non-dry-run) pod isolations performed")
circuit_breaker_trips_total = Counter("circuit_breaker_trips_total", "Times the circuit breaker tripped")
refused_protected_namespace_total = Counter(
    "refused_protected_namespace_total",
    "Refusals for critical-infrastructure namespaces (decision 11), by namespace",
    ["namespace"],
)
refused_noisy_probe_namespace_total = Counter(
    "refused_noisy_probe_namespace_total",
    "Refusals for noisy-probe namespaces (decision 11 addendum), by namespace",
    ["namespace"],
)

# Decision 4's sliding window: monotonic timestamps of real isolations only.
_isolation_window: deque[float] = deque()

# Decision 6 addendum: same 5-minute sliding window pattern as decision 4's
# circuit breaker, but keyed per (namespace, action) and capped at 1 push per
# window instead of a global count capped at 3 -- gates only the Loki push
# for refusal-type actions, never the Prometheus counters above or the
# stdout log. See module docstring and docs/known-issues.md.
LOKI_REFUSAL_THROTTLE_WINDOW_SECONDS = 300
_loki_refusal_windows: dict[tuple[str, str], deque[float]] = {}


def _loki_refusal_push_allowed(namespace: str, action: str) -> bool:
    window = _loki_refusal_windows.setdefault((namespace, action), deque())
    cutoff = time.monotonic() - LOKI_REFUSAL_THROTTLE_WINDOW_SECONDS
    while window and window[0] < cutoff:
        window.popleft()
    if window:
        return False
    window.append(time.monotonic())
    return True

_core_v1 = None
_networking_v1 = None


def _k8s_clients():
    global _core_v1, _networking_v1
    if _core_v1 is None:
        config.load_incluster_config()
        _core_v1 = client.CoreV1Api()
        _networking_v1 = client.NetworkingV1Api()
    return _core_v1, _networking_v1


def _loki_connection() -> http.client.HTTPConnection:
    global _loki_conn
    if _loki_conn is None:
        _loki_conn = http.client.HTTPConnection(
            _loki_push_host.hostname, _loki_push_host.port, timeout=LOKI_PUSH_TIMEOUT_SECONDS
        )
    return _loki_conn


def _push_incident_to_loki(record: dict) -> None:
    # Single static label (job) -- decision 6 asks for job="webhook-incidents"
    # specifically, not one label per field: the JSON detail stays in the log
    # line body, never promoted to labels, to avoid the high-cardinality-label
    # trap (a distinct series per pod_name/namespace/etc.).
    body = json.dumps(
        {
            "streams": [
                {
                    "stream": {"job": "webhook-incidents"},
                    "values": [[str(time.time_ns()), json.dumps(record)]],
                }
            ]
        }
    ).encode("utf-8")
    try:
        conn = _loki_connection()
        conn.request(
            "POST",
            "/loki/api/v1/push",
            body=body,
            headers={"Content-Type": "application/json"},
        )
        conn.getresponse().read()
    except (OSError, http.client.HTTPException) as exc:
        # Fail-open (decision 5): Loki being unreachable must never affect
        # the isolation/release action itself, which has already completed
        # by the time log_incident() is called. Drop the connection so the
        # next push reconnects instead of reusing a broken socket.
        global _loki_conn
        _loki_conn = None
        logger.warning("failed to push incident to Loki: %s", exc)


def log_incident(*, loki_throttle_key: tuple[str, str] | None = None, **fields):
    record = {
        "log_type": "webhook_incident",
        "timestamp": datetime.now(UTC).isoformat(),
        **fields,
    }
    print(json.dumps(record), flush=True)
    # Decision 6 addendum: throttle only applies when the caller passes a
    # (namespace, action) key -- refusal actions only, see module docstring.
    if loki_throttle_key is not None and not _loki_refusal_push_allowed(*loki_throttle_key):
        return
    _push_incident_to_loki(record)


def check_auth(authorization: str | None) -> None:
    if authorization != f"Bearer {WEBHOOK_TOKEN}":
        auth_failures_total.inc()
        logger.warning("rejected request: missing or invalid Authorization header")
        raise HTTPException(status_code=401, detail="unauthorized")


def _prune_window() -> None:
    cutoff = time.monotonic() - CIRCUIT_BREAKER_WINDOW_SECONDS
    while _isolation_window and _isolation_window[0] < cutoff:
        _isolation_window.popleft()


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.post("/webhook")
async def webhook(request: Request, authorization: str | None = Header(default=None)):
    check_auth(authorization)
    start = time.monotonic()

    payload = await request.json()
    rule = payload.get("rule", "")
    priority = payload.get("priority", "")
    output_fields = payload.get("output_fields") or {}
    namespace = output_fields.get("k8s.ns.name")
    pod_name = output_fields.get("k8s.pod.name")

    common = {
        "falco_rule": rule,
        "mitre_technique": MITRE_MAP.get(rule, "unmapped"),
        "namespace": namespace,
        "pod_name": pod_name,
    }

    if not namespace or not pod_name:
        log_incident(**common, action="malformed_payload", result="rejected", latency_ms=None)
        raise HTTPException(status_code=400, detail="missing k8s.ns.name/k8s.pod.name in output_fields")

    # Decision 11: critical-infrastructure namespaces are an absolute veto,
    # checked first.
    if namespace in CRITICAL_NAMESPACES:
        refused_protected_namespace_total.labels(namespace=namespace).inc()
        log_incident(
            **common,
            action="refused_protected_namespace",
            result="refused",
            severity="critical",
            latency_ms=None,
            loki_throttle_key=(namespace, "refused_protected_namespace"),
        )
        return {"status": "refused_protected_namespace"}

    # Noisy-probe namespaces: same veto point, distinct log action so this
    # stays distinguishable from decision 11's blast-radius exceptions (see
    # docs/known-issues.md for the security trade-off this implies).
    if namespace in NOISY_PROBE_NAMESPACES:
        refused_noisy_probe_namespace_total.labels(namespace=namespace).inc()
        log_incident(
            **common,
            action="refused_noisy_probe_namespace",
            result="refused",
            severity="critical",
            latency_ms=None,
            loki_throttle_key=(namespace, "refused_noisy_probe_namespace"),
        )
        return {"status": "refused_noisy_probe_namespace"}

    # Decision 9: only priority=Critical alerts reach the isolation path.
    if priority != "Critical":
        log_incident(**common, action="below_response_threshold", result="logged", priority=priority, latency_ms=None)
        return {"status": "below_response_threshold"}

    # Decision 13: dry-run short-circuits before any Kubernetes API call --
    # including the dedup read below, so DRY_RUN=true is a hard guarantee of
    # zero API calls, not just zero mutations.
    if DRY_RUN:
        log_incident(
            **common,
            action="dry_run_would_isolate",
            result="dry_run",
            would_patch_labels={QUARANTINE_LABEL: pod_name, "quarantine": "true"},
            would_create_networkpolicy=f"quarantine-{pod_name}",
            latency_ms=round((time.monotonic() - start) * 1000, 2),
        )
        return {"status": "dry_run_would_isolate"}

    core_v1, networking_v1 = _k8s_clients()

    # Decision 7: dedup via the label a prior real isolation would have set.
    try:
        pod = core_v1.read_namespaced_pod(name=pod_name, namespace=namespace)
    except ApiException as exc:
        log_incident(**common, action="isolation_error", result=f"error: {exc.reason}", latency_ms=None)
        return {"status": "error"}

    if QUARANTINE_LABEL in (pod.metadata.labels or {}):
        log_incident(**common, action="deduplicated", result="skipped", latency_ms=None)
        return {"status": "deduplicated"}

    # Decision 4: circuit breaker on real isolations only.
    _prune_window()
    if len(_isolation_window) >= CIRCUIT_BREAKER_THRESHOLD:
        circuit_breaker_trips_total.inc()
        log_incident(**common, action="circuit_breaker_tripped", result="alert_only", latency_ms=None)
        return {"status": "circuit_breaker_tripped"}

    # Decision 1/12: real action -- network isolation only, never delete the pod.
    result = "isolated"
    try:
        core_v1.patch_namespaced_pod(
            name=pod_name,
            namespace=namespace,
            body={"metadata": {"labels": {QUARANTINE_LABEL: pod_name, "quarantine": "true"}}},
        )
        network_policy = client.V1NetworkPolicy(
            metadata=client.V1ObjectMeta(
                name=f"quarantine-{pod_name}",
                namespace=namespace,
                labels={QUARANTINE_LABEL: pod_name},
            ),
            spec=client.V1NetworkPolicySpec(
                pod_selector=client.V1LabelSelector(match_labels={QUARANTINE_LABEL: pod_name}),
                policy_types=["Ingress", "Egress"],
                ingress=[],
                egress=[],
            ),
        )
        networking_v1.create_namespaced_network_policy(namespace=namespace, body=network_policy)
        _isolation_window.append(time.monotonic())
        isolations_total.inc()
    except ApiException as exc:
        result = f"error: {exc.reason}"

    log_incident(
        **common,
        action="isolated",
        result=result,
        latency_ms=round((time.monotonic() - start) * 1000, 2),
    )
    return {"status": result}


@app.post("/release")
async def release(request: Request, authorization: str | None = Header(default=None)):
    check_auth(authorization)

    body = await request.json()
    namespace = body.get("namespace")
    pod_name = body.get("pod_name")
    if not namespace or not pod_name:
        raise HTTPException(status_code=400, detail="namespace and pod_name are required")

    core_v1, networking_v1 = _k8s_clients()

    policies = networking_v1.list_namespaced_network_policy(
        namespace=namespace, label_selector=f"{QUARANTINE_LABEL}={pod_name}"
    )
    for policy in policies.items:
        networking_v1.delete_namespaced_network_policy(name=policy.metadata.name, namespace=namespace)

    core_v1.patch_namespaced_pod(
        name=pod_name,
        namespace=namespace,
        body={"metadata": {"labels": {QUARANTINE_LABEL: None, "quarantine": None}}},
    )

    log_incident(
        falco_rule=None,
        mitre_technique=None,
        namespace=namespace,
        pod_name=pod_name,
        action="released",
        result="released",
        latency_ms=None,
    )
    return {"status": "released"}


def main() -> None:
    # Only runs when this file is executed as the container's entrypoint
    # (see Dockerfile) -- never on `import app`, so pytest never binds a
    # real port or spawns the metrics server's background thread.
    metrics_port = int(os.environ.get("METRICS_PORT", "9090"))
    start_http_server(metrics_port)
    uvicorn.run(app, host="0.0.0.0", port=8080)


if __name__ == "__main__":
    main()
