"""S2 automated-response webhook.

Receives Falcosidekick's forwarded Falco alerts (POST /webhook) and, for
priority=Critical events outside the protected namespaces, isolates the
targeted pod's network access. DRY_RUN=true by default: no Kubernetes API
call is made until this is flipped via GitOps (decision 13,
docs/cadrage-s2-webhook-response.md).

Structured incident logs are written to stdout as JSON with a
"log_type": "webhook_incident" marker (decision 6) so Promtail/Loki can
route them to job="webhook-incidents" -- the same stdout-scrape mechanism
Falcosidekick's own Loki output relies on in S1, not a new transport (see
docs/known-issues.md).

/metrics is served twice, deliberately: once on the main FastAPI app
(port 8080, ClusterIP-only, alongside /webhook and /release) and once via
prometheus_client's own standalone server (port 9090, main() below). Only
the second is NodePort-exposed for the external Prometheus on
vm-monitoring to scrape -- /webhook and /release never need to leave the
cluster network, so only a metrics-only port does. See
docs/known-issues.md.
"""

import json
import logging
import os
import sys
import time
from collections import deque
from datetime import UTC, datetime

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from prometheus_client import CONTENT_TYPE_LATEST, Counter, generate_latest, start_http_server
from starlette.responses import Response

logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger("webhook")

WEBHOOK_TOKEN = os.environ["WEBHOOK_TOKEN"]
DRY_RUN = os.environ.get("DRY_RUN", "true").strip().lower() == "true"

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

# Decision 4's sliding window: monotonic timestamps of real isolations only.
_isolation_window: deque[float] = deque()

_core_v1 = None
_networking_v1 = None


def _k8s_clients():
    global _core_v1, _networking_v1
    if _core_v1 is None:
        config.load_incluster_config()
        _core_v1 = client.CoreV1Api()
        _networking_v1 = client.NetworkingV1Api()
    return _core_v1, _networking_v1


def log_incident(**fields):
    record = {
        "log_type": "webhook_incident",
        "timestamp": datetime.now(UTC).isoformat(),
        **fields,
    }
    print(json.dumps(record), flush=True)


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
        log_incident(
            **common,
            action="refused_protected_namespace",
            result="refused",
            severity="critical",
            latency_ms=None,
        )
        return {"status": "refused_protected_namespace"}

    # Noisy-probe namespaces: same veto point, distinct log action so this
    # stays distinguishable from decision 11's blast-radius exceptions (see
    # docs/known-issues.md for the security trade-off this implies).
    if namespace in NOISY_PROBE_NAMESPACES:
        log_incident(
            **common,
            action="refused_noisy_probe_namespace",
            result="refused",
            severity="critical",
            latency_ms=None,
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
