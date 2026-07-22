import json
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

import app as app_module

AUTH_HEADERS = {"Authorization": "Bearer test-token"}


def _client(monkeypatch, *, dry_run=True, token="test-token"):
    monkeypatch.setattr(app_module, "WEBHOOK_TOKEN", token)
    monkeypatch.setattr(app_module, "DRY_RUN", dry_run)
    app_module._isolation_window.clear()
    return TestClient(app_module.app)


def _payload(rule="Custom - Shell Spawned in Container", priority="Critical", namespace="default", pod="test-pod"):
    return {
        "rule": rule,
        "priority": priority,
        "output_fields": {"k8s.ns.name": namespace, "k8s.pod.name": pod},
        "output": "a shell was spawned",
        "time": "2026-07-22T00:00:00Z",
        "source": "syscall",
    }


def _forbid_k8s(monkeypatch):
    def _unexpected_call():
        raise AssertionError("Kubernetes API client should not be constructed here")

    monkeypatch.setattr(app_module, "_k8s_clients", _unexpected_call)


def test_missing_token_is_rejected(monkeypatch):
    client = _client(monkeypatch)

    resp = client.post("/webhook", json=_payload())

    assert resp.status_code == 401


def test_wrong_token_is_rejected(monkeypatch):
    client = _client(monkeypatch)

    resp = client.post("/webhook", json=_payload(), headers={"Authorization": "Bearer wrong-token"})

    assert resp.status_code == 401


def test_auth_failure_increments_counter(monkeypatch):
    client = _client(monkeypatch)
    before = app_module.auth_failures_total._value.get()

    client.post("/webhook", json=_payload())

    assert app_module.auth_failures_total._value.get() == before + 1


def test_protected_namespace_is_refused(monkeypatch):
    client = _client(monkeypatch)
    _forbid_k8s(monkeypatch)

    resp = client.post("/webhook", json=_payload(namespace="vault"), headers=AUTH_HEADERS)

    assert resp.status_code == 200
    assert resp.json()["status"] == "refused_protected_namespace"


def test_noisy_probe_namespace_is_refused(monkeypatch):
    client = _client(monkeypatch)
    _forbid_k8s(monkeypatch)

    resp = client.post("/webhook", json=_payload(namespace="celery"), headers=AUTH_HEADERS)

    assert resp.status_code == 200
    assert resp.json()["status"] == "refused_noisy_probe_namespace"


def test_below_response_threshold_alert_is_logged_only(monkeypatch):
    client = _client(monkeypatch)
    _forbid_k8s(monkeypatch)

    resp = client.post("/webhook", json=_payload(priority="Error"), headers=AUTH_HEADERS)

    assert resp.json()["status"] == "below_response_threshold"


def test_dry_run_logs_and_makes_zero_k8s_calls(monkeypatch, capsys):
    client = _client(monkeypatch, dry_run=True)
    _forbid_k8s(monkeypatch)

    resp = client.post("/webhook", json=_payload(), headers=AUTH_HEADERS)

    assert resp.json()["status"] == "dry_run_would_isolate"
    log_lines = [json.loads(line) for line in capsys.readouterr().out.strip().splitlines() if line.strip()]
    assert any(entry.get("action") == "dry_run_would_isolate" for entry in log_lines)


def test_already_labeled_pod_is_deduplicated(monkeypatch):
    client = _client(monkeypatch, dry_run=False)
    mock_core = MagicMock()
    mock_pod = MagicMock()
    mock_pod.metadata.labels = {app_module.QUARANTINE_LABEL: "test-pod"}
    mock_core.read_namespaced_pod.return_value = mock_pod
    mock_networking = MagicMock()
    monkeypatch.setattr(app_module, "_k8s_clients", lambda: (mock_core, mock_networking))

    resp = client.post("/webhook", json=_payload(), headers=AUTH_HEADERS)

    assert resp.json()["status"] == "deduplicated"
    mock_core.patch_namespaced_pod.assert_not_called()
    mock_networking.create_namespaced_network_policy.assert_not_called()


def test_circuit_breaker_trips_after_three_and_resets_after_window(monkeypatch):
    client = _client(monkeypatch, dry_run=False)
    mock_core = MagicMock()
    mock_pod = MagicMock()
    mock_pod.metadata.labels = {}
    mock_core.read_namespaced_pod.return_value = mock_pod
    mock_networking = MagicMock()
    monkeypatch.setattr(app_module, "_k8s_clients", lambda: (mock_core, mock_networking))

    fake_now = [1_000.0]
    monkeypatch.setattr(app_module.time, "monotonic", lambda: fake_now[0])

    for i in range(3):
        resp = client.post("/webhook", json=_payload(pod=f"pod-{i}"), headers=AUTH_HEADERS)
        assert resp.json()["status"] == "isolated"

    resp = client.post("/webhook", json=_payload(pod="pod-3"), headers=AUTH_HEADERS)
    assert resp.json()["status"] == "circuit_breaker_tripped"
    assert mock_networking.create_namespaced_network_policy.call_count == 3

    fake_now[0] += app_module.CIRCUIT_BREAKER_WINDOW_SECONDS + 1
    resp = client.post("/webhook", json=_payload(pod="pod-4"), headers=AUTH_HEADERS)

    assert resp.json()["status"] == "isolated"
    assert mock_networking.create_namespaced_network_policy.call_count == 4
