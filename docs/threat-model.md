# Threat model — S1 (Falco runtime detection)

## Scope

S1 covers **runtime detection only**, inside the K3s cluster
(`vm-k8s-master`, `vm-k8s-worker`) managed by `devops-saas-platform`.
No automated response: every rule below is alert/log only. Automated
response (kill pod, network isolate, revoke token, ...) is S2 scope,
gated on the (currently stub) `webhook/` service — see
`docs/cadrage.md`.

## Assets in scope

- Workload containers running in the `celery`, `rabbitmq`, `vault`
  namespaces (the actual SaaS platform, per `devops-saas-platform`).
- The K3s nodes themselves (Falco's DaemonSet also watches host-level
  syscalls, not just container ones).

## Décision de sécurité : pas de ClusterRole

Falco n'a pas besoin d'un ClusterRole cluster-wide car l'enrichissement
k8s.* provient du socket containerd local, pas d'un client API watch.
La surface RBAC est donc nulle pour ce composant, plus restreinte que
ce qui était anticipé dans le cadrage initial.

## Out of scope for S1

- Network-layer detection (no CNI-level policy enforcement, no IDS on
  the VPC) — Falco only sees syscalls on the two K8s nodes.
- Supply-chain / image scanning (Trivy, cosign, SBOM) — per
  `devops-saas-platform`'s own roadmap, planned S3/S4 there, not
  duplicated here.
- Anything requiring the webhook service (S2).

## 6 rules — MITRE ATT&CK mapping

Rule definitions: `gitops/falco/custom-rules.yaml`.

| # | Rule name (Falco) | MITRE technique | Severity (this doc) | Falco `priority` |
|---|---|---|---|---|
| 1 | Custom - Shell Spawned in Container | T1059 (Execution) | Critical | `CRITICAL` |
| 2 | Custom - New User Created in Container | T1136 (Persistence) | Critical | `CRITICAL` |
| 3 | Custom - Sudo Usage in Pod | T1068 (Privilege Escalation) | High | `ERROR` |
| 4 | Custom - Unexpected Outbound Connection | T1048 (Exfiltration) | Critical | `CRITICAL` |
| 5 | Custom - Write to Sensitive Account File | T1098 (Persistence) | Critical | `CRITICAL` |
| 6 | Custom - Unexpected Binary Execution From Writable Path | T1610 (Defense Evasion) | High | `ERROR` |

**Falco priority mapping note**: Falco's `priority` enum has no native
"High" level (valid values: `emergency`, `alert`, `critical`, `error`,
`warning`, `notice`, `informational`, `debug`). Rules scoped "High"
above are mapped to `ERROR`, the tier directly below `CRITICAL` — a
deliberate choice, not an oversight; flagging it here so it isn't
mistaken for a typo later.

## S2 — réponse automatisée (`webhook/app.py`)

Cadrage complet et les 13 décisions : `docs/cadrage-s2-webhook-response.md`.
Deux points qui affectent directement la surface de ce threat model :

- Seules les alertes de priorité Falco `Critical` (donc les 4 règles
  marquées "Critical" dans la table ci-dessus — pas les 2 règles
  "High"/`ERROR`) déclenchent une tentative d'isolation (décision 9).
  Les règles 3 (T1068, sudo) et 6 (T1610, binaire depuis un chemin
  inscriptible) restent détection/log uniquement en S2, comme en S1.
- La réponse automatisée est strictement une isolation réseau
  (label + `NetworkPolicy` deny-all ingress/egress sur le pod visé),
  jamais une suppression de pod (décision 1) — le pod reste
  investigable après isolation, au prix de ne pas garantir l'arrêt
  immédiat d'un process déjà lancé (seul le réseau est coupé, pas les
  syscalls locaux/disque).

## Known false-positive sources (S1, log-only — accepted for now)

- **Rule 4** (unexpected outbound): any legitimate egress to a public
  IP (e.g. an external API call from a workload) will match, since S1
  ships no per-workload allowlist. Acceptable in log-only mode; would
  need tuning before any S2 automated response is attached to it.
- **Rule 1** overlaps conceptually with Falco's own built-in default
  rule "Terminal shell in container" (fetched at runtime via falcoctl,
  not bundled in this repo) — both will fire for the same event. This
  is intentional: rule 1 adds explicit MITRE tagging that the stock
  rule doesn't have, rather than modifying the stock rule via
  `append: true` (kept the two independent for a cleaner "6 custom
  rules" story rather than a rule-editing story — see
  `docs/known-issues.md` for the corrected Grafana validation query
  this produces).
