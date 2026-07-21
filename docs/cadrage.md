# kubernetes-security-runtime — cadrage

## 1. Objectif

Ajouter une couche de détection runtime (Falco) au cluster K3s de
`devops-saas-platform`, en GitOps pur via le pattern App-of-Apps déjà en
place dans ce repo (ArgoCD, `gitops/apps/`). Portfolio technique pour
entretien DevSecOps — même contexte que `devops-saas-platform`
(Patrowl.io).

## 2. Périmètre

**S1 (ce repo, en cours)** : détection uniquement.
- Falco (driver modern eBPF) déployé en DaemonSet sur les deux nœuds
  K3s (`vm-k8s-master`, `vm-k8s-worker`).
- Falcosidekick (bundlé en subchart de `falcosecurity/falco`) route les
  alertes vers Loki (instance existante sur `vm-monitoring`, réutilisée
  — pas de second Loki).
- 6 règles custom mappées MITRE ATT&CK, mode audit/log uniquement (voir
  `docs/threat-model.md`).
- Aucune réponse automatisée : `responseActions`/Falco Talon désactivé
  partout, sortie Webhook de Falcosidekick laissée vide (stub
  `webhook/app.py` présent dans le repo mais non déployé).

**S2 (à venir, hors périmètre de ce repo pour l'instant)** : service
webhook Python (`webhook/app.py`) recevant les alertes Falcosidekick et
décidant d'une réponse automatisée (à définir — pas de logique
implémentée aujourd'hui, cadrage volontairement pas encore fait).

## 3. Non-négociables (hérités de `devops-saas-platform`)

1. **GitOps pur** : aucun `kubectl apply`/`argocd app` manuel hors
   validation ponctuelle. Tout changement = commit + push +
   auto-sync ArgoCD (`syncPolicy.automated`, voir
   `devops-saas-platform/gitops/apps/kubernetes-security-runtime/
   application.yaml`).
2. **Pas de version `latest`** : chart Falco, chart(s) sourcés,
   versions pinnées avec justification (section 5).
3. **Pas de secret en clair** dans `gitops/falco/` ni
   `gitops/falcosidekick/` — voir `docs/known-issues.md` pour la seule
   exception assumée (IP réelle de `vm-monitoring`, pas un secret
   d'authentification).
4. **CI gates** : ruff (webhook/) + yamllint (gitops/) + gitleaks
   avant tout merge (`.github/workflows/ci.yml`).

## 4. Architecture (S1)

```
Falco DaemonSet (namespace falco, K3s : vm-k8s-master + vm-k8s-worker)
  -> détection syscall (driver modern_ebpf)
  -> falco.http_output (auto-wiré par le chart) --http--> Falcosidekick
       (subchart bundlé, même release Helm "falco")
         -> output Loki --http--> vm-monitoring:3100 (instance existante)
         -> output Webhook --http--> DÉSACTIVÉ en S1 (adresse vide,
              cible future : webhook/app.py, S2)
```

Un seul repoURL Helm (`falcosecurity/charts`), une seule Application
ArgoCD multi-source (chart + `$values` git ref vers ce repo) — voir
`devops-saas-platform/gitops/apps/kubernetes-security-runtime/
application.yaml`.

## 5. Versions pinnées

| Composant | Version | Vérifié le | Comment |
|---|---|---|---|
| Chart `falcosecurity/falco` | `9.1.0` | 2026-07-21 | `helm search repo falcosecurity/falco --versions` |
| Falco (appVersion) | `0.44.1` | 2026-07-21 | via le chart ci-dessus |
| Falcosidekick (subchart bundlé) | chart `0.12.*` (contrainte du chart Falco 9.1.0) | 2026-07-21 | `helm show chart falcosecurity/falco --version 9.1.0` — pas choisi indépendamment, voir `docs/known-issues.md` |
| K3s | `v1.29.4+k3s1` | 2026-07-21 | `kubectl get nodes` sur le cluster existant, non géré par ce repo |
| ArgoCD | `v2.10.4` | 2026-07-21 | image `argocd-server` sur le cluster existant, non géré par ce repo |
| Loki (réutilisé, non déployé par ce repo) | `3.0.0` | — | `devops-saas-platform/ansible/roles/monitoring/defaults/main.yml` |

**Correction actée** (vs. plan initial) : Falco 0.44 a retiré
`grpc_output` — confirmé absent du schéma de valeurs du chart 9.1.0
(voir `docs/known-issues.md`). `http_output` est le seul mécanisme de
sortie configuré.

## 6. Roadmap

- **S1** : Falco + Falcosidekick, détection/log uniquement ← **en
  cours (ce repo)**
- **S2** : service webhook (`webhook/`), réponse automatisée — cadrage
  à faire
- **S3+** : à définir, alignement probable avec la roadmap
  `devops-saas-platform` (scan de vulnérabilités, supply chain)
