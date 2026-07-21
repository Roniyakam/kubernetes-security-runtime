# kubernetes-security-runtime — CLAUDE.md

## Contexte du projet

Couche de détection runtime (Falco) pour le cluster K3s de
`devops-saas-platform`, en GitOps pur. Portfolio DevSecOps — même
contexte que `devops-saas-platform` (Patrowl.io). Cadrage complet :
`docs/cadrage.md`. Menaces couvertes : `docs/threat-model.md`. Pièges
connus, à lire avant de toucher `gitops/` : `docs/known-issues.md`.

Ce repo ne déploie rien seul : il fournit uniquement des `values.yaml`
consommés par l'Application ArgoCD qui vit dans `devops-saas-platform`
(`gitops/apps/kubernetes-security-runtime/application.yaml`), en
source Helm multi-source (`$values` git ref vers ce repo). Le cluster
K3s, ArgoCD, et Loki (réutilisé) appartiennent tous à
`devops-saas-platform` — ne pas dupliquer leur configuration ici.

## Début de session

Ce repo ne gère ni Vault ni de VM — pas de script de démarrage propre.
Si une tâche touche le cluster ou Loki, lancer d'abord
`devops-saas-platform/scripts/session-start.sh` (unseal Vault, health
check) depuis ce repo-là.

```bash
export KUBECONFIG=~/devops-saas-platform/ansible/fetched/vm-k8s-master-k3s.yaml
kubectl get applications -n argocd   # kubernetes-security-runtime doit être Synced/Healthy
kubectl get pods -n falco            # daemonset falco + falcosidekick Running
```

## Règles non négociables

1. **GITOPS PUR** : toute modification de `gitops/falco/` ou
   `gitops/falcosidekick/` = commit + push sur `main`. ArgoCD
   (`syncPolicy.automated: {prune: true, selfHeal: true}` côté
   `devops-saas-platform`) synchronise automatiquement — jamais de
   `kubectl apply`/`argocd app sync` manuel en usage normal. Une
   modification de règle Falco (`custom-rules.yaml`) suit exactement
   le même chemin qu'une modification de `values.yaml`.

2. **PAS DE `latest`** : chart `falcosecurity/falco` et toute
   dépendance pinnés avec justification. Versions actuelles :
   `docs/cadrage.md` section 5. Avant de bumper une version, revérifier
   les clés de valeurs contre `helm show values` du chart réel — ne
   jamais supposer qu'une structure de config (driver, outputs) reste
   stable d'une version majeure à l'autre. Précédent direct :
   `grpc_output` a été retiré en Falco 0.44, remplacé par
   `http_output` (voir `docs/known-issues.md`).

3. **AUCUNE RÉPONSE AUTOMATISÉE EN S1** : `responseActions`/Falco
   Talon restent désactivés, la sortie Webhook de Falcosidekick reste
   à adresse vide. `webhook/app.py` est un stub, pas un service
   déployé — ne pas le brancher dans `gitops/falcosidekick/values.yaml`
   avant que le cadrage S2 soit fait.

4. **PAS DE SECRET EN CLAIR** dans `gitops/falco/` ou
   `gitops/falcosidekick/` — Falcosidekick S1 ne parle qu'à Loki (pas
   d'auth) et à une sortie Webhook désactivée ; s'il faut un jour un
   token/mot de passe ici, passer par le même mécanisme Vault que
   `devops-saas-platform` (jamais une valeur en clair committée),
   pas de placeholder `changeme-*` façon RabbitMQ dans ce repo-ci.

5. **6 règles custom = 6 règles custom** : elles restent
   auto-suffisantes (pas de dépendance à une macro du ruleset par
   défaut de Falco, qui est récupéré dynamiquement via `falcoctl` à
   chaque démarrage de pod, donc hors du contrôle de ce repo — voir
   `docs/known-issues.md`). Toute nouvelle règle doit suivre le même
   principe.

6. **CI GATES** : ruff (`webhook/`) + yamllint (`gitops/`) + gitleaks
   doivent passer avant tout merge (`.github/workflows/ci.yml`).

## Méthode de travail avec Claude Code

Même méthode que `devops-saas-platform` :

1. CLAUDE.md est la source de vérité unique — le lire avant toute
   tâche.
2. Workflow Explore→Plan→Code→Commit pour tout changement touchant 2
   fichiers ou plus.
3. Avant d'écrire une clé de values.yaml : vérifier qu'elle existe
   réellement dans le chart ciblé (`helm show values <chart> --version
   <x>`), ne jamais copier une structure supposée d'une version
   précédente.
4. Gates avant tout commit : yamllint (`gitops/`), ruff (`webhook/`),
   gitleaks.
5. Après chaque tâche : `git add`, `git commit` (conventional
   commits), `git push`.
6. Ne jamais afficher de secrets, IPs internes non déjà documentées
   comme trade-off assumé, tokens ou credentials dans un fichier.
7. Nouvelle mission = nouvelle session Claude Code.

## Plan d'exécution

- **S1** : Falco + Falcosidekick, détection/log uniquement ← **en
  cours**
- **S2** : service webhook (`webhook/`), réponse automatisée — cadrage
  à faire avant toute implémentation
