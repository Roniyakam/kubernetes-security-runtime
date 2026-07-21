# kubernetes-security-runtime — cadrage S2 (webhook de réponse automatisée)

## 0. Statut de ce document

Ce cadrage n'existait pas avant cette session — il n'y a aucune trace
dans `git log --all` d'un `docs/cadrage-s2-webhook-response.md`
antérieur. Il est reconstruit a posteriori, en session, à partir de la
consigne de mission qui référençait déjà "13 décisions" par numéro
sans que le document sous-jacent existe. Neuf décisions (2, 4, 6, 7, 8,
10, 11, 12, 13) sont reconstruites quasi mot pour mot depuis cette
consigne — marquées **reconstruite**. Quatre (1, 3, 5, 9) n'étaient
référencées que par leur numéro, jamais définies — marquées
**proposée, à confirmer** : ce sont mes propositions, pas des décisions
déjà prises par l'utilisateur. Aucune ligne de code S2 n'est écrite
avant validation de ce document.

## 1. Objectif et portée de S2

S1 (clos, validé) : Falco détecte et journalise, aucune réponse
automatisée. S2 active une réponse automatisée limitée à
**l'isolation réseau**, déclenchée par les alertes Falco relayées par
Falcosidekick vers `webhook/app.py` (jusqu'ici un stub, voir
`docs/cadrage.md` section 2).

## 2. Les 13 décisions

### Décision 1 — Nature de la réponse automatisée : isolation réseau, jamais suppression de pod
**Statut : proposée, à confirmer.**

Le webhook isole (label + `NetworkPolicy` deny-all ingress/egress) le
pod visé, il ne le supprime ni ne le tue jamais. Raison proposée :
préserver l'état du pod pour investigation (logs, `kubectl exec`
encore possible tant que le process incriminé ne relance pas de
connexion réseau, disque en l'état) et limiter le rayon d'impact d'un
faux positif — un pod isolé à tort reste réparable (`/release`), un
pod supprimé à tort ne l'est pas. Conséquence directe : voir décision
12 (le pod isolé peut quand même être recyclé par son contrôleur,
indépendamment de l'action du webhook).

### Décision 2 — RBAC : Role par défaut, ClusterRole seulement si strictement nécessaire et strictement scopé
**Statut : reconstruite** (le nom "décision 2" apparaît explicitement
dans la consigne au sujet de Role vs ClusterRole).

Principe hérité de S1 (`docs/threat-model.md`, "Décision de sécurité :
pas de ClusterRole" pour Falco) : jamais de RBAC cluster-wide par
défaut. Pour le webhook spécifiquement, le namespace cible d'une
isolation n'est pas connu à l'avance (n'importe quel namespace non
protégé) — si un `ClusterRole` s'avère réellement nécessaire pour
`get`/`patch` des pods et `create`/`delete`/`patch` des
`networkpolicies` cross-namespace, c'est une exception documentée
explicitement ici (voir Tâche 2 du prompt de mission), pas une
contradiction silencieuse du principe "Role par défaut". Verbes
autorisés dans ce cas : uniquement `get`, `list`, `patch` sur `pods`
et `get`, `list`, `create`, `delete`, `patch` sur
`networkpolicies.networking.k8s.io` — aucun wildcard, aucun autre verbe
ou ressource.

### Décision 3 — Authentification : jeton partagé, header `Authorization`, source Vault
**Statut : proposée, à confirmer** (le mécanisme est décrit dans la
consigne — "shared token (env var populated from Vault at deploy time,
same pattern as postgres_ha)" — mais jamais explicitement numéroté ;
proposé ici comme décision 3 car c'est la première décision
structurante rencontrée dans le flux `/webhook`).

Un jeton partagé (bearer token) est vérifié sur `Authorization` pour
`/webhook` et `/release`. Le jeton est généré et stocké dans Vault
(`secret/kubernetes-security-runtime/webhook-token`), injecté au pod
via un `Secret` Kubernetes peuplé par le même mécanisme que
`postgres_ha` dans `devops-saas-platform`
(`ansible/playbooks/deploy-vault-secrets.yml`) — jamais de valeur en
clair committée dans ce repo (règle non négociable n°4 du
`CLAUDE.md`).

### Décision 4 — Circuit breaker : fenêtre glissante de 5 minutes, seuil 3 isolations réelles
**Statut : reconstruite.**

Le webhook maintient en mémoire (processus du pod webhook, non
persisté) le nombre d'isolations *réelles* (hors dry-run, hors dédup)
des 5 dernières minutes. À la 4ᵉ dans la fenêtre : bascule en
alert-only (aucune action Kubernetes) pour la requête courante et
toutes les suivantes tant que la fenêtre ne s'est pas vidée sous le
seuil, log `action="circuit_breaker_tripped"`, retour 200. Limitation
assumée et documentée dans `docs/known-issues.md` (Tâche 8) : ce
compteur est en mémoire, il est perdu à tout redémarrage du pod
webhook — pas un état à considérer fiable pour de l'audit long terme,
seulement un garde-fou anti-emballement en runtime.

### Décision 5 — Mapping MITRE : réutilisation de la table `threat-model.md`, pas de duplication
**Statut : proposée, à confirmer** (la consigne renvoie à "la mapping
table dans `docs/cadrage.md` section 7", qui n'existe pas — cette
table existe réellement dans `docs/threat-model.md`, section "6 rules —
MITRE ATT&CK mapping").

Le champ `mitre_technique` du log d'incident (décision 6) est dérivé
du nom de règle Falco (`rule` dans le payload Falcosidekick) via la
table déjà présente dans `docs/threat-model.md` — encodée en dur dans
`webhook/app.py` sous forme d'un dict `{nom_regle: technique_mitre}`
reprenant exactement les 6 lignes de cette table, plutôt que dupliquée
ou redéfinie. Toute alerte dont la règle n'y figure pas (règle par
défaut Falco, hors des 6 custom — voir `docs/known-issues.md` "Falco's
default ruleset is not pinned by this repo") reçoit
`mitre_technique="unmapped"` plutôt que de faire échouer le traitement.

### Décision 6 — Format des logs d'incident structurés
**Statut : reconstruite.**

JSON sur stdout, avec un marqueur permettant au Promtail/Loki côté
`devops-saas-platform` de router ces lignes vers un label
`job="webhook-incidents"` distinct du `job` Falcosidekick existant —
même mécanisme d'ingestion que S1 (voir `docs/known-issues.md`,
section Falcosidekick/Loki), pas un nouveau pipeline. Champs communs à
toute action : `timestamp`, `falco_rule`, `mitre_technique`,
`namespace`, `pod_name`, `action`, `result`, `latency_ms` (ce dernier
`null` quand non pertinent, ex. `refused_protected_namespace`).
Valeurs possibles de `action` : `dry_run_would_isolate`, `isolated`,
`refused_protected_namespace`, `deduplicated`,
`circuit_breaker_tripped`, `released`.

### Décision 7 — Déduplication via le label `security.internal/quarantine-target`
**Statut : reconstruite.**

Si le pod visé porte déjà le label
`security.internal/quarantine-target`, le webhook considère qu'une
isolation est déjà en cours ou faite pour ce pod : log
`action="deduplicated"`, ne compte pas dans la fenêtre du circuit
breaker (décision 4), retour 200, aucune action Kubernetes.

### Décision 8 — Endpoint `/release`, déclenché par un analyste
**Statut : reconstruite.**

Même authentification que `/webhook` (décision 3). Entrée : `namespace`
+ `pod_name` en JSON. Actions : suppression de la `NetworkPolicy`
associée au label de quarantaine de ce pod, retrait des labels
`quarantine=true` et `security.internal/quarantine-target` du pod, log
`action="released"`, retour 200. Pas d'authentification différenciée
(pas de RBAC humain distinct dans ce projet portfolio) — le même jeton
partagé sert aux deux usages, trade-off assumé et à documenter dans
`docs/known-issues.md`.

### Décision 9 — Portée de la réponse : seules les alertes `priority=CRITICAL` déclenchent une tentative d'isolation
**Statut : proposée, à confirmer.**

La consigne de mission ne précise à aucun moment un filtre de sévérité
sur `/webhook` — sans lui, n'importe quelle alerte Falco relayée par
Falcosidekick (y compris `informational`/`notice`) déclencherait une
tentative d'isolation. Proposition, cohérente avec le découpage déjà
acté dans `docs/threat-model.md` (4 règles `CRITICAL`, 2 règles
`ERROR`/"High") : seules les alertes de priorité Falco `critical`
déclenchent le chemin d'isolation (dry-run ou réel) ; toute autre
priorité (`error` inclus) reste journalisée sans action, avec un
`action="below_response_threshold"` distinct pour rester traçable et
ne pas être confondue avec les autres cas. Réévaluation possible plus
tard si les règles `ERROR` (T1068 sudo, T1610 binaire écriture) doivent
elles aussi déclencher une réponse — hors périmètre S2 tel que cadré
ici.

### Décision 10 — Métriques Prometheus : 3 compteurs
**Statut : reconstruite.**

`isolations_total`, `circuit_breaker_trips_total`,
`auth_failures_total`, tous de type `Counter` (`prometheus_client`),
exposés sur `/metrics`.

### Décision 11 — Namespaces protégés : jamais d'isolation
**Statut : reconstruite.**

Liste fixe : `argocd`, `vault`, `kube-system`, `falco`. Si le namespace
cible d'une alerte est dans cette liste, aucune action d'isolation
(dry-run ou réelle) : log `action="refused_protected_namespace"`,
`severity` du log forcée à `critical` (une alerte critique visant un
de ces namespaces est en soi un signal fort, même sans réponse
automatisée), retour 200.

### Décision 12 — L'isolation n'empêche pas un contrôleur de recycler le pod ; comportement observé à documenter
**Statut : reconstruite** (référencée explicitement dans la séquence
de validation de la consigne).

Le webhook ne touche jamais au contrôleur (Deployment/ReplicaSet/etc.)
du pod isolé — seulement labels + `NetworkPolicy` sur le pod lui-même
(décision 1). Un pod nu (`kubectl run`) reste isolé tel quel ; un pod
géré par un Deployment peut être recyclé indépendamment de l'action du
webhook (liveness probe qui échoue une fois le réseau coupé, etc.). Le
comportement réel observé sur les deux cas (validation étape 3) est à
documenter dans `docs/known-issues.md`, pas supposé à l'avance.

### Décision 13 — Dry-run par défaut
**Statut : reconstruite.**

`DRY_RUN=true` par défaut (env var du Deployment, Tâche 2). En
dry-run : log `action="dry_run_would_isolate"` avec le détail complet
de ce qui aurait été fait (namespace, pod, règle, technique MITRE),
**aucun** appel à l'API Kubernetes, retour 200. Le passage en mode réel
se fait exclusivement par GitOps (`DRY_RUN: "false"` commité et poussé
sur `main`), jamais par `kubectl edit`/`kubectl set env` — cohérent
avec la règle non négociable n°1 du `CLAUDE.md` (GitOps pur).

## 3. Points laissés hors de ce cadrage (à traiter si besoin, pas dans S2 tel que défini ici)

- Pas de RBAC humain différencié pour `/release` (voir décision 8).
- Pas de réponse automatisée au-delà de l'isolation réseau (pas de
  revocation de token, pas de kill de process) — cohérent avec
  `docs/threat-model.md` qui ne mentionne ces options que comme
  exemples génériques, jamais comme périmètre S2 engagé.
- Pas de dédup basée sur autre chose que le label
  `security.internal/quarantine-target` (ex. pas de dédup par IP
  source, par règle, etc.).
