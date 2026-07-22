# Cadrage S2 — réponse automatisée (webhook Python)

Ce document complète `docs/cadrage.md` (qui scope S1 à S5) maintenant
que S1 est validé et clos. Il tranche les décisions spécifiques à S2
avant toute implémentation, conformément à la règle CLAUDE.md de ce
repo : cadrage à faire avant implémentation.

**Statut : validé par le porteur du projet.** Les 13 décisions
ci-dessous ont été discutées et approuvées par le porteur du projet
avant que l'implémentation ne soit autorisée. Note d'honnêteté sur
la trace documentaire : ce document a été formalisé et committé dans
ce repo dans le même mouvement que l'implémentation initiale de S2,
pas dans un commit distinct antérieur, l'historique git ne fait donc
pas apparaître de délai entre validation et code. Pour les projets
suivants du portfolio, le cadrage sera committé séparément et avant
toute implémentation, pour que cette vérification soit possible
directement depuis l'historique git plutôt que de dépendre d'un
contexte externe.

---

## Décisions à trancher avant tout code

### 1. Isolation, pas destruction

**Décision validée** : le webhook applique une NetworkPolicy
deny-all scopée au pod concerné (via un label unique posé par le
webhook lui-même) et ajoute un label `quarantine=true`. Il ne
supprime jamais le pod.

**Justification** : en réponse à incident réelle, détruire
immédiatement la preuve empêche toute investigation forensique
ultérieure. Isoler puis laisser un humain décider de la suite est la
pratique IR standard, pas une automatisation totale aveugle.

**Alternative rejetée** : `kubectl delete pod` immédiat, rejetée car
destructive et irréversible, incompatible avec une démarche
d'investigation sérieuse.

### 2. RBAC du webhook, moindre privilège strict

ServiceAccount dédié, `Role` (jamais `ClusterRole`) scopé au
namespace concerné uniquement. Droits limités à :
- `create`/`patch` sur `networkpolicies`
- `patch` sur `pods` (labels uniquement)

Jamais d'`exec`, jamais de `delete`, jamais de wildcard `*` sur `*`.

### 3. Authentifier l'appel Falcosidekick vers le webhook

Un secret partagé (header HMAC ou token), stocké dans Vault selon le
même mécanisme que le reste du projet, vérifié par le webhook avant
toute action.

Sans ça, n'importe quel pod sur le réseau du cluster peut forger un
faux payload d'alerte critique et déclencher une mise en quarantaine
arbitraire : un déni de service via le système censé protéger.

**Limitation documentée** : le secret est statique pour S2, pas de
rotation automatique. Acceptable pour ce périmètre, chemin
d'amélioration identifié : token Vault dynamique à courte durée de
vie, généré par requête plutôt qu'un secret fixe.

### 4. Garde-fou anti-tempête (circuit breaker)

**Seuil validé** : pas plus de 3 isolations automatiques sur une
fenêtre glissante de 5 minutes. Au-delà, le webhook bascule en mode
alerte seule (log uniquement, plus aucune action) et notifie.

**Justification** : un faux positif en boucle peut mettre en
quarantaine toute la production. Un système de réponse automatique
mal calibré est pire qu'aucun système.

### 5. Comportement en cas d'indisponibilité du webhook

Déjà tranché dans le cadrage initial (risque documenté) : fail-open.
Si le webhook est injoignable, Falco continue de logger dans Loki
normalement, sans blocage ni perte d'alerte.

### 6. Enregistrement structuré de l'incident

Chaque action de quarantaine génère un enregistrement structuré
(JSON), envoyé vers Loki sur un flux distinct labellisé
`job="webhook-incidents"` (jamais mélangé avec les logs
applicatifs). Contenu minimal : horodatage, règle Falco déclenchante,
technique MITRE ATT&CK associée, pod ciblé, namespace, action prise,
résultat (succès/échec).

**Justification** : une action automatisée sans trace structurée et
interrogeable n'est pas auditable. C'est la différence entre un
script qui réagit et un système de réponse à incident qui laisse une
preuve exploitable, exigence de base de tout outil SOAR sérieux
(TheHive, Shuffle, Tines suivent tous ce principe).

**Rétention** : réutilise la politique déjà configurée sur Loki
(15 jours, `devops-saas-platform`), pas de nouvelle politique à
définir.

### 7. Déduplication des événements

Falco peut émettre plusieurs événements pour un seul incident réel
(plusieurs syscalls correspondant à la même règle en quelques
secondes). Le webhook vérifie si le pod ciblé porte déjà le label
`quarantine=true` avant d'agir : si oui, l'événement est journalisé
mais ne déclenche ni nouvelle action ni nouveau compteur pour le
circuit breaker.

**Justification** : sans déduplication, un seul incident réel peut
artificiellement déclencher le circuit breaker (5 événements
dupliqués en 10 secondes ressemblent à 5 incidents distincts), ce qui
fausserait le comportement décrit en section 4.

### 8. Mécanisme de sortie de quarantaine

Une action automatisée doit avoir un chemin de retour arrière
documenté. Le webhook expose un second endpoint (`POST /release`) qui
retire le label `quarantine=true` et supprime la NetworkPolicy
associée, après la même authentification que la mise en quarantaine.
La levée de quarantaine reste une décision humaine : le webhook
exécute la commande, il ne la déclenche jamais lui-même.

**Justification** : un système qui isole sans offrir de moyen de
désisoler transforme un faux positif en incident opérationnel
permanent.

### 9. Tests unitaires du webhook

La logique critique (vérification d'authentification, comptage du
circuit breaker, déduplication) est couverte par des tests unitaires
(pytest), indépendants d'un cluster réel :
- rejet d'une requête sans le bon secret
- comptage correct du circuit breaker sur une fenêtre glissante
- pas de double action sur un pod déjà en quarantaine

Ajouté au CI : `pytest webhook/tests/`, en plus de `ruff`.

### 10. Observabilité du webhook lui-même

Le webhook expose un endpoint `/metrics` (Prometheus) avec au
minimum : `isolations_total`, `circuit_breaker_trips_total`,
`auth_failures_total`. Ajouté comme cible de scrape supplémentaire
dans `devops-saas-platform` (`prometheus.yml.j2`), visible dans le
dashboard Grafana `platform-overview` existant.

**Justification** : la couche de réponse automatisée ne doit pas être
un angle mort de l'observabilité déjà construite. Un expert qui
demande "comment tu sais si ton SOAR fonctionne bien dans le temps"
doit trouver une réponse mesurable, pas une affirmation.

### 11. Namespaces protégés, jamais isolés automatiquement

`argocd`, `vault`, `kube-system` et `falco` lui-même sont sur une
liste explicite de namespaces protégés. Si une règle critique se
déclenche sur un pod dans l'un de ces namespaces, le webhook refuse
l'isolation, journalise une alerte de sévérité maximale ("action
refusée, namespace protégé") et bascule immédiatement en notification
humaine.

**Justification** : c'est le parallèle direct de l'incident 001
(ArgoCD a supprimé Vault par un auto-sync mal scopé). Un webhook qui
isole ArgoCD ou Vault sur un faux positif transforme une alerte en
panne totale de la plateforme. La leçon est déjà écrite dans ce
portfolio, ne pas l'appliquer ici serait la répéter sciemment.

**Addendum (2026-07-22)** : `celery` et `rabbitmq` avaient été ajoutés
à cette même liste après validation live S2, avec la même
justification blast-radius. C'était une confusion — leur raison
d'exclusion n'a rien à voir avec la criticité d'infrastructure : c'est
un faux positif de la règle 1 sur leurs probes exec-based. `webhook/app.py`
sépare maintenant `CRITICAL_NAMESPACES` (cette décision 11, inchangée)
de `NOISY_PROBE_NAMESPACES` (`celery`, `rabbitmq`), avec des actions de
log distinctes. Le compromis de sécurité que cette deuxième liste
implique — zéro couverture d'isolation automatisée, y compris pour une
vraie compromission par shell — est documenté explicitement dans
`docs/known-issues.md`, pas résumé ici sous l'angle blast-radius.

### 12. Interaction avec le contrôleur du pod

Isoler le réseau d'un pod fait souvent échouer ses probes de
liveness/readiness. Kubernetes, ignorant l'isolement volontaire, peut
alors redémarrer le pod via son contrôleur (Deployment, ReplicaSet),
détruisant la fenêtre d'investigation que la décision 1 cherchait
justement à préserver.

**Décision pour S2** : ce comportement est documenté comme limitation
connue, pas automatiquement mitigé (scaler à zéro le déploiement
parent serait plus invasif que l'action initiale et risquerait
d'affecter d'autres pods sains du même déploiement). Mitigation
manuelle documentée pour l'analyste : retirer temporairement les
probes ou scaler le déploiement avant une investigation prolongée. Le
comportement réel (le pod est-il effectivement redémarré ou
survit-il à l'isolement) doit être observé et documenté pendant la
validation, pas supposé.

### 13. Activation graduée (dry-run avant action réelle)

Le webhook démarre avec `DRY_RUN=true` par défaut : il reçoit les
événements, applique toute la logique (auth, déduplication, circuit
breaker), journalise ce qu'il aurait fait, mais n'exécute aucune
action réelle sur le cluster. Le passage en `DRY_RUN=false` est un
changement de configuration explicite, décidé après une période
d'observation sans faux positif documentée.

**Justification** : cohérence avec le choix déjà fait en S1 (règles
Falco en mode audit avant toute conséquence). Un système de réponse
qui passe direct en action réelle dès son premier déploiement
contredit la discipline progressive posée dès le départ du projet.

---

## Note de maturité SOAR

Ce projet automatise une seule action réversible et scopée
(isolation réseau d'un pod, jamais suppression, jamais action sur
plusieurs pods à la fois). C'est un choix délibéré de maturité : les
frameworks SOAR d'entreprise (Tines, Torq, Shuffle) recommandent de
n'automatiser entièrement que des actions à faible risque et
réversibles, en gardant les actions plus destructives derrière une
validation humaine. Une automatisation totale non graduée dès le
premier projet serait un signal d'inexpérience, pas de compétence.

**Point non retenu pour S2, documenté pour référence future** : un
Custom Resource Definition (`SecurityIncident`) avec un contrôleur
dédié serait le pattern Kubernetes-natif le plus abouti pour tracer
ces incidents, au lieu d'un flux Loki structuré. Écarté pour S2 car ça
ajoute une complexité d'opérateur Kubernetes disproportionnée par
rapport à la valeur ajoutée à ce stade. Candidat naturel pour une
itération future si le projet évolue vers plusieurs types de réponse
automatisée.

**Lien réglementaire** : cette capacité de détection et réponse
documentée, avec traçabilité et procédure de retour arrière, répond
directement à l'esprit des obligations NIS2 de détection et
notification d'incident, un argument mobilisable aussi bien côté SOC
que côté GRC en entretien.

---

## Validation attendue en fin de S2

- [ ] Scénario simulé : événement critique déclenché, isolation
      appliquée et mesurée en moins de 10 secondes, chiffré et
      documenté (pas d'affirmation sans mesure)
- [ ] Scénario faux positif : un 4e déclenchement en moins de 5
      minutes ne déclenche pas de 4e isolation, bascule vérifiée en
      mode alerte seule
- [ ] RBAC audité :
      `kubectl auth can-i --list --as=system:serviceaccount:falco:webhook`
      confirme le périmètre exact, rien de plus
- [ ] Authentification testée : une requête sans le secret attendu
      vers le webhook est rejetée (401/403), pas silencieusement
      acceptée
- [ ] Un incident structuré est visible dans Loki
      (`job="webhook-incidents"`) après un scénario simulé, avec tous
      les champs attendus (règle, technique MITRE, résultat)
- [ ] Déduplication vérifiée : 3 événements dupliqués en 5 secondes
      sur le même pod ne comptent que pour 1 dans le circuit breaker
- [ ] `POST /release` testé : lève la quarantaine, supprime la
      NetworkPolicy, vérifié par un `kubectl get pod` sans label
      résiduel
- [ ] `pytest webhook/tests/` : 100% des tests passent, exécuté en
      CI, pas seulement en local
- [ ] `curl http://webhook:8080/metrics` : les 3 compteurs sont
      présents et incrémentent après un scénario simulé
- [ ] Namespaces protégés testés : un événement critique simulé dans
      `argocd` ou `vault` ne déclenche aucune isolation, seulement une
      alerte "action refusée, namespace protégé"
- [ ] Comportement de redémarrage observé et documenté : le pod isolé
      est-il effectivement redémarré par son contrôleur pendant le
      test ? Résultat réel noté dans `docs/known-issues.md`, pas
      supposé à l'avance
- [ ] Mode dry-run vérifié : avec `DRY_RUN=true`, un événement
      critique simulé produit un log "aurait isolé X" sans
      NetworkPolicy réellement créée

---

*Points 1 et 4 impliquaient le choix de comportement le plus sensible
de ce document, pas un détail d'implémentation. Validés explicitement
par le porteur du projet avant le lancement de l'implémentation S2,
au même titre que l'ensemble des 13 décisions ci-dessus.*
