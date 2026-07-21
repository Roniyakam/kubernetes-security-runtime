# kubernetes-security-runtime

Runtime security detection layer (Falco + Falcosidekick) for the K3s
cluster managed by
[`devops-saas-platform`](https://github.com/Roniyakam/devops-saas-platform),
deployed GitOps-pure via that repo's App-of-Apps.

**Status: S1** — detection only, log/audit mode, no automated
response. See `docs/cadrage.md` for scope, `docs/threat-model.md` for
the 6 MITRE ATT&CK-mapped rules, `docs/known-issues.md` for trade-offs
and gotchas worth knowing before touching this repo.

## Layout

```
gitops/
  falco/values.yaml           Falco chart values (driver, http_output, resources)
  falco/custom-rules.yaml     6 custom MITRE-mapped rules, audit mode
  falcosidekick/values.yaml   Falcosidekick subchart values (Loki + Webhook stub outputs)
webhook/
  app.py                      S2 stub — not implemented in S1
docs/
  cadrage.md, threat-model.md, known-issues.md
```

The ArgoCD `Application` for this repo lives in `devops-saas-platform`
(`gitops/apps/kubernetes-security-runtime/application.yaml`), not
here — see that repo's App-of-Apps.

## Making a change

Any change here is picked up automatically by ArgoCD
(`syncPolicy.automated`) once pushed to `main` — no manual
`kubectl apply`. See `CLAUDE.md` for the full workflow.
