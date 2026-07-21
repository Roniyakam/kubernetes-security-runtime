"""S2 stub — not implemented in S1.

S1 (this repo, current scope) is detection-only: Falco -> Falcosidekick ->
Loki, log/audit mode, no automated response. This file exists so the repo
structure and CI lint gate are in place ahead of S2, which will receive
Falcosidekick's Webhook output (see gitops/falcosidekick/values.yaml,
currently disabled with an empty address) and decide on/execute an
automated response. None of that logic is implemented yet.
"""
