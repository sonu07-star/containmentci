# Roadmap

ContainmentCI is building a vendor-neutral way to test identity kill switches as measurable,
repeatable security controls. Roadmap items are ordered by the confidence they add to a proof,
not by the number of integrations they add.

## 0.3 — Controlled Proofs

- [x] Explicit `ALLOWED`, `DENIED`, and `INDETERMINATE` access decisions
- [x] Independent healthy-control witness
- [x] Consecutive denial confirmation and per-target containment SLO
- [x] First-denial latency and proof-completion measurement
- [x] JUnit output, safe demo, and reusable GitHub Action
- [x] Full event-chain verification and hardened live API approval
- [x] Cross-process fixture leases for live identities and resources

## 0.4 — Repeatable Live Rehearsals

- [ ] Provider conformance suite and Python entry-point discovery
- [ ] Safe, provider-specific restoration with post-restore access verification
- [ ] Distributed fixture locks for runners that do not share a state directory
- [ ] Provider-declared isolation scopes for safely composing multiple live targets
- [ ] Redacted credential handles proving the same access artifact was replayed
- [ ] Historical p50/p95 containment-latency regression gates

## 0.5 — Identity Ecosystem

- [ ] Microsoft Entra ID account/session and Continuous Access Evaluation provider
- [ ] AWS IAM/STS access-key and assumed-role-session provider
- [ ] OAuth token revocation and OpenID CAEP `session-revoked` effectiveness tests
- [ ] Multi-region witness quorum for propagation-delay measurement
- [ ] KMS/Sigstore-backed asymmetric evidence attestations

## Open Revocation Latency Index

A future public test fixture will run scheduled synthetic containment scenarios and publish signed,
reproducible latency data across providers. The goal is an open dataset that incident responders,
identity teams, and provider maintainers can use to discuss real last-mile revocation behavior.

Ideas and provider proposals are welcome through GitHub issues. Live-provider contributions must
include a synthetic fixture, least-privilege permissions, explicit denial semantics, a control
witness, restoration instructions, and mocked outage/rate-limit tests.
