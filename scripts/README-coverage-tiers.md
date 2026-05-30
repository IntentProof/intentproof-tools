# Tiered coverage policy (intentproof-tools)

IntentProof uses **tiered statement coverage** instead of a single repo-wide
95% gate.

| Tier | Minimum | Scope |
|------|---------|--------|
| **Total** | 90% | All packages measured by `run-coverage-gate.sh` |
| **Critical** | 92–95% | Per-path floors in `coverage-tiers.conf` |

Critical paths use **per-package floors** (not one repo-wide 95%). Trust
kernels such as `pkg/verifier` and `pkg/policy` enforce **95%**. Adjacent
critical packages (for example `pkg/bundle`, `pkg/canon`) enforce a lower
floor today and **ratchet toward 95%** in follow-up work.

CLI, demo orchestration, doctor/init, and integration glue count toward the
repo total only.

Golden, conformance, and integration tests remain required for cross-service
acceptance; unit coverage does not replace them.

Configuration: `scripts/coverage-tiers.conf`. Enforcement:
`scripts/check-coverage.sh`.
