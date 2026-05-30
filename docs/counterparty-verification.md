# Counterparty and auditor verification

Third parties — buyers, regulators, and auditors — can verify an IntentProof
`.proof.tar.zst` bundle **without** an IntentProof account, API key, or trust
in our UI. Verification uses the same pure-Go evaluator the platform ships.

Golden fixture: [`intentproof-spec/golden/counterparty/`](https://github.com/IntentProof/intentproof-spec/tree/main/golden/counterparty).

Container image pre-pull verification is separate; see
[`intentproof-infra/docs/pre-pull-verification.md`](https://github.com/IntentProof/intentproof-infra/blob/main/docs/pre-pull-verification.md).

---

## 1. Install the verifier only

Pick one channel (no account required after download):

```bash
# macOS (Cosign-verified Homebrew formula)
brew tap IntentProof/tap
brew install intentproof-verify

# Linux/macOS/Windows — GitHub Release binary (verify Cosign signature first)
# https://github.com/IntentProof/intentproof-tools/releases

# Container (verify image digest before pull)
docker pull ghcr.io/intentproof/intentproof-verify:<tag>
```

See [`release-signing.md`](release-signing.md) for Cosign verification of release
artifacts.

---

## 2. Verify a bundle

Human-readable output (`intentproof-verify`):

```bash
intentproof-verify ./acme-q1-refund.proof.tar.zst
```

JSON output (`intentproof` CLI):

```bash
intentproof verify ./acme-q1-refund.proof.tar.zst
```

Exit code `0` means signatures and policy evaluation reproduced. Non-zero exit
prints structured findings on stderr/stdout — the same semantics as the hosted
platform.

### Worked example (golden bundle)

```bash
git clone https://github.com/IntentProof/intentproof-spec.git
cd intentproof-spec/golden/counterparty
intentproof-verify counterparty-refund.proof.tar.zst
```

Expected first line:

```text
✓ pass: bundle.verify_pass
```

Works on macOS (amd64/arm64) and Linux (amd64/arm64) with the published
`intentproof-verify` binary for your platform.

### Explain and replay (v0.1)

```bash
intentproof-verify explain counterparty-refund.proof.tar.zst
intentproof-verify replay counterparty-refund.proof.tar.zst > fresh-run.json
```

Set `INTENTPROOF_SPEC_DIR` to your `intentproof-spec` checkout so `explain`
can load signed reason-catalog copy.

Local smoke (current machine): from `intentproof-tools`, run
`scripts/smoke-counterparty-verify.sh`.

---

## 3. Read findings

- Reason codes come from signed `reasons.json` inside the bundle — not
  paraphrased marketing copy.
- Each stdout line after the status marker is a machine finding id
  (for example `event.signature_valid`, `policy.fingerprint_valid`).
- Use `intentproof verify --output result.json …` when you need the full JSON
  record for tooling.

---

## 4. Trust roots

Pin keys shipped inside the bundle:

| Key material | Location in bundle | Role |
|--------------|-------------------|------|
| Tenant / SDK signing keys | `keys/` | Event signature verification |
| Platform issuer key | `certificates/` (when present) | mTLS / identity claims |
| Webhook signer | separate envelope (if verifying webhooks) | Finding delivery integrity |

Cross-reference platform trust documentation in the spec repo and your sender's
key rotation policy. Never trust a bundle whose signature step fails even if
findings look acceptable.

---

## 5. Redaction profiles

When the sender exported with a `counterparty` or `auditor` profile, some
fields are hashed or omitted. **Verification still passes** when policy and
signatures are intact — the playbook documents which fields are redacted in
the bundle manifest.

Ask the sender which export profile they used if fields you expect are absent.

---

## Operator metrics

Hosted operators should track (dashboard implementation may follow separately):

| Metric | Meaning |
|--------|---------|
| `bundles_exported_total{profile="counterparty"}` | Bundles shared externally |
| `bundles_verified_external_total` | Distinct external re-verifications |

Year-one success signal: procurement accepts the bundle without a follow-up
workshop.

Optional anonymous telemetry when counterparty runs verify may increment
`bundles_verified_external_total` after privacy review — not required for
offline verification.

---

## Related material

- [`cmd/intentproof-verify/README.md`](../cmd/intentproof-verify/README.md)
- Golden bundle CI: `intentproof-spec/scripts/check-counterparty-golden.sh`
