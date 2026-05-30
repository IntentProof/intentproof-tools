# Offline refund verification (under 10 minutes)

No IntentProof account, no cloud ingest, no dashboard. You need Go (to build
from source) or a release `intentproof-verify` binary, plus this repo's spec
checkout for the golden bundle.

Contract reference: [`v0.1-local-contract.md`](v0.1-local-contract.md).

---

## 1. Clone and build (about 3 minutes)

```bash
git clone https://github.com/IntentProof/intentproof-tools.git
cd intentproof-tools
git clone https://github.com/IntentProof/intentproof-spec.git intentproof-spec
go build -o intentproof-verify ./cmd/intentproof-verify
go build -o intentproof ./cmd/intentproof
```

Homebrew install (macOS) skips the build step:

```bash
brew tap IntentProof/tap
brew install intentproof intentproof-verify
git clone https://github.com/IntentProof/intentproof-spec.git
```

---

## 2. Run the offline demo (about 2 minutes)

From `intentproof-tools`:

```bash
export INTENTPROOF_SPEC_DIR="$(pwd)/intentproof-spec"
export INTENTPROOF_LOCAL_OPEN_BROWSER=0
./intentproof demo refund
```

The command runs a local loop, replays the refund scenario, and prints paths
to the exported bundle and re-verification commands. No network egress.

---

## 3. Verify the bundle you exported (about 1 minute)

Use the bundle path printed by the demo, or the public golden fixture:

```bash
export INTENTPROOF_SPEC_DIR="$(pwd)/intentproof-spec"
./intentproof-verify intentproof-spec/golden/counterparty/counterparty-refund.proof.tar.zst
```

Expected first line:

```text
✓ pass: bundle.verify_pass
```

Non-zero exit means tampering, wrong platform binary, or a mismatched spec ref.

---

## 4. Explain and replay (about 2 minutes)

Human-readable summary (loads reason catalog when `INTENTPROOF_SPEC_DIR` is set):

```bash
./intentproof-verify explain intentproof-spec/golden/counterparty/counterparty-refund.proof.tar.zst
```

Fresh policy evaluation as JSON (after integrity checks):

```bash
./intentproof-verify replay intentproof-spec/golden/counterparty/counterparty-refund.proof.tar.zst | head
```

Machine-readable integrity result:

```bash
./intentproof verify intentproof-spec/golden/counterparty/counterparty-refund.proof.tar.zst
```

---

## 5. Reference policies (optional, about 2 minutes)

List the three refund preset packs:

```bash
./intentproof reference list | grep refund
```

Canonical packs live under
`intentproof-spec/reference-policies/payments/` (`refund-basic`,
`refund-with-ledger`, `refund-with-notification`). The demo uses
`refund-with-notification`.

---

## Troubleshooting

| Symptom | Check |
|---------|--------|
| Golden verify stdout drift | Spec ref must match `intentproof-tools/SPEC_REF`; rebuild verifier from same tools commit. |
| `explain` lacks friendly copy | Export `INTENTPROOF_SPEC_DIR` to the spec repo root. |
| Demo opens a browser | Set `INTENTPROOF_LOCAL_OPEN_BROWSER=0`. |

Counterparty playbook (auditors): [`counterparty-verification.md`](counterparty-verification.md).

Per-OS smoke (maintainers): `scripts/smoke-counterparty-verify.sh`.
