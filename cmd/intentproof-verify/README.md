# intentproof-verify

Pure-Go verifier for IntentProof `.proof.tar.zst` bundles. Verification needs
no network, database, or runtime services — suitable for counterparty and
auditor machines.

## Usage

```bash
intentproof-verify <bundle.proof.tar.zst>
intentproof-verify --output result.json <bundle.proof.tar.zst>
intentproof-verify --version
```

Flow/policy/attestation mode (advanced):

```bash
intentproof-verify <flow.json> <policy.json> <attestations.jsonl>
```

## Counterparty playbook

See [`docs/counterparty-verification.md`](../../docs/counterparty-verification.md)
for install channels, trust roots, redaction profiles, and the golden bundle
worked example in
[`intentproof-spec/golden/counterparty/`](https://github.com/IntentProof/intentproof-spec/tree/main/golden/counterparty).

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Bundle or flow verification passed |
| non-zero | Tampered bundle, bad signature, or policy findings |

Human stdout begins with `✓ pass:` or `✗ fail:` followed by finding lines.
