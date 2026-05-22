# intentproof-extra CodeQL query packs

Project-specific static analysis rules for IntentProof public repositories,
as defined in ADR-015 CI security gates.

## Packs

| Pack | Language | Path |
|------|----------|------|
| `intentproof-extra-go` | Go | `codeql/intentproof-extra-go/` |
| `intentproof-extra-javascript` | JS/TS | `codeql/intentproof-extra-javascript/` |

## Queries

| Query ID | Language | Rule |
|----------|----------|------|
| `intentproof/go/forbidden-math-rand` | Go | Forbid `math/rand` for security-sensitive randomness |
| `intentproof/go/forbidden-sha1` | Go | Forbid `crypto/sha1` outside legacy shim paths |
| `intentproof/go/raw-sql-interpolation` | Go | Forbid dynamic SQL string building in database calls |
| `intentproof/javascript/forbidden-eval-equivalent` | JS/TS | Forbid `eval`, `Function`, `vm.runInNewContext` |
| `intentproof/javascript/unsanitized-template-rendering` | JS/TS | Forbid `dangerouslySetInnerHTML` in server paths |

## Usage

Repositories reference the language-specific pack from `IntentProof/intentproof-tools`
in their CodeQL workflow. Error-severity findings are PR-blocking; warning-severity
findings are advisory.

Allowlist exceptions live in each repo's `.github/codeql-allowlist.yml` with
expiry dates and security on-call approval.
