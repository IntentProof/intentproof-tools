# Contributing to intentproof-tools

Thanks for your interest in contributing to the Apache 2.0 surface of
IntentProof.

## Developer Certificate of Origin (DCO)

This repository accepts contributions under the
[Developer Certificate of Origin 1.1](https://developercertificate.org/).
We deliberately use DCO instead of a Contributor License Agreement
for the Apache repositories so the contribution path stays
frictionless.

Every commit must carry a `Signed-off-by:` trailer matching the
author email. The easiest way to do this is to pass `-s` to `git
commit`:

```
git commit -s -m "..."
```

By signing off, you certify that you have the right to submit the
contribution under the project's license. The full text of the DCO
is:

> Developer Certificate of Origin
> Version 1.1
>
> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I
>     have the right to submit it under the open source license
>     indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best
>     of my knowledge, is covered under an appropriate open source
>     license and I have the right under that license to submit that
>     work with modifications, whether created in whole or in part
>     by me, under the same open source license (unless I am
>     permitted to submit under a different license), as indicated
>     in the file; or
>
> (c) The contribution was provided directly to me by some other
>     person who certified (a), (b) or (c) and I have not modified
>     it.
>
> (d) I understand and agree that this project and the contribution
>     are public and that a record of the contribution (including
>     all personal information I submit with it, including my
>     sign-off) is maintained indefinitely and may be redistributed
>     consistent with this project and the open source license(s)
>     involved.

Commits without `Signed-off-by:` will be rejected by CI.

## Trademark

"IntentProof" and "Verified by IntentProof" are trademarks of
IntentProof, Inc. Apache 2.0 grants you a copyright license; it does
not grant you a trademark license. See `TRADEMARK.md` (forthcoming)
for the certification-mark policy.

## Code style

- Determinism over cleverness. The verifier is the audit contract.
  In Go: sort map keys before iterating, use `time.UTC` and
  `RFC3339Nano`, never use `math/rand` in the verifier.
- Tests first. The product is a verification engine; testing is the
  core deliverable.
- No imports of `github.com/intentproof/intentproof-core/...` are
  permitted. CI will reject them. See ADR-010 for the dependency
  invariant rationale.

## License

By contributing, you agree your contributions are licensed under the
Apache License 2.0 (see `LICENSE`).
