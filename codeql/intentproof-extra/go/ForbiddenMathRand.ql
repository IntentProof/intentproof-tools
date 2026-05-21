/**
 * @name Forbidden math/rand for security-sensitive code
 * @description math/rand is not cryptographically secure. Use crypto/rand instead.
 * @kind problem
 * @problem.severity error
 * @id intentproof/go/forbidden-math-rand
 * @tags security
 *       external/cwe/cwe-338
 */

import go

/** Holds if `imp` is an import of package path "math/rand". */
predicate isMathRandImport(ImportSpec imp) {
  imp.getPath() = "\"math/rand\"" or imp.getPath() = "math/rand"
}

from ImportSpec imp
where isMathRandImport(imp)
select imp,
  "math/rand must not be used for security-sensitive randomness; use crypto/rand instead."
