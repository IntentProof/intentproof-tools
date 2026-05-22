/**
 * @name Forbidden crypto/sha1 outside legacy compatibility shims
 * @description SHA-1 is deprecated for integrity and signature use except in legacy shims.
 * @kind problem
 * @problem.severity error
 * @id intentproof/go/forbidden-sha1
 * @tags security
 *       external/cwe/cwe-327
 */

import go

/** Holds if the file is an approved legacy compatibility shim path. */
predicate isLegacyShimFile(File f) {
  exists(string p |
    p = f.getRelativePath() and
    (
      p.matches("%/legacy/%") or
      p.matches("%/shim/%") or
      p.matches("%/shims/%") or
      p.matches("%legacy_shim%") or
      p.matches("%_legacy.%")
    )
  )
}

/** Holds if `imp` imports crypto/sha1. */
predicate isSHA1Import(ImportSpec imp) {
  imp.getPath() = "crypto/sha1"
}

from ImportSpec imp
where
  isSHA1Import(imp) and
  not isLegacyShimFile(imp.getFile())
select imp,
  "crypto/sha1 is forbidden outside legacy compatibility shims; use SHA-256 or stronger."
