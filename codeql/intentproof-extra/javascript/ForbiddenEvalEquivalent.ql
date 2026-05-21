/**
 * @name Forbidden eval-equivalent dynamic code execution
 * @description eval, Function constructor, and vm.runInNewContext enable code injection.
 * @kind problem
 * @problem.severity error
 * @id intentproof/javascript/forbidden-eval-equivalent
 * @tags security
 *       external/cwe/cwe-94
 */

import javascript

/** Holds if `call` is eval() or new Function(...). */
predicate isEvalEquivalent(DataFlow::CallNode call) {
  call.getCalleeName() = "eval" or
  call.getCalleeName() = "Function" or
  (
    call.getCalleeName() = "runInNewContext" and
    exists(DataFlow::CallNode recv | recv = call.getReceiver())
  )
}

from DataFlow::CallNode call
where isEvalEquivalent(call)
select call.getNode(),
  "eval-equivalent dynamic code execution is forbidden; use static parsing instead."
