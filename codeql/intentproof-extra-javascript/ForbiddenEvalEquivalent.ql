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

/** Holds if `expr` is eval(), Function(), new Function(), or runInNewContext(). */
predicate isEvalEquivalent(Expr expr) {
  exists(CallExpr call |
    expr = call and
    (
      call.getCalleeName() = "eval" or
      call.getCalleeName() = "Function" or
      call.getCalleeName() = "runInNewContext"
    )
  )
  or
  exists(NewExpr ne |
    expr = ne and
    ne.getCalleeName() = "Function"
  )
  or
  exists(MethodCallExpr call |
    expr = call and
    call.getMethodName() = "runInNewContext"
  )
}

from Expr expr
where isEvalEquivalent(expr)
select expr,
  "eval-equivalent dynamic code execution is forbidden; use static parsing instead."
