/**
 * @name Forbidden raw SQL string interpolation
 * @description SQL statements must use parameterized queries, not fmt.Sprintf or concatenation.
 * @kind problem
 * @problem.severity error
 * @id intentproof/go/raw-sql-interpolation
 * @tags security
 *       external/cwe/cwe-89
 */

import go
import semmle.go.dataflow.DataFlow

/** Holds if `call` invokes a database query method by name. */
predicate isDatabaseQueryCall(CallExpr call) {
  exists(string name |
    name = call.getTarget().(Function).getName() and
    (
      name = "Query" or
      name = "QueryRow" or
      name = "QueryContext" or
      name = "QueryRowContext" or
      name = "Exec" or
      name = "ExecContext" or
      name = "Prepare" or
      name = "PrepareContext"
    )
  )
}

/** Holds if `expr` is built via fmt.Sprintf or string concatenation. */
predicate isDynamicSQLString(Expr expr) {
  exists(CallExpr call |
    call = expr and
    call.getTarget().(Function).getName() = "Sprintf" and
    call.getTarget().(Function).getPackage().getPath() = "fmt"
  )
  or
  exists(AddExpr add | add = expr)
  or
  exists(BinaryExpr bin |
    bin = expr and
    bin.getOperator() = "+"
  )
}

from CallExpr call, Expr sqlArg, int idx
where
  isDatabaseQueryCall(call) and
  idx = 0 and
  sqlArg = call.getArgument(idx) and
  isDynamicSQLString(sqlArg)
select call,
  "SQL query argument is built with string interpolation; use parameterized queries."
