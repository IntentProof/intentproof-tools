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
}

/** Holds if `name` is a database method whose SQL string is argument 0. */
predicate isNonContextDatabaseMethod(string name) {
  name = "Query" or name = "QueryRow" or name = "Exec" or name = "Prepare"
}

/** Holds if `name` is a database method whose SQL string is argument 1. */
predicate isContextDatabaseMethod(string name) {
  name = "QueryContext" or
  name = "QueryRowContext" or
  name = "ExecContext" or
  name = "PrepareContext"
}

from CallExpr call, Expr sqlArg, string name
where
  isDatabaseQueryCall(call) and
  name = call.getTarget().(Function).getName() and
  (
    (isNonContextDatabaseMethod(name) and sqlArg = call.getArgument(0)) or
    (isContextDatabaseMethod(name) and sqlArg = call.getArgument(1))
  ) and
  isDynamicSQLString(sqlArg)
select call,
  "SQL query argument is built with string interpolation; use parameterized queries."
