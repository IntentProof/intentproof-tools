/**
 * @name Forbidden unsanitized server-side template rendering
 * @description Server-side HTML rendering must not pass untrusted input to dangerouslySetInnerHTML or raw HTML sinks.
 * @kind problem
 * @problem.severity error
 * @id intentproof/javascript/unsanitized-template-rendering
 * @tags security
 *       external/cwe/cwe-79
 */

import javascript
import semmle.javascript.security.dataflow.UnsafeHtmlConstructionQuery

/** Holds if `prop` is dangerouslySetInnerHTML assignment. */
predicate isDangerousInnerHTML(DataFlow::PropWrite prop) {
  prop.getPropertyName() = "dangerouslySetInnerHTML"
}

from DataFlow::PropWrite prop
where isDangerousInnerHTML(prop)
select prop.getNode(),
  "Unsanitized dangerouslySetInnerHTML is forbidden in server-side rendering paths."
