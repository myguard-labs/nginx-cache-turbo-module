/**
 * @name Parked request read in a backend callback without CT_PARK_CHECK
 * @description A function reached from a Redis/memcached read handler reads
 *              `op->request` of a parked operation without a dominating
 *              `CT_PARK_CHECK(op)`. A completion may arrive after the parked
 *              request was finalized or freed; CT_PARK_CHECK (BP-B2) is the
 *              guard that proves the park is still current before the request
 *              is touched.
 * @kind problem
 * @problem.severity warning
 * @precision medium
 * @id myguard/nginx-lifetime/park-callback-unchecked
 * @tags correctness
 *       security
 *       external/cwe/cwe-416
 */

import cpp

/** A field `request` of a backend operation struct (`*_op_t` / `*_op_s`). */
class OpRequestField extends Field {
  OpRequestField() {
    this.hasName("request") and
    exists(Class op | op = this.getDeclaringType() |
      op.getName().matches("%\\_op\\_s")
      or
      exists(TypedefType td | td.getBaseType() = op and td.getName().matches("%\\_op\\_t"))
    )
  }
}

/** Holds if `e` is `fa` or a conditional expression choosing `fa`. */
predicate carriesFunction(Expr e, FunctionAccess fa) {
  e.getUnconverted() = fa
  or
  carriesFunction(e.getUnconverted().(ConditionalExpr).getThen(), fa)
  or
  carriesFunction(e.getUnconverted().(ConditionalExpr).getElse(), fa)
}

/**
 * A backend read handler: a function installed as `op->read_handler`, as
 * `c->read->handler`, or passed for a parameter named `read_handler`.
 */
class ReadHandler extends Function {
  ReadHandler() {
    exists(FunctionAccess fa | fa.getTarget() = this |
      exists(Assignment a, FieldAccess lhs |
        lhs = a.getLValue() and carriesFunction(a.getRValue(), fa)
      |
        lhs.getTarget().hasName("read_handler")
        or
        lhs.getTarget().hasName("handler") and
        lhs.getQualifier().(FieldAccess).getTarget().hasName("read")
      )
      or
      exists(FunctionCall call, int i |
        carriesFunction(call.getArgument(i), fa) and
        call.getTarget().getParameter(i).hasName("read_handler")
      )
    )
  }
}

/** A function a read handler reaches through direct calls (itself included). */
predicate reachedFromReadHandler(Function f, ReadHandler h) { h.calls*(f) }

/** Holds if `n` belongs to an expansion of `CT_PARK_CHECK`. */
predicate parkCheckNode(ControlFlowNode n) {
  exists(MacroInvocation mi |
    mi.getMacroName() = "CT_PARK_CHECK" and
    n = mi.getAnExpandedElement()
  )
}

/**
 * Holds if `fa` only tests `op->request` against NULL (or for truth): that
 * reads no request memory.
 */
predicate nullTestOnly(FieldAccess fa) {
  exists(EqualityOperation eq | eq.getAnOperand().getUnconverted() = fa |
    eq.getAnOperand().getUnconverted() instanceof Literal
  )
  or
  fa = any(NotExpr ne).getOperand().getUnconverted()
  or
  fa = any(IfStmt s).getCondition().getUnconverted()
  or
  fa = any(BinaryLogicalOperation b).getAnOperand().getUnconverted()
}

from FieldAccess fa, Function f, ReadHandler h
where
  fa.getTarget() instanceof OpRequestField and
  f = fa.getEnclosingFunction() and
  reachedFromReadHandler(f, h) and
  not fa.isUsedAsLValue() and
  not nullTestOnly(fa) and
  not exists(ControlFlowNode guard | parkCheckNode(guard) and dominates(guard, fa)) and
  // one handler per access is enough to explain the result
  h = min(ReadHandler h2 | reachedFromReadHandler(f, h2) | h2 order by h2.getName())
select fa,
  "'" + fa.getTarget().getName() + "' of a parked operation is read in " + f.getName() +
    ", reached from read handler $@, without a dominating CT_PARK_CHECK.", h, h.getName()
