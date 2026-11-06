/**
 * Shared vocabulary for the nginx request-lifetime queries: the nginx object
 * types and the calls after which a request (and what hangs off it) may
 * already be freed.
 */

import cpp

/** Holds if `t` is a pointer to the nginx struct `name` (typedefs stripped). */
bindingset[name]
predicate isNgxPtr(Type t, string name) {
  t.getUnspecifiedType().(PointerType).getBaseType().getUnspecifiedType().(Struct).hasName(name)
}

/** A local variable or parameter holding an `ngx_http_request_t *`. */
class RequestVar extends LocalScopeVariable {
  RequestVar() { isNgxPtr(this.getType(), "ngx_http_request_s") }
}

/**
 * A call after which the request it names, or the requests of the connection
 * it names, may be freed:
 *  - `ngx_http_finalize_request(r, rc)` / `ngx_http_terminate_request(r, rc)` /
 *    `ngx_http_free_request(r, rc)` may drop the last reference to `r`;
 *  - `ngx_http_run_posted_requests(c)` runs whatever was posted on `c`, and a
 *    posted `ngx_http_terminate_handler` frees the request regardless of its
 *    reference count (CT-RESUME-FINALIZE-UAF, #503).
 */
class ReleaseCall extends FunctionCall {
  ReleaseCall() {
    this.getTarget()
        .hasGlobalName([
            "ngx_http_finalize_request", "ngx_http_terminate_request", "ngx_http_free_request",
            "ngx_http_run_posted_requests"
          ])
  }

  /** Holds if this call runs the connection's posted requests. */
  predicate isRunPosted() { this.getTarget().hasGlobalName("ngx_http_run_posted_requests") }
}

/** Holds if `e` is a plain read of variable `v`, possibly parenthesised or cast. */
predicate readsVar(Expr e, LocalScopeVariable v) {
  e.getUnconverted().(VariableAccess).getTarget() = v
}

/** Holds if `v` is assigned (or initialised) from expression `src` somewhere. */
predicate assignedFrom(LocalScopeVariable v, Expr src) {
  src = v.getAnAssignedValue().getUnconverted()
}

/**
 * Holds if request variables `a` and `b` of the same function hold the same
 * request: one is copied from the other (`b = a`, `ngx_http_request_t *b = a`).
 * Symmetric; the transitive closure is `requestAlias`.
 */
private predicate requestCopy(RequestVar a, RequestVar b) {
  a != b and
  (
    readsVar(b.getAnAssignedValue(), a)
    or
    readsVar(a.getAnAssignedValue(), b)
  )
}

/** Holds if `a` and `b` alias the same request (reflexive, transitive). */
predicate requestAlias(RequestVar a, RequestVar b) {
  a = b
  or
  requestCopy+(a, b)
}

/**
 * Holds if `e` reads field `field` of a request held in `r`
 * (`r->connection`, `r->pool`).
 */
predicate requestField(Expr e, RequestVar r, string field) {
  exists(PointerFieldAccess pfa |
    pfa = e.getUnconverted() and
    pfa.getTarget().hasName(field) and
    readsVar(pfa.getQualifier(), r)
  )
}

/**
 * Holds if `c` is a connection variable that is never assigned from a
 * request's `->connection` (for example the `ngx_event_t *ev->data` of a
 * timer). Its posted requests may then belong to any request in scope.
 */
predicate connectionOfUnknownRequest(LocalScopeVariable c) {
  isNgxPtr(c.getType(), "ngx_connection_s") and
  not exists(Expr src | assignedFrom(c, src) and requestField(src, _, "connection"))
}

/**
 * Holds if, after `k`, the request in `v` may be freed: `v` aliases the
 * request `k` finalizes, or a request whose connection `k` drains.
 */
predicate deadRequest(ReleaseCall k, RequestVar v) {
  v.getFunction() = k.getEnclosingFunction() and
  (
    not k.isRunPosted() and
    exists(RequestVar a | readsVar(k.getArgument(0), a) and requestAlias(a, v))
    or
    k.isRunPosted() and
    (
      // ngx_http_run_posted_requests(r->connection)
      exists(RequestVar a | requestField(k.getArgument(0), a, "connection") and requestAlias(a, v))
      or
      // c = r->connection; ...; ngx_http_run_posted_requests(c)
      exists(LocalScopeVariable c, Expr src, RequestVar a |
        readsVar(k.getArgument(0), c) and
        assignedFrom(c, src) and
        requestField(src, a, "connection") and
        requestAlias(a, v)
      )
      or
      // a connection of unknown origin: every request in scope may be freed
      exists(LocalScopeVariable c | readsVar(k.getArgument(0), c) and connectionOfUnknownRequest(c))
    )
  )
}

/**
 * Holds if `v` holds a value derived from a request that `k` may free, of
 * kind `what`:
 *  - "request": an alias of the request itself;
 *  - "pool": a copy of its `->pool` (destroyed with the request);
 *  - "connection": a copy of its `->connection` (closed with the main request).
 */
predicate deadValue(ReleaseCall k, LocalScopeVariable v, string what) {
  deadRequest(k, v) and what = "request"
  or
  exists(RequestVar r, Expr src |
    deadRequest(k, r) and
    v.getFunction() = k.getEnclosingFunction() and
    assignedFrom(v, src) and
    (
      requestField(src, r, "pool") and what = "pool"
      or
      requestField(src, r, "connection") and what = "connection"
    )
  )
}

/** Holds if control-flow node `n` (re)defines `v`, which ends its old value. */
predicate redefines(ControlFlowNode n, LocalScopeVariable v) {
  n.(Assignment).getLValue().(VariableAccess).getTarget() = v
  or
  n.(DeclStmt).getADeclaration() = v
}

/** A control-flow node reachable from `k` without redefining `v`. */
ControlFlowNode afterRelease(ReleaseCall k, LocalScopeVariable v) {
  deadValue(k, v, _) and result = k.getASuccessor()
  or
  exists(ControlFlowNode prev |
    prev = afterRelease(k, v) and
    not redefines(prev, v) and
    result = prev.getASuccessor()
  )
}

/**
 * Holds if `use` reads `v` (of kind `what`) on a path after `k` that does not
 * redefine `v`. Writes to `v` are not uses. The one sanctioned use of a
 * connection captured before a finalize is the argument of
 * `ngx_http_run_posted_requests` (nginx's own resume idiom); that call checks
 * `c->destroyed` first.
 */
predicate useAfterRelease(ReleaseCall k, LocalScopeVariable v, string what, VariableAccess use) {
  deadValue(k, v, what) and
  use = afterRelease(k, v) and
  use.getTarget() = v and
  not use.isUsedAsLValue() and
  not (
    what = "connection" and
    not k.isRunPosted() and
    exists(ReleaseCall rp |
      rp.isRunPosted() and
      readsVar(rp.getArgument(0), v) and
      use = rp.getArgument(0).getUnconverted()
    )
  )
}
