/**
 * @name nginx request used after it may be freed
 * @description A request, or a copy of its pool or connection, is read after a
 *              call that may free it: ngx_http_finalize_request,
 *              ngx_http_terminate_request, ngx_http_free_request, or
 *              ngx_http_run_posted_requests (whose posted terminate handler
 *              frees the request whatever its count). Finalize first, run the
 *              posted requests last, on a connection captured before the
 *              finalize. Aliases are followed through local copies.
 * @kind problem
 * @problem.severity error
 * @precision high
 * @id myguard/nginx-lifetime/use-after-request-release
 * @tags correctness
 *       security
 *       external/cwe/cwe-416
 */

import cpp
import lib.NginxLifetime

from ReleaseCall k, LocalScopeVariable v, string what, VariableAccess use
where
  useAfterRelease(k, v, what, use) and
  // report the first use on each path only once per call: the earliest
  // reachable read of v is enough to locate the defect
  not exists(VariableAccess earlier |
    useAfterRelease(k, v, what, earlier) and
    earlier != use and
    use = afterRelease(k, v) and
    earlier.getASuccessor+() = use and
    not use.getASuccessor+() = earlier
  )
select use, "'" + v.getName() + "' (" + what + ") is used after $@, which may free the request.", k,
  k.getTarget().getName()
