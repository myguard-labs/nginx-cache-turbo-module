# nginx-lifetime CodeQL queries

Request-lifetime detectors for this module (plan row BP-E1). They complement
`ci/linter/lint-resume-order.sh`, which matches the name `r` only.

- `queries/UseAfterRequestRelease.ql`
  (`myguard/nginx-lifetime/use-after-request-release`): a request, a local
  alias of it, or a copy of its `->pool` or `->connection`, read after a call
  that may free it: `ngx_http_finalize_request`, `ngx_http_terminate_request`,
  `ngx_http_free_request` or `ngx_http_run_posted_requests`. This is the
  CT-RESUME-FINALIZE-UAF shape fixed in #503.
- `queries/ParkCallbackUnchecked.ql`
  (`myguard/nginx-lifetime/park-callback-unchecked`): a function reached from
  a Redis/memcached read handler that reads `op->request` without a
  dominating `CT_PARK_CHECK(op)` (BP-B2).

## Rules the queries encode

- After `ngx_http_finalize_request(r)` (or terminate/free), every alias of `r`
  is dead, and so are copies of `r->pool` and `r->connection`. The one allowed
  use is the connection captured *before* the finalize, passed to
  `ngx_http_run_posted_requests(c)`. That is nginx's own resume idiom, and the
  loop checks `c->destroyed` first.
- After `ngx_http_run_posted_requests(c)`, the requests on `c` are dead. If `c`
  was not read from some `r->connection` (for example it came from
  `ev->data`), every request in scope is treated as dead.
- Aliases are followed through local copies (`req = r`). Reassigning a variable
  ends its old value, and writes (`r = NULL`) are not uses.
- In query (b), a read handler is a function installed as `op->read_handler`,
  as `c->read->handler`, or passed for a parameter named `read_handler`.
  Reachability uses direct calls only. The guard must dominate the read
  within the same function, so every completion callback needs its own check,
  as BP-B2 requires. A NULL test of `op->request` is not counted as a read.

## Limits

- Query (a) does not follow aliases through struct fields (`op->request`) or
  through calls.
- Query (b) does not follow function-pointer callbacks such as `members_cb`.
  It finds `CT_PARK_CHECK` through the macro's expanded control-flow nodes, so
  build the database with `-DNGX_HTTP_CACHE_TURBO_TEST_FAULTS=1`.
  `ci/tools/ci-build.sh` sets it in every mode. If the macro expands to
  nothing, nothing counts as a guard and the query reports the read anyway.
- BP-B2 added `CT_PARK_CHECK` (and `CT_PARK_CHECK_SLOT`) at the completion
  sites, so query (b) no longer reports them on a TEST_FAULTS build. Wire
  query (a) as a gate now, and query (b) in BP-W1.

## Running

```sh
# from the module root
codeql test run ci/codeql/nginx-lifetime/test   # positive and negative cases

# database of the module (only `make modules` is traced, about 15 s)
cp <nginx-1.31.3.tar.gz> "$BUILD_ROOT"/
codeql database create /tmp/ct-db --language=cpp --source-root=. \
  --command="env CCACHE_DISABLE=1 BUILD_ROOT=$BUILD_ROOT \
    bash ci/tools/ci-build.sh nginx 1.31.3 module"
codeql database analyze /tmp/ct-db ci/codeql/nginx-lifetime/lifetime.qls \
  --format=csv --output=/tmp/ct.csv
```

`CCACHE_DISABLE=1` matters. A ccache hit skips the compiler, so the tracer
would never see that file. The tests use inline expectations (`// $ Alert`
marks each line that must be flagged, and a result on any other line fails the
test). The fixtures use `//` comments because the expectation parser reads
only those; the extractor is the only compiler that sees these files. Tested
with CodeQL CLI 2.26.4 and `codeql/cpp-all` 12.0.3.
