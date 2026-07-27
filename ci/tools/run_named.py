#!/usr/bin/env python3
r"""Run NAMED tests from ci/tools/test_runtime.py instead of the whole suite.

WHY THIS EXISTS
    The full runtime suite is ~13 min of mostly-wall-clock (entries must
    really expire), which is far too slow for a falsification loop -- and
    proving a negative control means rebuilding and re-running per attempt.
    This reuses test_runtime's own fixture stack (Origin, Nginx, redis,
    memcached) verbatim and only replaces run_all() with "call these N
    functions", so a single test costs seconds instead of minutes.

    s115 had a one-off variant of this (scratchpad/run_keepstale.py) that was
    never committed and is gone -- which is why this one lives in ci/tools/ and
    is tracked. It is generic: any test name, no edits.

USAGE
    python3 ci/tools/run_named.py \
        --nginx-binary .build/nginx-1.31.1/objs/nginx \
        --module .build/nginx-1.31.1/objs/ngx_http_cache_turbo_module.so \
        --port 18990 \
        test_5xx_never_overwrites_cached_body

    Multiple names are allowed. Every flag that test_runtime.py accepts is
    passed through unchanged (--redis-server, --memcached-server,
    --single-process, --sanitizer, ...), so an L2-dependent test still works:

    python3 ci/tools/run_named.py ... --redis-server /usr/bin/redis-server NAME

INPUTS / OUTPUTS
    Exit 0 = every named test passed. Non-zero = a test raised (traceback on
    stderr, same as the real suite). Prints one "PASS <name>" line per test.
    No files written; the fixture tree lives in a TemporaryDirectory.

SIDE EFFECTS
    Starts nginx (+ optionally redis/memcached) on --port and neighbours
    (origin = port+11, redis = +21/+22/+23, memcached = +24), exactly as the
    real suite does.

    /!\ THIS BOX HOSTS LIVE SELF-HOSTED CI RUNNERS. The suite's default range
    is 18870-18999 and a local run COLLIDES with a live CI wave, flaking the
    PR under test. Check first, and filter CI's own PIDs out of any pgrep:
        pgrep -af test_runtime.py | grep -v /opt/actions-runner
    Never `pkill -f test_runtime.py` -- it kills other repos' CI jobs.

LIMITS
    - Tests are called with (ng, origin) only. A test needing redis/memcached
      handles (see run_all's signature) needs its extra args wired here; the
      dispatch below inspects the signature and passes what it can.
    - No isolation between named tests: they share one nginx like the real
      run_all does, so ordering effects are the same as in the suite.

EXTEND
    The name -> callable lookup is just getattr on the imported module, so
    nothing needs touching when tests are added. To support a new fixture
    argument, add it to FIXTURES below.
"""
import argparse
import io
import inspect
import pathlib
import sys
import tempfile
import time

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import test_runtime as T  # noqa: E402


def _valueless_flags() -> set:
    """Option strings of test_runtime's flags that take NO value.

    Read from test_runtime's own parser declarations instead of being
    duplicated here, so adding a `store_true` flag there cannot silently
    desynchronise this tool's argv splitting. test_runtime builds its parser
    inside parse_args(), so we call it with add_argument() intercepted and
    argv emptied; the required= flags would otherwise abort the process.
    """
    captured: set = set()
    real_add = argparse.ArgumentParser.add_argument

    def spy(self, *args, **kwargs):
        action = real_add(self, *args, **kwargs)
        if action.nargs == 0:
            captured.update(action.option_strings)
        return action

    argparse.ArgumentParser.add_argument = spy
    saved_argv, saved_stderr = sys.argv, sys.stderr
    sys.argv = [saved_argv[0]]
    try:
        # argparse prints its usage block to stderr before raising; that is
        # noise here, not a diagnostic the caller should see.
        sys.stderr = io.StringIO()
        T.parse_args()
    except SystemExit:
        # Expected: --nginx-binary is required and absent under the empty argv.
        pass
    finally:
        argparse.ArgumentParser.add_argument = real_add
        sys.argv, sys.stderr = saved_argv, saved_stderr

    return captured


def main() -> int:
    # Split our positional test names off argv before test_runtime's parser
    # (which accepts no positionals) ever sees them.
    #
    # Flag arity is read from test_runtime's OWN parser rather than guessed
    # from the shape of the next token. Assuming every flag takes a value
    # makes a boolean flag swallow the following test name -- e.g.
    # `run_named.py --single-process test_foo` would forward "test_foo" as
    # the value of --single-process, leave `names` empty, and print usage.
    # That failure is quiet enough to be misread as a test result, which is
    # exactly the wrong thing in the tool used to prove negative controls.
    # Deriving arity here means a future store_true flag cannot reintroduce it.
    nargs_zero = _valueless_flags()

    names = []
    passthrough = []
    argv = sys.argv[1:]
    i = 0
    while i < len(argv):
        a = argv[i]
        if a.startswith("-"):
            passthrough.append(a)
            if (
                "=" not in a
                and a not in nargs_zero
                and i + 1 < len(argv)
                and not argv[i + 1].startswith("-")
            ):
                passthrough.append(argv[i + 1])
                i += 1
        else:
            names.append(a)
        i += 1

    if not names:
        print(__doc__)
        return 2

    fns = []
    for n in names:
        fn = getattr(T, n, None)
        if fn is None or not callable(fn):
            print(f"no such test: {n}", file=sys.stderr)
            return 2
        fns.append((n, fn))

    sys.argv = [sys.argv[0]] + passthrough
    args = T.parse_args()

    binary = pathlib.Path(args.nginx_binary).resolve()
    module = pathlib.Path(args.module).resolve() if args.module else None
    if not binary.exists():
        raise FileNotFoundError(binary)
    if module is not None and not module.exists():
        raise FileNotFoundError(module)

    origin_port = args.port + 11
    redis_port = args.port + 21 if args.redis_server else None
    redis_auth_port = args.port + 22 if args.redis_server else None
    redis_tls_port = args.port + 23 if args.redis_server else None
    memcached_port = args.port + 24 if args.memcached_server else None
    redis_password = "ctsecret"

    rc = 0
    with tempfile.TemporaryDirectory(prefix="cache-turbo-named-") as tmp:
        root = pathlib.Path(tmp)
        origin = T.Origin(origin_port, delay=0.05)
        redis = redis_auth = redis_tls = mc = None
        tls_certs = None

        if args.memcached_server:
            mc = T.MemcachedServer(pathlib.Path(args.memcached_server),
                                   memcached_port)
        if args.redis_server:
            rbin = pathlib.Path(args.redis_server)
            redis = T.RedisServer(rbin, root / "redis", redis_port)
            redis_auth = T.RedisServer(rbin, root / "redis-auth",
                                       redis_auth_port, password=redis_password)
            try:
                tls_certs = T.gen_tls_certs(root / "redis-tls-certs")
                redis_tls = T.RedisServer(rbin, root / "redis-tls",
                                          redis_tls_port, tls_certs=tls_certs)
            except Exception:
                redis_tls = None
                tls_certs = None

        ng = T.Nginx(binary, module, root / "server", args.port, origin_port,
                     args.runner, args.single_process, redis_port,
                     redis_auth_port=redis_auth_port if redis_auth else None,
                     redis_password=redis_password,
                     redis_tls_port=redis_tls_port if redis_tls else None,
                     redis_tls_ca=(tls_certs or {}).get("ca"),
                     memcached_port=memcached_port if mc else None,
                     fault_injection=args.fault_injection)
        ng.sanitizer = args.sanitizer

        try:
            origin.start()
            for srv in (redis, redis_auth):
                if srv is not None:
                    srv.start()
            if redis_tls is not None:
                try:
                    redis_tls.start()
                except Exception:
                    redis_tls = None
            if mc is not None:
                mc.start()

            ng.write_config()
            ng.config_test()
            ng.start()

            FIXTURES = {
                "ng": ng, "origin": origin, "redis": redis,
                "redis_auth": redis_auth, "redis_tls": redis_tls, "mc": mc,
            }
            for name, fn in fns:
                kw = {}
                for p in inspect.signature(fn).parameters:
                    if p in FIXTURES:
                        kw[p] = FIXTURES[p]
                fn(**kw)
                print(f"PASS {name}")

            time.sleep(0.2)
            ng.stop()
            ng.assert_clean_logs()
        finally:
            ng.stop()
            for srv in (redis, redis_auth, redis_tls, mc):
                if srv is not None:
                    srv.stop()
            origin.stop()

    return rc


if __name__ == "__main__":
    raise SystemExit(main())
