#!/usr/bin/env python3
"""Compile the legacy build's actual SSL error classifier and test its levels."""

import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path

HARNESS = r"""
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#ifdef WITHOUT_NEW_REASONS
#undef SSL_R_PACKET_LENGTH_TOO_LONG
#undef SSL_R_BAD_RECORD_TYPE
#endif
typedef unsigned long ngx_uint_t;
typedef int ngx_err_t;
typedef struct { int log_error; void *log; } ngx_connection_t;
#define NGX_LOG_CRIT 3
#define NGX_LOG_ERR 4
#define NGX_LOG_INFO 7
#define NGX_ERROR_ERR 1
#define NGX_ERROR_INFO 2
#define NGX_ERROR_IGNORE_ECONNRESET 3
#define NGX_ECONNRESET ECONNRESET
#define NGX_EPIPE EPIPE
#define NGX_ENOTCONN ENOTCONN
#define NGX_ETIMEDOUT ETIMEDOUT
#define NGX_ECONNREFUSED ECONNREFUSED
#define NGX_ENETDOWN ENETDOWN
#define NGX_ENETUNREACH ENETUNREACH
#define NGX_EHOSTDOWN EHOSTDOWN
#define NGX_EHOSTUNREACH EHOSTUNREACH
static ngx_uint_t observed;
static void ngx_ssl_error(ngx_uint_t level, void *log, ngx_err_t err, char *text) {
    (void) log; (void) err; (void) text;
    observed = level;
    ERR_clear_error();
}
#include "classifier.inc"
static void check(int lib, int reason, int sslerr, int err, int mode, int expected) {
    ngx_connection_t c = {mode, NULL};
    ERR_clear_error();
    ERR_put_error(lib, 0, reason, __FILE__, __LINE__);
    observed = 0;
    ngx_ssl_connection_error(&c, sslerr, err, "test SSL failure");
    if (observed != (ngx_uint_t) expected) {
        fprintf(stderr, "classifier lib=%d reason=%d mode=%d: level=%lu expected=%d\n",
                lib, reason, mode, observed, expected);
        abort();
    }
}
int main(void) {
    int reasons[] = {198, 443};
    unsigned i;
    for (i = 0; i < sizeof(reasons) / sizeof(reasons[0]); i++) {
        int reason = reasons[i];
        int expected = NGX_LOG_CRIT;
#ifdef SSL_R_PACKET_LENGTH_TOO_LONG
        if (reason == SSL_R_PACKET_LENGTH_TOO_LONG) expected = NGX_LOG_ERR;
#endif
#ifdef SSL_R_BAD_RECORD_TYPE
        if (reason == SSL_R_BAD_RECORD_TYPE) expected = NGX_LOG_ERR;
#endif
        check(ERR_LIB_SSL, reason, SSL_ERROR_SSL, 0, NGX_ERROR_ERR, expected);
        check(ERR_LIB_SSL, reason, SSL_ERROR_SSL, 0, NGX_ERROR_INFO,
              expected == NGX_LOG_ERR ? NGX_LOG_INFO : NGX_LOG_CRIT);
        check(ERR_LIB_SSL, reason, SSL_ERROR_SSL, 0, NGX_ERROR_IGNORE_ECONNRESET,
              expected == NGX_LOG_ERR ? NGX_LOG_INFO : NGX_LOG_CRIT);
        check(ERR_LIB_SSL, reason, SSL_ERROR_SSL, 0, 0, NGX_LOG_CRIT);
        check(ERR_LIB_USER, reason, SSL_ERROR_SSL, 0, NGX_ERROR_ERR, NGX_LOG_CRIT);
        check(ERR_LIB_SSL, reason, SSL_ERROR_SYSCALL, EINVAL, NGX_ERROR_ERR, NGX_LOG_CRIT);
    }
    check(ERR_LIB_SSL, ERR_R_MALLOC_FAILURE, SSL_ERROR_SSL, 0, NGX_ERROR_ERR, NGX_LOG_CRIT);
    check(ERR_LIB_SSL, 313, SSL_ERROR_SSL, 0, NGX_ERROR_ERR, NGX_LOG_CRIT);
    check(ERR_LIB_SSL, 4095, SSL_ERROR_SSL, 0, NGX_ERROR_ERR, NGX_LOG_CRIT);
    check(ERR_LIB_SSL, SSL_R_WRONG_VERSION_NUMBER, SSL_ERROR_SSL, 0, NGX_ERROR_ERR, NGX_LOG_ERR);
    check(ERR_LIB_SYS, EINVAL, SSL_ERROR_SYSCALL, EINVAL, NGX_ERROR_ERR, NGX_LOG_CRIT);
    check(ERR_LIB_SYS, ECONNRESET, SSL_ERROR_SYSCALL, ECONNRESET, NGX_ERROR_ERR, NGX_LOG_ERR);
    puts("legacy TLS classifier: 18 controls passed");
    return 0;
}
"""


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: check_legacy_tls_errors.py SOURCE_ROOT")
    source = (Path(sys.argv[1]) / "src/event/ngx_event_openssl.c").read_text()
    start = "static void\nngx_ssl_connection_error("
    end = "\n\nstatic void\nngx_ssl_clear_error("
    if source.count(start) != 1 or source.count(end) != 1:
        raise SystemExit("legacy TLS classifier boundaries changed")
    classifier = source[source.index(start):source.index(end)]
    # Use the actual patched function, not a restatement of its predicate.
    with tempfile.TemporaryDirectory(prefix="legacy-tls-classifier-") as name:
        scratch = Path(name)
        (scratch / "classifier.inc").write_text(classifier)
        (scratch / "test.c").write_text(HARNESS)
        compiler = shlex.split(os.environ.get("CC", "cc"))
        for extra in ([], ["-DWITHOUT_NEW_REASONS"]):
            subprocess.run(compiler + ["-O2", "-Wall", "-Wextra", "-Werror"] + extra
                           + [str(scratch / "test.c"), "-lssl", "-lcrypto",
                              "-o", str(scratch / "test")], check=True)
            subprocess.run([str(scratch / "test")], check=True)


if __name__ == "__main__":
    main()
