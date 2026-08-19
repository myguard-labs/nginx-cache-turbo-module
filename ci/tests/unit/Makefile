# C-level unit tests for the cache-turbo shm node state machine.
#
#   make check     extract + build + run under ASan/UBSan (the default gate)
#   make run       build + run without sanitizers
#   make clean
#
# NGINX_SRC points at an extracted nginx tree; ngx_rbtree.c and ngx_queue.h are
# compiled from it verbatim rather than faked, so node lifetime and rebalance
# behaviour under test are the real thing (and a use-after-free is a real ASan
# report, not a silent read out of a still-mapped fake arena).

# Resolve everything against THIS Makefile's directory, not the caller's cwd.
# `make -C ci/tests/unit` from the repo root would otherwise resolve a relative
# NGINX_SRC against ci/tests/unit/, and a caller passing a repo-root-relative path
# (as .github/workflows/build-test.yml does) would resolve it against the wrong
# base -- which is exactly how the first CI run failed with
# "layout_check.c:18: fatal error: ngx_config.h: No such file or directory"
# while `make check` from inside ci/tests/unit passed.
HERE := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
REPO := $(abspath $(HERE)/../../..)

NGINX_VERSION ?= 1.31.1
NGINX_SRC     ?= $(REPO)/.build/nginx-$(NGINX_VERSION)/src
NGINX_OBJS    ?= $(REPO)/.build/nginx-$(NGINX_VERSION)/objs

# A caller-supplied relative path is relative to the REPO ROOT (the natural base
# for a CI `run:` block), so make it absolute here rather than silently failing.
override NGINX_SRC  := $(abspath $(if $(filter /%,$(NGINX_SRC)),$(NGINX_SRC),$(REPO)/$(NGINX_SRC)))
override NGINX_OBJS := $(abspath $(if $(filter /%,$(NGINX_OBJS)),$(NGINX_OBJS),$(REPO)/$(NGINX_OBJS)))

CC      ?= cc
CFLAGS  ?= -O1 -g -std=c99 -Wall -Wextra -Werror -Wno-unused-parameter
SAN      = -fsanitize=address,undefined -fno-omit-frame-pointer \
           -fno-sanitize-recover=all

# The test TU uses ONLY the mirrored declarations in ngx_shim_shm.h (-I.), while
# ngx_rbtree.c and layout_check.c compile against the genuine nginx headers
# (-I$(NGINX_SRC)/core -I$(NGINX_OBJS)). Keeping the include paths apart is what
# stops ngx_core.h leaking into the test TU and colliding with the shim.
INCS_TEST = -I$(HERE)
INCS_NGX  = -I$(NGINX_SRC)/core -I$(NGINX_SRC)/event -I$(NGINX_SRC)/os/unix \
            -I$(NGINX_OBJS)

GEN = $(HERE)/generated_shm.inc

# frame_scan() (S231-L2-FRAMEQUAD) needs no nginx source tree at all -- it
# compiles the shared fuzz slice (ci/fuzz/generated_parser.inc, produced by
# ci/fuzz/extract_parser.sh from src/ngx_http_cache_turbo_redis.c) against
# ci/fuzz/ngx_shim.h's minimal nginx surface, the same production-code-no-copy
# approach as test_shm_state.c uses for the real nginx headers. It legitimately
# leaves several sibling functions in that shared slice unused (this test only
# exercises frame_scan()), hence -Wno-unused-function only for this target.
FUZZ_DIR    = $(HERE)/../../fuzz
FRAME_GEN   = $(FUZZ_DIR)/generated_parser.inc

.PHONY: check run extract layout-check extract-frame-scan clean

check: extract layout-check extract-frame-scan
	@$(CC) $(CFLAGS) $(SAN) $(INCS_NGX) -c $(NGINX_SRC)/core/ngx_rbtree.c \
	    -o $(HERE)/ngx_rbtree.san.o
	@$(CC) $(CFLAGS) $(SAN) $(INCS_TEST) -c $(HERE)/test_shm_state.c \
	    -o $(HERE)/test_shm_state.san.o
	@$(CC) $(SAN) $(HERE)/test_shm_state.san.o $(HERE)/ngx_rbtree.san.o -o $(HERE)/test_shm_state.san
	@ASAN_OPTIONS=detect_leaks=1 $(HERE)/test_shm_state.san
	@$(CC) $(CFLAGS) -Wno-unused-function $(SAN) -I$(FUZZ_DIR) \
	    -o $(HERE)/test_frame_scan.san $(HERE)/test_frame_scan.c
	@ASAN_OPTIONS=detect_leaks=1 $(HERE)/test_frame_scan.san
	@$(CC) $(CFLAGS) $(SAN) -o $(HERE)/test_ae_class_guard.san \
	    $(HERE)/test_ae_class_guard.c
	@ASAN_OPTIONS=detect_leaks=1 $(HERE)/test_ae_class_guard.san

run: extract layout-check extract-frame-scan
	@$(CC) $(CFLAGS) $(INCS_NGX) -c $(NGINX_SRC)/core/ngx_rbtree.c -o $(HERE)/ngx_rbtree.o
	@$(CC) $(CFLAGS) $(INCS_TEST) -c $(HERE)/test_shm_state.c -o $(HERE)/test_shm_state.o
	@$(CC) $(HERE)/test_shm_state.o $(HERE)/ngx_rbtree.o -o $(HERE)/test_shm_state
	@$(HERE)/test_shm_state
	@$(CC) $(CFLAGS) -Wno-unused-function -I$(FUZZ_DIR) \
	    -o $(HERE)/test_frame_scan $(HERE)/test_frame_scan.c
	@$(HERE)/test_frame_scan
	@$(CC) $(CFLAGS) -o $(HERE)/test_ae_class_guard $(HERE)/test_ae_class_guard.c
	@$(HERE)/test_ae_class_guard

extract-frame-scan: $(FRAME_GEN)

$(FRAME_GEN): $(REPO)/src/ngx_http_cache_turbo_redis.c $(FUZZ_DIR)/ngx_shim.h $(FUZZ_DIR)/extract_parser.sh
	@$(FUZZ_DIR)/extract_parser.sh

# Static-asserts the mirrored structs against the real nginx headers. Drift here
# would otherwise be silent memory corruption at run time, not a build error.
layout-check:
	@$(CC) $(CFLAGS) $(INCS_NGX) -c $(HERE)/layout_check.c -o $(HERE)/layout_check.o
	@echo "✓ nginx struct layouts match the mirrored declarations"

extract: $(GEN)

# ⚠ module.c is a prerequisite too: O4.2 slices the breaker's origin-failure
# predicate out of it by marker. Without it listed here, editing that predicate
# leaves a STALE generated_shm.inc in place and the suite silently tests the
# previous copy -- a mutation of the production predicate then "passes",
# which is exactly how a negative control ends up guarding nothing.
# access.c is a prerequisite for the same reason since MAINT-SPLIT step F: the
# O4.3 pre-origin gate canary is a CALL-SITE invariant checked against the
# access handler, which now lives there. Dropping the latch without this listed
# would leave a stale .inc and the canary unrun.
$(GEN): $(REPO)/src/ngx_http_cache_turbo_shm.c $(REPO)/src/ngx_http_cache_turbo_module.h $(REPO)/src/ngx_http_cache_turbo_internal.h $(REPO)/src/ngx_http_cache_turbo_module.c $(REPO)/src/ngx_http_cache_turbo_access.c $(HERE)/extract_shm.sh
	@$(HERE)/extract_shm.sh

clean:
	@rm -f $(HERE)/test_shm_state $(HERE)/test_shm_state.san $(HERE)/*.o $(GEN)
	@rm -f $(HERE)/test_frame_scan $(HERE)/test_frame_scan.san
