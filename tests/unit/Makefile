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
# `make -C tests/unit` from the repo root would otherwise resolve a relative
# NGINX_SRC against tests/unit/, and a caller passing a repo-root-relative path
# (as .github/workflows/build-test.yml does) would resolve it against the wrong
# base -- which is exactly how the first CI run failed with
# "layout_check.c:18: fatal error: ngx_config.h: No such file or directory"
# while `make check` from inside tests/unit passed.
HERE := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
REPO := $(abspath $(HERE)/../..)

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

.PHONY: check run extract layout-check clean

check: extract layout-check
	@$(CC) $(CFLAGS) $(SAN) $(INCS_NGX) -c $(NGINX_SRC)/core/ngx_rbtree.c \
	    -o $(HERE)/ngx_rbtree.san.o
	@$(CC) $(CFLAGS) $(SAN) $(INCS_TEST) -c $(HERE)/test_shm_state.c \
	    -o $(HERE)/test_shm_state.san.o
	@$(CC) $(SAN) $(HERE)/test_shm_state.san.o $(HERE)/ngx_rbtree.san.o -o $(HERE)/test_shm_state.san
	@ASAN_OPTIONS=detect_leaks=1 $(HERE)/test_shm_state.san

run: extract layout-check
	@$(CC) $(CFLAGS) $(INCS_NGX) -c $(NGINX_SRC)/core/ngx_rbtree.c -o $(HERE)/ngx_rbtree.o
	@$(CC) $(CFLAGS) $(INCS_TEST) -c $(HERE)/test_shm_state.c -o $(HERE)/test_shm_state.o
	@$(CC) $(HERE)/test_shm_state.o $(HERE)/ngx_rbtree.o -o $(HERE)/test_shm_state
	@$(HERE)/test_shm_state

# Static-asserts the mirrored structs against the real nginx headers. Drift here
# would otherwise be silent memory corruption at run time, not a build error.
layout-check:
	@$(CC) $(CFLAGS) $(INCS_NGX) -c $(HERE)/layout_check.c -o $(HERE)/layout_check.o
	@echo "✓ nginx struct layouts match the mirrored declarations"

extract: $(GEN)

$(GEN): $(REPO)/src/ngx_http_cache_turbo_shm.c $(REPO)/src/ngx_http_cache_turbo_module.h $(HERE)/extract_shm.sh
	@$(HERE)/extract_shm.sh

clean:
	@rm -f $(HERE)/test_shm_state $(HERE)/test_shm_state.san $(HERE)/*.o $(GEN)
