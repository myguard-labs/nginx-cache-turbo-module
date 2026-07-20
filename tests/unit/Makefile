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

NGINX_VERSION ?= 1.31.1
NGINX_SRC     ?= ../../.build/nginx-$(NGINX_VERSION)/src

NGINX_OBJS ?= ../../.build/nginx-$(NGINX_VERSION)/objs

CC      ?= cc
CFLAGS  ?= -O1 -g -std=c99 -Wall -Wextra -Werror -Wno-unused-parameter
SAN      = -fsanitize=address,undefined -fno-omit-frame-pointer \
           -fno-sanitize-recover=all

# The test TU uses ONLY the mirrored declarations in ngx_shim_shm.h (-I.), while
# ngx_rbtree.c and layout_check.c compile against the genuine nginx headers
# (-I$(NGINX_SRC)/core -I$(NGINX_OBJS)). Keeping the include paths apart is what
# stops ngx_core.h leaking into the test TU and colliding with the shim.
INCS_TEST = -I.
INCS_NGX  = -I$(NGINX_SRC)/core -I$(NGINX_SRC)/event -I$(NGINX_SRC)/os/unix \
            -I$(NGINX_OBJS)

GEN = generated_shm.inc

.PHONY: check run extract layout-check clean

check: extract layout-check
	@$(CC) $(CFLAGS) $(SAN) $(INCS_NGX) -c $(NGINX_SRC)/core/ngx_rbtree.c \
	    -o ngx_rbtree.san.o
	@$(CC) $(CFLAGS) $(SAN) $(INCS_TEST) -c test_shm_state.c \
	    -o test_shm_state.san.o
	@$(CC) $(SAN) test_shm_state.san.o ngx_rbtree.san.o -o test_shm_state.san
	@ASAN_OPTIONS=detect_leaks=1 ./test_shm_state.san

run: extract layout-check
	@$(CC) $(CFLAGS) $(INCS_NGX) -c $(NGINX_SRC)/core/ngx_rbtree.c -o ngx_rbtree.o
	@$(CC) $(CFLAGS) $(INCS_TEST) -c test_shm_state.c -o test_shm_state.o
	@$(CC) test_shm_state.o ngx_rbtree.o -o test_shm_state
	@./test_shm_state

# Static-asserts the mirrored structs against the real nginx headers. Drift here
# would otherwise be silent memory corruption at run time, not a build error.
layout-check:
	@$(CC) $(CFLAGS) $(INCS_NGX) -c layout_check.c -o layout_check.o
	@echo "✓ nginx struct layouts match the mirrored declarations"

extract: $(GEN)

$(GEN): ../../src/ngx_http_cache_turbo_shm.c ../../src/ngx_http_cache_turbo_module.h extract_shm.sh
	@./extract_shm.sh

clean:
	@rm -f test_shm_state test_shm_state.san *.o $(GEN)
