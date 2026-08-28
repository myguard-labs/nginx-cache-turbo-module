#!/usr/bin/env bash
# Redis topology coverage: real connect failure, fail-fast backoff, and a
# healthy-L2 control that distinguishes L2 fill from an origin refetch.
set -euo pipefail
# shellcheck source=/dev/null
. "$PROBER_LIB"

HOST=127.0.0.1
PORT="$PROBER_RESOLVED_PORT"
ELOG="$PROBER_PREFIX/logs/error.log"
ORIGIN_LOG="$PROBER_PREFIX/logs/origin.log"
FAILED=0

echo '1..5'
fail() {
  echo "not ok $1 - $2"
  FAILED=1
}
origin_hits() { [ -f "$ORIGIN_LOG" ] && wc -l <"$ORIGIN_LOG" || echo 0; }

request() {
  local uri="$1" out="$2" pid deadline
  (
    exec 3<>"/dev/tcp/$HOST/$PORT" || exit 1
    printf 'GET %s HTTP/1.1\r\nHost: prober\r\nConnection: close\r\n\r\n' "$uri" >&3
    cat <&3 2>/dev/null || true
  ) >"$out" 2>/dev/null &
  pid=$!
  deadline=$((SECONDS + 15))
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$SECONDS" -ge "$deadline" ]; then
      kill "$pid" 2>/dev/null || true
      break
    fi
    sleep 0.05
  done
  wait "$pid" 2>/dev/null || true
  grep -q '^HTTP/1.1 200' "$out"
}

header() {
  tr -d '\r' <"$1" | awk -v n="$2" '
        BEGIN { IGNORECASE=1 }
        /^$/ { exit }
        index(tolower($0),tolower(n) ":") == 1 {
            sub(/^[^:]*:[ \t]*/, ""); print tolower($0); exit
        }'
}

redis_skips() {
  local value
  value="$(header "$1" X-Cache-Turbo-Test-L2-Backoff)"
  case "$value" in
    redis=[0-9]*,memcached=[0-9]*) ;;
    *)
      echo "bad backoff header '$value'" >&2
      return 1
      ;;
  esac
  value="${value#redis=}"
  echo "${value%%,*}"
}

if [ "${CT_REDIS_UP:-0}" = 1 ]; then
  echo "ok 1 - healthy Redis accepted connections and the dead control port stayed closed"
else
  fail 1 "healthy Redis did not start on ${CT_REDIS_PORT:-?}"
fi

A_OUT="$PROBER_PREFIX/healthy-a.out"
B_OUT="$PROBER_PREFIX/healthy-b.out"
if [ "$FAILED" -eq 0 ] && request /healthy-a/item "$A_OUT"; then
  STORED=0
  for _i in $(seq 1 100); do
    if redis-cli -h "$HOST" -p "$CT_REDIS_PORT" --scan --pattern 'ctbo:*' 2>/dev/null | grep -q .; then
      STORED=1
      break
    fi
    sleep 0.05
  done
  if [ "$STORED" -eq 1 ]; then
    echo "ok 2 - healthy location A wrote the shared key to Redis"
  else
    fail 2 "healthy location A returned 200 but never wrote the L2 key"
  fi
else
  fail 2 "healthy location A did not return 200"
fi

HITS_A="$(origin_hits)"
N_A="$(redis_skips "$A_OUT" 2>/dev/null || echo invalid)"
LOG_A="$(wc -l <"$ELOG")"
if [ "$FAILED" -eq 0 ] && request /healthy-b/item "$B_OUT"; then
  N_B="$(redis_skips "$B_OUT" 2>/dev/null || echo invalid)"
  XC_B="$(header "$B_OUT" X-Cache)"
  if [ "$N_A" != invalid ] && [ "$N_B" != invalid ] \
    && [ "$XC_B" = hit ] && [ "$(origin_hits)" -eq "$HITS_A" ] \
    && [ "$N_A" = "$N_B" ] \
    && ! tail -n "+$((LOG_A + 1))" "$ELOG" | grep -Eqi '(connect|send|recv).*failed'; then
    echo "ok 3 - healthy Redis control filled cold L1 B as an L2 HIT with no failure log or backoff skip"
  else
    fail 3 "healthy control was not an L2 HIT: X-Cache=$XC_B origin=$(origin_hits)/$HITS_A skips=$N_A/$N_B"
  fi
else
  fail 3 "healthy location B did not return 200"
fi

DEAD1="$PROBER_PREFIX/dead-1.out"
DEAD2="$PROBER_PREFIX/dead-2.out"
LOG_BEFORE="$(wc -l <"$ELOG")"
if [ "$FAILED" -eq 0 ] && request /dead/one "$DEAD1"; then
  N1="$(redis_skips "$DEAD1" 2>/dev/null || echo invalid)"
  if [ "$N1" != invalid ] && [ "$N_B" != invalid ] && [ "$N1" = "$N_B" ] \
    && tail -n "+$((LOG_BEFORE + 1))" "$ELOG" | grep -Eqi '(connect|send|recv).*failed.*(refused|111)'; then
    echo "ok 4 - closed Redis produced the connect-failure log and armed backoff without counting a skip"
  else
    fail 4 "first dead-peer request lacked the connect-failure oracle or moved skips ($N_B -> $N1); log: $(tail -n "+$((LOG_BEFORE + 1))" "$ELOG" | tr '\n' ' ' | tail -c 600)"
  fi
else
  fail 4 "first dead-peer request did not fall back to the origin"
fi

LOG_SECOND="$(wc -l <"$ELOG")"
if request /dead/two "$DEAD2"; then
  N2="$(redis_skips "$DEAD2" 2>/dev/null || echo invalid)"
  if [ "$N2" -eq $((N1 + 1)) ] \
    && ! tail -n "+$((LOG_SECOND + 1))" "$ELOG" | grep -Eqi '(connect|send|recv).*failed'; then
    echo "ok 5 - immediate retry took one fail-fast skip with no second connect failure: redis backoff observable moved exactly once ($N1 -> $N2)"
  else
    fail 5 "retry did not take exactly one silent fail-fast skip ($N1 -> $N2)"
  fi
else
  fail 5 "second dead-peer request did not fall back to the origin: $(head -1 "$DEAD2" 2>/dev/null || echo no-response); log: $(tail -n "+$((LOG_SECOND + 1))" "$ELOG" | tr '\n' ' ' | tail -c 600)"
fi

[ "$FAILED" -eq 0 ]
