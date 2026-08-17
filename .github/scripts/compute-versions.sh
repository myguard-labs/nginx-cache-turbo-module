#!/usr/bin/env bash
# sync-sha: acade99127605db55abae2e0f5a579b910bd25c8b8ab93e6a816204204ca45cb
# Resolve current upstream server releases and rewrite .github/versions.env.
set -euo pipefail

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
html="$(curl -fsSL --retry 3 --connect-timeout 30 --max-time 300 https://nginx.org/en/download.html)"
mainline="$(printf '%s' "$html" | grep -oE 'nginx-1\.[0-9]+\.[0-9]+' | awk -F. '$2 % 2 == 1' | sort -uV | tail -1 | sed 's/nginx-//')"
stable="$(printf '%s' "$html" | grep -oE 'nginx-1\.[0-9]+\.[0-9]+' | awk -F. '$2 % 2 == 0' | sort -uV | tail -1 | sed 's/nginx-//')"
auth=()
[ -z "${GITHUB_TOKEN:-}" ] || auth=(-H "Authorization: Bearer $GITHUB_TOKEN")
angie_tag="$(curl -fsSL --retry 3 --connect-timeout 30 --max-time 300 "${auth[@]}" \
    https://api.github.com/repos/webserver-llc/angie/releases/latest | jq -r .tag_name)"
angie="${angie_tag#Angie-}"
for value in "$mainline" "$stable" "$angie"; do
    printf '%s' "$value" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "bad upstream version: $value" >&2; exit 1; }
done

hash_url() {
    local url=$1 out="$tmp/${2}.tar.gz"
    .github/scripts/fetch-verify.sh "$url" - "$out" | awk '{print $1}'
}
main_sha="$(hash_url "https://nginx.org/download/nginx-$mainline.tar.gz" mainline)"
stable_sha="$(hash_url "https://nginx.org/download/nginx-$stable.tar.gz" stable)"
angie_sha="$(hash_url "https://download.angie.software/files/angie-$angie.tar.gz" angie)"
# shellcheck disable=SC1091
source .github/versions.env

printf '%s\n' \
    '# Central upstream pins. Keep version and digest together; CI sources this file' \
    '# and refuses any archive whose digest is not listed here.' \
    "NGINX_MAINLINE=$mainline" "NGINX_MAINLINE_SHA256=$main_sha" \
    "NGINX_STABLE=$stable" "NGINX_STABLE_SHA256=$stable_sha" \
    "NGINX_VERSION=$mainline" "NGINX_VERSION_SHA256=$main_sha" \
    "LEGACY_NGINX_VERSION=$LEGACY_NGINX_VERSION" \
    "LEGACY_NGINX_VERSION_SHA256=$LEGACY_NGINX_VERSION_SHA256" \
    "ANGIE_VERSION=$angie" "ANGIE_SHA256=$angie_sha" > .github/versions.env

printf 'nginx mainline=%s stable=%s; angie=%s\n' "$mainline" "$stable" "$angie"
