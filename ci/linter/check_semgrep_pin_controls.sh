#!/usr/bin/env bash
# Each Semgrep consumer, engine pin, commit and individual rule URL must turn
# lint-semgrep-pin red when independently mutated.
set -euo pipefail

REPO="$(git rev-parse --show-toplevel)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
files=(ci/linter/run-semgrep.sh ci/linter/lint-semgrep-pin.sh ci/linter/lint-c.sh
       ci/linter/install-linters.sh .pre-commit-config.yaml
       .github/workflows/security-scanners.yml .github/workflows/ci-deep.yml)
for file in "${files[@]}"; do
    mkdir -p "$TMP/$(dirname "$file")"
    cp "$REPO/$file" "$TMP/$file"
done

expect_red() {
    local label="$1"
    if SEMGREP_PIN_ROOT="$TMP" bash "$TMP/ci/linter/lint-semgrep-pin.sh" >/dev/null 2>&1; then
        echo "✗ $label mutation stayed green" >&2
        exit 1
    fi
    echo "✓ $label mutation turns the Semgrep contract red"
}

for file in ci/linter/lint-c.sh .pre-commit-config.yaml \
            .github/workflows/security-scanners.yml .github/workflows/ci-deep.yml; do
    sed -i 's;ci/linter/run-semgrep\.sh;ci/linter/run-semgrep-disabled.sh;' "$TMP/$file"
    expect_red "$file consumer"
    cp "$REPO/$file" "$TMP/$file"
done
for file in ci/linter/install-linters.sh .github/workflows/security-scanners.yml \
            .github/workflows/ci-deep.yml; do
    sed -i 's/semgrep==1\.169\.0/semgrep==1.169.1/' "$TMP/$file"
    expect_red "$file engine"
    cp "$REPO/$file" "$TMP/$file"
done
sed -i "s/expected='1\.169\.0'/expected='1.169.1'/" "$TMP/ci/linter/run-semgrep.sh"
expect_red 'runner engine'
cp "$REPO/ci/linter/run-semgrep.sh" "$TMP/ci/linter/run-semgrep.sh"
sed -i "s/40b8c63f75dc7c22c8a77482d73bfb864b146f7e/0000000000000000000000000000000000000000/" \
    "$TMP/ci/linter/run-semgrep.sh"
expect_red 'rule revision'
cp "$REPO/ci/linter/run-semgrep.sh" "$TMP/ci/linter/run-semgrep.sh"
for rule in double-free insecure-use-gets-fn insecure-use-printf-fn \
            insecure-use-scanf-fn insecure-use-strcat-fn insecure-use-string-copy-fn \
            insecure-use-strtok-fn random-fd-exhaustion use-after-free; do
    sed -i "s;/$rule\.yaml;/$rule.disabled;" "$TMP/ci/linter/run-semgrep.sh"
    expect_red "$rule URL"
    cp "$REPO/ci/linter/run-semgrep.sh" "$TMP/ci/linter/run-semgrep.sh"
done
