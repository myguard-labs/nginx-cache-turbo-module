#!/usr/bin/env bash
# Keep every Semgrep engine and immutable-rule consumer aligned.
set -euo pipefail
ROOT="${SEMGREP_PIN_ROOT:-$(git rev-parse --show-toplevel)}"
cd "$ROOT"

expected='1.169.0'
commit='40b8c63f75dc7c22c8a77482d73bfb864b146f7e'
runner='ci/linter/run-semgrep.sh'
installs=(ci/linter/install-linters.sh .github/workflows/security-scanners.yml
          .github/workflows/ci-deep.yml)
consumers=(ci/linter/lint-c.sh .pre-commit-config.yaml
           .github/workflows/security-scanners.yml .github/workflows/ci-deep.yml)
rules=(double-free insecure-use-gets-fn insecure-use-printf-fn
       insecure-use-scanf-fn insecure-use-strcat-fn insecure-use-string-copy-fn
       insecure-use-strtok-fn random-fd-exhaustion use-after-free)

for file in "$runner" "${installs[@]}" "${consumers[@]}"; do
    [ -f "$file" ] || { echo "lint-semgrep-pin: missing $file" >&2; exit 1; }
done
for file in "${installs[@]}"; do
    grep -qF "semgrep==$expected" "$file" || {
        echo "lint-semgrep-pin: $file does not pin semgrep==$expected" >&2; exit 1; }
done
for file in "${consumers[@]}"; do
    grep -qF "$runner" "$file" || {
        echo "lint-semgrep-pin: $file bypasses $runner" >&2; exit 1; }
done
grep -qF "expected='$expected'" "$runner" || {
    echo "lint-semgrep-pin: runner engine pin drifted" >&2; exit 1; }
grep -qF "commit='$commit'" "$runner" || {
    echo "lint-semgrep-pin: runner rule commit drifted" >&2; exit 1; }
for rule in "${rules[@]}"; do
    url="/c/lang/security/$rule.yaml"
    [ "$(grep -cF "$url" "$runner")" -eq 1 ] || {
        echo "lint-semgrep-pin: missing or duplicate immutable rule $rule" >&2; exit 1; }
done
[ "$(grep -cF "raw.githubusercontent.com/semgrep/semgrep-rules/\$commit" "$runner")" -eq "${#rules[@]}" ] || {
    echo "lint-semgrep-pin: every rule URL must use the pinned commit" >&2; exit 1; }
if grep -R -qE -- '--config p/(c|security-audit)' "$runner" "${consumers[@]}"; then
    echo "lint-semgrep-pin: floating registry alias remains" >&2; exit 1
fi
echo "lint-semgrep-pin: semgrep==$expected; ${#rules[@]} immutable C rules at $commit in every consumer"
