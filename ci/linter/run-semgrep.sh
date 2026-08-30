#!/usr/bin/env bash
# Immutable C-rule snapshot: Semgrep Rules commit 40b8c63f75dc7c22c8a77482d73bfb864b146f7e.
set -euo pipefail

expected='1.169.0'
commit='40b8c63f75dc7c22c8a77482d73bfb864b146f7e'
rules=(
    "https://raw.githubusercontent.com/semgrep/semgrep-rules/$commit/c/lang/security/double-free.yaml"
    "https://raw.githubusercontent.com/semgrep/semgrep-rules/$commit/c/lang/security/insecure-use-gets-fn.yaml"
    "https://raw.githubusercontent.com/semgrep/semgrep-rules/$commit/c/lang/security/insecure-use-printf-fn.yaml"
    "https://raw.githubusercontent.com/semgrep/semgrep-rules/$commit/c/lang/security/insecure-use-scanf-fn.yaml"
    "https://raw.githubusercontent.com/semgrep/semgrep-rules/$commit/c/lang/security/insecure-use-strcat-fn.yaml"
    "https://raw.githubusercontent.com/semgrep/semgrep-rules/$commit/c/lang/security/insecure-use-string-copy-fn.yaml"
    "https://raw.githubusercontent.com/semgrep/semgrep-rules/$commit/c/lang/security/insecure-use-strtok-fn.yaml"
    "https://raw.githubusercontent.com/semgrep/semgrep-rules/$commit/c/lang/security/random-fd-exhaustion.yaml"
    "https://raw.githubusercontent.com/semgrep/semgrep-rules/$commit/c/lang/security/use-after-free.yaml"
)

actual="$(semgrep --version)"
if [ "$actual" != "$expected" ]; then
    echo "run-semgrep: expected semgrep $expected, got $actual" >&2
    exit 2
fi

args=(scan --jobs=1 --severity=WARNING --severity=ERROR --error --metrics=off)
for rule in "${rules[@]}"; do
    args+=(--config "$rule")
done
exec semgrep "${args[@]}" "$@"
