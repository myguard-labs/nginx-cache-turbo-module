#!/usr/bin/env bash
# ci/linter/install-linters.sh -- install every linter ci/linter/ needs.
#
# Order of preference, per tool: apt-get (distro-managed, no PEP 668 fight)
# -> pipx/pip (Python tools apt does not carry) -> cpan (Perl modules apt does
# not carry) -> upstream binary (actionlint, ast-grep). Nothing here is a silent
# skip: a tool that fails to install prints why and the script exits non-zero,
# so a half-installed toolchain cannot masquerade as a working gate.
#
# Usage:
#   ci/linter/install-linters.sh            install what is missing
#   ci/linter/install-linters.sh --check    report only, install nothing
#   ci/linter/install-linters.sh --force    reinstall even if present
#
# Needs sudo for the apt-get and cpan steps; the pipx step installs into
# ~/.local/bin (make sure it is on PATH).
#
# Side effects: apt-get install, pipx install, cpanm install, and one curl of
# the actionlint release tarball and the ast-grep release zip into
# /usr/local/bin.
#
# Extend: add a line to the APT/PIPX/CPAN lists. Anything needing a bespoke
# install gets its own function at the bottom, next to install_actionlint
# and install_astgrep.

set -uo pipefail

CHECK=0 FORCE=0
case "${1:-}" in
    --check) CHECK=1 ;;
    --force) FORCE=1 ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    "") ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
esac

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"

# tool<TAB>apt package -- checked with command -v <tool>
APT_TOOLS=(
    "shellcheck:shellcheck"      # sh/bash
    "cppcheck:cppcheck"          # C
    "flawfinder:flawfinder"      # C, risky-API scan
    "yamllint:yamllint"          # YAML
    "clang:clang"                # C, and the PARSER behind
                                 # ci/tools/lint-carve-init.sh -- that gate
                                 # reads a real clang AST rather than lexing
                                 # the header, so without clang it exits 2
                                 # ("could not run") instead of reporting a
                                 # verdict. It is a hard requirement of the
                                 # lint suite, not an optional lens.
    "clang-tidy:clang-tidy"      # C, CI-only (needs a configured nginx tree)
    "bear:bear"                  # records the build's real compiler argv into
                                 # compile_commands.json, so clang-tidy parses
                                 # the same TU that ships instead of a
                                 # hand-kept -I list that drifts from configure
    "perlcritic:libperl-critic-perl"  # Perl test suite
    "perl:perl"
)
# Python IMPORTS, not executables, so `command -v` cannot see them and they
# need their own list -- checked with `python3 -c "import <mod>"`.
#
# PyYAML is a hard requirement of ci/linter/workflow_policy.py, which refuses
# to run without it rather than falling back to a regex scan. Every policy
# check it makes was bypassable by valid YAML while it parsed workflows by
# regex, so "degrade quietly to the old behaviour" is the one option that is
# worse than failing the job.
PY_MODULES=(
    "yaml:python3-yaml"          # ci/linter/workflow_policy.py
)
# Not in Debian/Ubuntu at the versions this repo targets -> Python packaging.
# pipx, not pip: PEP 668 marks the system interpreter externally-managed, so a
# bare `pip3 install` fails on Debian 12+ and `--break-system-packages` is a
# worse answer than an isolated venv per tool.
PIPX_TOOLS=(
    "ruff:ruff==0.16.1"                # Python lint + format check, pinned:
                                      # an unpinned ruff changes findings under
                                      # you and local stops matching CI, same
                                      # reasoning as the semgrep pin below.
    "zizmor:zizmor"                   # GitHub Actions security audit. Not
                                      # pinned: its rule set is the point, and a
                                      # frozen security scanner stops finding
                                      # what it was added for. A new rule going
                                      # red is a finding to triage, not drift.
    "semgrep:semgrep==1.169.0"        # C, pinned to the CI version on purpose:
                                      # an unpinned semgrep changes findings
                                      # under you and local stops matching CI.
    "codespell:codespell"             # ci/linter/lint-spelling.sh. Unpinned: the
                                      # dictionary is the point, and a new entry
                                      # going red is one typo to fix, not drift.
    "pre-commit:pre-commit"           # .githooks/pre-commit runs the
                                      # .pre-commit-config.yaml hooks too, and
                                      # treats its absence as exit 2 rather than
                                      # skipping the secret and C SAST gates.
)
# apt has no libtest-nginx-perl on every target release; cpan always does.
#
# "Test::Nginx" IS the openresty test suite -- there is no separately-named
# openresty distribution to look for. The CPAN dist is AGENT/Test-Nginx-*.tar.gz
# (AGENT = agentzh / Yichun Zhang, openresty's author); confirm with
# `cpanm --info Test::Nginx`. The giveaway in an installed tree is the
# Test::Nginx::Socket::Lua* modules, which only that dist ships.
CPAN_MODULES=(
    "Test::Nginx::Socket"        # the ci/t/*.t suite; also makes `perl -c` work
    "Perl::Critic"               # fallback if libperl-critic-perl was missing
)

have() { command -v "$1" >/dev/null 2>&1; }
step() { printf '\n== %s\n' "$*"; }
rc=0

# Reports a tool AND fails the check when it is absent. Printing MISSING
# without touching rc left `--check` exiting 0 with every executable tool gone,
# which made lint.yml's "verify completeness" step incapable of failing for the
# thing it verifies -- a green step over an incomplete toolchain. The python
# module loop below already sets rc this way; this brings the executables in
# line with it.
report() {
    local path
    if path="$(command -v "$1" 2>/dev/null)"; then
        printf '%-14s %s\n' "$1" "$path"
    else
        printf '%-14s MISSING\n' "$1"
        rc=1
    fi
}

have_mod() { python3 -c "import $1" >/dev/null 2>&1; }

if [ "$CHECK" -eq 1 ]; then
    step "linter status"
    for e in "${APT_TOOLS[@]}" "${PIPX_TOOLS[@]}"; do report "${e%%:*}"; done
    report actionlint
    report zizmor
    report ast-grep
    # gitleaks: this repo's secret gate (see install_gitleaks below). A tool
    # installed but absent from --check is invisible to lint.yml's verify step,
    # which is how a gate goes missing without anything going red.
    report gitleaks
    for e in "${PY_MODULES[@]}"; do
        mod="${e%%:*}"
        if have_mod "$mod"; then
            printf '%-14s ok (python module)\n' "$mod"
        else
            printf '%-14s MISSING (apt: %s)\n' "$mod" "${e##*:}"
            rc=1
        fi
    done
    # if/else, not `A && B || C`: in the chain form a failing printf falls
    # through to the MISSING branch and sets rc=1, reporting an installed
    # Test::Nginx as absent (SC2015). CI validates this file at the default
    # severity, where that info-level finding is fatal.
    #
    # (The word "shellcheck" is kept off the start of these comment lines on
    # purpose -- a comment beginning with it is parsed as a directive, SC1073.)
    if perl -MTest::Nginx::Socket -e1 2>/dev/null; then
        printf '%-14s ok\n' 'Test::Nginx'
    else
        printf '%-14s MISSING\n' 'Test::Nginx'
        rc=1
    fi
    exit "$rc"
fi

step "apt-get"
NEED=()
for e in "${APT_TOOLS[@]}"; do
    tool="${e%%:*}"; pkg="${e##*:}"
    if [ "$FORCE" -eq 1 ] || ! have "$tool"; then NEED+=("$pkg"); fi
done
for e in "${PY_MODULES[@]}"; do
    mod="${e%%:*}"; pkg="${e##*:}"
    if [ "$FORCE" -eq 1 ] || ! have_mod "$mod"; then NEED+=("$pkg"); fi
done
if [ "${#NEED[@]}" -gt 0 ]; then
    echo "installing: ${NEED[*]}"
    $SUDO apt-get update -qq || rc=1
    $SUDO apt-get install -y --no-install-recommends "${NEED[@]}" || rc=1
else
    echo "nothing to do"
fi

step "pipx"
have pipx || $SUDO apt-get install -y --no-install-recommends pipx || rc=1
for e in "${PIPX_TOOLS[@]}"; do
    tool="${e%%:*}"; spec="${e#*:}"
    if [ "$FORCE" -eq 1 ] || ! have "$tool"; then
        echo "installing: $spec"
        pipx install "$spec" || pipx install --force "$spec" || rc=1
    fi
done

step "cpan"
have cpanm || $SUDO apt-get install -y --no-install-recommends cpanminus || rc=1
for m in "${CPAN_MODULES[@]}"; do
    if [ "$FORCE" -eq 1 ] || ! perl -M"$m" -e1 2>/dev/null; then
        echo "installing: $m"
        # --notest: Test::Nginx's own suite wants a live nginx binary and a
        # free port, which is not something an install step should demand.
        $SUDO cpanm --notest "$m" || rc=1
    fi
done

install_actionlint() {
    # No apt package on the target releases and no pip/cpan equivalent: a Go
    # binary from the upstream release, pinned by version AND sha256.
    #
    # The digest is COMPARED, not printed. Printing `sha256sum` and moving on
    # reads as a verification step but installs whatever arrived -- worse than
    # no check, because it stops anyone from adding a real one. Version and
    # digest sit on adjacent lines for the same reason .github/versions.env
    # does it: a version must not be able to move while its digest stays behind.
    # From the upstream release's actionlint_<ver>_checksums.txt.
    local ver="1.7.7"
    local sha="023070a287cd8cccd71515fedc843f1985bf96c436b7effaecce67290e7e0757"
    local tmp
    tmp="$(mktemp -d)"
    curl -fsSL -o "$tmp/al.tgz" \
        "https://github.com/rhysd/actionlint/releases/download/v${ver}/actionlint_${ver}_linux_amd64.tar.gz" || return 1
    if ! printf '%s  %s\n' "$sha" "$tmp/al.tgz" | sha256sum -c - >/dev/null 2>&1; then
        echo "actionlint ${ver}: sha256 mismatch" >&2
        echo "  expected: $sha" >&2
        echo "  got:      $(sha256sum < "$tmp/al.tgz" | cut -d' ' -f1)" >&2
        rm -rf "$tmp"
        return 1
    fi
    tar -xzf "$tmp/al.tgz" -C "$tmp" actionlint || return 1
    $SUDO install -m0755 "$tmp/actionlint" /usr/local/bin/actionlint || return 1
    rm -rf "$tmp"
}

step "actionlint"
if [ "$FORCE" -eq 1 ] || ! have actionlint; then
    install_actionlint || { echo "actionlint install failed" >&2; rc=1; }
else
    echo "present: $(command -v actionlint)"
fi

install_astgrep() {
    # Rust binary from the upstream release: no apt package on the target
    # releases, and the PyPI/npm wrappers pull a whole toolchain to land the
    # same executable. Pinned by version AND sha256, digest COMPARED not
    # printed -- same reasoning as install_actionlint above.
    #
    # Pinned rather than floating, unlike zizmor/codespell: ast-grep's ruleset
    # is vendored in ci/ast-grep/ and versioned with the repo, so the pair has
    # to move together. A floating binary meeting a pinned ruleset changes
    # findings under you and local stops matching CI -- the semgrep/ruff
    # reasoning, not the security-scanner reasoning.
    #
    # Digest verified 2026-08-10 against the GitHub release API's own
    # asset .digest field, not merely recomputed from the download.
    local ver="0.44.1"
    local sha="611f9e5e76f2611ecea1a35dd3468ceedf600641a11224b80341d79c6ee7b9dd"
    local tmp
    tmp="$(mktemp -d)"
    curl -fsSL -o "$tmp/ag.zip" \
        "https://github.com/ast-grep/ast-grep/releases/download/${ver}/app-x86_64-unknown-linux-gnu.zip" || return 1
    if ! printf '%s  %s\n' "$sha" "$tmp/ag.zip" | sha256sum -c - >/dev/null 2>&1; then
        echo "ast-grep ${ver}: sha256 mismatch" >&2
        echo "  expected: $sha" >&2
        echo "  got:      $(sha256sum < "$tmp/ag.zip" | cut -d' ' -f1)" >&2
        rm -rf "$tmp"
        return 1
    fi
    # The zip carries both `ast-grep` and its short alias `sg`. Only ast-grep is
    # installed: `sg` collides with util-linux's setgid tool on Debian, and
    # ci/linter/ and .pre-commit-config.yaml both spell it out in full.
    unzip -qo "$tmp/ag.zip" ast-grep -d "$tmp" || return 1
    $SUDO install -m0755 "$tmp/ast-grep" /usr/local/bin/ast-grep || return 1
    rm -rf "$tmp"
}

step "ast-grep"
if [ "$FORCE" -eq 1 ] || ! have ast-grep; then
    have unzip || $SUDO apt-get install -y --no-install-recommends unzip || rc=1
    install_astgrep || { echo "ast-grep install failed" >&2; rc=1; }
else
    echo "present: $(command -v ast-grep)"
fi

install_gitleaks() {
    # ADDED for this module (adoption step 32): the secret scan is a gate this
    # repo already had -- .pre-commit-config.yaml runs
    # `gitleaks git --staged --no-banner --redact` -- and rule 2 says a gate the
    # target has must survive the rollout. The skeleton has no gitleaks, so
    # nothing in the ported installer knew about it: the binary was present on
    # this build host by hand, invisible to `--check`, and would simply have
    # been absent on a fresh clone or a hosted runner, silently retiring the
    # secret gate. Also recorded in skeleton-findings.md for step 49.
    #
    # Upstream binary, not apt: Debian ships 8.16.0 against upstream's 8.30.1,
    # and the rule packs that decide what counts as a secret are the point of
    # keeping current. Pinned by version AND sha256, digest COMPARED not
    # printed -- same reasoning as install_actionlint above.
    #
    # Digest verified 2026-08-10 against the release's own
    # gitleaks_8.30.1_checksums.txt, not merely recomputed from the download.
    local ver="8.30.1"
    local sha="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
    local tmp
    tmp="$(mktemp -d)"
    curl -fsSL -o "$tmp/gl.tgz" \
        "https://github.com/gitleaks/gitleaks/releases/download/v${ver}/gitleaks_${ver}_linux_x64.tar.gz" || return 1
    if ! printf '%s  %s\n' "$sha" "$tmp/gl.tgz" | sha256sum -c - >/dev/null 2>&1; then
        echo "gitleaks ${ver}: sha256 mismatch" >&2
        echo "  expected: $sha" >&2
        echo "  got:      $(sha256sum < "$tmp/gl.tgz" | cut -d' ' -f1)" >&2
        rm -rf "$tmp"
        return 1
    fi
    tar -xzf "$tmp/gl.tgz" -C "$tmp" gitleaks || return 1
    $SUDO install -m0755 "$tmp/gitleaks" /usr/local/bin/gitleaks || return 1
    rm -rf "$tmp"
}

step "gitleaks"
if [ "$FORCE" -eq 1 ] || ! have gitleaks; then
    install_gitleaks || { echo "gitleaks install failed" >&2; rc=1; }
else
    echo "present: $(command -v gitleaks)"
fi

step "result"
if [ "$rc" -ne 0 ]; then
    echo "one or more installs FAILED -- ci/linter/ is not fully armed" >&2
    exit 1
fi
echo "all linters installed; verify with: ci/linter/install-linters.sh --check"
