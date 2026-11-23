"""The ASan single-process sigmask correction is exact, idempotent and checked."""

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "ci/tools/single_process_sigmask.py"
CHECK = ROOT / "ci/tools/check_single_process_sigmask.py"
SPEC = importlib.util.spec_from_file_location("single_process_sigmask", HELPER)
assert SPEC is not None and SPEC.loader is not None
sp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sp)

# Minimal sources around the exact upstream anchors (nginx 1.31.3 text); the
# asan CI build applies the helper to the real pinned tarball and fails there
# if upstream text drifts.
PRISTINE = {
    sp.CYCLE_C: (
        "#include <ngx_event.h>\n\n\n"
        + sp.GLOBAL_ANCHOR
        + "ngx_uint_t    ngx_worker;\n\n\n"
        "void\nngx_single_process_cycle(ngx_cycle_t *cycle)\n{\n"
        "    ngx_uint_t  i;\n\n"
        "    for (i = 0; cycle->modules[i]; i++) {\n"
        "        init(cycle);\n"
        "    }\n\n"
        + sp.LOOP_ANCHOR
        + "            ngx_master_process_exit(cycle);\n"
        "        }\n"
        "    }\n"
        "}\n\n\nstatic void\nngx_start_worker_processes(void)\n{\n}\n"
    ),
    sp.CYCLE_H: sp.EXTERN_ANCHOR + "extern ngx_uint_t      ngx_worker;\n",
    sp.EPOLL_C: (
        "static ngx_int_t\n"
        "ngx_epoll_process_events(ngx_cycle_t *cycle, ngx_msec_t timer,"
        " ngx_uint_t flags)\n{\n"
        "    int                events;\n\n"
        + sp.WAIT_ANCHOR
        + "\n    return NGX_OK;\n}\n"
    ),
    Path("src/event/modules/ngx_poll_module.c"): (
        "    ready = poll(event_list, (u_int) nevents, (int) timer);\n"
    ),
}


@pytest.fixture(name="tree")
def source_tree(tmp_path):
    for name, text in PRISTINE.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    (tmp_path / sp.CYCLE_C).chmod(0o640)
    return tmp_path


def snapshot(root):
    return {p: p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def run_check(root, expect):
    return subprocess.run(
        [sys.executable, str(CHECK), "--expect", expect, str(root)],
        capture_output=True, text=True, check=False,
    )


def test_anchor_present_is_transformed_and_checked(tree):
    assert run_check(tree, "pristine").returncode == 0
    assert sp.apply(tree) == "applied"
    cycle = (tree / sp.CYCLE_C).read_text()
    assert cycle.count(sp.LOOP_BLOCK + sp.LOOP_ANCHOR) == 1
    assert cycle.index("ngx_single_wait_masked = 1;") < cycle.index("for ( ;; )")
    epoll = (tree / sp.EPOLL_C).read_text()
    assert "epoll_pwait(ep, event_list, (int) nevents, timer," in epoll
    assert (tree / sp.CYCLE_C).stat().st_mode & 0o777 == 0o640
    ok = run_check(tree, "patched")
    assert ok.returncode == 0, ok.stderr
    assert "patched ok" in ok.stdout
    leaked = run_check(tree, "pristine")
    assert leaked.returncode == 1
    assert "carries the CI-only asan sigmask correction" in leaked.stderr


def test_already_transformed_is_idempotent_without_writes(tree):
    assert sp.apply(tree) == "applied"
    before = snapshot(tree)
    stamps = {p: p.stat().st_mtime_ns for p in before}
    assert sp.apply(tree) == "already patched"
    assert snapshot(tree) == before
    assert {p: p.stat().st_mtime_ns for p in before} == stamps
    assert not list(tree.rglob(".sp-sigmask-*"))


def test_negative_control_check_catches_untransformed_tree(tree):
    red = run_check(tree, "patched")
    assert red.returncode == 1
    for finding in ("loop is not epoll-guarded and masked",
                    "missing definition", "missing extern",
                    "epoll wait does not use the saved mask"):
        assert finding in red.stderr
    print("negative control untransformed: " + red.stderr.strip().splitlines()[0])


@pytest.mark.parametrize("index", range(len(sp.EDITS)))
@pytest.mark.parametrize("mode", ["missing", "duplicated", "whitespace"])
def test_anchor_drift_is_refused_without_writes(tree, index, mode):
    name, anchor, _new = sp.EDITS[index]
    path = tree / name
    text = path.read_text()
    drift = {
        "missing": text.replace(anchor, ""),
        "duplicated": text.replace(anchor, anchor + anchor),
        "whitespace": text.replace(anchor, anchor.replace("\n", " \n", 1)),
    }[mode]
    path.write_text(drift)
    before = snapshot(tree)
    with pytest.raises(ValueError, match="anchor drift in " + str(name)):
        sp.apply(tree)
    assert snapshot(tree) == before
    assert run_check(tree, "patched").returncode == 1


def test_partially_transformed_tree_is_refused(tree):
    assert sp.apply(tree) == "applied"
    (tree / sp.EPOLL_C).write_text(PRISTINE[sp.EPOLL_C])
    before = snapshot(tree)
    with pytest.raises(ValueError, match="partially transformed"):
        sp.apply(tree)
    assert snapshot(tree) == before
    red = run_check(tree, "patched")
    assert red.returncode == 1
    assert "epoll wait does not use the saved mask" in red.stderr


@pytest.mark.parametrize("name,old,new,finding", [
    (sp.CYCLE_C, "if (ngx_event_flags & NGX_USE_EPOLL_EVENT) {", "{",
     "loop is not epoll-guarded"),
    (sp.CYCLE_C, "        sigaddset(&set, ngx_signal_value(NGX_TERMINATE_SIGNAL));\n",
     "", "does not block ngx_signal_value(NGX_TERMINATE_SIGNAL)"),
    (sp.CYCLE_C, "        sigaddset(&set, SIGINT);\n", "", "does not block SIGINT"),
    (sp.CYCLE_C, "            ngx_single_wait_masked = 1;\n", "",
     "loop is not epoll-guarded"),
    (sp.CYCLE_C, "sigset_t      ngx_single_wait_mask;\n", "",
     "missing definition"),
    (sp.CYCLE_H, "extern ngx_uint_t      ngx_single_wait_masked;\n", "",
     "missing extern ngx_uint_t"),
    (sp.EPOLL_C, "&ngx_single_wait_mask);", "NULL);",
     "epoll wait does not use the saved mask"),
    (sp.EPOLL_C, "    if (ngx_single_wait_masked) {", "    if (1) {",
     "epoll wait does not use the saved mask"),
    (sp.EPOLL_C, "    err = (events",
     ("    events = epoll_wait(ep, event_list,"
      " (int) nevents, timer);\n    err = (events"),
     "epoll wait does not use the saved mask"),
    # Flag set in the sigprocmask() failure branch instead of the success one.
    (sp.CYCLE_C,
     ('                          "sigprocmask() failed");\n\n'
      '        } else {\n            ngx_single_wait_masked = 1;\n'),
     ('                          "sigprocmask() failed");\n'
      '            ngx_single_wait_masked = 1;\n\n        } else {\n'),
     "not set only in the sigprocmask() success branch"),
    # Flag set in both branches.
    (sp.CYCLE_C, "sigprocmask() failed\");\n",
     "sigprocmask() failed\");\n            ngx_single_wait_masked = 1;\n",
     "not set only in the sigprocmask() success branch"),
    # Failure-branch assignment spelled without whitespace.
    (sp.CYCLE_C, '                          "sigprocmask() failed");\n',
     ('                          "sigprocmask() failed");\n'
      '            ngx_single_wait_masked=1;\n'),
     "not set only in the sigprocmask() success branch"),
    # Extra flag assignment after the if/else, still inside the guard.
    (sp.CYCLE_C, "            ngx_single_wait_masked = 1;\n        }\n",
     ("            ngx_single_wait_masked = 1;\n        }\n"
      "        ngx_single_wait_masked = 1;\n"),
     "not set only in the sigprocmask() success branch"),
    # Empty epoll guard followed by an unconditional mask block.
    (sp.CYCLE_C, "if (ngx_event_flags & NGX_USE_EPOLL_EVENT) {",
     "if (ngx_event_flags & NGX_USE_EPOLL_EVENT) {\n    }\n\n    {",
     "epoll guard does not contain the mask operation"),
    # Detached conditional: second wait runs unconditionally.
    (sp.EPOLL_C, "    } else {\n        events = epoll_wait(",
     "    }\n    if (0) {\n    } else {\n        events = epoll_wait(",
     "epoll wait does not use the saved mask"),
])
def test_check_catches_broken_transform(tree, name, old, new, finding):
    assert sp.apply(tree) == "applied"
    path = tree / name
    text = path.read_text()
    assert old in text
    path.write_text(text.replace(old, new, 1))
    red = run_check(tree, "patched")
    assert red.returncode == 1
    assert finding in red.stderr


@pytest.mark.parametrize("line", [
    "        sigemptyset(&set);\n",
    "        sigaddset(&set, SIGINT);\n",
    "        sigaddset(&set, ngx_signal_value(NGX_TERMINATE_SIGNAL));\n",
])
def test_check_requires_full_set_before_sigprocmask(tree, line):
    assert sp.apply(tree) == "applied"
    path = tree / sp.CYCLE_C
    text = path.read_text()
    assert text.count(line) == 1
    # Move the statement below the sigprocmask() conditional, inside the guard.
    tail = "            ngx_single_wait_masked = 1;\n        }\n"
    assert text.count(tail) == 1
    path.write_text(text.replace(line, "", 1).replace(tail, tail + line, 1))
    red = run_check(tree, "patched")
    assert red.returncode == 1
    assert "signal set is not fully built before sigprocmask()" in red.stderr


def test_check_requires_sigemptyset_before_sigaddset(tree):
    assert sp.apply(tree) == "applied"
    path = tree / sp.CYCLE_C
    text = path.read_text()
    empty = "        sigemptyset(&set);\n"
    last = "        sigaddset(&set, ngx_signal_value(NGX_SHUTDOWN_SIGNAL));\n"
    assert text.count(empty) == 1 and text.count(last) == 1
    # sigemptyset() after the adds, still before sigprocmask(): clears the set.
    path.write_text(text.replace(empty, "", 1).replace(last, last + empty, 1))
    red = run_check(tree, "patched")
    assert red.returncode == 1
    assert "signal set is not fully built before sigprocmask()" in red.stderr


def test_check_rejects_correction_use_outside_edited_files(tree):
    assert sp.apply(tree) == "applied"
    poll = tree / "src/event/modules/ngx_poll_module.c"
    poll.write_text(poll.read_text() + "    (void) &ngx_single_wait_mask;\n")
    red = run_check(tree, "patched")
    assert red.returncode == 1
    assert "ngx_poll_module.c: unexpected use" in red.stderr
    assert "ngx_poll_module.c: carries" in run_check(tree, "pristine").stderr


@pytest.mark.parametrize("kind", ["missing", "symlink"])
def test_irregular_source_is_refused(tree, kind):
    target = tree / sp.EPOLL_C
    outside = tree / "outside.c"
    outside.write_text(target.read_text())
    target.unlink()
    if kind == "symlink":
        target.symlink_to(outside)
    with pytest.raises(ValueError, match="must be a regular file"):
        sp.apply(tree)
    assert outside.read_text() == PRISTINE[sp.EPOLL_C]
    assert (tree / sp.CYCLE_C).read_text() == PRISTINE[sp.CYCLE_C]


def test_cli_exit_codes(tree):
    def helper(*args):
        return subprocess.run([sys.executable, str(HELPER), *args],
                              capture_output=True, text=True, check=False)

    assert helper().returncode == 2
    (tree / sp.CYCLE_H).write_text("drift\n")
    drift = helper(str(tree))
    assert drift.returncode == 1
    assert "anchor drift" in drift.stderr
    (tree / sp.CYCLE_H).write_text(PRISTINE[sp.CYCLE_H])
    ok = helper(str(tree))
    assert ok.returncode == 0
    assert ok.stdout.strip() == "single-process sigmask correction: applied"
    assert helper(str(tree)).stdout.strip().endswith("already patched")
    assert run_check(tree / "absent", "pristine").returncode == 1
    usage = subprocess.run([sys.executable, str(CHECK), str(tree)],
                           capture_output=True, text=True, check=False)
    assert usage.returncode == 2


HELPER_CALL = "single_process_sigmask.py /build/nginx"
PATCHED_CALL = "check_single_process_sigmask.py --expect patched"
PRISTINE_CALL = "check_single_process_sigmask.py --expect pristine"


@pytest.mark.parametrize("flavor,mode,expected", [
    ("nginx", "asan", [HELPER_CALL, PATCHED_CALL]),
    ("nginx", "debug", [PRISTINE_CALL]),
    ("nginx", "coverage", [PRISTINE_CALL]),
    ("nginx", "configure", [PRISTINE_CALL]),
    ("angie", "asan", []),
    ("angie", "debug", []),
])
def test_build_invocation_is_mode_and_flavor_limited(flavor, mode, expected):
    text = (ROOT / "ci/tools/ci-build.sh").read_text()
    start = text.index('if [ "$FLAVOR" = nginx ]; then\n    if [ "$MODE" = asan ]')
    snippet = text[start:text.index("\nfi\n", start) + 3]
    result = subprocess.run(
        ["bash", "-c", 'python3() { printf "%s\\n" "${1##*/} $2 $3"; }; '
         "MODULE_DIR=/module; ROOT=/build; DIR=nginx; "
         f"FLAVOR={flavor}; MODE={mode}; " + snippet],
        capture_output=True, text=True, check=True,
    )
    calls = result.stdout.splitlines()
    assert len(calls) == len(expected), calls
    for call, want in zip(calls, expected, strict=True):
        assert call.startswith(want), (call, want)



@pytest.mark.parametrize("index", range(len(sp.EDITS)))
def test_extra_pristine_anchor_on_patched_tree_is_drift(tree, index):
    assert sp.apply(tree) == "applied"
    name, anchor, _new = sp.EDITS[index]
    path = tree / name
    # A second pristine anchor outside the edited function: the replacement is
    # still present exactly once, so only the anchor surplus reveals the drift.
    path.write_text(path.read_text() + "\n/* stray */\n" + anchor)
    before = snapshot(tree)
    with pytest.raises(ValueError, match="anchor drift in " + str(name)):
        sp.apply(tree)
    assert snapshot(tree) == before


def test_extra_loop_anchor_on_patched_tree_refuses_without_writes(tree):
    assert sp.apply(tree) == "applied"
    path = tree / sp.CYCLE_C
    path.write_text(path.read_text() + "\n" + sp.LOOP_ANCHOR)
    before = snapshot(tree)
    with pytest.raises(ValueError, match="anchor drift in " + str(sp.CYCLE_C)):
        sp.apply(tree)
    assert snapshot(tree) == before


def test_extra_wait_anchor_on_patched_tree_refuses_without_writes(tree):
    assert sp.apply(tree) == "applied"
    path = tree / sp.EPOLL_C
    path.write_text(path.read_text() + "\n" + sp.WAIT_ANCHOR)
    before = snapshot(tree)
    with pytest.raises(ValueError, match="anchor drift in " + str(sp.EPOLL_C)):
        sp.apply(tree)
    assert snapshot(tree) == before


def test_unchanged_patched_tree_stays_patched_and_idempotent(tree):
    assert sp.apply(tree) == "applied"
    before = snapshot(tree)
    assert sp.apply(tree) == "already patched"
    assert snapshot(tree) == before
    assert run_check(tree, "patched").returncode == 0


def test_pristine_tree_is_still_pristine(tree):
    before = snapshot(tree)
    assert run_check(tree, "pristine").returncode == 0
    assert sp.apply(tree) == "applied"
    assert sp.apply(tree) == "already patched"
    assert snapshot(tree) != before
