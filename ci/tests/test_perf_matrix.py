"""Controls for the verdict, MAD, margin and INCONCLUSIVE logic in
ci/tools/perf_matrix_stats.py (the pure half of ci/tools/perf-matrix.sh), plus
the schedule, --dry-run and --from-samples paths of the wrapper (no wrk)."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "ci/tools/perf_matrix_stats.py"
WRAPPER = ROOT / "ci/tools/perf-matrix.sh"
_spec = importlib.util.spec_from_file_location("perf_matrix_stats", TOOL)
assert _spec is not None and _spec.loader is not None
pm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pm)

OPTS = {
    "threads": 4,
    "wrk_cpu_count": 4,
    "mask_pct": 80.0,
    "idle_max_busy_pct": 10.0,
    "hit_min_pct": 99.9,
    "margin_pct": 3.0,
    "mad_mult": 3.0,
    "min_pairs": 3,
}


def sample(side, pair, rps, *, cpu=150.0, hits=1000000, misses=0, stale=0, size="tiny"):
    return {
        "size": size,
        "side": side,
        "pair": pair,
        "rps": rps,
        "p50": "1ms",
        "p99": "2ms",
        "wrk_cpu_pct": cpu,
        "hits": hits,
        "misses": misses,
        "stale": stale,
    }


def matrix(base, cand, **kw):
    rows = []
    for i, (b, c) in enumerate(zip(base, cand, strict=True)):
        rows.append(sample("base", i, b, **kw))
        rows.append(sample("cand", i, c, **kw))
    return rows


BASE = [100000.0, 100100.0, 99900.0, 100050.0, 99950.0]


class StatsTests(unittest.TestCase):
    def test_median_and_mad(self):
        self.assertEqual(pm.median([3, 1, 2]), 2)
        self.assertEqual(pm.median([4, 1, 2, 3]), 2.5)
        self.assertEqual(pm.mad([1, 2, 3, 4, 100]), 1)
        self.assertEqual(pm.mad([5, 5, 5]), 0)

    def test_margin_is_max_of_pct_and_mad(self):
        # tight data: 3% of median wins
        self.assertAlmostEqual(pm.margin_for(BASE, 3, 3), 3000.0)
        # noisy data: 3 x MAD wins
        noisy = [100.0, 200.0, 300.0, 400.0, 500.0]
        self.assertEqual(pm.margin_for(noisy, 3, 3), 300.0)

    def test_verdict_boundary(self):
        base = [100.0] * 5
        v, _, margin = pm.verdict_for(base, [97.0] * 5, 3, 3)
        self.assertEqual((v, margin), ("PASS", 3.0))  # exactly at margin
        v, _, _ = pm.verdict_for(base, [96.99] * 5, 3, 3)
        self.assertEqual(v, "REGRESSION")  # just beyond
        v, _, _ = pm.verdict_for(base, [120.0] * 5, 3, 3)
        self.assertEqual(v, "PASS")  # improvement is not a regression

    def test_client_capacity_uses_usable_cores(self):
        self.assertEqual(pm.client_capacity_pct(100.0, 4, 1), 100.0)  # forced onto one core
        self.assertEqual(pm.client_capacity_pct(100.0, 4, 4), 25.0)

    def test_hit_ratio(self):
        self.assertIsNone(pm.hit_ratio_pct(0, 0, 0))
        self.assertEqual(pm.hit_ratio_pct(99, 1, 0), 99.0)
        self.assertEqual(pm.hit_ratio_pct(90, 10, 10), 100.0 * 100 / 110)

    def test_cpulist(self):
        self.assertEqual(pm.expand_cpulist("2,4-6,4"), [2, 4, 5, 6])
        for bad in ("", "a", "5-2", "1,,2", "-1"):
            with self.assertRaises(ValueError, msg=bad):
                pm.expand_cpulist(bad)


class AnalyzeTests(unittest.TestCase):
    def run_it(self, rows, idle=()):
        return pm.analyze(rows, list(idle), OPTS)

    def test_clean_aa_passes(self):
        res, code = self.run_it(matrix(BASE, BASE))
        self.assertEqual((res["verdict"], code), ("PASS", 0))
        self.assertEqual(res["sizes"]["tiny"]["inconclusive_reasons"], [])

    def test_regression(self):
        res, code = self.run_it(matrix(BASE, [x * 0.9 for x in BASE]))
        self.assertEqual((res["verdict"], code), ("REGRESSION", 1))

    def test_masked_client_is_inconclusive(self):
        res, code = self.run_it(matrix(BASE, BASE, cpu=400.0 * 0.85))
        self.assertEqual((res["verdict"], code), ("INCONCLUSIVE", 3))
        self.assertIn("MASKED", res["sizes"]["tiny"]["inconclusive_reasons"][0])

    def test_one_masked_sample_is_enough(self):
        rows = matrix(BASE, BASE)
        rows[3]["wrk_cpu_pct"] = 380.0
        _res, code = self.run_it(rows)
        self.assertEqual(code, 3)

    def test_inconclusive_beats_regression(self):
        rows = matrix(BASE, [x * 0.5 for x in BASE], cpu=390.0)
        res, code = self.run_it(rows)
        self.assertEqual((res["sizes"]["tiny"]["statistical_verdict"], code), ("REGRESSION", 3))

    def test_low_hit_ratio_is_inconclusive(self):
        res, code = self.run_it(matrix(BASE, BASE, hits=900000, misses=100000))
        self.assertEqual(code, 3)
        self.assertIn("hit ratio", res["sizes"]["tiny"]["inconclusive_reasons"][0])

    def test_zero_counter_delta_is_inconclusive(self):
        _res, code = self.run_it(matrix(BASE, BASE, hits=0))
        self.assertEqual(code, 3)

    def test_busy_pinned_cpu_is_inconclusive(self):
        idle = [{"sample": "tiny/base/pair0", "kind": "pre", "cpu": 2, "busy_pct": 100.0}]
        res, code = self.run_it(matrix(BASE, BASE), idle)
        self.assertEqual(code, 3)
        self.assertIn("cpu2", res["sizes"]["tiny"]["inconclusive_reasons"][0])

    def test_idle_at_threshold_is_clean(self):
        idle = [{"sample": "tiny/base/pair0", "kind": "pre", "cpu": 2, "busy_pct": 10.0}]
        self.assertEqual(self.run_it(matrix(BASE, BASE), idle)[1], 0)

    def test_too_few_or_unpaired_samples(self):
        self.assertEqual(self.run_it(matrix(BASE[:2], BASE[:2]))[1], 3)
        rows = matrix(BASE, BASE)[:-1]
        self.assertEqual(self.run_it(rows)[1], 3)
        self.assertEqual(self.run_it([])[1], 3)

    def test_mismatched_or_duplicate_pair_ids(self):
        rows = matrix(BASE, BASE)
        for r in rows:  # same count per side, but cand pair ids shifted by one
            if r["side"] == "cand":
                r["pair"] += 1
        self.assertEqual(self.run_it(rows)[1], 3)
        rows = matrix(BASE, BASE)
        rows[2]["pair"] = 0  # duplicate base pair id 0
        self.assertEqual(self.run_it(rows)[1], 3)

    def test_nonfinite_numbers_are_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            for bad in ("nan", "inf", "-inf"):
                tsv = Path(d) / "s.tsv"
                tsv.write_text(f"tiny\tbase\t0\t{bad}\t1ms\t2ms\t100\t5\t0\t0\n")
                with self.assertRaises(ValueError, msg=bad):
                    pm.load_samples(str(tsv))
                tsv.write_text(f"tiny\tbase\t0\t1000\t1ms\t2ms\t{bad}\t5\t0\t0\n")
                with self.assertRaises(ValueError, msg=bad):
                    pm.load_samples(str(tsv))
                idle = Path(d) / "i.tsv"
                idle.write_text(f"tiny/base/pair0\tpre\t2\t{bad}\n")
                with self.assertRaises(ValueError, msg=bad):
                    pm.load_idle(str(idle))

    def test_one_inconclusive_size_taints_the_run(self):
        rows = matrix(BASE, BASE) + matrix(BASE, BASE, size="medium", cpu=390.0)
        res, code = self.run_it(rows)
        self.assertEqual(code, 3)
        self.assertEqual(res["sizes"]["tiny"]["verdict"], "PASS")
        self.assertEqual(res["sizes"]["medium"]["verdict"], "INCONCLUSIVE")


class ProcStatTests(unittest.TestCase):
    def snap(self, d, name, busy, idle):
        p = Path(d) / name
        p.write_text(f"cpu  0 0 0 0 0 0 0 0\ncpu2 {busy} 0 0 {idle} 0 0 0 0 0 0\n")
        return str(p)

    def test_busy_pct(self):
        with tempfile.TemporaryDirectory() as d:
            a = self.snap(d, "a", 0, 0)
            b = self.snap(d, "b", 75, 25)
            r = pm.busy_pct(pm.read_cpu_ticks(a, [2]), pm.read_cpu_ticks(b, [2]), [2])
            self.assertEqual(r, [(2, 75.0)])
            with self.assertRaises(ValueError):
                pm.busy_pct(pm.read_cpu_ticks(a, [2]), pm.read_cpu_ticks(b, [2]), [3])

    def test_siblings(self):
        with tempfile.TemporaryDirectory() as d:
            t = Path(d) / "cpu2" / "topology"
            t.mkdir(parents=True)
            (t / "thread_siblings_list").write_text("2-3\n")
            self.assertEqual(pm.sibling_cpus([2], d), [2, 3])
            with self.assertRaises(OSError):  # unknown topology must not be skipped silently
                pm.sibling_cpus([5], d)


class CliTests(unittest.TestCase):
    def cli(self, *args):
        env = dict(os.environ)
        env.pop("OPENROUTER_API_KEY", None)
        return subprocess.run(
            [sys.executable, "-I", "-B", str(TOOL), *args],
            capture_output=True,
            text=True,
            env=env,
            check=False,
        )

    def test_analyze_exit_codes_and_json(self):
        with tempfile.TemporaryDirectory() as d:
            tsv = Path(d) / "s.tsv"
            rows = matrix(BASE, BASE)
            tsv.write_text(
                "".join(
                    "\t".join(
                        str(r[k])
                        for k in ("size", "side", "pair", "rps", "p50", "p99")
                        + ("wrk_cpu_pct", "hits", "misses", "stale")
                    )
                    + "\n"
                    for r in rows
                )
            )
            out = Path(d) / "m.json"
            common = ["analyze", "--samples", str(tsv), "--threads", "4"]
            p = self.cli(*common, "--wrk-cpu-count", "4", "--out", str(out))
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads(out.read_text())["verdict"], "PASS")
            p = self.cli(*common, "--wrk-cpu-count", "1")
            self.assertEqual(p.returncode, 3)  # same wrk CPU, one usable core: MASKED

    def test_bad_input_is_usage_error(self):
        with tempfile.TemporaryDirectory() as d:
            tsv = Path(d) / "s.tsv"
            tsv.write_text("tiny\tbase\n")
            p = self.cli("analyze", "--samples", str(tsv), "--threads", "4", "--wrk-cpu-count", "4")
            self.assertEqual(p.returncode, 2)


class ScheduleTests(unittest.TestCase):
    def test_alternation_order(self):
        got = pm.schedule(2, ["tiny", "medium"])
        self.assertEqual(
            got,
            [
                ("tiny", "base", 0), ("tiny", "cand", 0),
                ("medium", "base", 0), ("medium", "cand", 0),
                ("tiny", "cand", 1), ("tiny", "base", 1),
                ("medium", "cand", 1), ("medium", "base", 1),
            ],
        )  # fmt: skip

    def test_counts_and_balance(self):
        for pairs in (1, 2, 7, 8):
            got = pm.schedule(pairs, ["tiny"])
            self.assertEqual(len(got), 2 * pairs)
            self.assertEqual(sum(1 for g in got if g[1] == "base"), pairs)
            firsts = [got[i][1] for i in range(0, len(got), 2)]
            self.assertEqual(firsts.count("base"), (pairs + 1) // 2)  # odd count: base leads once more

    def test_invalid(self):
        with self.assertRaises(ValueError):
            pm.schedule(0, ["tiny"])
        with self.assertRaises(ValueError):
            pm.schedule(3, [])


class MutationControl(unittest.TestCase):
    """Negative control: the same checks must go red against a mutated MAD."""

    def test_mutated_mad_is_detected(self):
        src = TOOL.read_text()
        self.assertIn("def mad(", src)
        orig = pm.mad
        try:
            pm.mad = lambda values: 2 * orig(values)  # mutated formula
            with self.assertRaises(AssertionError):
                StatsTests("test_median_and_mad").test_median_and_mad()
            with self.assertRaises(AssertionError):
                StatsTests("test_margin_is_max_of_pct_and_mad").test_margin_is_max_of_pct_and_mad()
        finally:
            pm.mad = orig
        StatsTests("test_median_and_mad").test_median_and_mad()  # restored: green


class WrapperTests(unittest.TestCase):
    def run_wrapper(self, *args):
        env = dict(os.environ)
        env.pop("SERVER_CPU", None)
        return subprocess.run(
            ["bash", str(WRAPPER), *args], capture_output=True, text=True, env=env, check=False
        )

    def test_dry_run_plan(self):
        p = self.run_wrapper("--dry-run", "--pairs", "2", "--base-bin", "A", "--cand-bin", "B")
        self.assertEqual(p.returncode, 0, p.stderr)
        lines = p.stdout.splitlines()
        self.assertIn("server_cpu=2 wrk_cpus=4,6,8,10", lines[0])
        self.assertEqual(len(lines), 1 + 8)
        self.assertIn("tiny/base/pair0", lines[1])
        self.assertIn("NGINX_CPUS=2 WRK_CPUS=4,6,8,10 WARMUP=2", lines[1])
        self.assertTrue(lines[1].endswith("bench.sh A 10 32"))
        self.assertIn("tiny/cand/pair1", lines[5])
        self.assertTrue(lines[5].endswith("bench.sh B 10 32"))

    def test_dry_run_defaults_to_eight_pairs(self):
        p = self.run_wrapper("--dry-run")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(len(p.stdout.splitlines()), 1 + 8 * 2 * 2)

    def test_usage_errors(self):
        self.assertEqual(self.run_wrapper("--bogus").returncode, 2)
        self.assertEqual(self.run_wrapper("--dry-run", "--pairs", "x").returncode, 2)
        self.assertEqual(self.run_wrapper("--dry-run", "--pairs", "0").returncode, 2)
        self.assertEqual(self.run_wrapper("--from-samples", "/nonexistent/s.tsv").returncode, 2)
        self.assertEqual(self.run_wrapper("--base-bin").returncode, 2)  # missing value

    def write_tsv(self, d, rows):
        tsv = Path(d) / "s.tsv"
        keys = ("size", "side", "pair", "rps", "p50", "p99", "wrk_cpu_pct", "hits", "misses", "stale")
        tsv.write_text("".join("\t".join(str(r[k]) for k in keys) + "\n" for r in rows))
        return tsv

    def test_from_samples_verdicts(self):
        with tempfile.TemporaryDirectory() as d:
            ok = self.write_tsv(d, matrix(BASE, BASE))
            out = Path(d) / "o"
            p = self.run_wrapper("--from-samples", str(ok), "--out", str(out))
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads((out / "matrix.json").read_text())["verdict"], "PASS")
            bad = self.write_tsv(d, matrix(BASE, [x * 0.9 for x in BASE]))
            self.assertEqual(self.run_wrapper("--from-samples", str(bad)).returncode, 1)
            masked = self.write_tsv(d, matrix(BASE, BASE, cpu=399.0))
            self.assertEqual(self.run_wrapper("--from-samples", str(masked)).returncode, 3)

    def test_from_samples_malformed(self):
        with tempfile.TemporaryDirectory() as d:
            tsv = Path(d) / "s.tsv"
            tsv.write_text("tiny\tbase\n")
            self.assertEqual(self.run_wrapper("--from-samples", str(tsv)).returncode, 2)


if __name__ == "__main__":
    unittest.main()
