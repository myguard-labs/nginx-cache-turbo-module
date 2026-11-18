"""Registry ci/fuzz/targets.tsv: positive, negative control and malformed rows."""
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

FUZZ = Path(__file__).resolve().parents[1] / "fuzz"
HELPER = FUZZ / "targets.sh"
HEADER = "name\tsource\tcorpus\tdict\textract\n"
GOOD = "fuzz_norm_args\tfuzz_norm_args.c\tcorpus_norm_args\t-\textract_norm_args.sh"


def real_names():
    """Target names read straight from the checked-in registry (data, not a list here)."""
    rows = (FUZZ / "targets.tsv").read_text().splitlines()[1:]
    return [r.split("\t")[0] for r in rows if r and not r.startswith("#")]


def fixture(names):
    """Registry rows over files that exist in ci/fuzz/, one distinct name each."""
    return HEADER + "".join(
        f"{n}\tfuzz_norm_args.c\tcorpus_norm_args\t-\textract_norm_args.sh\n"
        for n in names)


def run(cmd, registry=None):
    env = dict(os.environ)
    # Never inherit a developer's override: no registry argument means the real one.
    env.pop("FUZZ_TARGETS_TSV", None)
    if registry is not None:
        env["FUZZ_TARGETS_TSV"] = str(registry)
    return subprocess.run(["bash", str(HELPER), *cmd], env=env,
                          capture_output=True, text=True, check=False)


class TargetsRegistryTest(unittest.TestCase):
    def scratch(self, body):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        p = Path(d.name) / "targets.tsv"
        p.write_text(body)
        return p

    def test_real_registry_lists_every_target(self):
        r = run(["validate"])
        self.assertEqual(r.returncode, 0, r.stderr)
        names = real_names()
        self.assertTrue(names)
        self.assertEqual(run(["names"]).stdout.split(), names)
        specs = run(["specs", "all"]).stdout.split()
        self.assertEqual([x.split(":")[0] for x in specs], names)
        for x in specs:
            self.assertEqual(x.count(":"), 2, x)

    def test_every_registry_corpus_has_a_gitignore_pair(self):
        """Fuzz-generated corpus files must stay untracked except numbered seeds."""
        ignore = (FUZZ.parents[1] / ".gitignore").read_text().splitlines()
        rows = (FUZZ / "targets.tsv").read_text().splitlines()[1:]
        for corpus in {r.split("\t")[2] for r in rows if r}:
            self.assertIn(f"ci/fuzz/{corpus}/*", ignore, corpus)
            self.assertIn(f"!ci/fuzz/{corpus}/[0-9][0-9]_*", ignore, corpus)

    def test_real_lane_partition_covers_every_target_once(self):
        a = run(["specs", "a"]).stdout.split()
        b = run(["specs", "b"]).stdout.split()
        self.assertTrue(a and b)
        self.assertEqual(a + b, run(["specs", "all"]).stdout.split())
        self.assertEqual(len(set(a + b)), len(a) + len(b))
        self.assertEqual(run(["specs", "c"]).returncode, 2)

    def test_fixture_exact_specs_and_split(self):
        reg = self.scratch(fixture(["fuzz_one", "fuzz_two", "fuzz_three",
                                    "fuzz_four", "fuzz_five"]))
        line = "{}:corpus_norm_args:"
        want = [line.format(n) for n in
                ("fuzz_one", "fuzz_two", "fuzz_three", "fuzz_four", "fuzz_five")]
        self.assertEqual(run(["specs", "all"], reg).stdout.split(), want)
        self.assertEqual(run(["specs", "a"], reg).stdout.split(), want[:3])
        self.assertEqual(run(["specs", "b"], reg).stdout.split(), want[3:])

    def test_inherited_override_does_not_leak_into_real_calls(self):
        reg = self.scratch(fixture(["fuzz_only"]))
        old = os.environ.get("FUZZ_TARGETS_TSV")
        os.environ["FUZZ_TARGETS_TSV"] = str(reg)
        try:
            self.assertEqual(run(["names"]).stdout.split(), real_names())
        finally:
            if old is None:
                del os.environ["FUZZ_TARGETS_TSV"]
            else:
                os.environ["FUZZ_TARGETS_TSV"] = old

    def test_name_must_be_entirely_lowercase_digits_underscore(self):
        for bad in ("fuzz_demo extra", "fuzz_Upper", "fuzz_", "fuzz_a-b", "fuzz_a.b"):
            r = run(["validate"], self.scratch(fixture([bad])))
            self.assertEqual(r.returncode, 1, bad)
            self.assertIn("invalid or empty name", r.stderr, bad)
        self.assertEqual(run(["validate"], self.scratch(fixture(["fuzz_a1_b2"]))).returncode, 0)

    def test_colon_in_corpus_or_dict_is_rejected(self):
        for col, val in ((2, "corpus_norm_args:variant"), (3, "dict:variant")):
            cols = GOOD.split("\t")
            cols[col] = val
            r = run(["validate"], self.scratch(HEADER + "\t".join(cols) + "\n"))
            self.assertEqual(r.returncode, 1, val)
            self.assertIn("name:corpus:dict spec", r.stderr, val)

    def test_header_skipped_only_when_complete(self):
        # Headerless file whose first row is an invalid row named "name": it must
        # be validated as data, not swallowed as a header.
        bad_first = "name\tfuzz_norm_args.c\tcorpus_norm_args\t-\textract_norm_args.sh\n"
        r = run(["validate"], self.scratch(bad_first + GOOD + "\n"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("invalid or empty name 'name'", r.stderr)
        # A truncated header is not a header either.
        r = run(["validate"], self.scratch("name\tsource\n" + GOOD + "\n"))
        self.assertEqual(r.returncode, 1)
        # The complete header is skipped; a headerless valid file also works.
        self.assertEqual(run(["validate"], self.scratch(HEADER + GOOD + "\n")).returncode, 0)
        self.assertEqual(run(["validate"], self.scratch(GOOD + "\n")).returncode, 0)

    def test_scratch_registry_good_row(self):
        r = run(["names"], self.scratch(HEADER + GOOD + "\n"))
        self.assertEqual((r.returncode, r.stdout.split()), (0, ["fuzz_norm_args"]))

    def test_missing_source_fails_naming_the_row(self):
        row = GOOD.replace("fuzz_norm_args\t", "fuzz_nope\t").replace(
            "fuzz_norm_args.c", "fuzz_nope.c")
        r = run(["validate"], self.scratch(HEADER + GOOD + "\n" + row + "\n"))
        self.assertEqual(r.returncode, 1)
        self.assertIn("row 'fuzz_nope'", r.stderr)
        self.assertIn("harness source 'fuzz_nope.c' not found", r.stderr)

    def test_missing_corpus_dict_extract_fail(self):
        for col, field in ((2, "corpus_nope"), (3, "nope.dict"), (4, "extract_nope.sh")):
            cols = GOOD.split("\t")
            cols[col] = field
            r = run(["validate"], self.scratch(HEADER + "\t".join(cols) + "\n"))
            self.assertEqual(r.returncode, 1, field)
            self.assertIn("row 'fuzz_norm_args'", r.stderr)
            self.assertIn(field, r.stderr)

    def test_malformed_rows_fail(self):
        cases = {
            "too few columns": "fuzz_norm_args\tfuzz_norm_args.c\tcorpus_norm_args\t-",
            "too many columns": GOOD + "\textra",
            "empty name": "\tfuzz_norm_args.c\tcorpus_norm_args\t-\textract_norm_args.sh",
            "bad name": "norm\tfuzz_norm_args.c\tcorpus_norm_args\t-\textract_norm_args.sh",
            "empty dict": "fuzz_norm_args\tfuzz_norm_args.c\tcorpus_norm_args\t\textract_norm_args.sh",
            "duplicate": GOOD + "\n" + GOOD,
        }
        for label, row in cases.items():
            r = run(["validate"], self.scratch(HEADER + row + "\n"))
            self.assertEqual(r.returncode, 1, label)
            self.assertIn("targets:", r.stderr, label)

    def test_empty_and_missing_registry_fail(self):
        self.assertEqual(run(["validate"], self.scratch(HEADER)).returncode, 1)
        self.assertEqual(run(["validate"], Path("/nonexistent/targets.tsv")).returncode, 1)

    def stub_cc(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        marker = Path(d.name) / "invoked"
        cc = Path(d.name) / "cc"
        # Records each call and creates the -o output so a build "succeeds".
        cc.write_text(f'#!/bin/sh\necho x >> "{marker}"\nwhile [ $# -gt 0 ]; do\n'
                      '  [ "$1" = -o ] && : > "$2"\n  shift\ndone\n')
        cc.chmod(0o755)
        return cc, marker

    def build(self, registry, out, cc):
        env = dict(os.environ, FUZZ_TARGETS_TSV=str(registry), CC=str(cc),
                   LIB_FUZZING_ENGINE="-fsanitize=fuzzer")
        return subprocess.run(["bash", str(FUZZ / "build.sh"), out], env=env,
                              capture_output=True, text=True, check=False)

    def test_build_fails_on_bad_row_before_compiling(self):
        # A good row precedes the bad one: the whole registry is validated
        # first, so the compiler must never run for the good row either.
        cc, marker = self.stub_cc()
        bad = GOOD.replace("fuzz_norm_args\t", "fuzz_bad\t", 1).replace(
            "fuzz_norm_args.c", "fuzz_nope.c")
        reg = self.scratch(HEADER + GOOD + "\n" + bad + "\n")
        with tempfile.TemporaryDirectory() as out:
            r = self.build(reg, out, cc)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("row 'fuzz_bad'", r.stderr)
        self.assertFalse(marker.exists(), "compiler ran before validation failed")

    def test_explicit_output_requires_the_resp_row(self):
        cc, marker = self.stub_cc()
        reg = self.scratch(HEADER + GOOD + "\n")
        with tempfile.TemporaryDirectory() as d:
            out = str(Path(d) / "resp_bin")
            r = self.build(reg, out, cc)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("no fuzz_resp_parser row", r.stderr)
            self.assertFalse(Path(out).exists())
        self.assertFalse(marker.exists())

    def test_explicit_output_builds_the_resp_row(self):
        cc, marker = self.stub_cc()
        with tempfile.TemporaryDirectory() as d:
            out = str(Path(d) / "resp_bin")
            r = self.build(FUZZ / "targets.tsv", out, cc)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertTrue(Path(out).exists())
        self.assertEqual(marker.read_text().count("x"), 1)


if __name__ == "__main__":
    unittest.main()
