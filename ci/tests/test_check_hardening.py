"""Per-property controls for ci/tools/check-hardening.sh on tiny shared objects."""
import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "ci/tools/check-hardening.sh"
SRC = (
    "#include <string.h>\n"
    "int ct_copy(char *dst, const char *src, unsigned long n)\n"
    "{ char buf[64]; memcpy(buf, src, n); memcpy(dst, buf, n); return buf[0]; }\n"
)
HARD = ["-O2", "-fPIC", "-shared", "-fstack-protector-strong",
        "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=3",
        "-Wl,-z,relro", "-Wl,-z,now", "-Wl,-z,noexecstack"]


def run_check(so, path=None):
    env = dict(os.environ)
    env.pop("OPENROUTER_API_KEY", None)
    if path is not None:
        env["PATH"] = path
    return subprocess.run(["bash", str(SCRIPT), str(so)], env=env, text=True,
                          capture_output=True, check=False)


class CheckHardeningTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.tmp.name)
        (cls.dir / "t.c").write_text(SRC)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def build(self, name, flags):
        out = self.dir / (name + ".so")
        subprocess.run(["gcc", *flags, "-o", str(out), str(self.dir / "t.c")],
                       check=True)
        return out

    def test_hardened_passes(self):
        r = run_check(self.build("hard", HARD))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("ok FORTIFY", r.stdout)
        self.assertIn("ok RELRO", r.stdout)

    def test_plain_names_each_missing_property(self):
        so = self.build("plain", ["-O0", "-fPIC", "-shared", "-fno-stack-protector",
                                  "-U_FORTIFY_SOURCE", "-D_FORTIFY_SOURCE=0",
                                  "-Wl,-z,norelro", "-Wl,-z,lazy"])
        r = run_check(so)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        for prop in ("RELRO", "canary", "FORTIFY", "checksec"):
            self.assertIn("MISSING " + prop, r.stdout)

    def test_each_property_detected_alone(self):
        cases = {
            # Explicit opposites: a distro gcc (Ubuntu) enables now/fortify/
            # canary by default, so merely dropping the flag proves nothing.
            "RELRO": [f for f in HARD if f != "-Wl,-z,now"] + ["-Wl,-z,lazy"],
            "canary": [f for f in HARD if f != "-fstack-protector-strong"]
                      + ["-fno-stack-protector"],
            "FORTIFY": [f for f in HARD if f != "-D_FORTIFY_SOURCE=3"]
                       + ["-D_FORTIFY_SOURCE=0"],
            "NX": [f for f in HARD if f != "-Wl,-z,noexecstack"]
                  + ["-Wl,-z,execstack"],
        }
        for prop, flags in cases.items():
            with self.subTest(prop=prop):
                r = run_check(self.build("one_" + prop, flags))
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("MISSING " + prop, r.stdout)
                others = [ln for ln in r.stdout.splitlines()
                          if ln.startswith("MISSING ")
                          and not ln.startswith(("MISSING " + prop,
                                                 "MISSING checksec",
                                                 "MISSING execstack"))]
                self.assertEqual(others, [], r.stdout)

    def patched(self, name, ptype, new_flags):
        """Copy the hardened .so, rewriting p_flags of the first phdr of ptype."""
        data = bytearray(self.build("base_" + name, HARD).read_bytes())
        off, = struct.unpack_from("<Q", data, 32)
        esz, num = struct.unpack_from("<HH", data, 54)
        for i in range(num):
            b = off + i * esz
            if struct.unpack_from("<I", data, b)[0] == ptype:
                struct.pack_into("<I", data, b + 4, new_flags)
                out = self.dir / (name + ".so")
                out.write_bytes(data)
                return out
        raise AssertionError(f"no phdr of type {ptype:#x}")

    PT_LOAD, PT_GNU_STACK = 1, 0x6474E551
    PF_X, PF_W, PF_R = 1, 2, 4

    def test_gnu_stack_rx_is_executable(self):
        r = run_check(self.patched("stack_rx", self.PT_GNU_STACK, self.PF_R | self.PF_X))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("MISSING NX", r.stdout)
        self.assertIn("MISSING execstack", r.stdout)

    def test_gnu_stack_rwx_still_detected(self):
        r = run_check(self.patched("stack_rwx", self.PT_GNU_STACK, 7))
        self.assertIn("MISSING NX", r.stdout)
        self.assertIn("MISSING execstack", r.stdout)

    def test_gnu_stack_rw_stays_ok(self):
        r = run_check(self.patched("stack_rw", self.PT_GNU_STACK, self.PF_R | self.PF_W))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("ok NX", r.stdout)
        self.assertIn("ok execstack", r.stdout)

    def test_load_wx_without_r_is_rwx(self):
        r = run_check(self.patched("load_wx", self.PT_LOAD, self.PF_W | self.PF_X))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("MISSING RWX", r.stdout)

    def test_load_rx_and_rw_split_is_ok(self):
        r = run_check(self.patched("load_rx", self.PT_LOAD, self.PF_R | self.PF_X))
        self.assertIn("ok RWX", r.stdout)

    def test_missing_checksec_fails_not_skips(self):
        bindir = self.dir / "nochecksec"
        bindir.mkdir(exist_ok=True)
        for tool in ("bash", "readelf", "nm", "grep", "head", "python3", "env",
                     "awk", "sed"):
            real = shutil.which(tool)
            self.assertIsNotNone(real, tool)
            link = bindir / tool
            if not link.exists():
                link.symlink_to(real)
        r = run_check(self.build("hard2", HARD), path=str(bindir))
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        self.assertIn("checksec not installed", r.stderr)

    def test_usage_error(self):
        r = subprocess.run(["bash", str(SCRIPT), "/nonexistent.so"], text=True,
                           capture_output=True, check=False)
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main()
