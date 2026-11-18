# Fuzz regression corpus

Every input that has ever crashed, hung or tripped an assertion in a fuzz target
lives here, one file per crash, forever. This directory is **fully tracked** —
unlike `../corpus*/`, which tracks only the hand-written `NN_*` seeds and ignores
libFuzzer's discoveries, nothing here is gitignored.

`fuzzing.yml` replays these before it starts the fresh time-boxed run, so a crash
that comes back fails in seconds instead of after the whole fuzz budget — and
fails deterministically, rather than depending on the fuzzer rediscovering it.

## Layout

One subdirectory per target, named exactly after the binary:

```text
regressions/
  fuzz_resp_parser/
  fuzz_norm_args/
  fuzz_mc_parser/
  fuzz_auto_classify/
  fuzz_blob/
  fuzz_cache_control/
  fuzz_vary/
```

Every target must hold at least one unit; the replay step FAILS on an empty
target so the gate cannot silently replay nothing. No target has ever produced
a libFuzzer crash artifact (bounded discovery runs found none), so units are of
two kinds:

- **crash**: a minimised input that actually crashed (`fuzz_resp_parser/
  scan_cursor_len_signed_overflow`).
- **pin**: a hand-built boundary input for a bug class fixed earlier (empty
  Cookie header, over-bound arg sort, forged `BLOBF_HDRS_VETTED`, u32-max
  lengths, truncated payloads). Pins are not crash artifacts; they replay clean
  today and guard the fix. Say which in the file name or here.

## Adding a crash

When a fuzz run produces a `crash-<target>-<hash>` artifact:

1. Minimise it, from `ci/fuzz/`:
   `./<target> -minimize_crash=1 -max_total_time=60 crash-<target>-<hash>`
2. Commit the minimised unit under this target's directory, named for the bug —
   `redis_bulk_len_overflow`, not the libFuzzer hash. The name is what a future
   reader sees when it fails.
3. Fix the bug in `src/`, and confirm the replay goes from red to green on that
   file alone.

Never delete a file here after the bug is fixed. A fixed bug is exactly the one
worth replaying — that is the whole point of the directory.
