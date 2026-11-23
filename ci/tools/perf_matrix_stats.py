#!/usr/bin/env python3
"""Pure statistics and verdict logic for ci/tools/perf-matrix.sh.

Subcommands:
  cpus     expand a CPU list, add SMT siblings (--count / --siblings-only)
  busy     per-CPU busy percent between two /proc/stat snapshots
  analyze  samples + idle rows -> JSON verdict, exit 0/1/3

Verdicts per size (A/B, base vs cand, medians of the per-sample req/s):
  margin   = max(margin_pct% of base median, mad_mult * MAD(base))
  PASS        cand median >= base median - margin
  REGRESSION  cand median <  base median - margin
  INCONCLUSIVE  any sample client-MASKED, a pinned CPU busy outside the run, a
              per-pass hit ratio below threshold, fewer than min_pairs pairs, a
              missing or zero sample. INCONCLUSIVE overrides PASS/REGRESSION.
Exit: 0 all sizes PASS, 1 a REGRESSION and nothing inconclusive,
3 any INCONCLUSIVE, 2 usage/input error.
"""

import argparse
import json
import math
import os
import statistics
import sys

EXIT_PASS, EXIT_REGRESSION, EXIT_USAGE, EXIT_INCONCLUSIVE = 0, 1, 2, 3


def expand_cpulist(text):
    """'2,4-6' -> [2, 4, 5, 6]. Raises ValueError on a malformed list."""
    out = []
    for part in text.split(","):
        part = part.strip()
        if not part:
            raise ValueError("empty CPU list element")
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo_i, hi_i = int(lo), int(hi)
            if lo_i > hi_i or lo_i < 0:
                raise ValueError(f"bad CPU range {part}")
            out.extend(range(lo_i, hi_i + 1))
        else:
            n = int(part)
            if n < 0:
                raise ValueError(f"negative CPU {part}")
            out.append(n)
    return sorted(set(out))


def median(values):
    return statistics.median(values)


def mad(values):
    """Median absolute deviation (unscaled)."""
    m = median(values)
    return median([abs(v - m) for v in values])


def margin_for(base_values, margin_pct, mad_mult):
    return max(margin_pct / 100.0 * median(base_values), mad_mult * mad(base_values))


def verdict_for(base_values, cand_values, margin_pct, mad_mult):
    """Return (verdict, delta, margin) for PASS/REGRESSION only."""
    margin = margin_for(base_values, margin_pct, mad_mult)
    delta = median(cand_values) - median(base_values)
    return ("REGRESSION" if delta < -margin else "PASS"), delta, margin


def client_capacity_pct(wrk_cpu_pct, threads, wrk_cpu_count):
    """wrk CPU as a percent of the cores it can actually use."""
    usable = max(1, min(threads, wrk_cpu_count))
    return wrk_cpu_pct / (usable * 100.0) * 100.0


def hit_ratio_pct(hits, misses, stale):
    total = hits + misses + stale
    if total <= 0:
        return None
    return 100.0 * (hits + stale) / total


def read_cpu_ticks(path, cpus):
    """{cpu: (busy_ticks, total_ticks)} from a /proc/stat copy."""
    want = set(cpus)
    out = {}
    with open(path, encoding="ascii") as fh:
        for line in fh:
            f = line.split()
            if not f or not f[0].startswith("cpu") or f[0] == "cpu":
                continue
            n = int(f[0][3:])
            if n not in want:
                continue
            v = [int(x) for x in f[1:]]
            total = sum(v[:8])  # user..steal; guest is already in user
            idle = v[3] + (v[4] if len(v) > 4 else 0)
            out[n] = (total - idle, total)
    return out


def busy_pct(before, after, cpus):
    rows = []
    for c in cpus:
        if c not in before or c not in after:
            raise ValueError(f"cpu{c} missing from /proc/stat snapshot")
        dt = after[c][1] - before[c][1]
        db = after[c][0] - before[c][0]
        if dt <= 0:
            raise ValueError(f"cpu{c}: no elapsed ticks between snapshots")
        rows.append((c, 100.0 * db / dt))
    return rows


def sibling_cpus(cpus, sysfs="/sys/devices/system/cpu"):
    out = set(cpus)
    for c in cpus:
        p = os.path.join(sysfs, f"cpu{c}", "topology", "thread_siblings_list")
        with open(p, encoding="ascii") as fh:
            out.update(expand_cpulist(fh.read().strip()))
    return sorted(out)


def finite(text):
    """float() that refuses nan/inf, which would slip past every comparison."""
    v = float(text)
    if not math.isfinite(v):
        raise ValueError(f"non-finite number {text!r}")
    return v


def load_samples(path):
    """TSV: size side pair rps p50 p99 wrk_cpu_pct hits misses stale."""
    rows = []
    with open(path, encoding="ascii") as fh:
        for ln, line in enumerate(fh, 1):
            f = line.rstrip("\n").split("\t")
            if len(f) != 10:
                raise ValueError(f"{path}:{ln}: want 10 fields, got {len(f)}")
            try:
                rows.append(
                    {
                        "size": f[0],
                        "side": f[1],
                        "pair": int(f[2]),
                        "rps": finite(f[3]),
                        "p50": f[4],
                        "p99": f[5],
                        "wrk_cpu_pct": finite(f[6]),
                        "hits": int(f[7]),
                        "misses": int(f[8]),
                        "stale": int(f[9]),
                    }
                )
            except ValueError as e:
                raise ValueError(f"{path}:{ln}: {e}") from e
    return rows


def load_idle(path):
    """TSV: sample kind cpu busy_pct. None means no idle evidence; a path that
    cannot be opened raises OSError (exit 2), never a silent skip."""
    rows = []
    if path is None:
        return rows
    with open(path, encoding="ascii") as fh:
        for ln, line in enumerate(fh, 1):
            f = line.rstrip("\n").split("\t")
            if len(f) != 4:
                raise ValueError(f"{path}:{ln}: want 4 fields, got {len(f)}")
            rows.append(
                {"sample": f[0], "kind": f[1], "cpu": int(f[2]), "busy_pct": finite(f[3])}
            )
    return rows


def _pass_row(s, opts):
    """One per-pass record plus the INCONCLUSIVE reasons it triggers."""
    cap = client_capacity_pct(s["wrk_cpu_pct"], opts["threads"], opts["wrk_cpu_count"])
    ratio = hit_ratio_pct(s["hits"], s["misses"], s["stale"])
    masked = cap >= opts["mask_pct"]
    tag = f"pair{s['pair']}/{s['side']}"
    reasons = []
    if masked:
        reasons.append(f"{tag} client MASKED ({cap:.1f}% >= {opts['mask_pct']:g}%)")
    if ratio is None:
        reasons.append(f"{tag} hit ratio n/a (no counter delta)")
    elif ratio < opts["hit_min_pct"]:
        reasons.append(f"{tag} hit ratio {ratio:.4f}% below {opts['hit_min_pct']:g}%")
    if s["rps"] <= 0:
        reasons.append(f"{tag} zero req/s")
    row = {
        "pair": s["pair"],
        "side": s["side"],
        "rps": s["rps"],
        "client_capacity_pct": round(cap, 1),
        "masked": masked,
        "hit_ratio_pct": None if ratio is None else round(ratio, 4),
        "hits": s["hits"],
        "misses": s["misses"],
        "stale": s["stale"],
    }
    return row, reasons


def _idle_reasons(size, idle, opts):
    limit = opts["idle_max_busy_pct"]
    return [
        f"{r['sample']} {r['kind']} cpu{r['cpu']} busy {r['busy_pct']:.1f}% > {limit:g}%"
        for r in idle
        if r["busy_pct"] > opts["idle_max_busy_pct"] and r["sample"].split("/")[0] == size
    ]


def _stats_entry(base, cand, opts):
    bv = [s["rps"] for s in base]
    cv = [s["rps"] for s in cand]
    v, delta, margin = verdict_for(bv, cv, opts["margin_pct"], opts["mad_mult"])
    bm = median(bv)
    return {
        "base_median": bm,
        "base_mad": mad(bv),
        "cand_median": median(cv),
        "cand_mad": mad(cv),
        "delta": delta,
        "delta_pct": 100.0 * delta / bm if bm else None,
        "margin": margin,
        "margin_pct_of_base": 100.0 * margin / bm if bm else None,
        "statistical_verdict": v,
    }


def _size_entry(size, samples, idle, opts):
    side = {"base": [], "cand": []}
    for s in samples:
        if s["size"] == size and s["side"] in side:
            side[s["side"]].append(s)
    reasons = []
    passes = []
    for s in sorted(side["base"] + side["cand"], key=lambda r: (r["pair"], r["side"])):
        row, why = _pass_row(s, opts)
        passes.append(row)
        reasons.extend(why)
    nb, nc = len(side["base"]), len(side["cand"])
    ids_b = sorted(s["pair"] for s in side["base"])
    ids_c = sorted(s["pair"] for s in side["cand"])
    if ids_b != ids_c or len(set(ids_b)) != len(ids_b):
        reasons.append(f"pairs do not match one-to-one: base={ids_b} cand={ids_c}")
    if min(nb, nc) < opts["min_pairs"]:
        reasons.append(f"fewer than {opts['min_pairs']} pairs (base={nb} cand={nc})")
    reasons.extend(_idle_reasons(size, idle, opts))
    entry = {"pairs": min(nb, nc), "passes": passes}
    stat = "INCONCLUSIVE"
    if nb and nc:
        entry.update(_stats_entry(side["base"], side["cand"], opts))
        stat = entry["statistical_verdict"]
    entry["verdict"] = "INCONCLUSIVE" if reasons else stat
    entry["inconclusive_reasons"] = reasons
    return entry


def analyze(samples, idle, opts):
    sizes = []
    for s in samples:
        if s["size"] not in sizes:
            sizes.append(s["size"])
    result = {"params": opts, "idle_checks": len(idle)}
    if not idle:
        result["idle_note"] = "no idle evidence recorded"
    result["sizes"] = {size: _size_entry(size, samples, idle, opts) for size in sizes}
    verdicts = [e["verdict"] for e in result["sizes"].values()]
    if not verdicts or "INCONCLUSIVE" in verdicts:
        result["verdict"], code = "INCONCLUSIVE", EXIT_INCONCLUSIVE
    elif "REGRESSION" in verdicts:
        result["verdict"], code = "REGRESSION", EXIT_REGRESSION
    else:
        result["verdict"], code = "PASS", EXIT_PASS
    return result, code


def schedule(pairs, sizes):
    """Alternation schedule: (size, side, pair) in run order. Even pairs run
    base first, odd pairs cand first, so drift hits both sides equally."""
    if pairs < 1:
        raise ValueError("pairs must be >= 1")
    if not sizes:
        raise ValueError("sizes must not be empty")
    out = []
    for pair in range(pairs):
        order = ("base", "cand") if pair % 2 == 0 else ("cand", "base")
        for size in sizes:
            out.extend((size, side, pair) for side in order)
    return out


def main(argv):
    ap = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("cpus")
    c.add_argument("cpulist")
    c.add_argument("--sysfs", default="/sys/devices/system/cpu")
    c.add_argument("--count", action="store_true", help="print only the CPU count")
    c.add_argument("--siblings-only", action="store_true", help="omit the listed CPUs")
    b = sub.add_parser("busy")
    b.add_argument("--before", required=True)
    b.add_argument("--after", required=True)
    b.add_argument("--cpus", required=True)
    b.add_argument("--sample", required=True)
    b.add_argument("--kind", required=True)
    sc = sub.add_parser("schedule")
    sc.add_argument("--pairs", type=int, required=True)
    sc.add_argument("--sizes", required=True, help="space separated size names")
    a = sub.add_parser("analyze")
    a.add_argument("--samples", required=True)
    a.add_argument("--idle", default=None)
    a.add_argument("--out")
    a.add_argument("--threads", type=int, required=True)
    a.add_argument("--wrk-cpu-count", type=int, required=True)
    a.add_argument("--mask-pct", type=finite, default=80.0)
    a.add_argument("--idle-max-busy-pct", type=finite, default=10.0)
    a.add_argument("--hit-min-pct", type=finite, default=99.9)
    a.add_argument("--margin-pct", type=finite, default=3.0)
    a.add_argument("--mad-mult", type=finite, default=3.0)
    a.add_argument("--min-pairs", type=int, default=3)
    args = ap.parse_args(argv)
    try:
        if args.cmd == "cpus":
            base = expand_cpulist(args.cpulist)
            if args.count:
                print(len(base))
                return 0
            out = sibling_cpus(base, args.sysfs)
            if args.siblings_only:
                out = [x for x in out if x not in base]
            print(",".join(str(x) for x in out))
            return 0
        if args.cmd == "schedule":
            for size, side, pair in schedule(args.pairs, args.sizes.split()):
                print(f"{size}\t{side}\t{pair}")
            return 0
        if args.cmd == "busy":
            cpus = expand_cpulist(args.cpus)
            before = read_cpu_ticks(args.before, cpus)
            after = read_cpu_ticks(args.after, cpus)
            rows = busy_pct(before, after, cpus)
            for cpu, pct in rows:
                print(f"{args.sample}\t{args.kind}\t{cpu}\t{pct:.2f}")
            return 0
        opts = {
            "threads": args.threads,
            "wrk_cpu_count": args.wrk_cpu_count,
            "mask_pct": args.mask_pct,
            "idle_max_busy_pct": args.idle_max_busy_pct,
            "hit_min_pct": args.hit_min_pct,
            "margin_pct": args.margin_pct,
            "mad_mult": args.mad_mult,
            "min_pairs": args.min_pairs,
        }
        result, code = analyze(load_samples(args.samples), load_idle(args.idle), opts)
    except (ValueError, OSError) as e:
        print(f"perf_matrix_stats: {e}", file=sys.stderr)
        return EXIT_USAGE
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        try:
            with open(args.out, "w", encoding="ascii") as fh:
                fh.write(text + "\n")
        except OSError as e:
            print(f"perf_matrix_stats: {e}", file=sys.stderr)
            return EXIT_USAGE
    print(text)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
