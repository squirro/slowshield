"""`uv run python -m perf ...` — see perf/README.md."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from perf import micro, runner


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m perf")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("run", help="A/B load test of container images")
    p.add_argument("--candidate", required=True, help="image under test")
    p.add_argument("--baseline", help="image to compare against (omit to establish a baseline)")
    p.add_argument("--fakeupstream", default="slowshield-fakeupstream:dev")
    p.add_argument("--rounds", type=int, default=5)
    p.add_argument("--profile", choices=sorted(runner.PROFILES), default="full")
    p.add_argument("--duration", default="20s")
    p.add_argument("--workers", type=int, default=1)
    p.add_argument("--k6", default=os.environ.get("K6", "k6"))
    p.add_argument("--thresholds", type=Path, default=Path(__file__).parent / "thresholds.toml")
    p.add_argument("--out", type=Path, default=Path("perf/results/latest"))
    p.add_argument("--gate", action="store_true", help="exit 3 when a confirmed regression is found")

    m = sub.add_parser("micro", help="in-process micro benchmarks of hot code paths")
    m.add_argument("--out", type=Path, default=Path("perf/results/micro.json"))
    m.add_argument("--compare", type=Path, help="previous micro.json to compare against")
    m.add_argument("--repeat", type=int, default=7)

    args = parser.parse_args(argv)
    if args.cmd == "micro":
        return micro.main(out=args.out, compare=args.compare, repeat=args.repeat)

    thresholds = runner.load_thresholds(args.thresholds)
    res = runner.run(
        candidate=args.candidate,
        baseline=args.baseline,
        fakeupstream=args.fakeupstream,
        rounds=args.rounds,
        profile=args.profile,
        duration=args.duration,
        k6=args.k6,
        workers=args.workers,
    )
    findings = runner.evaluate(res, thresholds)
    regressed = {f.scenario for f in findings if f.regression and ":" in f.scenario}
    if regressed and args.gate:
        print(f"possible regressions in {sorted(regressed)}; re-measuring once to confirm", flush=True)
        confirm = runner.run(
            candidate=args.candidate,
            baseline=args.baseline,
            fakeupstream=args.fakeupstream,
            rounds=max(5, args.rounds),
            profile=args.profile,
            duration=args.duration,
            k6=args.k6,
            workers=args.workers,
            only=regressed,
        )
        res.samples = [s for s in res.samples if f"{s.scenario}:{s.mode}" not in regressed] + confirm.samples
        findings = runner.evaluate(res, thresholds)
    runner.save(res, findings, args.out)
    text = runner.report(res, findings)
    print(text)
    if summary := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(text)
    if args.gate and any(f.regression for f in findings):
        print("performance regression detected", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
