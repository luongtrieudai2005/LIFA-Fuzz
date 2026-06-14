#!/usr/bin/env python3
"""
Ablation: generic black-box core vs +FTP ProtocolModule on LightFTP.

THE HONEST EXPERIMENT (plan B6). The paper's thesis is a black-box fuzzer for
unknown protocols. The refactor (B1-B5) made the Fast Loop core protocol-agnostic
(NullModule = pure black-box) with FTP as a disclosed opt-in module. This script
runs LightFTP under BOTH configurations and reports — honestly — what each finds.

- core-only (protocol_module=null): pure black-box. 0 FTP knowledge. This is
  what the thesis claims works on an "unknown" protocol. Uses only the 15 generic
  binary operators + LLM/math-inferred offset rules.
- +FTP-module (protocol_module=ftp): disclosed case-study knowledge (FTP token
  operators, CRLF framing, FTP state tracker).

Metrics: time-to-first-crash, cumulative unique crashes (reproduced=True only,
via confirm_crashes — the deterministic honesty oracle), code coverage % (the #9
gcov pipeline), EPS.

TRUTH ABOVE ALL: if core-only does NOT find the LightFTP CVE, that is the real
result. Report it. The paper must say "black-box core inference + disclosed FTP
case-study module", NOT "general fuzzer found crash". No fabrication — reviewers
re-run and must see the same.

Usage:
    python3 scripts/ablation_generic_vs_module.py --duration 600
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def _run_config(protocol_module: str, duration: int, out_tag: str) -> dict:
    """Run one evaluation_runner campaign with a given protocol_module.

    Sets fast_loop.protocol_module via a temporary config override. Uses the
    Firecracker coverage rootfs (--coverage) so real code coverage is measured.
    """
    cmd = [
        sys.executable, "-m", "evaluation.evaluation_runner",
        "--baseline", "B,C",            # B=math-only, C=LLM (skip A random)
        "--duration", str(duration),
        "--driver", "firecracker",
        "--target", "lightftp",
        "--coverage",
        "--no-dashboard",
    ]
    env_module = protocol_module  # passed via a temp config tweak below
    print(f"\n{'='*60}\n  ABLATION: protocol_module={protocol_module} ({out_tag})\n{'='*60}")
    print(f"  cmd: {' '.join(cmd)}")
    # Patch config.yaml's protocol_module in place for this run, restore after.
    cfg_path = _ROOT / "config.yaml"
    original = cfg_path.read_text()
    patched = original
    import re
    patched = re.sub(
        r'(protocol_module:\s*)"\w+"', rf'\1"{protocol_module}"', patched, count=1,
    )
    cfg_path.write_text(patched)
    t0 = time.time()
    try:
        proc = subprocess.run(cmd, cwd=str(_ROOT), capture_output=True,
                              text=True, timeout=duration * 4 + 600)
        ok = proc.returncode == 0
        tail = (proc.stdout + proc.stderr)[-2000:]
    except subprocess.TimeoutExpired as e:
        ok = False
        tail = (e.stdout or b"")[-2000:].decode(errors="replace") if e.stdout else "TIMEOUT"
    finally:
        cfg_path.write_text(original)  # ALWAYS restore
    elapsed = time.time() - t0
    # Harvest per-baseline summary.json (unique_crashes, coverage, eps).
    results_dir = _ROOT / "evaluation/results"
    summary = {}
    for b in ("baseline_B_math", "baseline_C_full"):
        sj = results_dir / b / "summary.json"
        if sj.exists():
            try:
                summary[b] = json.loads(sj.read_text())
            except Exception:
                pass
    return {
        "protocol_module": protocol_module,
        "tag": out_tag,
        "duration_s": duration,
        "elapsed_s": round(elapsed, 1),
        "ok": ok,
        "summaries": summary,
        "log_tail": tail,
    }


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--duration", type=int, default=600, help="per-baseline seconds")
    p.add_argument("--out", default="evaluation/results/ablation_generic_vs_module.json")
    args = p.parse_args()

    results = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "note": "Honest ablation: black-box core (null) vs disclosed FTP module (ftp). "
                "If core-only finds no CVE, that is the real result — report it.",
        "configs": {},
    }
    # Order: ftp first (known-good baseline), then null (the thesis test).
    for module, tag in [("ftp", "+FTP-module (case-study)"),
                        ("null", "core-only (black-box thesis)")]:
        results["configs"][module] = _run_config(module, args.duration, tag)

    out = _ROOT / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2, default=str))
    print(f"\n{'='*60}\n  ABLATION SUMMARY\n{'='*60}")
    for module, r in results["configs"].items():
        s = r["summaries"]
        line = f"  module={module}: ok={r['ok']} elapsed={r['elapsed_s']}s"
        for b, d in s.items():
            line += (f"\n    {b}: unique_crashes={d.get('unique_crashes','?')}"
                     f" coverage={d.get('coverage',{}).get('branch_coverage_pct','?')}%"
                     f" eps={d.get('avg_eps','?')}")
        print(line)
    print(f"\n  saved → {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
