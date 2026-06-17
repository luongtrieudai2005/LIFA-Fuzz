#!/usr/bin/env bash
# =============================================================================
# run_golden_campaign.sh
# ──────────────────────
# Golden overnight campaign for the final report — runs the A/B/C baselines
# on Firecracker/LightFTP, back-to-back, with REAL LLM for baseline C.
#
# Design intent (black-box discipline):
#   - NOTHING here tunes the target or reads LightFTP source. The campaign is
#     a pure measurement harness: it launches the standard evaluation_runner
#     with the same flags a reviewer would use.
#   - Baseline C is forced to LLM_MODE=REAL so the full-fusion pipeline
#     (math → LLM → P-PSM → rules) actually runs end-to-end.
#   - Results land in evaluation/results/ and are archived per-baseline so a
#     later run cannot silently overwrite them.
#
# Usage:
#   bash run_golden_campaign.sh                 # defaults: A,B,C, 4h each
#   DURATION=28800 bash run_golden_campaign.sh  # 8h each
#   BASELINES="B,C" bash run_golden_campaign.sh # subset
#   DRIVER=docker bash run_golden_campaign.sh   # fallback (no KVM)
#
# Env knobs:
#   BASELINES   comma list   default "A,B,C"
#   DURATION    seconds/baseline   default 14400 (4h)
#   DRIVER      firecracker|docker default firecracker
#   TARGET      lifa|lightftp|lighttpd   default lightftp
#   DASHBOARD   1 to keep Streamlit dashboard, 0 to skip (default 0)
# =============================================================================
set -euo pipefail

BASELINES="${BASELINES:-A,B,C}"
DURATION="${DURATION:-14400}"
DRIVER="${DRIVER:-firecracker}"
TARGET="${TARGET:-lightftp}"
DASHBOARD="${DASHBOARD:-0}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# Activate venv if present (evaluation_runner needs the project's deps).
if [ -f .venv/bin/activate ]; then
    # shellcheck disable=SC1091
    source .venv/bin/activate
fi

# Prerequisites — fail fast with an actionable message.
if [ "${DRIVER}" = "firecracker" ] && [ ! -e /dev/kvm ]; then
    echo "ERROR: /dev/kvm not found — Firecracker needs KVM." >&2
    echo "       Re-run with DRIVER=docker, or enable KVM." >&2
    exit 1
fi
if [ ! -f .env ]; then
    echo "WARNING: no .env found — baseline C (REAL LLM) needs OPENAI_API_KEY." >&2
fi

DASH_FLAG=""
[ "${DASHBOARD}" = "1" ] && DASH_FLAG=""

echo "============================================================"
echo "  GOLDEN CAMPAIGN"
echo "  Baselines : ${BASELINES}"
echo "  Duration  : ${DURATION}s each (~$(( DURATION / 3600 ))h $(( (DURATION % 3600) / 60 ))m)"
echo "  Driver    : ${DRIVER}"
echo "  Target    : ${TARGET}"
echo "  Start     : $(date '+%Y-%m-%d %H:%M:%S')"
echo "============================================================"

# Archive any prior results so this run starts clean and old data is preserved
# for comparison (evaluation_runner also archives, but this guards the common
# re-run case).
if [ -d evaluation/results ] && [ "$(ls -A evaluation/results 2>/dev/null)" ]; then
    python3 scripts/cleanup.py --archive-only 2>/dev/null || true
fi

# Run each baseline sequentially. evaluation_runner handles sandbox lifecycle,
# telemetry, crash corpus, and per-baseline archiving internally.
IFS=',' read -ra BL <<< "${BASELINES}"
for B in "${BL[@]}"; do
    B="$(echo "${B}" | tr -d '[:space:]')"
    [ -z "${B}" ] && continue

    echo ""
    echo "────────────────────────────────────────────────────────────"
    echo "  Baseline ${B} — starting $(date '+%H:%M:%S')"
    echo "────────────────────────────────────────────────────────────"

    # Baseline C = full fusion → must use the REAL LLM. A/B have LLM off anyway,
    # but we export it unconditionally so a misconfigured config can't silently
    # drop C back to MOCK.
    export LLM_MODE=REAL
    export LIFA_PROTOCOL_MODULE=ftp

    set +e
    python3 -m evaluation.evaluation_runner \
        --baseline "${B}" \
        --duration "${DURATION}" \
        --driver "${DRIVER}" \
        --target "${TARGET}" \
        ${DASH_FLAG} \
        2>&1 | tee "logs/golden_baseline_${B}.log"
    RC=${PIPESTATUS[0]}
    set -e

    if [ "${RC}" -ne 0 ]; then
        echo "WARNING: baseline ${B} exited non-zero (rc=${RC}); continuing." >&2
    fi
    echo "Baseline ${B} done — $(date '+%H:%M:%S')"
done

echo ""
echo "============================================================"
echo "  GOLDEN CAMPAIGN COMPLETE — $(date '+%Y-%m-%d %H:%M:%S')"
echo "  Results : evaluation/results/"
echo "  Logs    : logs/golden_baseline_{A,B,C}.log"
echo "  Plots   : python -m evaluation.plot_generator"
echo "============================================================"
