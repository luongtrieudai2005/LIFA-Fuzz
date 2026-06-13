#!/bin/bash
# scripts/link_crashes.sh
# Tự động symlink ./crashes → evaluation/results/baseline_X/crashes
# của baseline đang chạy (dựa trên PID của evaluation_runner).
#
# Chạy: bash scripts/link_crashes.sh
# Cron: */1 * * * * bash /home/trieudai/LIFA-Fuzz/scripts/link_crashes.sh

cd /home/trieudai/LIFA-Fuzz

# Tìm baseline nào có crash dir mới nhất (đang active)
LATEST=""
LATEST_MT=0

for d in evaluation/results/baseline_*/crashes; do
    if [ -d "$d" ]; then
        # Lấy modification time mới nhất trong dir
        mt=$(find "$d" -type f -newer "$d" -printf '%T@\n' 2>/dev/null | sort -rn | head -1)
        if [ -z "$mt" ]; then
            mt=$(stat -c '%Y' "$d" 2>/dev/null || echo 0)
        fi
        if [ "$(echo "$mt > $LATEST_MT" | bc 2>/dev/null)" = "1" ]; then
            LATEST_MT=$mt
            LATEST=$d
        fi
    fi
done

if [ -n "$LATEST" ]; then
    ln -sfn "$(realpath "$LATEST")" ./crashes
fi
