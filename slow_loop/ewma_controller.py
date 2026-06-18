"""
slow_loop/ewma_controller.py
─────────────────────────────
EWMA Adaptive Controller — coordinates Fast Loop recv() sampling interval.

Mathematical model:
    λ_C(t) = δ·ΔC_t + (1-δ)·λ_C(t-1)       [EWMA coverage intensity]
    k(t)   = ⌊K_max / (1 + θ·λ_C(t))⌋        [Adaptive sampling interval]

IPC: File-based (shared/adaptive_k.json), NOT multiprocessing.Value.
     Slow Loop writes, Fast Loop polls — same pattern as active_rules.json.

Proxy metrics (Slow Loop has NO server response visibility):
    Metric A — field_groups count from DifferentialAnalyzer (protocol discovery)
    Metric B — unique response hex_prefix from response_buffer.jsonl (Fast Loop writes)
    Combined: ΔC = (w_A·ΔA + w_B·B) / epoch_duration  (normalized by time)
"""

from __future__ import annotations

import json
import math
import os
import time
from pathlib import Path
from typing import Optional

from shared.logger import get_logger
from shared.protocol_module import ProtocolModule
from typing import Optional

log = get_logger("slow_loop.ewma_controller")


class EWMAController:
    """EWMA Adaptive Controller for Fast Loop recv() sampling.

    Parameters:
        output_path:        Where to write adaptive_k.json (Slow Loop → Fast Loop IPC).
        delta:              EWMA smoothing factor (0.05=slow adapt, 0.2=fast adapt).
        theta:              Sensitivity gain (2.0=moderate, 5.0=aggressive).
        K_max:              Max sampling interval (fire-and-forget ceiling).
        k_min:              Min sampling interval (never recv more than every k_min packets).
        weight_A:           Weight for field_groups proxy metric.
        weight_B:           Weight for response diversity proxy metric.
        response_buf_path:  Path to response_buffer.jsonl written by Fast Loop.
    """

    def __init__(
        self,
        output_path: str = "shared/adaptive_k.json",
        delta: float = 0.1,
        theta: float = 2.0,
        K_max: int = 200,
        k_min: int = 5,
        weight_A: float = 0.3,
        weight_B: float = 0.7,
        response_buf_path: str = "shared/response_buffer.jsonl",
        protocol_module: Optional[ProtocolModule] = None,
    ) -> None:
        self.output_path = Path(output_path)
        self.response_buf_path = Path(response_buf_path)
        self.delta = delta
        self.theta = theta
        self.K_max = K_max
        self.k_min = k_min
        self.weight_A = weight_A
        self._protocol_module = protocol_module
        self.weight_B = weight_B

        # EWMA state — persists across epochs
        self._lambda_c: float = 0.0
        self._prev_field_groups: int = 0

        # Write initial state so Fast Loop has a default on first read
        self._write_state(self.K_max, "sparse")

        log.info(
            "EWMAController initialized",
            extra={"context": {
                "delta": delta, "theta": theta, "K_max": K_max, "k_min": k_min,
                "weight_A": weight_A, "weight_B": weight_B,
                "output": str(self.output_path),
            }},
        )

    # ------------------------------------------------------------------
    # Main update — called once per Slow Loop analysis epoch
    # ------------------------------------------------------------------

    def update(
        self,
        field_groups_count: int,
        epoch_duration_s: float,
    ) -> int:
        """Compute new sampling interval k from proxy coverage metrics.

        Args:
            field_groups_count: Number of field groups from DifferentialAnalyzer.
            epoch_duration_s:   Elapsed seconds since last update.

        Returns:
            New k value (also written to adaptive_k.json).
        """
        # Step 1: Metric A — protocol discovery progress
        delta_A = max(0, field_groups_count - self._prev_field_groups)
        self._prev_field_groups = field_groups_count

        # Step 2: Metric B — response diversity from Fast Loop's sampled responses
        proxy_B = self._read_and_truncate_response_buffer()

        # Step 3: Combine and normalize by epoch duration
        raw_delta_C = (self.weight_A * delta_A) + (self.weight_B * proxy_B)
        epoch_s = max(1.0, epoch_duration_s)  # prevent division by zero
        delta_C = raw_delta_C / epoch_s

        # Step 4: EWMA update — Stochastic Approximation (Robbins-Monro)
        self._lambda_c = (self.delta * delta_C) + ((1.0 - self.delta) * self._lambda_c)

        # Step 5: Compute new k — continuous formula (no hard reset)
        k_raw = self.K_max / (1.0 + self.theta * self._lambda_c)
        k_new = max(self.k_min, math.floor(k_raw))

        # Step 6: Classify regime for logging
        regime = self._classify_regime(k_new)

        # Step 7: Write to IPC file (atomic)
        self._write_state(k_new, regime)

        log.info(
            "EWMA Adaptive Controller update",
            extra={"context": {
                "delta_A": delta_A,
                "proxy_B": proxy_B,
                "delta_C": f"{delta_C:.4f}",
                "lambda_c": f"{self._lambda_c:.4f}",
                "k_raw": f"{k_raw:.1f}",
                "k_new": k_new,
                "regime": regime,
                "epoch_s": f"{epoch_s:.1f}",
            }},
        )

        return k_new

    # ------------------------------------------------------------------
    # Metric B: Read + truncate response buffer
    # ------------------------------------------------------------------

    def _read_and_truncate_response_buffer(self) -> int:
        """Read response_buffer.jsonl, count unique hex_prefix, then truncate.

        Uses atomic rename-swap to prevent data loss: first renames the live
        file to a staging name, then reads from staging. Any new Fast Loop
        writes during processing go to a fresh file (open("a") creates it).

        If a ProtocolModule is attached, it may boost the diversity count via
        ``response_diversity_multiplier`` to reward reaching deep protocol
        states (e.g. post-auth replies). The core itself is protocol-agnostic;
        the module owns all protocol-specific logic.

        Returns:
            Effective response diversity score (unique prefixes × module bonus).
        """
        buf_path = self.response_buf_path
        if not buf_path.exists():
            return 0

        # Step 1: Atomically claim the file by renaming to staging.
        # After this, Fast Loop writes go to a NEW file (created by open("a")).
        staging = buf_path.with_suffix(".reading")
        try:
            os.replace(str(buf_path), str(staging))
        except FileNotFoundError:
            return 0
        except OSError:
            return 0

        # Step 2: Read from staging (no race with Fast Loop)
        try:
            lines = staging.read_text().strip().splitlines()
        except Exception:
            try:
                staging.unlink(missing_ok=True)
            except OSError:
                pass
            return 0

        # Step 3: Count unique hex_prefix values + collect protocol extras
        unique_prefixes: set[str] = set()
        extra_fields: list[dict] = []

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                hp = entry.get("hex_prefix", "")
                if hp:
                    unique_prefixes.add(hp)
                extra = entry.get("_extra")
                if extra:
                    extra_fields.append(extra)
            except (json.JSONDecodeError, AttributeError):
                continue

        # Step 4: Compute effective diversity with protocol-specific bonus
        diversity = len(unique_prefixes)

        if self._protocol_module is not None and extra_fields:
            multiplier = self._protocol_module.response_diversity_multiplier(
                extra_fields
            )
            if multiplier != 1.0:
                diversity = round(diversity * multiplier)
                log.debug(
                    "EWMA diversity multiplier applied",
                    extra={"context": {
                        "module": self._protocol_module.name,
                        "multiplier": multiplier,
                        "diversity_before": len(unique_prefixes),
                        "diversity_after": diversity,
                    }},
                )

        # Step 5: Delete staging file (data has been consumed)
        try:
            staging.unlink(missing_ok=True)
        except OSError:
            pass

        return diversity

    # ------------------------------------------------------------------
    # IPC: Write adaptive_k.json (atomic)
    # ------------------------------------------------------------------

    def _write_state(self, k: int, regime: str) -> None:
        """Write current k and telemetry to adaptive_k.json (atomic rename)."""
        payload = {
            "current_k": k,
            "lambda_c": round(self._lambda_c, 6),
            "regime": regime,
            "updated_at": time.time(),
        }

        try:
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self.output_path.with_suffix(".tmp")
            with open(tmp_path, "w") as f:
                json.dump(payload, f)
            os.replace(str(tmp_path), str(self.output_path))
            # Force mtime update (rename may preserve source mtime)
            self.output_path.touch()
        except Exception as exc:
            log.warning(
                f"Failed to write adaptive_k.json: {exc}",
                extra={"context": {"path": str(self.output_path)}},
            )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _classify_regime(self, k: int) -> str:
        """Human-readable regime label for logging."""
        ratio = k / max(1, self.K_max)
        if ratio <= 0.1:
            return "intensive"
        if ratio <= 0.33:
            return "active"
        if ratio <= 0.66:
            return "normal"
        return "sparse"

    @property
    def lambda_c(self) -> float:
        """Current coverage intensity estimate (for telemetry)."""
        return self._lambda_c
