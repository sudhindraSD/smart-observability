"""Tier 2 statistical AIOps detector — pure Python stdlib, ZERO ML
dependencies (no river, no Half-Space-Trees: HST failed separation on 6-D
telemetry and erased zero-variance counters).

Per-source robust baselines: a rolling window of NORMAL samples per metric,
scored with median + MAD scaled by 1.4826 (Gaussian-consistent), with a floor
per metric (``MIN_MAD``) so quiet or zero-variance counters stay detectable.
Scoring is upward-only for workload/counter metrics and two-sided for
throughput (``bandwidth_mbps``).
"""

from __future__ import annotations

import math
from collections import deque
from dataclasses import dataclass
from math import sqrt
from statistics import median
from typing import Deque, Dict, List, Mapping, Optional

# -- locked constants ---------------------------------------------------------

WINDOW_SIZE = 60
WARMUP_MIN = 15
ESCAPE_AFTER = 30

SINGLE_Z = 4.0
ELEVATED_Z = 1.7
JOINT_Z = 3.2

MIN_MAD = {
    "cpu_pct": 2.0,
    "memory_pct": 1.5,
    "disk_pct": 1.0,
    "latency_ms": 3.0,
    "packet_loss_pct": 0.2,
    "bandwidth_mbps": 15.0,
    "failed_logins_1m": 1.0,
}

TWO_SIDED_METRICS = {"bandwidth_mbps"}

_SECURITY_TRIGGER_RISKS = ("high", "critical")


@dataclass
class DetectionResult:
    triggered: bool
    warmed_up: bool
    max_z_score: float
    joint_l2_z: float
    elevated_metric_count: int
    z_scores: Dict[str, float]
    baselines: Dict[str, float]
    elevated_metrics: List[str]
    trigger_reason: str


class SourceBaseline:
    """Rolling robust baseline for one source. ``evaluate`` is pure scoring;
    ``process`` learns during warm-up and afterwards admits only non-flagged
    samples (poisoning guard) with a 1-in-3 escape hatch after
    ``ESCAPE_AFTER`` consecutive flags."""

    def __init__(self, source_id: str = "", window_size: int = WINDOW_SIZE) -> None:
        self.source_id = source_id
        self.window_size = window_size
        self._history: Dict[str, Deque[float]] = {}
        self._samples_seen = 0
        self._consecutive_flagged = 0

    # -- baseline math ---------------------------------------------------------

    @staticmethod
    def _median_abs_dev(values: List[float], med: float) -> float:
        devs = sorted(abs(v - med) for v in values)
        n = len(devs)
        mid = n // 2
        if n % 2:
            return devs[mid]
        return (devs[mid - 1] + devs[mid]) / 2.0

    # -- scoring -----------------------------------------------------------------

    def evaluate(
        self,
        sample: Mapping[str, Optional[float]],
        security_risk: str = "none",
        connectivity: Optional[str] = None,
    ) -> DetectionResult:
        """Pure scoring: no state mutation. Triggers on security risk
        high/critical, connectivity down, or (once warmed up) a single-metric
        z >= SINGLE_Z or a joint l2 z >= JOINT_Z across >= 2 elevated metrics."""
        values = dict(sample)
        z_scores: Dict[str, float] = {}
        baselines: Dict[str, float] = {}
        for metric in MIN_MAD:
            if metric not in values:
                continue
            value = values[metric]
            if value is None:
                continue
            value = float(value)
            history = self._history.get(metric)
            if history is not None and len(history) >= 2:
                med = median(history)
                mad = self._median_abs_dev(list(history), med)
                scale = 1.4826 * max(mad, MIN_MAD[metric])  # floor BEFORE 1.4826
                delta = value - med
                if metric in TWO_SIDED_METRICS:
                    z = abs(delta) / scale
                else:
                    z = max(0.0, delta / scale)
            else:
                med = value
                z = 0.0
            z_scores[metric] = z
            baselines[metric] = med

        elevated = {m: z for m, z in z_scores.items() if z >= ELEVATED_Z}
        joint_l2_z = sqrt(sum(z * z for z in elevated.values()))
        max_z = max(z_scores.values(), default=0.0)
        elevated_metrics = sorted(elevated, key=lambda m: (-elevated[m], m))
        warmed_up = self._samples_seen >= WARMUP_MIN

        triggered = False
        reason = ""
        if security_risk in _SECURITY_TRIGGER_RISKS:
            triggered = True
            reason = f"security_risk={security_risk}"
        elif connectivity == "down":
            triggered = True
            reason = "connectivity=down"
        elif warmed_up:
            if max_z >= SINGLE_Z:
                top = sorted(z_scores.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
                triggered = True
                reason = f"single-metric z={max_z:.2f} >= {SINGLE_Z} on {top}"
            elif len(elevated) >= 2 and joint_l2_z >= JOINT_Z:
                triggered = True
                reason = (
                    f"joint l2 z={joint_l2_z:.2f} >= {JOINT_Z} across "
                    f"{len(elevated)} elevated metrics"
                )

        return DetectionResult(
            triggered=triggered,
            warmed_up=warmed_up,
            max_z_score=max_z,
            joint_l2_z=joint_l2_z,
            elevated_metric_count=len(elevated),
            z_scores=z_scores,
            baselines=baselines,
            elevated_metrics=elevated_metrics,
            trigger_reason=reason,
        )

    # -- stateful learning ------------------------------------------------------

    def _admit(self, sample: Mapping[str, Optional[float]]) -> None:
        for metric, value in dict(sample).items():
            if metric not in MIN_MAD or value is None:
                continue
            history = self._history.get(metric)
            if history is None:
                history = deque(maxlen=self.window_size)
                self._history[metric] = history
            history.append(float(value))

    def process(
        self,
        sample: Mapping[str, Optional[float]],
        security_risk: str = "none",
        connectivity: Optional[str] = None,
    ) -> DetectionResult:
        """Score one sample and update the baseline. Learns during warm-up
        (unless security-critical/down); after warm-up admits only
        non-triggered samples, with the escape hatch admitting 1 in 3 flagged
        samples once ``consecutive_flagged > ESCAPE_AFTER``."""
        self._samples_seen += 1
        result = self.evaluate(
            sample, security_risk=security_risk, connectivity=connectivity
        )
        hard_trigger = security_risk in _SECURITY_TRIGGER_RISKS or connectivity == "down"

        if not result.warmed_up:
            if not hard_trigger:
                self._admit(sample)
            return result

        if result.triggered:
            self._consecutive_flagged += 1
            if (
                self._consecutive_flagged > ESCAPE_AFTER
                and self._consecutive_flagged % 3 == 0
            ):
                self._admit(sample)
            return result

        self._consecutive_flagged = 0
        self._admit(sample)
        return result


# -- explanation helpers --------------------------------------------------------


def compute_signal_weights(z_map: Dict[str, float]) -> Dict[str, int]:
    """Convert z-scores to integer percentage weights proportional to z^2,
    largest-remainder rounded so the values sum to exactly 100. Metrics with
    non-positive z contribute nothing; an empty/all-zero map returns {}."""
    positive = {m: float(z) for m, z in z_map.items() if z is not None and z > 0}
    if not positive:
        return {}
    squares = {m: z * z for m, z in positive.items()}
    total = sum(squares.values())
    exact = {m: 100.0 * sq / total for m, sq in squares.items()}
    weights = {m: int(math.floor(p)) for m, p in exact.items()}
    remaining = 100 - sum(weights.values())
    by_remainder = sorted(exact, key=lambda m: (-(exact[m] - weights[m]), m))
    for m in by_remainder[:remaining]:
        weights[m] += 1
    return weights


def compute_confidence_pct(
    max_z: float,
    joint_l2_z: float,
    elevated_count: int,
    security_or_down: bool = False,
) -> int:
    """0..100 confidence: how far past the single/joint thresholds the evidence
    reaches, plus how many metrics agree. Security/down triggers floor at 90."""
    z_component = min(max_z / SINGLE_Z, 1.0)
    joint_component = min(joint_l2_z / JOINT_Z, 1.0)
    count_component = min(elevated_count / 3.0, 1.0)
    pct = 100.0 * (0.40 * z_component + 0.35 * joint_component + 0.25 * count_component)
    if security_or_down:
        pct = max(pct, 90.0)
    return int(round(min(100.0, max(0.0, pct))))
