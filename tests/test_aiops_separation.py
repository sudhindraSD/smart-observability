"""Slice 1 verification: statistical separation quality of ``saas.detector``.

Five seeds, each running 300 warm-up normals + 200 fresh normals through
``SourceBaseline.process`` (false-positive measurement), then 20 draws each of
five anomalies scored with the pure ``evaluate`` path (detection measurement).
"""

import random

import pytest

from saas.detector import (
    WARMUP_MIN,
    SourceBaseline,
    compute_confidence_pct,
    compute_signal_weights,
)

SEEDS = [11, 23, 37, 41, 53]
WARMUP_N = 300
FRESH_N = 200
DRAWS = 20


def _normal_sample(rng: random.Random) -> dict:
    return {
        "cpu_pct": max(0.0, rng.gauss(20.0, 2.5)),
        "memory_pct": max(0.0, rng.gauss(45.0, 5.0)),
        "disk_pct": max(0.0, rng.gauss(60.0, 4.0)),
        "bandwidth_mbps": max(0.0, rng.gauss(300.0, 40.0)),
        "latency_ms": max(0.5, rng.gauss(12.0, 2.0)),
        "packet_loss_pct": max(0.0, rng.gauss(0.1, 0.05)),
        "failed_logins_1m": 1 if rng.random() < 0.05 else 0,
    }


def _with_background(rng: random.Random, **overrides: float) -> dict:
    sample = _normal_sample(rng)
    sample.update(overrides)
    return sample


def _cpu_spike(rng: random.Random) -> dict:
    return _with_background(rng, cpu_pct=rng.gauss(65.0, 1.5))


def _latency_spike(rng: random.Random) -> dict:
    return _with_background(rng, latency_ms=rng.gauss(185.0, 3.0))


def _loss_spike(rng: random.Random) -> dict:
    return _with_background(rng, packet_loss_pct=rng.gauss(4.2, 0.1))


def _login_spike(rng: random.Random) -> dict:
    return _with_background(rng, failed_logins_1m=15 + rng.randrange(0, 3))


def _subtle_drift(rng: random.Random) -> dict:
    return _with_background(
        rng,
        cpu_pct=rng.gauss(28.0, 0.8),
        latency_ms=rng.gauss(21.0, 0.9),
        packet_loss_pct=rng.gauss(0.7, 0.05),
    )


def test_statistical_separation_across_seeds():
    rng_by_seed = {seed: random.Random(seed) for seed in SEEDS}
    baselines = {}
    for seed, rng in rng_by_seed.items():
        sb = SourceBaseline(source_id=f"src-{seed}")
        for _ in range(WARMUP_N):
            sb.process(_normal_sample(rng))
        assert sb.evaluate(_normal_sample(rng)).warmed_up
        baselines[seed] = sb

    false_positives = 0
    total_normals = 0
    for seed, rng in rng_by_seed.items():
        sb = baselines[seed]
        for _ in range(FRESH_N):
            total_normals += 1
            if sb.process(_normal_sample(rng)).triggered:
                false_positives += 1

    assert total_normals == len(SEEDS) * FRESH_N
    assert false_positives <= 0.01 * total_normals, (
        f"false positives {false_positives}/{total_normals} exceed 1%"
    )

    spike_hits = {"cpu": 0, "latency": 0, "packet_loss": 0, "failed_logins": 0}
    subtle_hits = 0
    for seed, rng in rng_by_seed.items():
        sb = baselines[seed]
        for _ in range(DRAWS):
            if sb.evaluate(_cpu_spike(rng)).triggered:
                spike_hits["cpu"] += 1
            if sb.evaluate(_latency_spike(rng)).triggered:
                spike_hits["latency"] += 1
            if sb.evaluate(_loss_spike(rng)).triggered:
                spike_hits["packet_loss"] += 1
            if sb.evaluate(_login_spike(rng)).triggered:
                spike_hits["failed_logins"] += 1
            if sb.evaluate(_subtle_drift(rng)).triggered:
                subtle_hits += 1

    expected = len(SEEDS) * DRAWS
    for name, hits in spike_hits.items():
        assert hits == expected, f"{name} spike detected {hits}/{expected}, want 100%"
    assert subtle_hits >= 0.9 * expected, (
        f"subtle drift detected {subtle_hits}/{expected}, want >= 90%"
    )


def test_warmup_gates_statistics_but_not_security():
    rng = random.Random(97)
    sb = SourceBaseline(source_id="warmup-gate")
    for _ in range(WARMUP_MIN - 1):
        sb.process(_normal_sample(rng))

    cold = sb.evaluate(_with_background(rng, cpu_pct=95.0))
    assert not cold.warmed_up
    assert not cold.triggered, "statistical trigger must not fire before warm-up"

    hot = sb.process(_normal_sample(rng), security_risk="critical")
    assert hot.triggered
    assert "security" in hot.trigger_reason

    down = sb.process(_normal_sample(rng), connectivity="down")
    assert down.triggered
    assert down.trigger_reason == "connectivity=down"


def test_poisoning_guard_keeps_baseline_clean():
    rng = random.Random(101)
    sb = SourceBaseline(source_id="poison-guard")
    for _ in range(WARMUP_N):
        sb.process(_normal_sample(rng))
    before = sb.evaluate(_normal_sample(rng)).baselines["cpu_pct"]

    for _ in range(25):
        flagged = _with_background(rng, cpu_pct=90.0)
        assert sb.process(flagged).triggered

    after = sb.evaluate(_normal_sample(rng)).baselines["cpu_pct"]
    assert after == before, "flagged samples must never be admitted into the baseline"


def test_compute_signal_weights_sum_to_exactly_100():
    weights = compute_signal_weights(
        {"cpu_pct": 6.2, "latency_ms": 2.1, "packet_loss_pct": 2.0, "memory_pct": 0.0}
    )
    assert sum(weights.values()) == 100
    assert "memory_pct" not in weights
    assert all(isinstance(w, int) and 0 <= w <= 100 for w in weights.values())
    assert compute_signal_weights({}) == {}
    assert compute_signal_weights({"cpu_pct": 0.0}) == {}


def test_compute_confidence_pct_bounds_and_monotonic():
    low = compute_confidence_pct(4.0, 3.2, 2)
    high = compute_confidence_pct(9.0, 6.0, 4)
    assert 0 <= low < high <= 100
    assert compute_confidence_pct(0.0, 0.0, 0) == 0
    assert compute_confidence_pct(0.5, 0.5, 0, security_or_down=True) >= 90
