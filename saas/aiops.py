"""Slice 3 AIOps: health evaluation, robust z-score detection and the
2-level incident correlator.

Pure stdlib statistics via ``saas/detector.py`` (no ML libraries). Events are
stored idempotently in regional telemetry history; only live, in-order,
non-backlog events advance ``sources_state``, health transitions and
incidents (Amendment A6 + out-of-order guard).
"""

from __future__ import annotations

import json
import math
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from saas.db import SaasDatabase
from saas.detector import (
    ELEVATED_Z,
    SourceBaseline,
    compute_confidence_pct,
    compute_signal_weights,
)
from saas.remediation import (
    build_remediation_plan,
    choose_remediation_action,
)
from shared.contracts import (
    ConnectivityState,
    EgressMetadataPayload,
    HealthState,
    IncidentExplanation,
    IncidentRecord,
    Metrics,
    RemediationPlan,
    SecurityRisk,
    Severity,
    SourceType,
    ThresholdConfig,
    ContributingSignal,
    parse_utc_iso,
    utc_now_iso,
)

CORRELATION_WINDOW_SEC = 45.0

_BASELINE_KEYS = (
    "cpu_pct",
    "memory_pct",
    "disk_pct",
    "latency_ms",
    "packet_loss_pct",
    "bandwidth_mbps",
)

_HEALTH_RANK = {
    HealthState.EXCELLENT: 0,
    HealthState.GOOD: 1,
    HealthState.FAIR: 2,
    HealthState.POOR: 3,
}
_RANK_HEALTH = {rank: state for state, rank in _HEALTH_RANK.items()}

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def evaluate_health_state(
    metrics: Metrics,
    security_summary,
    cfg: ThresholdConfig,
) -> HealthState:
    """Map metrics + security risk onto the worst of the 4 health states."""
    rank = 0

    def worse(value: int) -> None:
        nonlocal rank
        rank = max(rank, value)

    if metrics is not None:
        for value, good_max, fair_max in (
            (metrics.cpu_pct, cfg.cpu_good_max, cfg.cpu_fair_max),
            (metrics.memory_pct, cfg.memory_good_max, cfg.memory_fair_max),
            (metrics.disk_pct, cfg.disk_good_max, cfg.disk_fair_max),
            (metrics.latency_ms, cfg.latency_good_max_ms, cfg.latency_fair_max_ms),
            (
                metrics.packet_loss_pct,
                cfg.packet_loss_good_max_pct,
                cfg.packet_loss_fair_max_pct,
            ),
        ):
            if value is None:
                continue
            if value > fair_max:
                worse(3)
            elif value > good_max:
                worse(2)
        if metrics.service_up is False:
            worse(3)
        if metrics.connectivity == ConnectivityState.DOWN:
            worse(3)
        elif metrics.connectivity == ConnectivityState.DEGRADED:
            worse(2)

    risk = (
        security_summary.security_risk.value
        if security_summary is not None
        else SecurityRisk.NONE.value
    )
    if risk in (SecurityRisk.HIGH.value, SecurityRisk.CRITICAL.value):
        worse(3)
    elif risk == SecurityRisk.MEDIUM.value:
        worse(2)
    elif risk == SecurityRisk.LOW.value:
        # Any observed security signal means the tenant is not "Excellent".
        worse(1)
    if security_summary is not None:
        failed = security_summary.failed_logins_1m
        if failed >= cfg.failed_logins_poor_min:
            worse(3)
        elif failed >= cfg.failed_logins_fair_min:
            worse(2)

    return _RANK_HEALTH[rank]


@dataclass
class EventOutcome:
    inserted: bool = False
    duplicate: bool = False
    late: bool = False
    backlog: bool = False
    health_state: Optional[HealthState] = None
    old_state: Optional[str] = None
    incident_id: Optional[str] = None
    merged_incident_id: Optional[str] = None
    transitions: List[dict] = field(default_factory=list)
    incident_record: Optional[IncidentRecord] = None


def _sample_value(payload: EgressMetadataPayload, metric: str) -> Optional[float]:
    if metric == "failed_logins_1m":
        return float(payload.security_summary.failed_logins_1m)
    if metric == "connectivity":
        return None
    return getattr(payload.metrics, metric, None)


def _build_sample(payload: EgressMetadataPayload) -> Dict[str, float]:
    sample: Dict[str, float] = {}
    for key in _BASELINE_KEYS:
        value = getattr(payload.metrics, key, None)
        if value is not None:
            sample[key] = float(value)
    sample["failed_logins_1m"] = float(payload.security_summary.failed_logins_1m)
    return sample


def _is_hard_trigger(risk_value: str, connectivity_value: Optional[str]) -> bool:
    return risk_value in (
        SecurityRisk.HIGH.value,
        SecurityRisk.CRITICAL.value,
    ) or connectivity_value == ConnectivityState.DOWN.value


def _explicit_signal(
    payload: EgressMetadataPayload,
    z_scores: Dict[str, float],
    risk_value: str,
    connectivity_value: Optional[str],
) -> ContributingSignal:
    """Cold-start / hard-trigger fallback: one signal carrying weight 100."""
    if risk_value in (SecurityRisk.HIGH.value, SecurityRisk.CRITICAL.value):
        metric = "failed_logins_1m"
    elif connectivity_value == ConnectivityState.DOWN.value:
        metric = "connectivity"
    elif z_scores:
        metric = max(z_scores.items(), key=lambda kv: kv[1])[0]
    else:
        metric = "cpu_pct"
    return ContributingSignal(
        source_id=payload.source_id,
        metric=metric,
        value=_sample_value(payload, metric),
        baseline=None,
        z_score=None,
        weight_pct=100,
    )


def _signals_from_elevated(
    payload: EgressMetadataPayload,
    z_map: Dict[str, float],
    baselines: Dict[str, float],
    prior_by_metric: Optional[Dict[str, ContributingSignal]] = None,
) -> List[ContributingSignal]:
    elevated = {m: z for m, z in z_map.items() if z >= ELEVATED_Z}
    if not elevated:
        return []
    weights = compute_signal_weights(elevated)
    prior = prior_by_metric or {}
    signals: List[ContributingSignal] = []
    for metric, z in sorted(elevated.items(), key=lambda kv: (-kv[1], kv[0])):
        previous = prior.get(metric)
        signals.append(
            ContributingSignal(
                source_id=previous.source_id if previous else payload.source_id,
                metric=metric,
                value=previous.value if previous else _sample_value(payload, metric),
                baseline=previous.baseline if previous else baselines.get(metric),
                z_score=z,
                weight_pct=weights.get(metric, 0),
            )
        )
    return signals


def _severity_for(health: HealthState, risk_value: str) -> Severity:
    if risk_value == SecurityRisk.CRITICAL.value:
        return Severity.CRITICAL
    if risk_value == SecurityRisk.HIGH.value:
        return Severity.HIGH
    if health == HealthState.POOR:
        return Severity.HIGH
    if health == HealthState.FAIR:
        return Severity.MEDIUM
    return Severity.LOW


def incident_row_to_record(row: dict, region: str) -> IncidentRecord:
    """Rebuild an ``IncidentRecord`` from a regional ``incidents`` row.

    The frozen ``incidents`` table has no ``region`` column — the row's region
    is whichever regional DB it was read from, so the caller supplies it.
    """
    return IncidentRecord(
        incident_id=row["incident_id"],
        tenant_id=row["tenant_id"],
        region=region,
        collector_id=row["collector_id"],
        status=row["status"],
        severity=Severity(row["severity"]),
        root_cause_source_id=row["root_cause_source_id"] or "",
        affected_source_ids=json.loads(row["affected_sources_json"] or "[]"),
        merged_alert_count=int(row["merged_alert_count"] or 1),
        first_event_time_utc=row["first_event_time_utc"],
        alert_created_utc=row["alert_created_utc"],
        explanation=IncidentExplanation.model_validate_json(row["explanation_json"]),
        remediation=RemediationPlan.model_validate_json(row["remediation_json"]),
    )


def _parse_affected(row: dict) -> List[str]:
    try:
        parsed = json.loads(row.get("affected_sources_json") or "[]")
    except json.JSONDecodeError:
        return []
    return [str(item) for item in parsed] if isinstance(parsed, list) else []


class AiopsEngine:
    """Per-source robust baselines + incident correlation over regional DBs."""

    def __init__(self, db: SaasDatabase) -> None:
        self._db = db
        self._baselines: Dict[Tuple[str, str], SourceBaseline] = {}

    async def process_event(
        self,
        region: str,
        payload: EgressMetadataPayload,
        cfg: ThresholdConfig,
    ) -> EventOutcome:
        ingested_time_utc = utc_now_iso()
        health = evaluate_health_state(payload.metrics, payload.security_summary, cfg)

        inserted = await self._db.insert_telemetry_event(
            region,
            payload,
            ingested_time_utc=ingested_time_utc,
            health_state=health.value,
        )
        if not inserted:
            await self._db.bump_collector_counter(
                region, payload.tenant_id, payload.collector_id,
                "duplicates_blocked_count",
            )
            return EventOutcome(inserted=False, duplicate=True, health_state=health)

        await self._db.bump_collector_counter(
            region, payload.tenant_id, payload.collector_id, "total_received_count"
        )

        if payload.is_backlog_replay:
            # Amendment A6: backlog replay is history + totals only. It never
            # touches live state, incidents or live SLA latency stats.
            return EventOutcome(inserted=True, backlog=True, health_state=health)

        existing = await self._db.get_source_state(region, payload.tenant_id, payload.source_id)
        existing_latest = existing.get("latest_event_time_utc") if existing else None
        if existing_latest:
            try:
                if parse_utc_iso(payload.event_time_utc) < parse_utc_iso(existing_latest):
                    # Out-of-order: keep in history (plotted at its exact
                    # event_time_utc) but never regress live state.
                    return EventOutcome(inserted=True, late=True, health_state=health)
            except (TypeError, ValueError):
                pass

        risk_value = payload.security_summary.security_risk.value
        connectivity_value = (
            payload.metrics.connectivity.value
            if payload.metrics.connectivity is not None
            else None
        )

        baseline = self._baselines.get((payload.tenant_id, payload.source_id))
        if baseline is None:
            baseline = SourceBaseline(source_id=payload.source_id)
            self._baselines[(payload.tenant_id, payload.source_id)] = baseline
        result = baseline.process(
            _build_sample(payload),
            security_risk=risk_value,
            connectivity=connectivity_value,
        )

        old_state = existing.get("health_state") if existing else None
        await self._db.upsert_source_state(
            region,
            tenant_id=payload.tenant_id,
            source_id=payload.source_id,
            collector_id=payload.collector_id,
            source_type=payload.source_type.value,
            upstream_source_id=payload.upstream_source_id,
            health_state=health.value,
            latest_event_time_utc=payload.event_time_utc,
            last_ingested_utc=ingested_time_utc,
            latest_metrics_json=payload.metrics.model_dump_json(),
            latest_security_json=payload.security_summary.model_dump_json(),
            secrets_scrubbed_delta=payload.redaction_audit.secrets_scrubbed_count,
        )

        outcome = EventOutcome(inserted=True, health_state=health, old_state=old_state)
        if old_state != health.value:
            transition = await self._db.record_transition(
                region,
                tenant_id=payload.tenant_id,
                entity_id=payload.source_id,
                entity_type="source",
                old_state=old_state,
                new_state=health.value,
                reason="Telemetry health evaluation",
                transition_time_utc=ingested_time_utc,
            )
            outcome.transitions.append(transition)

        hard_trigger = _is_hard_trigger(risk_value, connectivity_value)
        cold_start = (not result.warmed_up) and (
            health == HealthState.POOR or hard_trigger
        )
        if not (result.triggered or cold_start):
            return outcome

        alert_created_utc = utc_now_iso()
        merge_target = await self._find_merge_target(
            region, payload, alert_created_utc
        )
        if merge_target is not None:
            merged = await self._merge_into_incident(
                region,
                payload,
                merge_target,
                result,
                health,
                risk_value,
                connectivity_value,
                hard_trigger,
                alert_created_utc,
            )
            outcome.merged_incident_id = merged.incident_id
            outcome.incident_record = merged
            return outcome

        record = self._build_new_incident(
            region,
            payload,
            result,
            health,
            risk_value,
            connectivity_value,
            hard_trigger,
            cold_start,
            alert_created_utc,
        )
        await self._db.insert_incident(region, record)
        outcome.incident_id = record.incident_id
        outcome.incident_record = record
        return outcome

    # -- 2-level correlator -----------------------------------------------------------

    async def _find_merge_target(
        self,
        region: str,
        payload: EgressMetadataPayload,
        alert_created_utc: str,
    ) -> Optional[dict]:
        open_incidents = await self._db.list_incidents(
            region, payload.tenant_id, open_only=True
        )
        if not open_incidents:
            return None
        now = parse_utc_iso(alert_created_utc)
        candidates = []
        for incident in open_incidents:
            created = incident.get("alert_created_utc")
            if not created:
                continue
            try:
                age = (now - parse_utc_iso(created)).total_seconds()
            except (TypeError, ValueError):
                continue
            if 0 <= age <= CORRELATION_WINDOW_SEC:
                candidates.append(incident)
        if not candidates:
            return None

        upstream = payload.upstream_source_id
        if upstream:
            # Level 1: topology correlation.
            for incident in candidates:
                affected = _parse_affected(incident)
                if upstream == incident.get("root_cause_source_id") or upstream in affected:
                    return incident
            sources = await self._db.list_sources_state(region, payload.tenant_id)
            upstream_of = {
                row["source_id"]: row.get("upstream_source_id") for row in sources
            }
            for incident in candidates:
                for affected_id in _parse_affected(incident):
                    if upstream_of.get(affected_id) == payload.source_id:
                        return incident
            return None

        # Level 2: topology absent -> same (tenant, collector) within window.
        for incident in candidates:
            if incident.get("collector_id") == payload.collector_id:
                return incident
        return None

    async def _merge_into_incident(
        self,
        region: str,
        payload: EgressMetadataPayload,
        incident: dict,
        result,
        health: HealthState,
        risk_value: str,
        connectivity_value: Optional[str],
        hard_trigger: bool,
        alert_created_utc: str,
    ) -> IncidentRecord:
        incident_id = incident["incident_id"]
        affected = _parse_affected(incident)
        if payload.source_id not in affected:
            affected = [*affected, payload.source_id]
        merged_count = int(incident.get("merged_alert_count") or 1) + 1

        root = incident.get("root_cause_source_id") or payload.source_id
        first_event = incident.get("first_event_time_utc") or payload.event_time_utc
        try:
            new_time = parse_utc_iso(payload.event_time_utc)
            old_time = parse_utc_iso(first_event)
        except (TypeError, ValueError):
            new_time = old_time = None
        if new_time is not None and old_time is not None:
            if new_time < old_time:
                root, first_event = payload.source_id, payload.event_time_utc
            elif new_time == old_time and root != payload.source_id:
                # Tie-break: prefer a network_device root cause.
                if payload.source_type == SourceType.NETWORK_DEVICE:
                    root = payload.source_id

        previous = incident_row_to_record(incident, region)
        new_severity = _severity_for(health, risk_value)
        severity = (
            previous.severity
            if _SEVERITY_RANK.get(previous.severity.value, 0)
            >= _SEVERITY_RANK[new_severity.value]
            else new_severity
        )

        prior_by_metric = {
            signal.metric: signal
            for signal in previous.explanation.contributing_signals
        }
        z_map: Dict[str, float] = {
            signal.metric: float(signal.z_score or 0.0)
            for signal in previous.explanation.contributing_signals
        }
        for metric, z in result.z_scores.items():
            if z > z_map.get(metric, 0.0):
                z_map[metric] = z
        signals = _signals_from_elevated(
            payload, z_map, result.baselines, prior_by_metric
        )
        if not signals:
            signals = [
                _explicit_signal(payload, z_map, risk_value, connectivity_value)
            ]
        elevated = {m: z for m, z in z_map.items() if z >= ELEVATED_Z}
        max_z = max(z_map.values(), default=0.0)
        joint_l2 = math.sqrt(sum(z * z for z in elevated.values()))
        confidence = compute_confidence_pct(
            max_z, joint_l2, len(elevated), security_or_down=hard_trigger
        )
        explanation = IncidentExplanation(
            summary=(
                f"Merged incident rooted at {root}: {len(affected)} affected "
                f"source(s), {merged_count} correlated alerts."
            ),
            max_z_score=max_z,
            joint_l2_z=joint_l2,
            elevated_metric_count=len(elevated),
            confidence_pct=confidence,
            contributing_signals=signals,
            recommended_action="",
            reasoning_path=(
                f"{previous.explanation.reasoning_path}; merged alert from "
                f"{payload.source_id} (max_z={result.max_z_score:.2f}) at "
                f"{alert_created_utc}"
            ),
        )
        await self._db.update_incident_merge(
            region,
            incident_id=incident_id,
            tenant_id=payload.tenant_id,
            severity=severity.value,
            root_cause_source_id=root,
            affected_source_ids=affected,
            merged_alert_count=merged_count,
            first_event_time_utc=first_event,
            explanation_json=explanation.model_dump_json(),
        )
        row = await self._db.get_incident(region, payload.tenant_id, incident_id)
        return incident_row_to_record(row, region) if row else previous

    # -- new incident ------------------------------------------------------------------

    def _build_new_incident(
        self,
        region: str,
        payload: EgressMetadataPayload,
        result,
        health: HealthState,
        risk_value: str,
        connectivity_value: Optional[str],
        hard_trigger: bool,
        cold_start: bool,
        alert_created_utc: str,
    ) -> IncidentRecord:
        elevated = {m: z for m, z in result.z_scores.items() if z >= ELEVATED_Z}
        signals = _signals_from_elevated(payload, result.z_scores, result.baselines)
        if not signals:
            signals = [
                _explicit_signal(payload, result.z_scores, risk_value, connectivity_value)
            ]
        if cold_start and not result.triggered:
            trigger_label = "cold-start policy"
        elif result.trigger_reason:
            trigger_label = result.trigger_reason
        else:
            trigger_label = "robust z-score threshold"
        max_z = result.max_z_score
        joint_l2 = result.joint_l2_z
        confidence = compute_confidence_pct(
            max_z, joint_l2, result.elevated_metric_count, security_or_down=hard_trigger
        )
        top_metric = (
            max(result.z_scores.items(), key=lambda kv: kv[1])[0]
            if result.z_scores
            else None
        )
        action = choose_remediation_action(
            event_category=payload.event_category,
            security_risk=risk_value,
            metrics=payload.metrics,
            top_metric=top_metric,
        )
        remediation = build_remediation_plan(
            action,
            context=(
                f"{trigger_label} on {payload.source_id} "
                f"(max_z={max_z:.2f}, health={health.value})"
            ),
        )
        explanation = IncidentExplanation(
            summary=(
                f"Anomaly on {payload.source_id}: {trigger_label} "
                f"(health={health.value}, severity driver max_z={max_z:.2f})"
            ),
            max_z_score=max_z,
            joint_l2_z=joint_l2,
            elevated_metric_count=result.elevated_metric_count,
            confidence_pct=confidence,
            contributing_signals=signals,
            recommended_action=action,
            reasoning_path=(
                f"Robust z-score evaluation on {payload.source_id}; trigger="
                f"{trigger_label}; signals weighted by compute_signal_weights "
                f"(sum=100); remediation {action} proposed"
            ),
        )
        return IncidentRecord(
            incident_id=f"INC-{uuid.uuid4().hex[:12]}",
            tenant_id=payload.tenant_id,
            region=region,
            collector_id=payload.collector_id,
            status="OPEN",
            severity=_severity_for(health, risk_value),
            root_cause_source_id=payload.source_id,
            affected_source_ids=[payload.source_id],
            merged_alert_count=1,
            first_event_time_utc=payload.event_time_utc,
            alert_created_utc=alert_created_utc,
            explanation=explanation,
            remediation=remediation,
        )
