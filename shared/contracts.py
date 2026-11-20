"""Frozen cross-tier contracts for the two-tier secure AIOps observability platform.

Slice 1 locks every name, enum value and field here: Slices 2, 3 and 4 import
them directly. Do not rename, retype or remove anything without a contract
review. The only structure allowed to cross Tier 1 -> Tier 2 is
``EgressMetadataPayload`` (strict allow-list); ``InternalRawEvent`` never
leaves Box 1.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import List, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


def utc_now_iso() -> str:
    """Current UTC time as ISO-8601 with millisecond precision, ending in ``Z``."""
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def parse_utc_iso(ts: str) -> datetime:
    """Parse an ISO-8601 UTC timestamp (``Z`` or numeric offset) to tz-aware UTC."""
    cleaned = ts.strip()
    if cleaned.endswith(("Z", "z")):
        cleaned = cleaned[:-1] + "+00:00"
    parsed = datetime.fromisoformat(cleaned)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


class HealthState(str, Enum):
    EXCELLENT = "Excellent"
    GOOD = "Good"
    FAIR = "Fair"
    POOR = "Poor"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RemediationState(str, Enum):
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED_EXECUTED = "APPROVED_EXECUTED"
    ROLLED_BACK = "ROLLED_BACK"
    POLICY_BLOCKED = "POLICY_BLOCKED"


class SourceType(str, Enum):
    SERVER = "server"
    NETWORK_DEVICE = "network_device"
    APPLICATION = "application"
    SECURITY_SOURCE = "security_source"


class ConnectivityState(str, Enum):
    UP = "up"
    DEGRADED = "degraded"
    DOWN = "down"


class SecurityRisk(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class StrictBaseModel(BaseModel):
    """Base for every model that crosses a trust boundary: no extra fields, and
    rejected input values are never echoed back in validation errors."""

    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class Metrics(StrictBaseModel):
    cpu_pct: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    memory_pct: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    disk_pct: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    service_up: Optional[bool] = None
    bandwidth_mbps: Optional[float] = Field(default=None, ge=0.0)
    latency_ms: Optional[float] = Field(default=None, ge=0.0)
    packet_loss_pct: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    connectivity: Optional[ConnectivityState] = None


class SecuritySummary(StrictBaseModel):
    failed_logins_1m: int = 0
    suspicious_signals_1m: int = 0
    security_risk: SecurityRisk = SecurityRisk.NONE


class RedactionAudit(StrictBaseModel):
    raw_fields_dropped: List[str]
    secrets_scrubbed_count: int = 0
    secret_types_detected: List[str]
    pseudonymized: bool = True


class InternalRawEvent(BaseModel):
    """Box 1 only. Holds raw hostnames, IPs and log lines; NEVER serialized
    across the tier boundary. Unknown keys are ignored, not rejected."""

    model_config = ConfigDict(extra="ignore")

    raw_id: str = Field(default_factory=lambda: f"raw-{uuid4()}")
    event_time_utc: str = Field(default_factory=utc_now_iso)
    source_timezone: str = "Asia/Kolkata"
    real_hostname: str
    real_ip: Optional[str] = None
    source_type: SourceType = SourceType.SERVER
    upstream_device_real_name: Optional[str] = None
    metrics: Metrics
    raw_log_line: Optional[str] = None
    failed_login_event: bool = False
    suspicious_event: bool = False
    forced_payload_id: Optional[str] = None


class EgressMetadataPayload(StrictBaseModel):
    """Strict allow-list payload crossing Tier 1 -> Tier 2. ``egress_sent_utc``
    and ``is_backlog_replay`` are stamped ONLY in sender.py."""

    payload_id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str
    region: str
    collector_id: str
    source_id: str
    source_type: SourceType
    upstream_source_id: Optional[str] = None
    event_time_utc: str
    source_timezone: str
    collected_time_utc: str
    egress_sent_utc: Optional[str] = None
    is_backlog_replay: Optional[bool] = None
    metrics: Metrics
    security_summary: SecuritySummary
    event_category: str = "normal"
    severity: Severity = Severity.LOW
    local_health_hint: HealthState = HealthState.EXCELLENT
    alert_context: str = "No local anomaly detected"
    redaction_audit: RedactionAudit


class IngestBatchRequest(StrictBaseModel):
    collector_id: str
    batch: List[EgressMetadataPayload]


class CollectorHeartbeat(StrictBaseModel):
    heartbeat_id: str
    tenant_id: str
    region: str
    collector_id: str
    sent_time_utc: str
    collector_version: str = "1.0.0"
    collector_cpu_pct: float = 0.0
    collector_mem_mb: float = 0.0
    outbox_pending_count: int = 0
    config_status: str = "synced"
    total_sent_count: int = 0


class ContributingSignal(StrictBaseModel):
    source_id: str
    metric: str
    value: Optional[float] = None
    baseline: Optional[float] = None
    z_score: Optional[float] = None
    weight_pct: int = Field(ge=0, le=100)


class IncidentExplanation(StrictBaseModel):
    """Statistical explanation of an incident. Intentionally has NO
    ``hst_anomaly_score``: the Half-Space-Tree approach was retired."""

    summary: str
    max_z_score: float
    joint_l2_z: float
    elevated_metric_count: int
    confidence_pct: int = Field(ge=0, le=100)
    contributing_signals: List[ContributingSignal]
    recommended_action: str
    reasoning_path: str


class RemediationAuditEntry(StrictBaseModel):
    timestamp_utc: str
    actor: str
    action: str
    details: str


class RemediationPlan(StrictBaseModel):
    action_id: str
    proposed_action: str
    policy_check_passed: bool
    policy_rule_matched: str
    state: RemediationState = RemediationState.AWAITING_APPROVAL
    rollback_plan: str
    audit_trail: List[RemediationAuditEntry]


class IncidentRecord(StrictBaseModel):
    incident_id: str
    tenant_id: str
    region: str
    collector_id: str
    status: Literal["OPEN", "ACKNOWLEDGED", "RESOLVED"] = "OPEN"
    severity: Severity
    root_cause_source_id: str
    affected_source_ids: List[str]
    merged_alert_count: int = 1
    first_event_time_utc: str
    alert_created_utc: str
    explanation: IncidentExplanation
    remediation: RemediationPlan


class ThresholdConfig(StrictBaseModel):
    """Locally tunable health/security thresholds (defaults are the shipped
    policy). Percent thresholds are inclusive-good / exclusive-fair ceilings."""

    cpu_good_max: float = 60.0
    cpu_fair_max: float = 80.0
    memory_good_max: float = 65.0
    memory_fair_max: float = 85.0
    disk_good_max: float = 75.0
    disk_fair_max: float = 90.0
    latency_good_max_ms: float = 50.0
    latency_fair_max_ms: float = 150.0
    packet_loss_good_max_pct: float = 0.5
    packet_loss_fair_max_pct: float = 2.0
    failed_logins_fair_min: int = 5
    failed_logins_poor_min: int = 12
    collector_offline_sec: int = 50
    source_stale_fair_sec: int = 35
    source_stale_poor_sec: int = 55
    local_retention_minutes: int = 60
