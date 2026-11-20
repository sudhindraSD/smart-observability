"""Tier 1 (Box 1) local scrubber, running on the collector inside the
customer network.

Everything privacy-sensitive dies in this module: raw hostnames become
deterministic HMAC pseudonyms, raw log lines are scanned for secrets and are
NEVER exported, and only aggregate counters plus fixed-template alert context
cross the tier boundary (see ``shared.contracts.EgressMetadataPayload`` for
the strict allow-list).
"""

from __future__ import annotations

import hmac
import math
import re
import time
from collections import deque
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Deque, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from shared.contracts import (
    ConnectivityState,
    EgressMetadataPayload,
    HealthState,
    InternalRawEvent,
    Metrics,
    RedactionAudit,
    SecurityRisk,
    SecuritySummary,
    Severity,
    SourceType,
    ThresholdConfig,
    utc_now_iso,
)

# ---------------------------------------------------------------------------
# Pass 1: pre-compiled secret/PII patterns (raw strings, merged on overlap so
# one contiguous secret is never double-counted).
# ---------------------------------------------------------------------------

_API_KEY_RE = re.compile(
    r"\b(?:sk_live|sk_test|pk_live|pk_test|ghp|gho|ghu|ghs|AIza|xoxb|xoxp|AKIA)"
    r"[A-Za-z0-9_\-]{6,}"
)
_BEARER_RE = re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{6,}")
_CREDENTIAL_RE = re.compile(
    r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key"
    r"|auth[_-]?token|private[_-]?key)\s*[:=]\s*['\"]?[^\s,'\";]+"
)
_HEX_KEY_RE = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{32,}(?![0-9A-Za-z])")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_PRIVATE_IP_RE = re.compile(
    r"\b(?:"
    r"(?:10(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){3})"
    r"|(?:192\.168(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){2})"
    r"|(?:172\.(?:1[6-9]|2[0-9]|3[01])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])){2})"
    r")\b"
)

_PASS1_SCANNERS: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("api_key", _API_KEY_RE),
    ("api_key", _BEARER_RE),
    ("credential", _CREDENTIAL_RE),
    ("hex_key", _HEX_KEY_RE),
    ("email", _EMAIL_RE),
    ("private_ip", _PRIVATE_IP_RE),
)

# ---------------------------------------------------------------------------
# Pass 2: bare high-entropy token detection (locked thresholds).
# ---------------------------------------------------------------------------

MIN_BARE_LEN = 12
MIN_CLASSES = 2
ENTROPY_RATIO_MIN = 0.85
CLASS_TRANSITION_MIN = 0.45

_ALNUM_RUN_RE = re.compile(r"[A-Za-z0-9]{%d,}" % MIN_BARE_LEN)

# ---------------------------------------------------------------------------
# Local auth-failure / suspicious-activity heuristics (counted, never exported).
# ---------------------------------------------------------------------------

_AUTH_FAIL_RE = re.compile(
    r"(?i)\b(?:failed\s+(?:password|publickey|login|auth(?:entication)?)"
    r"|authentication\s+failure|auth\s+failure|invalid\s+user"
    r"|login\s+failed|incorrect\s+password|access\s+denied"
    r"|connection\s+closed\s+by\s+authenticating)\b"
)
_SUSPICIOUS_RE = re.compile(
    r"(?i)\b(?:sudo|nmap|malware|exploit|meterpreter|keylogger"
    r"|reverse\s*shell|port\s*scan|brute\s*force|root\s*login"
    r"|sql\s*inject\w*|privilege\s*escalat\w*)\b|su\[\d+\]"
)

_WINDOW_SECONDS = 60.0
_HEALTH_STEPS = (
    HealthState.EXCELLENT,
    HealthState.GOOD,
    HealthState.FAIR,
    HealthState.POOR,
)
_SEVERITY_BY_RISK = {
    SecurityRisk.NONE: Severity.LOW,
    SecurityRisk.LOW: Severity.LOW,
    SecurityRisk.MEDIUM: Severity.MEDIUM,
    SecurityRisk.HIGH: Severity.HIGH,
    SecurityRisk.CRITICAL: Severity.CRITICAL,
}


@dataclass(frozen=True)
class ScanResult:
    """Outcome of scanning one raw log line. ``redacted_preview`` is for the
    local Box 1 UI only; ``raw_log_line`` itself is always dropped on egress."""

    secrets_scrubbed_count: int = 0
    secret_types_detected: List[str] = field(default_factory=list)
    redacted_preview: str = ""


def _char_class(ch: str) -> int:
    if ch.isdigit():
        return 2
    if ch.isupper():
        return 0
    return 1


def _normalized_entropy(token: str) -> float:
    """Shannon entropy in bits normalized by log2(min(len, 62)) — 1.0 when the
    token uses its length's worth of alphabet uniformly."""
    if not token:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in token:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(token)
    entropy = -sum((c / n) * math.log2(c / n) for c in freq.values())
    return entropy / math.log2(min(n, 62))


def looks_random(token: str) -> bool:
    """True when ``token`` behaves like a generated secret rather than an
    identifier: long enough, spans >= MIN_CLASSES character classes, has high
    normalized Shannon entropy (>= 0.85) and a high adjacent character-class
    transition ratio (>= 0.45), so camelCase names like
    ``AuthenticationService`` are never flagged."""
    if len(token) < MIN_BARE_LEN:
        return False
    classes = {_char_class(ch) for ch in token}
    if len(classes) < MIN_CLASSES:
        return False
    if _normalized_entropy(token) < ENTROPY_RATIO_MIN:
        return False
    transitions = 0
    pairs = 0
    prev = _char_class(token[0])
    for ch in token[1:]:
        cur = _char_class(ch)
        pairs += 1
        if cur != prev:
            transitions += 1
        prev = cur
    if pairs == 0:
        return False
    return (transitions / pairs) >= CLASS_TRANSITION_MIN


def _merge_spans(
    spans: List[Tuple[int, int, str]],
) -> List[Tuple[int, int, Set[str]]]:
    """Union overlapping/adjacent matches so one contiguous secret counts once."""
    merged: List[List[object]] = []  # [start, end, {types}]
    for start, end, kind in sorted(spans, key=lambda s: (s[0], s[1])):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)  # type: ignore[arg-type]
            merged[-1][2].add(kind)  # type: ignore[union-attr]
        else:
            merged.append([start, end, {kind}])
    return [(s, e, t) for s, e, t in merged]  # type: ignore[misc]


def scan_raw_text(text: Optional[str]) -> ScanResult:
    """Scan a raw log line for secrets/PII. Returns the number of scrubbed
    regions, the detected types, and a redacted preview for the local UI."""
    if not text:
        return ScanResult(
            secrets_scrubbed_count=0,
            secret_types_detected=[],
            redacted_preview=(text or ""),
        )

    pass1: List[Tuple[int, int, str]] = []
    for kind, pattern in _PASS1_SCANNERS:
        for match in pattern.finditer(text):
            pass1.append((match.start(), match.end(), kind))
    merged = _merge_spans(pass1)

    # Pass 2: bare high-entropy alphanumeric runs not already matched above.
    bare: List[Tuple[int, int, str]] = []
    for match in _ALNUM_RUN_RE.finditer(text):
        start, end = match.span()
        if any(start < span_end and span_start < end for span_start, span_end, _ in merged):
            continue
        if looks_random(match.group(0)):
            bare.append((start, end, "bare_token"))
    if bare:
        merged = _merge_spans(pass1 + bare)

    detected_types: Set[str] = set()
    pieces: List[str] = []
    cursor = 0
    for start, end, kinds in merged:
        detected_types.update(kinds)
        pieces.append(text[cursor:start])
        pieces.append("[REDACTED]")
        cursor = end
    pieces.append(text[cursor:])

    return ScanResult(
        secrets_scrubbed_count=len(merged),
        secret_types_detected=sorted(detected_types),
        redacted_preview="".join(pieces),
    )


class LocalScrubber:
    """Box 1 worker: pseudonymization, secret scrubbing and the local 60s
    sliding security window feeding ``SecuritySummary``."""

    def __init__(self, local_hmac_salt: str) -> None:
        if not local_hmac_salt:
            raise ValueError("local_hmac_salt must be a non-empty string")
        self._salt = local_hmac_salt.encode("utf-8")
        self._thresholds = ThresholdConfig()
        self._failed_logins: Dict[str, Deque[float]] = {}
        self._suspicious_signals: Dict[str, Deque[float]] = {}

    # -- identity -----------------------------------------------------------

    def pseudonymize(self, real_name: str, is_network: bool = False) -> str:
        """Deterministic HMAC-SHA256 6-hex pseudonym. The same salt derives
        both ``source_id`` and ``upstream_source_id`` so joins still work."""
        digest = hmac.new(self._salt, real_name.encode("utf-8"), sha256).hexdigest()[:6]
        return ("net-" if is_network else "src-") + digest

    # -- local sliding security window ---------------------------------------

    @staticmethod
    def _prune(window: Deque[float], now: float) -> None:
        cutoff = now - _WINDOW_SECONDS
        while window and window[0] <= cutoff:
            window.popleft()

    def security_snapshot(
        self, source_id: str, now: Optional[float] = None
    ) -> Tuple[int, int, SecurityRisk]:
        """(failed_logins_1m, suspicious_signals_1m, security_risk) for a
        pseudonymized source over the last 60 seconds."""
        current = time.time() if now is None else now
        failed_window = self._failed_logins.get(source_id, deque())
        susp_window = self._suspicious_signals.get(source_id, deque())
        self._prune(failed_window, current)
        self._prune(susp_window, current)
        failed = len(failed_window)
        suspicious = len(susp_window)
        return failed, suspicious, self._classify_risk(failed, suspicious)

    def _classify_risk(self, failed_logins: int, suspicious: int) -> SecurityRisk:
        t = self._thresholds
        poor_min = t.failed_logins_poor_min
        if (
            failed_logins >= 2 * poor_min
            or suspicious >= 10
            or (failed_logins >= poor_min and suspicious >= 3)
        ):
            return SecurityRisk.CRITICAL
        if failed_logins >= poor_min:
            return SecurityRisk.HIGH
        if failed_logins >= t.failed_logins_fair_min or suspicious >= 5:
            return SecurityRisk.MEDIUM
        if failed_logins >= 1 or suspicious >= 1:
            return SecurityRisk.LOW
        return SecurityRisk.NONE

    # -- local health hint ----------------------------------------------------

    def _health_hint(self, metrics: Metrics, summary: SecuritySummary) -> HealthState:
        t = self._thresholds
        steps = 0
        if metrics.cpu_pct is not None:
            steps += 2 if metrics.cpu_pct > t.cpu_fair_max else (
                1 if metrics.cpu_pct > t.cpu_good_max else 0
            )
        if metrics.memory_pct is not None:
            steps += 2 if metrics.memory_pct > t.memory_fair_max else (
                1 if metrics.memory_pct > t.memory_good_max else 0
            )
        if metrics.disk_pct is not None:
            steps += 2 if metrics.disk_pct > t.disk_fair_max else (
                1 if metrics.disk_pct > t.disk_good_max else 0
            )
        if metrics.latency_ms is not None:
            steps += 2 if metrics.latency_ms > t.latency_fair_max_ms else (
                1 if metrics.latency_ms > t.latency_good_max_ms else 0
            )
        if metrics.packet_loss_pct is not None:
            steps += 2 if metrics.packet_loss_pct > t.packet_loss_fair_max_pct else (
                1 if metrics.packet_loss_pct > t.packet_loss_good_max_pct else 0
            )
        if metrics.service_up is False:
            steps += 2
        if metrics.connectivity == ConnectivityState.DOWN:
            steps += 2
        elif metrics.connectivity == ConnectivityState.DEGRADED:
            steps += 1
        if summary.security_risk in (SecurityRisk.HIGH, SecurityRisk.CRITICAL):
            steps += 2
        elif summary.security_risk == SecurityRisk.MEDIUM:
            steps += 1
        return _HEALTH_STEPS[min(steps, 3)]

    # -- fixed-template alert context (never copies raw_log_line substrings) --

    @staticmethod
    def _alert_context(
        source_id: str, summary: SecuritySummary, health: HealthState
    ) -> str:
        parts: List[str] = []
        if summary.failed_logins_1m > 0:
            parts.append(f"{summary.failed_logins_1m} failed logins in the last 60s")
        if summary.suspicious_signals_1m > 0:
            parts.append(
                f"{summary.suspicious_signals_1m} suspicious activity signals in the last 60s"
            )
        if health in (HealthState.FAIR, HealthState.POOR):
            parts.append(f"local resource health is {health.value}")
        if not parts:
            return "No local anomaly detected"
        return f"Local watch on {source_id}: " + "; ".join(parts)

    # -- the Box 1 -> egress transform -----------------------------------------

    def scrub_to_egress(
        self,
        raw: InternalRawEvent,
        tenant_id: str,
        region: str,
        collector_id: str,
        collected_time_utc: Optional[str] = None,
    ) -> Tuple[EgressMetadataPayload, ScanResult]:
        """Turn one raw event into the strict egress payload plus its scan.

        Keeps ``egress_sent_utc`` and ``is_backlog_replay`` unset (stamped
        later in sender.py) and preserves ``raw.forced_payload_id`` as
        ``payload_id`` when provided. ``raw_log_line``, ``real_hostname`` and
        ``real_ip`` never leave this method."""
        now = time.time()
        is_network = raw.source_type == SourceType.NETWORK_DEVICE
        source_id = self.pseudonymize(raw.real_hostname, is_network=is_network)
        upstream_source_id = (
            self.pseudonymize(raw.upstream_device_real_name, is_network=True)
            if raw.upstream_device_real_name
            else None
        )

        scan = scan_raw_text(raw.raw_log_line)

        if raw.failed_login_event or (
            raw.raw_log_line and _AUTH_FAIL_RE.search(raw.raw_log_line)
        ):
            self._failed_logins.setdefault(source_id, deque()).append(now)
        if raw.suspicious_event or (
            raw.raw_log_line and _SUSPICIOUS_RE.search(raw.raw_log_line)
        ):
            self._suspicious_signals.setdefault(source_id, deque()).append(now)

        failed_count, susp_count, risk = self.security_snapshot(source_id, now=now)
        summary = SecuritySummary(
            failed_logins_1m=failed_count,
            suspicious_signals_1m=susp_count,
            security_risk=risk,
        )
        health = self._health_hint(raw.metrics, summary)

        if risk != SecurityRisk.NONE or raw.failed_login_event or raw.suspicious_event:
            category = "security"
        elif health in (HealthState.FAIR, HealthState.POOR):
            category = "performance"
        else:
            category = "normal"

        severity = _SEVERITY_BY_RISK[risk]
        if health == HealthState.POOR and severity == Severity.LOW:
            severity = Severity.MEDIUM

        dropped = ["real_hostname"]
        if raw.real_ip:
            dropped.append("real_ip")
        if raw.raw_log_line:
            dropped.append("raw_log_line")
        audit = RedactionAudit(
            raw_fields_dropped=sorted(dropped),
            secrets_scrubbed_count=scan.secrets_scrubbed_count,
            secret_types_detected=scan.secret_types_detected,
            pseudonymized=True,
        )

        payload = EgressMetadataPayload(
            payload_id=raw.forced_payload_id or str(uuid4()),
            tenant_id=tenant_id,
            region=region,
            collector_id=collector_id,
            source_id=source_id,
            source_type=raw.source_type,
            upstream_source_id=upstream_source_id,
            event_time_utc=raw.event_time_utc,
            source_timezone=raw.source_timezone,
            collected_time_utc=collected_time_utc or utc_now_iso(),
            metrics=raw.metrics,
            security_summary=summary,
            event_category=category,
            severity=severity,
            local_health_hint=health,
            alert_context=self._alert_context(source_id, summary, health),
            redaction_audit=audit,
        )
        return payload, scan
