"""Slice 2 pluggable stream adapter for Box 1.

Five modes selected by ``STREAM_MODE``:

* ``live``  (default) — real OS + network telemetry from ``psutil`` plus async
  TCP probes. No synthetic numbers anywhere: CPU/memory/disk come from the
  kernel, bandwidth from ``net_io_counters`` deltas, latency from a real TCP
  handshake to ``LIVE_PROBE_HOST``.
* ``ws``    — consumes live JSON events from a WebSocket URL.
* ``sse``   — consumes live Server-Sent Events from an HTTP URL.
* ``poll``  — polls an HTTP JSON endpoint.
* ``file``  — tails a growing JSONL/log file.

Every external shape funnels through :func:`normalize_external_event`, so
adapting to an unknown organizer JSON format on demo day means editing this
file only.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import time
from collections import deque
from typing import AsyncIterator, Deque, Dict, Iterator, List, Optional, Tuple

import httpx
import psutil

from shared.contracts import (
    ConnectivityState,
    InternalRawEvent,
    Metrics,
    SourceType,
    utc_now_iso,
)

LOGGER = logging.getLogger("collector.adapter")

VALID_MODES: Tuple[str, ...] = ("live", "ws", "sse", "poll", "file")

PROBE_TIMEOUT_SEC = 1.5
PROBE_DEGRADED_MS = 150.0
PROBE_LOSSY_PCT = 2.0
LOSS_WINDOW_SIZE = 20
RECONNECT_DELAY_SEC = 1.0
LOG_TAIL_MAX_LINES = 20

# -- module-level live-collection state -----------------------------------------

_cpu_primed = False
_lan_ip_cache: Optional[str] = None
_net_io_state: Optional[Tuple[float, int, int]] = None  # (monotonic, sent, recv)
_probe_window: Deque[bool] = deque(maxlen=LOSS_WINDOW_SIZE)  # True = failed probe
_log_tail_offsets: Dict[str, int] = {}


def _prime_cpu() -> None:
    """First ``cpu_percent`` call returns 0.0 unless primed; prime once."""
    global _cpu_primed
    if not _cpu_primed:
        psutil.cpu_percent(interval=None)
        _cpu_primed = True


def _detect_lan_ip() -> str:
    global _lan_ip_cache
    if _lan_ip_cache:
        return _lan_ip_cache
    ip = "127.0.0.1"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))  # UDP connect: no packet is sent
        ip = sock.getsockname()[0] or "127.0.0.1"
    except OSError:
        pass
    finally:
        sock.close()
    _lan_ip_cache = ip
    return ip


def _bandwidth_mbps() -> float:
    """Real throughput from the net_io_counters byte delta since last tick."""
    global _net_io_state
    counters = psutil.net_io_counters()
    now = time.monotonic()
    if _net_io_state is None:
        _net_io_state = (now, counters.bytes_sent, counters.bytes_recv)
        return 0.0
    elapsed = now - _net_io_state[0]
    if elapsed <= 0:
        return 0.0
    delta_bytes = (counters.bytes_sent - _net_io_state[1]) + (
        counters.bytes_recv - _net_io_state[2]
    )
    _net_io_state = (now, counters.bytes_sent, counters.bytes_recv)
    return max(0.0, (delta_bytes * 8.0) / elapsed / 1_000_000.0)


def _packet_loss_pct() -> float:
    if not _probe_window:
        return 0.0
    return round(100.0 * sum(1 for failed in _probe_window if failed) / len(_probe_window), 2)


def _connectivity(latency_ms: Optional[float]) -> ConnectivityState:
    if latency_ms is None:
        return ConnectivityState.DOWN
    if latency_ms >= PROBE_DEGRADED_MS or _packet_loss_pct() >= PROBE_LOSSY_PCT:
        return ConnectivityState.DEGRADED
    return ConnectivityState.UP


async def tcp_probe_latency(
    host: str, port: int, timeout: float = PROBE_TIMEOUT_SEC
) -> Optional[float]:
    """Real async TCP handshake time in ms, or None when the probe fails.
    Never raises: an offline network simply marks the probe failed."""
    loop = asyncio.get_running_loop()
    start = loop.time()
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        return round((loop.time() - start) * 1000.0, 3)
    except asyncio.CancelledError:
        raise
    except (OSError, asyncio.TimeoutError, EOFError):
        return None
    finally:
        if writer is not None:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=0.5)
            except (OSError, asyncio.TimeoutError):
                pass


def _tail_new_lines(path: str) -> str:
    """Return log lines appended to ``path`` since the last call."""
    offset = _log_tail_offsets.get(path, 0)
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            handle.seek(offset)
            data = handle.read()
            new_offset = handle.tell()
    except OSError:
        return ""
    _log_tail_offsets[path] = new_offset
    lines = [line for line in data.splitlines() if line.strip()]
    if not lines:
        return ""
    return "\n".join(lines[-LOG_TAIL_MAX_LINES:])


# ---------------------------------------------------------------------------
# Live collection (real telemetry, no synthetic values)
# ---------------------------------------------------------------------------


async def collect_live_host_events(
    probe_host: str,
    probe_port: int,
    *,
    source_timezone: str = "Asia/Kolkata",
    live_log_file: Optional[str] = None,
) -> Tuple[InternalRawEvent, InternalRawEvent]:
    """Collect one real tick: (local host event, network uplink event).

    Emits exactly two ``InternalRawEvent`` objects built from live ``psutil``
    readings and a real async TCP handshake to ``(probe_host, probe_port)``.
    When the probe cannot connect (offline lab, firewalled port) the probe is
    marked failed — ``latency_ms`` is None and connectivity degrades to
    ``down`` — instead of raising.
    """
    _prime_cpu()
    probe_latency = await tcp_probe_latency(probe_host, probe_port)
    _probe_window.append(probe_latency is None)
    loss_pct = _packet_loss_pct()
    bandwidth = _bandwidth_mbps()
    connectivity = _connectivity(probe_latency)

    log_tail = _tail_new_lines(live_log_file) if live_log_file else ""

    host_event = InternalRawEvent(
        event_time_utc=utc_now_iso(),
        source_timezone=source_timezone,
        real_hostname=socket.gethostname(),
        real_ip=_detect_lan_ip(),
        source_type=SourceType.SERVER,
        upstream_device_real_name="wan-uplink-1.1.1.1",
        metrics=Metrics(
            cpu_pct=round(psutil.cpu_percent(interval=None), 3),
            memory_pct=round(psutil.virtual_memory().percent, 3),
            disk_pct=round(psutil.disk_usage(os.path.abspath(os.sep)).percent, 3),
            service_up=True,
            bandwidth_mbps=bandwidth,
            latency_ms=probe_latency,
            packet_loss_pct=loss_pct,
            connectivity=connectivity,
        ),
        raw_log_line=log_tail or None,
    )

    uplink_event = InternalRawEvent(
        event_time_utc=utc_now_iso(),
        source_timezone=source_timezone,
        real_hostname="wan-uplink-1.1.1.1",
        real_ip=probe_host,
        source_type=SourceType.NETWORK_DEVICE,
        metrics=Metrics(
            bandwidth_mbps=bandwidth,
            latency_ms=probe_latency,
            packet_loss_pct=loss_pct,
            connectivity=connectivity,
        ),
    )
    return host_event, uplink_event


# ---------------------------------------------------------------------------
# External event normalization (single adaptation point)
# ---------------------------------------------------------------------------


def _as_float(value: object) -> Optional[float]:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return None
    return None


def normalize_external_event(raw_obj: dict) -> InternalRawEvent:
    """Defensively map an arbitrary external JSON object to InternalRawEvent.

    Known alias keys are accepted (``ts``/``timestamp`` -> ``event_time_utc``,
    ``host``/``hostname`` -> ``real_hostname``, ``cpu``/``cpu_usage`` ->
    ``metrics.cpu_pct``, ...) and values are clamped into the contract's
    ranges so one weird field can never crash the stream.
    """
    obj = dict(raw_obj) if isinstance(raw_obj, dict) else {}
    canonical_metrics = (
        obj["metrics"] if isinstance(obj.get("metrics"), dict) else {}
    )

    def pick(*keys: str, default: object = None) -> object:
        for source in (obj, canonical_metrics):
            for key in keys:
                if key in source and source[key] is not None:
                    return source[key]
        return default

    def clamped_pct(*keys: str) -> Optional[float]:
        value = _as_float(pick(*keys))
        if value is None:
            return None
        return round(min(100.0, max(0.0, value)), 3)

    def non_negative(*keys: str) -> Optional[float]:
        value = _as_float(pick(*keys))
        if value is None:
            return None
        return round(max(0.0, value), 3)

    source_type = pick("source_type", default=SourceType.SERVER)
    if isinstance(source_type, SourceType):
        resolved_type = source_type
    else:
        try:
            resolved_type = SourceType(str(source_type))
        except ValueError:
            resolved_type = SourceType.SERVER

    connectivity = pick("connectivity", default=None)
    if isinstance(connectivity, ConnectivityState):
        resolved_connectivity = connectivity
    else:
        try:
            resolved_connectivity = (
                ConnectivityState(str(connectivity)) if connectivity else None
            )
        except ValueError:
            resolved_connectivity = None

    service_up = pick("service_up")
    resolved_service_up = service_up if isinstance(service_up, bool) else None

    hostname = pick("real_hostname", "host", "hostname")
    metrics = Metrics(
        cpu_pct=clamped_pct("cpu_pct", "cpu", "cpu_usage"),
        memory_pct=clamped_pct("memory_pct", "mem", "memory"),
        disk_pct=clamped_pct("disk_pct", "disk", "disk_usage"),
        service_up=resolved_service_up,
        bandwidth_mbps=non_negative("bandwidth_mbps", "bandwidth"),
        latency_ms=non_negative("latency_ms", "latency"),
        packet_loss_pct=clamped_pct("packet_loss_pct", "packet_loss"),
        connectivity=resolved_connectivity,
    )
    log_line = pick("raw_log_line", "log", "message")
    event_kwargs = {
        "event_time_utc": str(
            pick("event_time_utc", "timestamp", "ts", default=utc_now_iso())
        ),
        "source_timezone": str(pick("source_timezone", default="Asia/Kolkata")),
        "real_hostname": str(hostname) if hostname else "unknown-host",
        "real_ip": (
            str(pick("real_ip", "ip", "ip_address"))
            if pick("real_ip", "ip", "ip_address")
            else None
        ),
        "source_type": resolved_type,
        "upstream_device_real_name": (
            str(upstream)
            if (upstream := pick("upstream_device_real_name", "upstream_device"))
            else None
        ),
        "metrics": metrics,
        "raw_log_line": str(log_line) if log_line is not None else None,
        "failed_login_event": bool(pick("failed_login_event", default=False)),
        "suspicious_event": bool(pick("suspicious_event", default=False)),
        "forced_payload_id": (
            str(forced) if (forced := pick("forced_payload_id")) else None
        ),
    }
    raw_id = pick("raw_id")
    if raw_id:
        # The frozen contract declares raw_id as a required str: omit the
        # field entirely instead of passing None.
        event_kwargs["raw_id"] = str(raw_id)
    return InternalRawEvent(**event_kwargs)


def _parse_json_event(blob: str) -> Optional[InternalRawEvent]:
    try:
        data = json.loads(blob)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(data, dict):
        return normalize_external_event(data)
    return None


def _coerce_event_dicts(data: object) -> List[dict]:
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict):
        events = data.get("events")
        if isinstance(events, list):
            return [item for item in events if isinstance(item, dict)]
        return [data]
    return []


# ---------------------------------------------------------------------------
# The adapter
# ---------------------------------------------------------------------------


def split_probe_target(target: str, default_port: int = 443) -> Tuple[str, int]:
    """Split ``1.1.1.1:443`` into ``("1.1.1.1", 443)`` with safe fallbacks."""
    target = (target or "").strip()
    if not target:
        return "1.1.1.1", default_port
    host, _, port_part = target.rpartition(":")
    if not host:
        host = target
        port_part = ""
    try:
        return host, int(port_part) if port_part else default_port
    except ValueError:
        return host, default_port


class StreamAdapter:
    """Yields InternalRawEvent objects from one of five pluggable sources."""

    def __init__(
        self,
        mode: str = "live",
        stream_url: str = "",
        probe_host: str = "1.1.1.1",
        probe_port: int = 443,
        interval_sec: float = 1.0,
        live_log_file: Optional[str] = None,
        source_timezone: str = "Asia/Kolkata",
    ) -> None:
        if mode not in VALID_MODES:
            raise ValueError(
                f"unsupported STREAM_MODE {mode!r}; expected one of {VALID_MODES}"
            )
        self.mode = mode
        self.stream_url = stream_url
        self.probe_host = probe_host
        self.probe_port = probe_port
        self.interval_sec = max(0.05, interval_sec)
        self.live_log_file = live_log_file
        self.source_timezone = source_timezone

    @classmethod
    def from_env(cls) -> "StreamAdapter":
        probe_host, probe_port = split_probe_target(
            os.getenv("LIVE_PROBE_HOST", "1.1.1.1:443")
        )
        try:
            interval = float(os.getenv("LIVE_INTERVAL_SEC", "1.0"))
        except ValueError:
            interval = 1.0
        return cls(
            mode=os.getenv("STREAM_MODE", "live").strip().lower(),
            stream_url=os.getenv("STREAM_URL", ""),
            probe_host=probe_host,
            probe_port=probe_port,
            interval_sec=interval,
            live_log_file=os.getenv("LIVE_LOG_FILE") or None,
            source_timezone=os.getenv("SOURCE_TIMEZONE", "Asia/Kolkata"),
        )

    async def events(self) -> AsyncIterator[InternalRawEvent]:
        if self.mode == "live":
            async for event in self._events_live():
                yield event
        elif self.mode == "ws":
            async for event in self._events_ws():
                yield event
        elif self.mode == "sse":
            async for event in self._events_sse():
                yield event
        elif self.mode == "poll":
            async for event in self._events_poll():
                yield event
        else:
            async for event in self._events_file():
                yield event

    # -- live ------------------------------------------------------------------

    async def _events_live(self) -> AsyncIterator[InternalRawEvent]:
        while True:
            try:
                host_event, uplink_event = await collect_live_host_events(
                    self.probe_host,
                    self.probe_port,
                    source_timezone=self.source_timezone,
                    live_log_file=self.live_log_file,
                )
                yield host_event
                yield uplink_event
            except asyncio.CancelledError:
                raise
            except Exception:
                LOGGER.exception("live collection tick failed; retrying")
            await asyncio.sleep(self.interval_sec)

    # -- websocket -------------------------------------------------------------

    async def _events_ws(self) -> AsyncIterator[InternalRawEvent]:
        import websockets  # deferred: only the ws mode needs it

        while True:
            try:
                async with websockets.connect(
                    self.stream_url, open_timeout=5.0
                ) as websocket:
                    async for message in websocket:
                        if isinstance(message, bytes):
                            message = message.decode("utf-8", errors="replace")
                        if not isinstance(message, str):
                            continue
                        try:
                            data = json.loads(message)
                        except (json.JSONDecodeError, ValueError):
                            continue
                        for event_dict in _coerce_event_dicts(data):
                            yield normalize_external_event(event_dict)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOGGER.warning("ws stream %s disconnected (%s); reconnecting",
                               self.stream_url, exc)
            await asyncio.sleep(RECONNECT_DELAY_SEC)

    # -- server-sent events ------------------------------------------------------

    async def _events_sse(self) -> AsyncIterator[InternalRawEvent]:
        while True:
            try:
                async with httpx.AsyncClient(timeout=None) as client:
                    async with client.stream(
                        "GET",
                        self.stream_url,
                        headers={"Accept": "text/event-stream"},
                    ) as response:
                        response.raise_for_status()
                        data_lines: List[str] = []
                        async for raw_line in response.aitalines():
                            line = raw_line.rstrip("\r\n")
                            if line.startswith("data:"):
                                data_lines.append(line[len("data:"):].strip())
                            elif not line.strip() and data_lines:
                                blob = "\n".join(data_lines)
                                data_lines = []
                                event = _parse_json_event(blob)
                                if event is not None:
                                    yield event
                        if data_lines:
                            event = _parse_json_event("\n".join(data_lines))
                            if event is not None:
                                yield event
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOGGER.warning("sse stream %s dropped (%s); reconnecting",
                               self.stream_url, exc)
            await asyncio.sleep(RECONNECT_DELAY_SEC)

    # -- http poll ----------------------------------------------------------------

    async def _events_poll(self) -> AsyncIterator[InternalRawEvent]:
        async with httpx.AsyncClient(timeout=5.0) as client:
            while True:
                try:
                    response = await client.get(self.stream_url)
                    response.raise_for_status()
                    for event_dict in _coerce_event_dicts(response.json()):
                        yield normalize_external_event(event_dict)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    LOGGER.warning("poll %s failed (%s)", self.stream_url, exc)
                await asyncio.sleep(max(0.1, self.interval_sec))

    # -- file tail -----------------------------------------------------------------

    async def _events_file(self) -> AsyncIterator[InternalRawEvent]:
        path = self.stream_url
        offset = 0
        while True:
            try:
                size = os.path.getsize(path)
                if size < offset:  # rotated or truncated: start over
                    offset = 0
                if size > offset:
                    with open(path, "r", encoding="utf-8", errors="replace") as handle:
                        handle.seek(offset)
                        chunk = handle.read()
                        offset = handle.tell()
                    for line in chunk.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        event = _parse_json_event(line)
                        if event is None:
                            event = normalize_external_event({"message": line})
                        yield event
            except asyncio.CancelledError:
                raise
            except OSError:
                pass  # file not created yet; keep waiting
            await asyncio.sleep(max(0.1, self.interval_sec))
