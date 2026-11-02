from __future__ import annotations

import json
import os
from dataclasses import dataclass, field


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    return int(raw) if raw not in (None, "") else default


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    return float(raw) if raw not in (None, "") else default


def _load_wan_map(raw: str | None) -> dict[str, str]:
    if not raw:
        return {}
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError("WAN_LINK_MAP_JSON must be a JSON object")
    result: dict[str, str] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise ValueError("WAN_LINK_MAP_JSON keys and values must be strings")
        result[key] = item
    return result


@dataclass(slots=True)
class Settings:
    api_bind: str = "0.0.0.0"
    api_port: int = 9100

    influx_url: str = "http://127.0.0.1:8086"
    influx_org: str = "thesis"
    influx_bucket: str = "vcpe"
    influx_token: str = ""
    influx_enabled: bool = True

    wan_link_map: dict[str, str] = field(default_factory=dict)

    # STAMP / RFC 8762 base unauthenticated mode.
    stamp_enabled: bool = True
    stamp_port: int = 862
    stamp_reply_wait_ms: int = 1000
    stamp_clock_sync_check: bool = True
    stamp_assume_clock_synced: bool = False
    stamp_error_scale: int = 10
    stamp_error_multiplier: int = 4

    # Passive TCP observation.
    passive_enabled: bool = True
    passive_max_events: int = 100_000

    # iperf3 bandwidth measurement. The local server is optional but convenient in
    # a two-CPE lab because every peer automatically exposes a measurement endpoint.
    iperf_port: int = 5201
    iperf_duration_sec: int = 3
    iperf_process_timeout_sec: float = 12.0
    iperf_bind_device: bool = True
    iperf_parallel_streams: int = 1
    iperf_server_enabled: bool = True
    iperf_server_port: int = 5201
    iperf_server_bind: str = "0.0.0.0"

    run_probe_immediately: bool = True
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            api_bind=os.getenv("API_BIND", "0.0.0.0"),
            api_port=_env_int("API_PORT", 9100),
            influx_url=os.getenv("INFLUX_URL", "http://127.0.0.1:8086"),
            influx_org=os.getenv("INFLUX_ORG", "thesis"),
            influx_bucket=os.getenv("INFLUX_BUCKET", "vcpe"),
            influx_token=os.getenv("INFLUX_TOKEN", ""),
            influx_enabled=_env_bool("INFLUX_ENABLED", True),
            wan_link_map=_load_wan_map(os.getenv("WAN_LINK_MAP_JSON")),
            stamp_enabled=_env_bool("STAMP_ENABLED", True),
            stamp_port=_env_int("STAMP_PORT", 862),
            stamp_reply_wait_ms=_env_int("STAMP_REPLY_WAIT_MS", 1000),
            stamp_clock_sync_check=_env_bool("STAMP_CLOCK_SYNC_CHECK", True),
            stamp_assume_clock_synced=_env_bool("STAMP_ASSUME_CLOCK_SYNCED", False),
            stamp_error_scale=_env_int("STAMP_ERROR_SCALE", 10),
            stamp_error_multiplier=_env_int("STAMP_ERROR_MULTIPLIER", 4),
            passive_enabled=_env_bool("PASSIVE_ENABLED", True),
            passive_max_events=_env_int("PASSIVE_MAX_EVENTS", 100_000),
            iperf_port=_env_int("IPERF_PORT", 5201),
            iperf_duration_sec=_env_int("IPERF_DURATION_SEC", 3),
            iperf_process_timeout_sec=_env_float("IPERF_PROCESS_TIMEOUT_SEC", 12.0),
            iperf_bind_device=_env_bool("IPERF_BIND_DEVICE", True),
            iperf_parallel_streams=_env_int("IPERF_PARALLEL_STREAMS", 1),
            iperf_server_enabled=_env_bool("IPERF_SERVER_ENABLED", True),
            iperf_server_port=_env_int("IPERF_SERVER_PORT", 5201),
            iperf_server_bind=os.getenv("IPERF_SERVER_BIND", "0.0.0.0"),
            run_probe_immediately=_env_bool("RUN_PROBE_IMMEDIATELY", True),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
        )
