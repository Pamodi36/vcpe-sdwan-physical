from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, field_validator


ProbeTool = Literal["passive", "stamp", "iperf3"]


class FlowFilter(BaseModel):
    src_prefix: str | None = None
    dst_prefix: str | None = None
    protocol: Literal["tcp", "udp", "any"] = "tcp"
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)

    @field_validator("src_prefix", "dst_prefix")
    @classmethod
    def validate_prefix(cls, value: str | None) -> str | None:
        if value in (None, "", "any"):
            return None
        ipaddress.ip_network(value, strict=False)
        return value


class SLOPolicy(BaseModel):
    max_latency_ms: float | None = Field(default=None, ge=0)
    max_jitter_ms: float | None = Field(default=None, ge=0)
    max_loss_percent: float | None = Field(default=None, ge=0, le=100)
    min_bandwidth_kbps: float | None = Field(default=None, ge=0)


class AdaptivePolicy(BaseModel):
    enabled: bool = True
    passive_window_sec: int = Field(default=10, ge=1, le=600)
    passive_min_tcp_packets: int = Field(default=200, ge=0, le=1_000_000)
    warning_ratio: float = Field(default=0.80, gt=0, le=1)

    stable_probe_count: int = Field(default=10, ge=1, le=100_000)
    stable_probe_spacing_ms: float = Field(default=200.0, ge=0.1, le=60_000)
    low_traffic_probe_count: int = Field(default=50, ge=1, le=100_000)
    low_traffic_probe_spacing_ms: float = Field(default=100.0, ge=0.1, le=60_000)
    warning_probe_count: int = Field(default=200, ge=1, le=100_000)
    warning_probe_spacing_ms: float = Field(default=20.0, ge=0.1, le=60_000)

    # Low-loss verification window. 2000 probes over 10 s gives 0.05 percentage-point
    # granularity and can verify an SLO such as loss < 0.5% with much better resolution
    # than one sparse probe every few seconds.
    compliance_probe_count: int = Field(default=2000, ge=10, le=100_000)
    compliance_window_sec: float = Field(default=10.0, ge=0.1, le=600)
    compliance_interval_sec: int = Field(default=10, ge=1, le=86_400)

    passive_retrans_warning_percent: float = Field(default=1.0, ge=0, le=100)

    # iperf3 is intentionally sampled less frequently because it creates a much heavier
    # active load than STAMP. The interval can be reduced while the path is degraded.
    bandwidth_interval_sec: int = Field(default=60, ge=1, le=86_400)
    bandwidth_warning_interval_sec: int = Field(default=30, ge=1, le=86_400)
    bandwidth_critical_interval_sec: int = Field(default=10, ge=1, le=86_400)


class FlowMonitoringRequest(BaseModel):
    flow_id: str = Field(min_length=1, max_length=128)
    wan_link: str = Field(min_length=1, max_length=128)
    destination_ip: str
    # Optional dedicated measurement node for iperf3. This is useful when the user/app
    # destination does not run an iperf3 server.
    bandwidth_destination_ip: str | None = None
    probe_tools: list[ProbeTool] = Field(default_factory=lambda: ["passive", "stamp"])
    interval_sec: int = Field(default=5, ge=1, le=86400)
    flow_filter: FlowFilter | None = None
    slo: SLOPolicy = Field(default_factory=SLOPolicy)
    adaptive: AdaptivePolicy = Field(default_factory=AdaptivePolicy)

    @field_validator("destination_ip", "bandwidth_destination_ip")
    @classmethod
    def validate_destination_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        ipaddress.ip_address(value)
        return value

    @field_validator("probe_tools")
    @classmethod
    def deduplicate_probe_tools(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(value))


class TunnelMonitoringRequest(BaseModel):
    tunnel_id: str = Field(min_length=1, max_length=128)
    destination_ip: str
    bandwidth_destination_ip: str | None = None
    probe_tools: list[ProbeTool] = Field(default_factory=lambda: ["passive", "stamp", "iperf3"])
    interval_sec: int = Field(default=5, ge=1, le=86400)
    slo: SLOPolicy = Field(default_factory=SLOPolicy)
    adaptive: AdaptivePolicy = Field(default_factory=AdaptivePolicy)

    @field_validator("destination_ip", "bandwidth_destination_ip")
    @classmethod
    def validate_destination_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        ipaddress.ip_address(value)
        return value

    @field_validator("probe_tools")
    @classmethod
    def deduplicate_probe_tools(cls, value: list[str]) -> list[str]:
        return list(dict.fromkeys(value))


class PassiveSnapshot(BaseModel):
    tcp_packets: int = 0
    tcp_data_segments: int = 0
    retransmissions: int = 0
    retransmission_percent: float | None = None
    passive_rtt_ms: float | None = None


class MetricSample(BaseModel):
    # Legacy contract consumed by the existing Agent MetricReader. DO NOT RENAME.
    latency_ms: float | None = None
    jitter_ms: float | None = None
    loss_percent: float | None = None
    available_bandwidth_kbps: float | None = None

    # Additional observability fields. Existing MetricReader can ignore them.
    forward_delay_ms: float | None = None
    reverse_delay_ms: float | None = None
    rtt_ms: float | None = None
    forward_jitter_ms: float | None = None
    reverse_jitter_ms: float | None = None
    round_trip_loss_percent: float | None = None
    forward_loss_percent: float | None = None
    reverse_loss_percent: float | None = None

    passive_tcp_packets: int | None = None
    passive_tcp_data_segments: int | None = None
    passive_retransmissions: int | None = None
    passive_retransmission_percent: float | None = None
    passive_rtt_ms: float | None = None

    active_probe_count: int | None = None
    received_probe_count: int | None = None
    clock_synchronized: bool | None = None
    measurement_state: str | None = None
    metric_source: str | None = None

    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def has_any_metric(self) -> bool:
        return any(
            value is not None
            for value in (
                self.latency_ms,
                self.jitter_ms,
                self.loss_percent,
                self.available_bandwidth_kbps,
                self.forward_delay_ms,
                self.reverse_delay_ms,
                self.rtt_ms,
                self.passive_retransmission_percent,
            )
        )


class JobResponse(BaseModel):
    status: Literal["running", "stopped"]
    job_type: Literal["flow", "tunnel"]
    job_key: str
    interface: str | None = None
    updated: bool | None = None


class JobView(BaseModel):
    job_type: Literal["flow", "tunnel"]
    job_key: str
    interface: str
    destination_ip: str
    bandwidth_destination_ip: str | None = None
    probe_tools: list[str]
    interval_sec: int
    state: str = "starting"
    started_at: datetime
    run_count: int = 0
    last_error: str | None = None
    last_sample: MetricSample | None = None
    last_passive: PassiveSnapshot | None = None
