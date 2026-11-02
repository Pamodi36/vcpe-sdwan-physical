from __future__ import annotations

import logging

from .models import FlowMonitoringRequest, MetricSample, TunnelMonitoringRequest
from .settings import Settings

LOG = logging.getLogger(__name__)


class InfluxWriter:
    """Writes the legacy Agent contract plus optional numeric extension fields."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.enabled = bool(
            settings.influx_enabled
            and settings.influx_url
            and settings.influx_org
            and settings.influx_bucket
            and settings.influx_token
        )
        self._client = None
        self._write_api = None
        if not self.enabled:
            LOG.warning("InfluxDB writer disabled or incomplete configuration")
            return

        from influxdb_client import InfluxDBClient
        from influxdb_client.client.write_api import SYNCHRONOUS

        self._client = InfluxDBClient(
            url=settings.influx_url,
            token=settings.influx_token,
            org=settings.influx_org,
        )
        self._write_api = self._client.write_api(write_options=SYNCHRONOUS)

    def close(self) -> None:
        if self._client is not None:
            self._client.close()

    def ping(self) -> bool | None:
        if not self.enabled or self._client is None:
            return None
        try:
            return bool(self._client.ping())
        except Exception:
            LOG.exception("InfluxDB ping failed")
            return False

    def write_flow(self, request: FlowMonitoringRequest, sample: MetricSample) -> bool:
        return self._write_or_log(
            "sdwan_flow_metrics",
            {"flow_id": request.flow_id, "wan_link": request.wan_link},
            sample,
        )

    def write_tunnel(self, request: TunnelMonitoringRequest, sample: MetricSample) -> bool:
        return self._write_or_log(
            "sdwan_tunnel_metrics",
            {"tunnel_id": request.tunnel_id},
            sample,
        )

    def _write_or_log(self, measurement: str, tags: dict[str, str], sample: MetricSample) -> bool:
        if not self.enabled:
            LOG.info("Influx disabled: %s tags=%s sample=%s", measurement, tags, sample.model_dump(mode="json"))
            return False
        return self._write_point(measurement, tags, sample)

    def _write_point(self, measurement: str, tags: dict[str, str], sample: MetricSample) -> bool:
        if not sample.has_any_metric():
            LOG.warning("Skipping empty metric sample for %s", measurement)
            return False

        from influxdb_client import Point, WritePrecision

        point = Point(measurement)
        for key, value in tags.items():
            point = point.tag(key, str(value))

        numeric_fields = (
            # Legacy contract - DO NOT RENAME.
            "latency_ms", "jitter_ms", "loss_percent", "available_bandwidth_kbps",
            # Extensions.
            "forward_delay_ms", "reverse_delay_ms", "rtt_ms",
            "forward_jitter_ms", "reverse_jitter_ms",
            "round_trip_loss_percent", "forward_loss_percent", "reverse_loss_percent",
            "passive_tcp_packets", "passive_tcp_data_segments", "passive_retransmissions",
            "passive_retransmission_percent", "passive_rtt_ms",
            "active_probe_count", "received_probe_count",
        )
        for field_name in numeric_fields:
            value = getattr(sample, field_name)
            if value is not None:
                point = point.field(field_name, float(value))

        if sample.clock_synchronized is not None:
            point = point.field("clock_synchronized", bool(sample.clock_synchronized))
        if sample.measurement_state:
            point = point.tag("measurement_state", sample.measurement_state)
        if sample.metric_source:
            point = point.tag("metric_source", sample.metric_source)

        point = point.time(sample.timestamp, WritePrecision.NS)
        self._write_api.write(
            bucket=self.settings.influx_bucket,
            org=self.settings.influx_org,
            record=point,
        )
        return True
