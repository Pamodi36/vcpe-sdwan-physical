from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Literal

from .clock_sync import ClockSyncChecker
from .influx import InfluxWriter
from .interface_resolver import InterfaceResolver
from .models import (
    FlowMonitoringRequest,
    JobView,
    MetricSample,
    PassiveSnapshot,
    TunnelMonitoringRequest,
)
from .passive_tcp import PassiveManager
from .probes import run_iperf3
from .rule_engine import RuleEngine
from .settings import Settings
from .stamp import run_stamp

LOG = logging.getLogger(__name__)


@dataclass(slots=True)
class JobHandle:
    job_type: Literal["flow", "tunnel"]
    key: str
    interface: str
    request: FlowMonitoringRequest | TunnelMonitoringRequest
    task: asyncio.Task
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    run_count: int = 0
    last_error: str | None = None
    last_sample: MetricSample | None = None
    last_passive: PassiveSnapshot | None = None
    state: str = "starting"
    last_compliance_mono: float | None = None
    last_bandwidth_mono: float | None = None


class JobManager:
    def __init__(
        self,
        settings: Settings,
        resolver: InterfaceResolver,
        writer: InfluxWriter,
        passive: PassiveManager,
        clock_checker: ClockSyncChecker,
    ) -> None:
        self.settings = settings
        self.resolver = resolver
        self.writer = writer
        self.passive = passive
        self.clock_checker = clock_checker
        self.rule_engine = RuleEngine()
        self._jobs: dict[str, JobHandle] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def flow_key(flow_id: str, wan_link: str) -> str:
        return f"flow:{flow_id}:{wan_link}"

    @staticmethod
    def tunnel_key(tunnel_id: str) -> str:
        return f"tunnel:{tunnel_id}"

    async def start_flow(self, request: FlowMonitoringRequest) -> tuple[JobHandle, bool]:
        interface = self.resolver.resolve_wan(request.wan_link)
        key = self.flow_key(request.flow_id, request.wan_link)
        updated = await self._stop_key(key, missing_ok=True)
        self.passive.ensure(interface)
        task = asyncio.create_task(self._flow_worker(key, request, interface), name=f"monitor-{key}")
        handle = JobHandle("flow", key, interface, request, task)
        async with self._lock:
            self._jobs[key] = handle
        return handle, updated

    async def start_tunnel(self, request: TunnelMonitoringRequest) -> tuple[JobHandle, bool]:
        interface = self.resolver.resolve_tunnel(request.tunnel_id)
        key = self.tunnel_key(request.tunnel_id)
        updated = await self._stop_key(key, missing_ok=True)
        self.passive.ensure(interface)
        task = asyncio.create_task(self._tunnel_worker(key, request, interface), name=f"monitor-{key}")
        handle = JobHandle("tunnel", key, interface, request, task)
        async with self._lock:
            self._jobs[key] = handle
        return handle, updated

    async def stop_flow(self, flow_id: str, wan_link: str) -> bool:
        return await self._stop_key(self.flow_key(flow_id, wan_link), missing_ok=False)

    async def stop_tunnel(self, tunnel_id: str) -> bool:
        return await self._stop_key(self.tunnel_key(tunnel_id), missing_ok=False)

    async def _stop_key(self, key: str, *, missing_ok: bool) -> bool:
        async with self._lock:
            handle = self._jobs.pop(key, None)
        if handle is None:
            if missing_ok:
                return False
            raise KeyError(key)
        handle.task.cancel()
        try:
            await handle.task
        except asyncio.CancelledError:
            pass
        except Exception:
            LOG.exception("Monitoring job %s failed during cancellation", key)
        return True

    async def stop_all(self) -> None:
        async with self._lock:
            keys = list(self._jobs)
        for key in keys:
            await self._stop_key(key, missing_ok=True)

    async def list_jobs(self) -> list[JobView]:
        async with self._lock:
            handles = list(self._jobs.values())
        return [self._view(handle) for handle in handles]

    async def counts(self) -> dict[str, int]:
        async with self._lock:
            handles = list(self._jobs.values())
        return {
            "total": len(handles),
            "flows": sum(handle.job_type == "flow" for handle in handles),
            "tunnels": sum(handle.job_type == "tunnel" for handle in handles),
        }

    def _view(self, handle: JobHandle) -> JobView:
        return JobView(
            job_type=handle.job_type,
            job_key=handle.key,
            interface=handle.interface,
            destination_ip=handle.request.destination_ip,
            bandwidth_destination_ip=handle.request.bandwidth_destination_ip,
            probe_tools=list(handle.request.probe_tools),
            interval_sec=handle.request.interval_sec,
            state=handle.state,
            started_at=handle.started_at,
            run_count=handle.run_count,
            last_error=handle.last_error,
            last_sample=handle.last_sample,
            last_passive=handle.last_passive,
        )

    async def _flow_worker(self, key: str, request: FlowMonitoringRequest, interface: str) -> None:
        if not self.settings.run_probe_immediately:
            await asyncio.sleep(request.interval_sec)
        while True:
            await self._run_once(key, request, interface, is_flow=True)
            await asyncio.sleep(request.interval_sec)

    async def _tunnel_worker(self, key: str, request: TunnelMonitoringRequest, interface: str) -> None:
        if not self.settings.run_probe_immediately:
            await asyncio.sleep(request.interval_sec)
        while True:
            await self._run_once(key, request, interface, is_flow=False)
            await asyncio.sleep(request.interval_sec)

    async def _run_once(
        self,
        key: str,
        request: FlowMonitoringRequest | TunnelMonitoringRequest,
        interface: str,
        *,
        is_flow: bool,
    ) -> None:
        async with self._lock:
            handle = self._jobs.get(key)
            if handle is None:
                return
            last_sample = handle.last_sample
            last_compliance = handle.last_compliance_mono
            last_bandwidth = handle.last_bandwidth_mono

        flow_filter = request.flow_filter if isinstance(request, FlowMonitoringRequest) else None
        passive = await asyncio.to_thread(
            self.passive.snapshot,
            interface,
            request.adaptive.passive_window_sec,
            flow_filter,
        )

        now_mono = time.monotonic()
        decision = self.rule_engine.decide(
            passive=passive,
            last_sample=last_sample,
            slo=request.slo,
            policy=request.adaptive,
            seconds_since_compliance=None if last_compliance is None else now_mono - last_compliance,
            seconds_since_bandwidth=None if last_bandwidth is None else now_mono - last_bandwidth,
            iperf_requested="iperf3" in request.probe_tools,
        )

        sample = MetricSample(
            measurement_state=decision.state,
            passive_tcp_packets=passive.tcp_packets,
            passive_tcp_data_segments=passive.tcp_data_segments,
            passive_retransmissions=passive.retransmissions,
            passive_retransmission_percent=passive.retransmission_percent,
            passive_rtt_ms=passive.passive_rtt_ms,
        )
        errors: list[str] = []
        sources: list[str] = []

        if "stamp" in request.probe_tools and self.settings.stamp_enabled:
            stamp_result = await run_stamp(
                request.destination_ip,
                interface,
                settings=self.settings,
                clock_checker=self.clock_checker,
                count=decision.probe_count,
                spacing_ms=decision.spacing_ms,
            )
            _apply_stamp(sample, stamp_result)
            sources.append("stamp")
            if stamp_result.error:
                errors.append(f"stamp: {stamp_result.error}")

        # Bandwidth is sampled independently and less frequently than STAMP.
        if decision.run_bandwidth:
            target = request.bandwidth_destination_ip or request.destination_ip
            try:
                source_ip = await self.resolver.get_ipv4_address(interface)
                iperf_result = await run_iperf3(
                    target,
                    interface,
                    source_ip,
                    port=self.settings.iperf_port,
                    duration_sec=self.settings.iperf_duration_sec,
                    timeout_sec=self.settings.iperf_process_timeout_sec,
                    bind_device=self.settings.iperf_bind_device,
                    parallel_streams=self.settings.iperf_parallel_streams,
                )
                sample.available_bandwidth_kbps = iperf_result.available_bandwidth_kbps
                sources.append("iperf3")
                if iperf_result.error:
                    errors.append(f"iperf3: {iperf_result.error}")
            except Exception as exc:
                errors.append(f"iperf3: {exc}")

        # Passive RTT is an operational fallback. TCP retransmissions are not converted
        # into formal packet loss; STAMP remains the active loss measurement source.
        if sample.latency_ms is None and passive.passive_rtt_ms is not None:
            sample.latency_ms = passive.passive_rtt_ms
            sources.append("passive-tcp")

        sample.metric_source = "+".join(dict.fromkeys(sources)) or "passive-tcp"

        if is_flow:
            write: Callable[[], bool] = lambda: self.writer.write_flow(request, sample)  # type: ignore[arg-type]
        else:
            write = lambda: self.writer.write_tunnel(request, sample)  # type: ignore[arg-type]

        await self._finalize_run(key, sample, passive, errors, write=write)

        async with self._lock:
            handle = self._jobs.get(key)
            if handle is not None:
                handle.state = decision.state
                if decision.state in {"VERIFY", "CRITICAL"}:
                    handle.last_compliance_mono = time.monotonic()
                if decision.run_bandwidth:
                    handle.last_bandwidth_mono = time.monotonic()

    async def _finalize_run(
        self,
        key: str,
        sample: MetricSample,
        passive: PassiveSnapshot,
        errors: list[str],
        *,
        write: Callable[[], bool],
    ) -> None:
        if sample.has_any_metric():
            try:
                await asyncio.to_thread(write)
            except Exception as exc:
                LOG.exception("InfluxDB write failed for %s", key)
                errors.append(f"influx: {exc}")
        else:
            errors.append("no metrics produced")

        async with self._lock:
            handle = self._jobs.get(key)
            if handle is not None:
                handle.run_count += 1
                handle.last_sample = sample
                handle.last_passive = passive
                handle.last_error = "; ".join(errors) if errors else None

        if errors:
            LOG.warning("Monitoring job %s completed with issues: %s", key, "; ".join(errors))
        else:
            LOG.info("Monitoring job %s wrote sample %s", key, sample.model_dump(mode="json"))


def _apply_stamp(sample: MetricSample, result) -> None:
    sample.latency_ms = result.latency_ms
    sample.jitter_ms = result.jitter_ms
    sample.loss_percent = result.loss_percent
    sample.forward_delay_ms = result.forward_delay_ms
    sample.reverse_delay_ms = result.reverse_delay_ms
    sample.rtt_ms = result.rtt_ms
    sample.forward_jitter_ms = result.forward_jitter_ms
    sample.reverse_jitter_ms = result.reverse_jitter_ms
    sample.round_trip_loss_percent = result.round_trip_loss_percent
    sample.forward_loss_percent = result.forward_loss_percent
    sample.reverse_loss_percent = result.reverse_loss_percent
    sample.active_probe_count = result.sent
    sample.received_probe_count = result.received
    sample.clock_synchronized = result.clock_synchronized
