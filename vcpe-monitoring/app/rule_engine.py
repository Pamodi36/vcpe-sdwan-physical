from __future__ import annotations

from dataclasses import dataclass

from .models import AdaptivePolicy, MetricSample, PassiveSnapshot, SLOPolicy


@dataclass(slots=True)
class ProbeDecision:
    state: str
    probe_count: int
    spacing_ms: float
    run_bandwidth: bool
    reason: str


class RuleEngine:
    """Deterministic hybrid passive + STAMP + iperf3 policy."""

    def decide(
        self,
        *,
        passive: PassiveSnapshot,
        last_sample: MetricSample | None,
        slo: SLOPolicy,
        policy: AdaptivePolicy,
        seconds_since_compliance: float | None,
        seconds_since_bandwidth: float | None,
        iperf_requested: bool,
    ) -> ProbeDecision:
        violated = _violates(last_sample, slo)
        near = _near_threshold(last_sample, slo, policy.warning_ratio)
        passive_warn = (
            passive.retransmission_percent is not None
            and passive.retransmission_percent >= policy.passive_retrans_warning_percent
        )
        insufficient = passive.tcp_packets < policy.passive_min_tcp_packets
        low_loss_slo = slo.max_loss_percent is not None and slo.max_loss_percent <= 0.5
        compliance_due = low_loss_slo and _due(seconds_since_compliance, policy.compliance_interval_sec)

        if not policy.enabled:
            return ProbeDecision(
                state="FIXED",
                probe_count=policy.stable_probe_count,
                spacing_ms=policy.stable_probe_spacing_ms,
                run_bandwidth=iperf_requested and _due(seconds_since_bandwidth, policy.bandwidth_interval_sec),
                reason="adaptive probing disabled",
            )

        if violated or passive_warn:
            spacing = 1000.0 * policy.compliance_window_sec / policy.compliance_probe_count
            return ProbeDecision(
                state="CRITICAL",
                probe_count=policy.compliance_probe_count,
                spacing_ms=spacing,
                run_bandwidth=iperf_requested and _due(
                    seconds_since_bandwidth, policy.bandwidth_critical_interval_sec
                ),
                reason="SLO violation or strong passive retransmission signal; verify with a paced STAMP window",
            )

        if compliance_due:
            spacing = 1000.0 * policy.compliance_window_sec / policy.compliance_probe_count
            return ProbeDecision(
                state="VERIFY",
                probe_count=policy.compliance_probe_count,
                spacing_ms=spacing,
                run_bandwidth=iperf_requested and _due(
                    seconds_since_bandwidth, policy.bandwidth_warning_interval_sec
                ),
                reason="periodic low-loss SLO compliance window",
            )

        if near:
            return ProbeDecision(
                state="WARNING",
                probe_count=policy.warning_probe_count,
                spacing_ms=policy.warning_probe_spacing_ms,
                run_bandwidth=iperf_requested and _due(
                    seconds_since_bandwidth, policy.bandwidth_warning_interval_sec
                ),
                reason="metric is approaching an SLO threshold",
            )

        if insufficient:
            return ProbeDecision(
                state="LOW_TRAFFIC",
                probe_count=policy.low_traffic_probe_count,
                spacing_ms=policy.low_traffic_probe_spacing_ms,
                run_bandwidth=iperf_requested and _due(
                    seconds_since_bandwidth, policy.bandwidth_interval_sec
                ),
                reason="passive sample is insufficient; active STAMP probes fill the measurement gap",
            )

        return ProbeDecision(
            state="STABLE",
            probe_count=policy.stable_probe_count,
            spacing_ms=policy.stable_probe_spacing_ms,
            run_bandwidth=iperf_requested and _due(
                seconds_since_bandwidth, policy.bandwidth_interval_sec
            ),
            reason="passive sample is sufficient and metrics are comfortably within SLO",
        )


def _due(age: float | None, interval: float) -> bool:
    return age is None or age >= interval


def _violates(sample: MetricSample | None, slo: SLOPolicy) -> bool:
    if sample is None:
        return False
    if slo.max_latency_ms is not None and sample.latency_ms is not None and sample.latency_ms > slo.max_latency_ms:
        return True
    if slo.max_jitter_ms is not None and sample.jitter_ms is not None and sample.jitter_ms > slo.max_jitter_ms:
        return True
    if slo.max_loss_percent is not None and sample.loss_percent is not None and sample.loss_percent > slo.max_loss_percent:
        return True
    if (
        slo.min_bandwidth_kbps is not None
        and sample.available_bandwidth_kbps is not None
        and sample.available_bandwidth_kbps < slo.min_bandwidth_kbps
    ):
        return True
    return False


def _near_threshold(sample: MetricSample | None, slo: SLOPolicy, ratio: float) -> bool:
    if sample is None:
        return False
    if slo.max_latency_ms is not None and sample.latency_ms is not None and sample.latency_ms >= ratio * slo.max_latency_ms:
        return True
    if slo.max_jitter_ms is not None and sample.jitter_ms is not None and sample.jitter_ms >= ratio * slo.max_jitter_ms:
        return True
    if slo.max_loss_percent is not None and sample.loss_percent is not None and sample.loss_percent >= ratio * slo.max_loss_percent:
        return True
    if (
        slo.min_bandwidth_kbps is not None
        and sample.available_bandwidth_kbps is not None
        and sample.available_bandwidth_kbps <= slo.min_bandwidth_kbps / ratio
    ):
        return True
    return False
