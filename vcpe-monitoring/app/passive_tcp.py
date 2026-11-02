from __future__ import annotations

import ipaddress
import logging
import threading
import time
from collections import deque
from dataclasses import dataclass
from statistics import median

from scapy.all import AsyncSniffer, IP, IPv6, TCP  # type: ignore

from .models import FlowFilter, PassiveSnapshot

LOG = logging.getLogger(__name__)


@dataclass(slots=True)
class TcpEvent:
    ts: float
    src: str
    dst: str
    sport: int
    dport: int
    payload_len: int
    retransmission: bool
    rtt_ms: float | None = None


class PassiveTcpObserver:
    """Interface-scoped TCP observer used as a low-overhead measurement signal.

    Retransmissions are a diagnostic signal, not a formal one-way packet-loss
    measurement. STAMP remains the authoritative active measurement source.
    """

    def __init__(self, interface: str, max_events: int = 100_000) -> None:
        self.interface = interface
        self.events: deque[TcpEvent] = deque(maxlen=max_events)
        self._seen_segments: dict[tuple, float] = {}
        self._outstanding: dict[tuple, float] = {}
        self._lock = threading.Lock()
        self._sniffer = AsyncSniffer(
            iface=interface,
            filter="tcp",
            store=False,
            promisc=False,
            prn=self._on_packet,
        )

    def start(self) -> None:
        self._sniffer.start()
        LOG.info("Passive TCP observer started on %s", self.interface)

    def stop(self) -> None:
        try:
            if self._sniffer.running:
                self._sniffer.stop()
        except Exception:
            LOG.debug("Passive sniffer stop failed on %s", self.interface, exc_info=True)

    def _on_packet(self, packet) -> None:
        try:
            if TCP not in packet:
                return
            if IP in packet:
                src, dst = packet[IP].src, packet[IP].dst
            elif IPv6 in packet:
                src, dst = packet[IPv6].src, packet[IPv6].dst
            else:
                return

            tcp = packet[TCP]
            now = float(packet.time) if getattr(packet, "time", None) is not None else time.time()
            payload_len = len(bytes(tcp.payload))
            seq = int(tcp.seq)
            ack = int(tcp.ack)
            sport, dport = int(tcp.sport), int(tcp.dport)
            flow = (src, sport, dst, dport)
            reverse = (dst, dport, src, sport)

            retransmission = False
            rtt_ms: float | None = None

            with self._lock:
                self._prune_state(now)

                if payload_len > 0:
                    seg_key = (flow, seq, payload_len)
                    previous = self._seen_segments.get(seg_key)
                    retransmission = previous is not None and now - previous <= 120.0
                    self._seen_segments[seg_key] = now
                    end_seq = (seq + payload_len) & 0xFFFFFFFF
                    self._outstanding[(flow, end_seq)] = now

                if ack > 0:
                    candidates = [
                        (key, sent_ts)
                        for key, sent_ts in self._outstanding.items()
                        if key[0] == reverse and _seq_leq(key[1], ack)
                    ]
                    if candidates:
                        key, sent_ts = max(candidates, key=lambda item: item[0][1])
                        rtt_ms = max(0.0, (now - sent_ts) * 1000.0)
                        for old_key, _ in candidates:
                            self._outstanding.pop(old_key, None)

                self.events.append(
                    TcpEvent(now, src, dst, sport, dport, payload_len, retransmission, rtt_ms)
                )
        except Exception:
            LOG.debug("Passive packet processing failed on %s", self.interface, exc_info=True)

    def _prune_state(self, now: float) -> None:
        cutoff = now - 120.0
        if len(self._seen_segments) > 50_000:
            self._seen_segments = {k: v for k, v in self._seen_segments.items() if v >= cutoff}
        if len(self._outstanding) > 50_000:
            self._outstanding = {k: v for k, v in self._outstanding.items() if v >= cutoff}

    def snapshot(self, window_sec: int, flow_filter: FlowFilter | None = None) -> PassiveSnapshot:
        cutoff = time.time() - window_sec
        with self._lock:
            items = [event for event in self.events if event.ts >= cutoff and _matches(event, flow_filter)]

        packets = len(items)
        data_segments = sum(event.payload_len > 0 for event in items)
        retransmissions = sum(event.retransmission for event in items if event.payload_len > 0)
        retrans_pct = (
            100.0 * retransmissions / data_segments
            if data_segments > 0
            else None
        )
        rtts = [event.rtt_ms for event in items if event.rtt_ms is not None and event.rtt_ms < 60_000]
        return PassiveSnapshot(
            tcp_packets=packets,
            tcp_data_segments=data_segments,
            retransmissions=retransmissions,
            retransmission_percent=round(retrans_pct, 4) if retrans_pct is not None else None,
            passive_rtt_ms=round(float(median(rtts)), 3) if rtts else None,
        )


class PassiveManager:
    def __init__(self, *, enabled: bool, max_events: int) -> None:
        self.enabled = enabled
        self.max_events = max_events
        self._observers: dict[str, PassiveTcpObserver] = {}
        self._lock = threading.Lock()

    def ensure(self, interface: str) -> None:
        if not self.enabled:
            return
        with self._lock:
            if interface in self._observers:
                return
            observer = PassiveTcpObserver(interface, self.max_events)
            observer.start()
            self._observers[interface] = observer

    def snapshot(self, interface: str, window_sec: int, flow_filter: FlowFilter | None = None) -> PassiveSnapshot:
        if not self.enabled:
            return PassiveSnapshot()
        self.ensure(interface)
        return self._observers[interface].snapshot(window_sec, flow_filter)

    def stop_all(self) -> None:
        with self._lock:
            observers = list(self._observers.values())
            self._observers.clear()
        for observer in observers:
            observer.stop()


def _matches(event: TcpEvent, flow_filter: FlowFilter | None) -> bool:
    if flow_filter is None:
        return True
    if flow_filter.protocol not in ("tcp", "any"):
        return False

    # Treat both directions as belonging to the same application flow so ACKs can
    # contribute passive RTT samples and reverse-direction TCP is not discarded.
    return _matches_direction(
        event.src, event.dst, event.sport, event.dport, flow_filter
    ) or _matches_direction(
        event.dst, event.src, event.dport, event.sport, flow_filter
    )


def _matches_direction(src: str, dst: str, sport: int, dport: int, flow_filter: FlowFilter) -> bool:
    if flow_filter.src_prefix and ipaddress.ip_address(src) not in ipaddress.ip_network(flow_filter.src_prefix, strict=False):
        return False
    if flow_filter.dst_prefix and ipaddress.ip_address(dst) not in ipaddress.ip_network(flow_filter.dst_prefix, strict=False):
        return False
    if flow_filter.src_port is not None and sport != flow_filter.src_port:
        return False
    if flow_filter.dst_port is not None and dport != flow_filter.dst_port:
        return False
    return True


def _seq_leq(a: int, b: int) -> bool:
    return ((b - a) & 0xFFFFFFFF) < 0x80000000
