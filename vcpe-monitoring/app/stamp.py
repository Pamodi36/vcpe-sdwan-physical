from __future__ import annotations

import asyncio
import logging
import socket
import struct
import threading
import time
from dataclasses import dataclass
from statistics import mean

from .clock_sync import ClockSyncChecker
from .settings import Settings

LOG = logging.getLogger(__name__)

NTP_UNIX_EPOCH_DELTA = 2_208_988_800
SENDER_PACKET_LEN = 44
REFLECTOR_PACKET_LEN = 44

# RFC 8762 unauthenticated base packet formats.
# Sender: seq(4), timestamp(8), error estimate(2), MBZ(30)
_SENDER_FMT = "!I8sH30s"
# Reflector: seq(4), tx ts(8), error(2), MBZ(2), rx ts(8), sender seq(4),
# sender ts(8), sender error(2), MBZ(2), sender TTL(1), MBZ(3)
_REFLECTOR_FMT = "!I8sH2s8sI8sH2sB3s"


@dataclass(slots=True)
class StampResult:
    latency_ms: float | None = None
    jitter_ms: float | None = None
    loss_percent: float | None = None
    forward_delay_ms: float | None = None
    reverse_delay_ms: float | None = None
    rtt_ms: float | None = None
    forward_jitter_ms: float | None = None
    reverse_jitter_ms: float | None = None
    round_trip_loss_percent: float | None = None
    forward_loss_percent: float | None = None
    reverse_loss_percent: float | None = None
    sent: int = 0
    received: int = 0
    clock_synchronized: bool = False
    error: str | None = None


@dataclass(slots=True)
class _Reply:
    sender_seq: int
    reflector_seq: int
    t1: float
    t2: float
    t3: float
    t4: float
    remote_clock_synchronized: bool


class StampReflector:
    """Stateful STAMP Session-Reflector for RFC 8762 base unauthenticated packets."""

    def __init__(self, settings: Settings, clock_checker: ClockSyncChecker) -> None:
        self.settings = settings
        self.clock_checker = clock_checker
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._session_seq: dict[tuple[str, int], int] = {}
        
    async def start(self) -> None:
        if not self.settings.stamp_enabled or self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="stamp-reflector", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        sock = self._sock
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        thread = self._thread
        if thread is not None:
            thread.join(timeout=2.0)
        self._thread = None

    def _run(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock = sock
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_RECVTTL", 12), 1)
        except OSError:
            pass
        sock.bind(("0.0.0.0", self.settings.stamp_port))
        sock.settimeout(0.5)
        LOG.info("STAMP stateful reflector listening on UDP/%s", self.settings.stamp_port)

        while not self._stop.is_set():
            try:
                data, ancdata, _, addr = sock.recvmsg(65535, 1024)
            except socket.timeout:
                continue
            except OSError:
                break

            if len(data) < SENDER_PACKET_LEN:
                continue
            try:
                sender_seq, sender_ts_raw, sender_err, _ = struct.unpack(
                    _SENDER_FMT, data[:SENDER_PACKET_LEN]
                )
            except struct.error:
                continue

            t2 = time.time()
            sender_ttl = _extract_ttl(ancdata)
            session = (addr[0], addr[1])
            refl_seq = self._session_seq.get(session, 0)
            self._session_seq[session] = (refl_seq + 1) & 0xFFFFFFFF
            t3 = time.time()

            reply = struct.pack(
                _REFLECTOR_FMT,
                refl_seq,
                _unix_to_ntp_bytes(t3),
                _error_estimate(
                    self.clock_checker.cached,
                    self.settings.stamp_error_scale,
                    self.settings.stamp_error_multiplier,
                ),
                b"\x00\x00",
                _unix_to_ntp_bytes(t2),
                sender_seq,
                sender_ts_raw,
                sender_err,
                b"\x00\x00",
                sender_ttl,
                b"\x00\x00\x00",
            )
            try:
                sock.sendto(reply, addr)
            except OSError:
                continue


async def run_stamp(
    destination_ip: str,
    interface: str,
    *,
    settings: Settings,
    clock_checker: ClockSyncChecker,
    count: int,
    spacing_ms: float,
) -> StampResult:
    if count <= 0:
        return StampResult(error="STAMP probe count must be > 0")

    local_synced = await clock_checker.synchronized()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\x00")
    except OSError as exc:
        sock.close()
        return StampResult(sent=0, received=0, error=f"SO_BINDTODEVICE({interface}) failed: {exc}")

    target = (destination_ip, settings.stamp_port)
    loop = asyncio.get_running_loop()
    replies: dict[int, _Reply] = {}
    send_times: dict[int, float] = {}
    done_sending = asyncio.Event()

    async def receiver() -> None:
        deadline: float | None = None
        while True:
            if done_sending.is_set() and deadline is None:
                deadline = loop.time() + settings.stamp_reply_wait_ms / 1000.0
            if deadline is not None and loop.time() >= deadline:
                break
            timeout = 0.1 if deadline is None else max(0.01, min(0.1, deadline - loop.time()))
            try:
                data, _ = await asyncio.wait_for(loop.sock_recvfrom(sock, 65535), timeout=timeout)
            except asyncio.TimeoutError:
                continue
            except (OSError, asyncio.CancelledError):
                break
            if len(data) < REFLECTOR_PACKET_LEN:
                continue
            t4 = time.time()
            try:
                (
                    refl_seq,
                    refl_tx_raw,
                    refl_err,
                    _,
                    refl_rx_raw,
                    sender_seq,
                    sender_ts_raw,
                    _,
                    _,
                    _,
                    _,
                ) = struct.unpack(_REFLECTOR_FMT, data[:REFLECTOR_PACKET_LEN])
            except struct.error:
                continue
            t1 = send_times.get(sender_seq, _ntp_bytes_to_unix(sender_ts_raw))
            replies[sender_seq] = _Reply(
                sender_seq=sender_seq,
                reflector_seq=refl_seq,
                t1=t1,
                t2=_ntp_bytes_to_unix(refl_rx_raw),
                t3=_ntp_bytes_to_unix(refl_tx_raw),
                t4=t4,
                remote_clock_synchronized=_error_is_synchronized(refl_err),
            )

    recv_task = asyncio.create_task(receiver())
    try:
        base = loop.time()
        spacing = spacing_ms / 1000.0
        for seq in range(count):
            target_time = base + seq * spacing
            delay = target_time - loop.time()
            if delay > 0:
                await asyncio.sleep(delay)
            t1 = time.time()
            send_times[seq] = t1
            packet = struct.pack(
                _SENDER_FMT,
                seq,
                _unix_to_ntp_bytes(t1),
                _error_estimate(
                    local_synced,
                    settings.stamp_error_scale,
                    settings.stamp_error_multiplier,
                ),
                b"\x00" * 30,
            )
            try:
                await loop.sock_sendto(sock, packet, target)
            except OSError as exc:
                LOG.debug("STAMP send failed seq=%s: %s", seq, exc)
        done_sending.set()
        await recv_task
    except asyncio.CancelledError:
        recv_task.cancel()
        raise
    finally:
        sock.close()

    return _calculate_stamp_result(count, replies, local_synced)


def _calculate_stamp_result(count: int, replies: dict[int, _Reply], local_synced: bool) -> StampResult:
    ordered = [replies[key] for key in sorted(replies)]
    received = len(ordered)
    rt_loss = 100.0 * (count - received) / count if count else None

    rtts: list[float] = []
    forward: list[float] = []
    reverse: list[float] = []
    for item in ordered:
        remote_processing = max(0.0, item.t3 - item.t2)
        rtt = max(0.0, (item.t4 - item.t1) - remote_processing) * 1000.0
        rtts.append(rtt)
        if local_synced and item.remote_clock_synchronized:
            fwd = (item.t2 - item.t1) * 1000.0
            rev = (item.t4 - item.t3) * 1000.0
            # Large negative values normally mean the clocks should not be treated as synchronized.
            if fwd >= -1.0 and rev >= -1.0:
                forward.append(max(0.0, fwd))
                reverse.append(max(0.0, rev))

    fwd_loss, rev_loss = _estimate_directional_loss(ordered)

    fwd_mean = _safe_mean(forward)
    rev_mean = _safe_mean(reverse)
    rtt_mean = _safe_mean(rtts)
    fwd_jitter = _variation(forward)
    rev_jitter = _variation(reverse)
    rtt_jitter = _variation(rtts)

    # Legacy fields: prefer MEF-oriented forward one-way metrics when clock sync is valid,
    # otherwise fall back to RTT-derived operational metrics.
    latency = fwd_mean if fwd_mean is not None else rtt_mean
    jitter = fwd_jitter if fwd_jitter is not None else rtt_jitter
    loss = fwd_loss if fwd_loss is not None else rt_loss

    return StampResult(
        latency_ms=_round(latency),
        jitter_ms=_round(jitter),
        loss_percent=_round(loss, 4),
        forward_delay_ms=_round(fwd_mean),
        reverse_delay_ms=_round(rev_mean),
        rtt_ms=_round(rtt_mean),
        forward_jitter_ms=_round(fwd_jitter),
        reverse_jitter_ms=_round(rev_jitter),
        round_trip_loss_percent=_round(rt_loss, 4),
        forward_loss_percent=_round(fwd_loss, 4),
        reverse_loss_percent=_round(rev_loss, 4),
        sent=count,
        received=received,
        clock_synchronized=bool(local_synced and ordered and all(x.remote_clock_synchronized for x in ordered)),
        error=None if received else "no STAMP replies received",
    )


def _estimate_directional_loss(replies: list[_Reply]) -> tuple[float | None, float | None]:
    """Estimate interior forward/reverse loss gaps using RFC 8762 stateful sequences.

    Leading/trailing loss cannot be assigned directionally from a single train, so this is
    deliberately reported only when at least two replies are available. Reciprocal sessions
    remain the preferred way to obtain strong directional evidence.
    """
    if len(replies) < 2:
        return None, None
    forward_lost = 0
    reverse_lost = 0
    sent_span = 0
    for prev, cur in zip(replies, replies[1:]):
        sender_gap = max(0, _seq_delta(cur.sender_seq, prev.sender_seq) - 1)
        reflector_gap = max(0, _seq_delta(cur.reflector_seq, prev.reflector_seq) - 1)
        reverse_gap = min(sender_gap, reflector_gap)
        forward_gap = max(0, sender_gap - reverse_gap)
        forward_lost += forward_gap
        reverse_lost += reverse_gap
        sent_span += _seq_delta(cur.sender_seq, prev.sender_seq)
    if sent_span <= 0:
        return None, None
    return (
        100.0 * forward_lost / sent_span,
        100.0 * reverse_lost / sent_span,
    )


def _seq_delta(new: int, old: int) -> int:
    return (new - old) & 0xFFFFFFFF


def _unix_to_ntp_bytes(ts: float) -> bytes:
    sec = int(ts) + NTP_UNIX_EPOCH_DELTA
    frac = int((ts - int(ts)) * (1 << 32)) & 0xFFFFFFFF
    return struct.pack("!II", sec & 0xFFFFFFFF, frac)


def _ntp_bytes_to_unix(raw: bytes) -> float:
    sec, frac = struct.unpack("!II", raw)
    return (sec - NTP_UNIX_EPOCH_DELTA) + frac / float(1 << 32)


def _error_estimate(synchronized: bool, scale: int, multiplier: int) -> int:
    value = ((scale & 0x3F) << 8) | (multiplier & 0xFF)
    if synchronized:
        value |= 0x8000
    return value


def _error_is_synchronized(value: int) -> bool:
    return bool(value & 0x8000)


def _extract_ttl(ancdata) -> int:
    for level, ctype, data in ancdata:
        if level == socket.IPPROTO_IP and ctype == socket.IP_TTL and len(data) >= 4:
            try:
                return max(0, min(255, struct.unpack("i", data[:4])[0]))
            except struct.error:
                pass
    return 255


def _variation(values: list[float]) -> float | None:
    if len(values) < 2:
        return 0.0 if len(values) == 1 else None
    return mean(abs(cur - prev) for prev, cur in zip(values, values[1:]))


def _safe_mean(values: list[float]) -> float | None:
    return mean(values) if values else None


def _round(value: float | None, digits: int = 3) -> float | None:
    return round(float(value), digits) if value is not None else None
