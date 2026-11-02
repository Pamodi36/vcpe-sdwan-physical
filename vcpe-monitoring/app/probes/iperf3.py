from __future__ import annotations

import json
from dataclasses import dataclass

from .common import run_command


@dataclass(slots=True)
class IperfResult:
    available_bandwidth_kbps: float | None
    error: str | None = None


def parse_iperf3_json(output: str) -> IperfResult:
    try:
        payload = json.loads(output)
    except json.JSONDecodeError as exc:
        return IperfResult(None, error=f"invalid iperf3 JSON: {exc}")

    end = payload.get("end", {})
    candidates = [
        end.get("sum_received", {}).get("bits_per_second"),
        end.get("sum_sent", {}).get("bits_per_second"),
        end.get("sum", {}).get("bits_per_second"),
    ]
    for value in candidates:
        if isinstance(value, (int, float)):
            return IperfResult(round(float(value) / 1000.0, 3))

    return IperfResult(None, error=str(payload.get("error") or "iperf3 returned no bandwidth value"))


async def run_iperf3(
    destination_ip: str,
    interface: str,
    source_ip: str,
    *,
    port: int,
    duration_sec: int,
    timeout_sec: float,
    bind_device: bool,
    parallel_streams: int = 1,
) -> IperfResult:
    args = [
        "iperf3", "-c", destination_ip, "-p", str(port), "-J",
        "-t", str(duration_sec), "-B", source_ip,
    ]
    if parallel_streams > 1:
        args.extend(["-P", str(parallel_streams)])
    if bind_device:
        args.extend(["--bind-dev", interface])

    try:
        result = await run_command(args, timeout_sec)
    except Exception as exc:
        return IperfResult(None, error=str(exc))

    parsed = parse_iperf3_json(result.stdout)
    if result.returncode != 0 and parsed.available_bandwidth_kbps is None:
        parsed.error = (
            parsed.error
            or result.stderr.strip()
            or result.stdout.strip()
            or f"iperf3 exited with {result.returncode}"
        )
    return parsed
