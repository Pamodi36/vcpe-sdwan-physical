"""IPv4 Best Effort routing reconciliation for the vCPE Forwarder.

The renderer publishes the authoritative list of configured WAN interfaces.
DHCP lease callbacks only update gateway availability; they cannot authorize a
WAN by themselves.  This keeps Best Effort routing aligned with YANG/Agent
intent while allowing the dataplane to react immediately to lease changes.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
from pathlib import Path
import subprocess
from typing import Callable

RUN_DIR = Path("/run/forwarder")
HASH_POLICY_PATH = Path("/proc/sys/net/ipv4/fib_multipath_hash_policy")
PROTOCOL = "186"
METRIC = "100"


def gateway(wan: dict, run_dir: Path = RUN_DIR) -> str | None:
    """Return the current IPv4 gateway for one renderer-authorized WAN."""
    if wan["mode"] == "dhcp":
        try:
            fields = dict(
                line.split("=", 1)
                for line in (run_dir / "dhcp" / (wan["dev"] + ".env")).read_text().splitlines()
                if "=" in line
            )
            # A lease without a valid IPv4 address is not usable even if ROUTER exists.
            ipaddress.IPv4Address(fields["IP"])
            value = fields.get("ROUTER")
        except (OSError, KeyError, ValueError):
            return None
    else:
        value = wan.get("gateway")

    try:
        return str(ipaddress.IPv4Address(value)) if value else None
    except ipaddress.AddressValueError:
        return None


def route_command(config: dict, run_dir: Path = RUN_DIR) -> list[str]:
    """Build the Forwarder-owned Best Effort default route in the main table."""
    nexthops: list[str] = []
    for wan in config.get("wans", []):
        gw = gateway(wan, run_dir)
        # Ethernet WANs normally require a gateway. A device-only default is used
        # only when the Agent/YANG-derived static route explicitly declares it.
        if gw:
            nexthops += ["nexthop", "via", gw, "dev", wan["dev"], "onlink", "weight", "1"]
        elif wan.get("mode") != "dhcp" and wan.get("direct", False):
            nexthops += ["nexthop", "dev", wan["dev"], "weight", "1"]

    base = ["ip", "-4", "route", "replace"]
    if not nexthops:
        # Do not let forwarded BE traffic silently use a lower-priority management
        # default if none of the configured SD-WAN WANs is currently usable.
        base += ["unreachable"]
    return base + ["default", "table", "main", "proto", PROTOCOL, "metric", METRIC] + nexthops


def _warn_if_l4_hash_policy_missing(
    *,
    hash_policy_path: Path = HASH_POLICY_PATH,
    stderr = sys.stderr,
) -> None:
    """Check, but never mutate, the host ECMP hash policy from the container.

    The physical deployment provisions net.ipv4.fib_multipath_hash_policy=1 on
    the host.  Writing this sysctl from the Forwarder container previously failed
    on read-only /proc/sys mounts, so the runtime reconciler only verifies it.
    ECMP routing remains functional with policy 0, but per-flow distribution for
    flows differing only by L4 ports may be less visible in tests.
    """
    try:
        current = hash_policy_path.read_text(encoding="utf-8").strip()
    except OSError:
        current = "unknown"

    if current != "1":
        print(
            "WARNING: net.ipv4.fib_multipath_hash_policy is not 1 "
            f"(current={current!r}); configure it on the host for L4-aware ECMP",
            file=stderr,
        )


def reconcile(
    config: dict,
    run_dir: Path = RUN_DIR,
    run: Callable = subprocess.run,
    hash_policy_path: Path = HASH_POLICY_PATH,
) -> None:
    command = route_command(config, run_dir)
    if command.count("nexthop") > 1:
        _warn_if_l4_hash_policy_missing(hash_policy_path=hash_policy_path)
    run(command, check=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--configure", type=Path)
    parser.add_argument("--publish-only", action="store_true")
    parser.add_argument("--gateway")
    args = parser.parse_args()

    # Linux-only lock; importing this module remains possible for offline tests.
    import fcntl

    RUN_DIR.mkdir(parents=True, exist_ok=True)
    with (RUN_DIR / "best-effort.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        config_path = RUN_DIR / "best-effort.json"

        if args.configure:
            config = json.loads(args.configure.read_text(encoding="utf-8"))
            temp = config_path.with_suffix(".tmp")
            temp.write_text(json.dumps(config), encoding="utf-8")
            os.replace(temp, config_path)
        elif config_path.exists():
            config = json.loads(config_path.read_text(encoding="utf-8"))
        else:
            return  # DHCP hook may run before the first desired state is published.

        if args.gateway:
            wan = next((w for w in config.get("wans", []) if w.get("dev") == args.gateway), None)
            print((gateway(wan) if wan else None) or "")
        elif not args.publish_only:
            reconcile(config)


if __name__ == "__main__":
    main()
