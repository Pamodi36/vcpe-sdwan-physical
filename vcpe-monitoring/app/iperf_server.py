from __future__ import annotations

import asyncio
import logging

from .settings import Settings

LOG = logging.getLogger(__name__)


class Iperf3Server:
    """Optional local iperf3 server used by the peer CPE/measurement node."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._process: asyncio.subprocess.Process | None = None

    @property
    def running(self) -> bool:
        return self._process is not None and self._process.returncode is None

    async def start(self) -> None:
        if not self.settings.iperf_server_enabled or self.running:
            return

        args = [
            "iperf3",
            "-s",
            "-p",
            str(self.settings.iperf_server_port),
        ]
        if self.settings.iperf_server_bind:
            args.extend(["-B", self.settings.iperf_server_bind])

        self._process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.sleep(0.2)
        if self._process.returncode is not None:
            stdout, stderr = await self._process.communicate()
            self._process = None
            raise RuntimeError(
                "iperf3 server failed to start: "
                + (stderr.decode(errors="replace").strip() or stdout.decode(errors="replace").strip())
            )
        LOG.info("iperf3 server listening on TCP/%s", self.settings.iperf_server_port)

    async def stop(self) -> None:
        process = self._process
        self._process = None
        if process is None or process.returncode is not None:
            return
        process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
