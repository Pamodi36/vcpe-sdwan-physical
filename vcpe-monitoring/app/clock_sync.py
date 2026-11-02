from __future__ import annotations

import asyncio
import logging
import re

from .settings import Settings

LOG = logging.getLogger(__name__)


class ClockSyncChecker:
    """Tracks whether the host clock is synchronized.

    vcpe-monitoring runs with host networking, but not the host filesystem. Therefore
    chronyc queries the host chronyd command socket over loopback UDP instead of relying
    on /run/chrony/chronyd.sock inside the container.
    """

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.cached = bool(settings.stamp_assume_clock_synced)
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        await self.synchronized()
        if self.settings.stamp_clock_sync_check and not self.settings.stamp_assume_clock_synced:
            self._task = asyncio.create_task(self._refresh_loop(), name="clock-sync-refresh")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    async def synchronized(self) -> bool:
        if self.settings.stamp_assume_clock_synced:
            self.cached = True
            return True
        if not self.settings.stamp_clock_sync_check:
            self.cached = False
            return False

        try:
            proc = await asyncio.create_subprocess_exec(
                "chronyc", "-h", "127.0.0.1", "tracking",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=2.0)
            text = stdout.decode(errors="replace")
            match = re.search(r"^Leap status\s*:\s*(.+)$", text, re.MULTILINE | re.IGNORECASE)
            self.cached = bool(match and match.group(1).strip().lower() == "normal")
        except Exception:
            LOG.debug("Unable to determine host chrony synchronization state", exc_info=True)
            self.cached = False
        return self.cached

    async def _refresh_loop(self) -> None:
        while True:
            await asyncio.sleep(30)
            await self.synchronized()
