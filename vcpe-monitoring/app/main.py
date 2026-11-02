from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse

from .clock_sync import ClockSyncChecker
from .influx import InfluxWriter
from .interface_resolver import InterfaceResolutionError, InterfaceResolver
from .iperf_server import Iperf3Server
from .jobs import JobManager
from .models import FlowMonitoringRequest, JobResponse, TunnelMonitoringRequest
from .passive_tcp import PassiveManager
from .settings import Settings
from .stamp import StampReflector

settings = Settings.from_env()
logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
LOG = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    writer = InfluxWriter(settings)
    resolver = InterfaceResolver(settings)
    clock_checker = ClockSyncChecker(settings)
    passive = PassiveManager(enabled=settings.passive_enabled, max_events=settings.passive_max_events)
    stamp_reflector = StampReflector(settings, clock_checker)
    iperf_server = Iperf3Server(settings)

    await clock_checker.start()
    await stamp_reflector.start()
    await iperf_server.start()

    manager = JobManager(settings, resolver, writer, passive, clock_checker)
    app.state.writer = writer
    app.state.manager = manager
    app.state.clock_checker = clock_checker
    app.state.iperf_server = iperf_server

    LOG.info(
        "vcpe-monitoring starting WAN map=%s Influx=%s STAMP=%s iperf3-server=%s passive=%s",
        settings.wan_link_map,
        "enabled" if writer.enabled else "disabled",
        settings.stamp_enabled,
        iperf_server.running,
        settings.passive_enabled,
    )
    try:
        yield
    finally:
        await manager.stop_all()
        passive.stop_all()
        stamp_reflector.stop()
        await iperf_server.stop()
        await clock_checker.stop()
        writer.close()


app = FastAPI(title="SD-WAN CPE Hybrid Monitoring API", version="1.1.0", lifespan=lifespan)


@app.exception_handler(InterfaceResolutionError)
async def interface_error_handler(_, exc: InterfaceResolutionError):
    return JSONResponse(status_code=422, content={"detail": str(exc)})


@app.get("/health")
async def health():
    manager: JobManager = app.state.manager
    writer: InfluxWriter = app.state.writer
    clock_checker: ClockSyncChecker = app.state.clock_checker
    iperf_server: Iperf3Server = app.state.iperf_server
    return {
        "status": "healthy",
        "jobs": await manager.counts(),
        "influx_configured": writer.enabled,
        "influx_reachable": writer.ping(),
        "clock_synchronized": await clock_checker.synchronized(),
        "stamp_reflector_port": settings.stamp_port if settings.stamp_enabled else None,
        "iperf3_server_port": settings.iperf_server_port if iperf_server.running else None,
    }


@app.get("/api/v1/monitoring/jobs")
async def list_jobs():
    manager: JobManager = app.state.manager
    return {"items": await manager.list_jobs()}


@app.post("/api/v1/monitoring/flows", response_model=JobResponse)
async def start_flow(request: FlowMonitoringRequest):
    manager: JobManager = app.state.manager
    handle, updated = await manager.start_flow(request)
    return JobResponse(
        status="running",
        job_type="flow",
        job_key=f"{request.flow_id}:{request.wan_link}",
        interface=handle.interface,
        updated=updated,
    )


@app.delete("/api/v1/monitoring/flows/{flow_id}/{wan_link}", response_model=JobResponse)
async def stop_flow(flow_id: str, wan_link: str):
    manager: JobManager = app.state.manager
    try:
        await manager.stop_flow(flow_id, wan_link)
    except KeyError:
        raise HTTPException(status_code=404, detail="flow monitoring job not found")
    return JobResponse(status="stopped", job_type="flow", job_key=f"{flow_id}:{wan_link}")


@app.post("/api/v1/monitoring/tunnels", response_model=JobResponse)
async def start_tunnel(request: TunnelMonitoringRequest):
    manager: JobManager = app.state.manager
    handle, updated = await manager.start_tunnel(request)
    return JobResponse(
        status="running",
        job_type="tunnel",
        job_key=request.tunnel_id,
        interface=handle.interface,
        updated=updated,
    )


@app.delete("/api/v1/monitoring/tunnels/{tunnel_id}", response_model=JobResponse)
async def stop_tunnel(tunnel_id: str):
    manager: JobManager = app.state.manager
    try:
        await manager.stop_tunnel(tunnel_id)
    except KeyError:
        raise HTTPException(status_code=404, detail="tunnel monitoring job not found")
    return JobResponse(status="stopped", job_type="tunnel", job_key=tunnel_id)
