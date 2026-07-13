"""Optional web dashboard for real-time monitoring.

Requires: pip install fwtrash[dashboard]
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.responses import HTMLResponse
    HAS_FASTAPI = True
except ImportError:
    HAS_FASTAPI = False
    FastAPI = None
    WebSocket = None

logger = logging.getLogger("fwtrash.dashboard")

_pipeline_state: Any = None
_connected_websockets: set = set()


def set_pipeline_state(state: Any) -> None:
    global _pipeline_state
    _pipeline_state = state


async def broadcast_stats() -> None:
    if not _connected_websockets or _pipeline_state is None:
        return
    
    stats = _get_stats_dict()
    message = json.dumps(stats)
    
    disconnected = set()
    for ws in _connected_websockets:
        try:
            await ws.send_text(message)
        except Exception:
            disconnected.add(ws)
    
    _connected_websockets.difference_update(disconnected)


def _get_stats_dict() -> dict[str, Any]:
    if _pipeline_state is None:
        return {"status": "initializing"}
    
    stats = _pipeline_state.stats
    
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "status": "running" if _pipeline_state.is_running else "stopped",
        "stats": {
            "total_processed": stats.total_processed,
            "total_allowed": stats.total_allowed,
            "total_trash": stats.total_trash,
            "total_blocked": stats.total_blocked,
            "total_errors": stats.total_errors,
            "rate_eps": round(stats.entries_per_second, 2),
            "uptime_seconds": round(stats.uptime_seconds, 1),
        },
        "blocks": {
            "active": len(_pipeline_state.active_blocks),
            "recent": [
                {
                    "ip": d.ip,
                    "reason": d.reason,
                    "confidence": d.confidence,
                    "detected_at": d.detected_at.isoformat(),
                }
                for d in list(_pipeline_state.active_blocks.values())[:10]
            ]
        },
        "recent_trash": [
            {
                "ip": e.ip,
                "timestamp": e.timestamp.isoformat(),
                "request": e.parsed_fields.get('req', '-'),
            }
            for e in stats.recent_trash[-5:]
        ],
    }


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Dashboard starting")
    broadcast_task = asyncio.create_task(_broadcast_loop())
    yield
    broadcast_task.cancel()
    try:
        await broadcast_task
    except asyncio.CancelledError:
        pass
    logger.info("Dashboard stopped")


async def _broadcast_loop() -> None:
    while True:
        try:
            await broadcast_stats()
            await asyncio.sleep(1)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.exception(f"Broadcast error: {e}")
            await asyncio.sleep(1)


def create_app() -> FastAPI:
    if not HAS_FASTAPI:
        raise ImportError("Dashboard dependencies not installed. Run: pip install fwtrash[dashboard]")
    
    app = FastAPI(title="FWTrash Dashboard", version="2.0.0", lifespan=lifespan)
    
    @app.get("/", response_class=HTMLResponse)
    async def root():
        return HTMLResponse(content=DASHBOARD_HTML)
    
    @app.get("/api/stats")
    async def get_stats():
        return _get_stats_dict()
    
    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket):
        await websocket.accept()
        _connected_websockets.add(websocket)
        
        try:
            await websocket.send_json(_get_stats_dict())
            while True:
                try:
                    data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                    if data == "ping":
                        await websocket.send_text("pong")
                except asyncio.TimeoutError:
                    await websocket.send_json({"type": "keepalive"})
        except WebSocketDisconnect:
            pass
        finally:
            _connected_websockets.discard(websocket)
    
    return app


DASHBOARD_HTML = """<!DOCTYPE html>
<html>
<head>
    <title>FWTrash Dashboard</title>
    <meta charset="utf-8">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: system-ui, sans-serif; background: #1a1a2e; color: #eee; padding: 2rem; }
        h1 { color: #e94560; margin-bottom: 1rem; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .card { background: #16213e; padding: 1.5rem; border-radius: 8px; }
        .card h3 { color: #e94560; font-size: 0.9rem; text-transform: uppercase; margin-bottom: 1rem; }
        .metric { display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid #0f3460; }
        .metric:last-child { border-bottom: none; }
        .value { font-size: 1.5rem; font-weight: bold; color: #4ecca3; }
        table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
        th, td { text-align: left; padding: 0.75rem; border-bottom: 1px solid #0f3460; }
        th { color: #e94560; font-size: 0.8rem; }
        .ip { font-family: monospace; color: #4ecca3; }
        #status { position: fixed; bottom: 20px; right: 20px; padding: 10px 20px; border-radius: 4px; }
        #status.connected { background: #4ecca3; color: #1a1a2e; }
        #status.disconnected { background: #e94560; }
    </style>
</head>
<body>
    <h1>FWTrash Dashboard <span id="status" class="disconnected">Connecting...</span></h1>
    
    <div class="grid">
        <div class="card">
            <h3>Throughput</h3>
            <div class="metric"><span>Entries/sec</span><span class="value" id="eps">0.0</span></div>
            <div class="metric"><span>Total</span><span class="value" id="total">0</span></div>
        </div>
        <div class="card">
            <h3>Threats</h3>
            <div class="metric"><span>Trash</span><span class="value" id="trash">0</span></div>
            <div class="metric"><span>Blocked</span><span class="value" id="blocked">0</span></div>
            <div class="metric"><span>Active</span><span class="value" id="active">0</span></div>
        </div>
        <div class="card">
            <h3>System</h3>
            <div class="metric"><span>Uptime</span><span class="value" id="uptime">0s</span></div>
            <div class="metric"><span>Errors</span><span class="value" id="errors">0</span></div>
        </div>
    </div>
    
    <div class="card">
        <h3>Recent Blocks</h3>
        <table id="blocks"><thead><tr><th>IP</th><th>Reason</th><th>Confidence</th></tr></thead><tbody></tbody></table>
    </div>
    
    <script>
        const ws = new WebSocket('ws://' + window.location.host + '/ws');
        const status = document.getElementById('status');
        
        ws.onopen = () => { status.className = 'connected'; status.textContent = 'Connected'; };
        ws.onclose = () => { status.className = 'disconnected'; status.textContent = 'Disconnected'; };
        
        ws.onmessage = (e) => {
            const d = JSON.parse(e.data);
            if (d.type === 'keepalive') return;
            
            document.getElementById('eps').textContent = d.stats.rate_eps.toFixed(1);
            document.getElementById('total').textContent = d.stats.total_processed.toLocaleString();
            document.getElementById('trash').textContent = d.stats.total_trash;
            document.getElementById('blocked').textContent = d.stats.total_blocked;
            document.getElementById('active').textContent = d.blocks.active;
            document.getElementById('errors').textContent = d.stats.total_errors;
            
            const hrs = Math.floor(d.stats.uptime_seconds / 3600);
            const mins = Math.floor((d.stats.uptime_seconds % 3600) / 60);
            document.getElementById('uptime').textContent = hrs > 0 ? hrs + 'h ' + mins + 'm' : mins + 'm';
            
            const tbody = document.querySelector('#blocks tbody');
            if (d.blocks.recent.length > 0) {
                tbody.innerHTML = d.blocks.recent.map(b => 
                    '<tr><td class="ip">' + b.ip + '</td><td>' + b.reason + '</td><td>' + 
                    Math.round(b.confidence * 100) + '%</td></tr>'
                ).join('');
            }
        };
    </script>
</body>
</html>"""
