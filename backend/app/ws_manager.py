"""
ws_manager.py - a small in-memory pub/sub so the frontend can get scan
progress pushed to it instantly instead of polling every 5 seconds.

Plain-language: think of this as a mailing list per project. When a
browser tab opens a project's page, it "subscribes" via a WebSocket.
Whenever checkpoint.py changes a phase's status (started, completed,
failed), it "publishes" that change here, and every subscribed tab for
that project gets it immediately.

Deliberately in-process, in-memory - no Redis pub/sub, no cross-worker
fan-out. This is safe ONLY because the backend runs as a single uvicorn
process (confirmed in docker-compose.yml/Dockerfile: no --workers flag,
one container). If this app ever moves to multiple backend replicas,
this needs to become a real pub/sub backed by the existing Redis
instance - noted here rather than silently breaking at that point.

The frontend is NOT required to use this - ProjectDetail.jsx still
falls back to its existing 5s polling if the WebSocket never connects
or drops, so a proxy that doesn't support WebSocket upgrades (misconfigured
Caddy, corporate proxy, etc.) degrades gracefully instead of losing
updates entirely.
"""

import json
import logging

from fastapi import WebSocket

logger = logging.getLogger("swas.ws_manager")


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: dict[int, set[WebSocket]] = {}

    async def connect(self, project_id: int, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.setdefault(project_id, set()).add(websocket)

    def disconnect(self, project_id: int, websocket: WebSocket) -> None:
        conns = self._connections.get(project_id)
        if conns is not None:
            conns.discard(websocket)
            if not conns:
                self._connections.pop(project_id, None)

    async def broadcast(self, project_id: int, message: dict) -> None:
        """
        Sends a JSON message to every tab currently watching this
        project. Never raises - a dead/slow socket shouldn't take down
        the actual scan it's reporting on, so failures here are logged
        and the socket is dropped, not re-raised.
        """
        conns = self._connections.get(project_id)
        if not conns:
            return

        payload = json.dumps(message)
        dead = []
        for ws in conns:
            try:
                await ws.send_text(payload)
            except Exception:
                dead.append(ws)

        for ws in dead:
            self.disconnect(project_id, ws)


manager = ConnectionManager()
