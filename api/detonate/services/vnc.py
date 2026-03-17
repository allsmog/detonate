"""VNC session manager.

Bridges browser WebSocket connections to VNC servers running inside
sandbox containers via ``websockify``.  Each analysis gets at most one
VNC session, and sessions are auto-cleaned after a configurable timeout.
"""

import asyncio
import logging
import signal
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime

logger = logging.getLogger("detonate.services.vnc")


@dataclass
class VNCSession:
    """Tracks a single websockify bridge process for an analysis."""

    analysis_id: str
    vnc_host: str       # target VNC server host (container IP)
    vnc_port: int       # target VNC port (5900)
    ws_port: int        # websockify listen port
    process: subprocess.Popen | None = None
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    timeout: int = 300  # seconds until auto-cleanup


class VNCManager:
    """Manages VNC sessions via websockify processes.

    Singleton -- use ``VNCManager.get_instance()`` to obtain the shared
    manager.  Each analysis can have at most one active VNC session.
    Sessions are automatically destroyed after the configured timeout.
    """

    _instance: "VNCManager | None" = None

    def __init__(self) -> None:
        self._sessions: dict[str, VNCSession] = {}
        self._next_port = 6080  # starting websockify port
        self._lock = asyncio.Lock()
        self._cleanup_handles: dict[str, asyncio.TimerHandle] = {}

    @classmethod
    def get_instance(cls) -> "VNCManager":
        if cls._instance is None:
            cls._instance = VNCManager()
        return cls._instance

    @classmethod
    def reset_instance(cls) -> None:
        """Reset the singleton (useful for testing)."""
        cls._instance = None

    async def create_session(
        self,
        analysis_id: str,
        vnc_host: str = "localhost",
        vnc_port: int = 5900,
        timeout: int = 300,
    ) -> VNCSession:
        """Start a websockify process bridging WebSocket to VNC.

        If a session for the given analysis already exists, returns the
        existing session without creating a new one.

        Args:
            analysis_id: The analysis UUID string.
            vnc_host: Host running the VNC server (container IP).
            vnc_port: VNC server port (typically 5900).
            timeout: Seconds until automatic cleanup.

        Returns:
            The created (or existing) VNCSession.
        """
        async with self._lock:
            if analysis_id in self._sessions:
                existing = self._sessions[analysis_id]
                logger.debug(
                    "Returning existing VNC session for analysis %s on port %d",
                    analysis_id,
                    existing.ws_port,
                )
                return existing

            ws_port = self._next_port
            self._next_port += 1

            # Start websockify: websockify <listen_port> <vnc_host>:<vnc_port>
            # websockify bridges WebSocket connections to a raw TCP VNC server.
            try:
                process = subprocess.Popen(
                    [
                        "websockify",
                        "--heartbeat=30",
                        str(ws_port),
                        f"{vnc_host}:{vnc_port}",
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
            except FileNotFoundError:
                logger.error(
                    "websockify not found -- install it with: pip install websockify"
                )
                raise RuntimeError(
                    "websockify is not installed. "
                    "Install it with: pip install websockify"
                )

            session = VNCSession(
                analysis_id=analysis_id,
                vnc_host=vnc_host,
                vnc_port=vnc_port,
                ws_port=ws_port,
                process=process,
                timeout=timeout,
            )
            self._sessions[analysis_id] = session

            # Schedule auto-cleanup after timeout
            loop = asyncio.get_running_loop()
            handle = loop.call_later(
                timeout,
                lambda aid=analysis_id: asyncio.ensure_future(
                    self.destroy_session(aid)
                ),
            )
            self._cleanup_handles[analysis_id] = handle

            logger.info(
                "Started VNC session for analysis %s: "
                "websockify :%d -> %s:%d (timeout=%ds)",
                analysis_id,
                ws_port,
                vnc_host,
                vnc_port,
                timeout,
            )
            return session

    async def destroy_session(self, analysis_id: str) -> bool:
        """Stop the websockify process and remove the session.

        Returns True if a session was found and destroyed, False otherwise.
        """
        async with self._lock:
            # Cancel the auto-cleanup timer if it has not fired yet
            handle = self._cleanup_handles.pop(analysis_id, None)
            if handle is not None:
                handle.cancel()

            session = self._sessions.pop(analysis_id, None)
            if session is None:
                return False

            if session.process is not None:
                try:
                    session.process.send_signal(signal.SIGTERM)
                    session.process.wait(timeout=5)
                    logger.info(
                        "Stopped VNC session for analysis %s (port %d)",
                        analysis_id,
                        session.ws_port,
                    )
                except subprocess.TimeoutExpired:
                    logger.warning(
                        "websockify for analysis %s did not exit after SIGTERM, "
                        "sending SIGKILL",
                        analysis_id,
                    )
                    try:
                        session.process.kill()
                        session.process.wait(timeout=3)
                    except Exception:
                        logger.exception(
                            "Failed to kill websockify for analysis %s",
                            analysis_id,
                        )
                except Exception:
                    logger.exception(
                        "Error stopping websockify for analysis %s",
                        analysis_id,
                    )
            return True

    async def get_session(self, analysis_id: str) -> VNCSession | None:
        """Return the active session for an analysis, or None."""
        return self._sessions.get(analysis_id)

    @property
    def active_session_count(self) -> int:
        """Number of currently active VNC sessions."""
        return len(self._sessions)

    async def destroy_all(self) -> int:
        """Destroy all active sessions. Returns the count destroyed.

        Useful during application shutdown.
        """
        # Collect IDs first to avoid mutating dict during iteration
        analysis_ids = list(self._sessions.keys())
        count = 0
        for aid in analysis_ids:
            if await self.destroy_session(aid):
                count += 1
        return count
