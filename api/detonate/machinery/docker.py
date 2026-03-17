import asyncio
import io
import json
import logging
import tarfile
import threading
import uuid as _uuid
from typing import Any
from uuid import UUID

import docker
from docker.errors import ContainerError, DockerException

from detonate.machinery.base import BaseMachinery

logger = logging.getLogger("detonate.machinery.docker")

SANDBOX_IMAGE = "detonate-sandbox-linux"
DEFAULT_TIMEOUT = 60
MEM_LIMIT = "512m"
CPU_QUOTA = 50000
PCAP_CONTAINER_PATH = "/tmp/capture.pcap"


class DockerMachinery(BaseMachinery):
    def __init__(self) -> None:
        self._client = docker.from_env()

    async def start(
        self,
        sample_data: bytes,
        filename: str,
        config: dict[str, Any] | None = None,
        analysis_id: UUID | str | None = None,
        container_id: str | None = None,
    ) -> dict:
        config = config or {}
        timeout = config.get("timeout", DEFAULT_TIMEOUT)
        network_enabled = config.get("network", False)

        if container_id:
            return await asyncio.to_thread(
                self._run_pooled_sync, sample_data, filename, timeout, container_id
            )
        return await asyncio.to_thread(
            self._run_sync, sample_data, filename, timeout, network_enabled,
            analysis_id, config
        )

    def _run_sync(
        self,
        sample_data: bytes,
        filename: str,
        timeout: int,
        network_enabled: bool = False,
        analysis_id: UUID | str | None = None,
        config: dict[str, Any] | None = None,
    ) -> dict:
        config = config or {}
        container = None
        network = None
        network_name = None
        event_thread = None

        try:
            # Create an isolated bridge network if network capture is enabled
            if network_enabled:
                network_name = f"detonate-sandbox-{_uuid.uuid4().hex[:12]}"
                network = self._client.networks.create(
                    network_name,
                    driver="bridge",
                    internal=True,  # No external internet access
                )
                logger.info("Created sandbox network: %s", network_name)

            # Build container creation kwargs
            create_kwargs: dict[str, Any] = {
                "image": SANDBOX_IMAGE,
                "command": [f"/sample/{filename}", str(timeout)],
                "mem_limit": MEM_LIMIT,
                "cpu_quota": CPU_QUOTA,
                "security_opt": ["no-new-privileges"],
            }

            # Build environment variables
            env_vars: dict[str, str] = {}
            if network_enabled:
                env_vars["DETONATE_PCAP"] = "1"

            # Screenshots/video support
            screenshots_enabled = config.get("screenshots", False)
            if screenshots_enabled:
                env_vars["DETONATE_SCREENSHOTS"] = "1"
                interval = config.get("screenshots_interval", 1.0)
                env_vars["DETONATE_SCREENSHOT_INTERVAL"] = str(interval)

            # VNC support
            if config.get("vnc", False):
                env_vars["DETONATE_VNC"] = "1"

            if network_enabled and network:
                create_kwargs["network"] = network_name
                env_vars["DETONATE_PCAP"] = "1"
                create_kwargs["cap_add"] = ["NET_RAW"]
            else:
                create_kwargs["network_mode"] = "none"

            if env_vars:
                create_kwargs["environment"] = env_vars

            container = self._client.containers.create(**create_kwargs)

            self._inject_file(container, f"/sample/{filename}", sample_data)
            container.start()

            # Start streaming events from the container to Redis if we have an analysis_id
            stop_streaming = threading.Event()
            if analysis_id:
                event_thread = threading.Thread(
                    target=self._stream_events_from_container,
                    args=(container, analysis_id, stop_streaming),
                    daemon=True,
                )
                event_thread.start()

            # Wait for container to finish (with extra buffer for strace overhead)
            wait_timeout = timeout + 15
            try:
                container.wait(timeout=wait_timeout)
            except Exception:
                logger.warning("Container timed out, killing")
                try:
                    container.kill()
                except Exception:
                    pass

            # Signal event streaming thread to stop and wait for it
            stop_streaming.set()
            if event_thread is not None:
                event_thread.join(timeout=5)

            result = self._extract_results(container)

            # Publish completion event to Redis
            if analysis_id:
                self._publish_complete(analysis_id)

            # Extract raw PCAP data if network was enabled
            if network_enabled:
                pcap_data = self._extract_pcap(container)
                if pcap_data is not None:
                    result["_pcap_data"] = pcap_data

            # Extract screenshots and video if available
            screenshots = self._extract_screenshots(container)
            if screenshots:
                import base64 as _b64
                result["_screenshot_data"] = [
                    (name, _b64.b64encode(data).decode())
                    for name, data in screenshots
                ]

            video = self._extract_video(container)
            if video:
                import base64 as _b64
                result["_video_data"] = _b64.b64encode(video).decode()

            return result

        except (ContainerError, DockerException) as exc:
            logger.error("Docker machinery error: %s", exc)
            if analysis_id:
                self._publish_complete(analysis_id)
            return {
                "execution": {
                    "exit_code": -1,
                    "duration_seconds": 0,
                    "timed_out": False,
                },
                "error": str(exc),
                "processes": [],
                "network": [],
                "files_created": [],
                "files_modified": [],
                "files_deleted": [],
                "stdout": "",
                "stderr": "",
            }
        finally:
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
            if network:
                try:
                    network.remove()
                    logger.info("Removed sandbox network: %s", network_name)
                except Exception:
                    logger.warning("Failed to remove network: %s", network_name)

    def _stream_events_from_container(
        self,
        container: Any,
        analysis_id: UUID | str,
        stop_event: threading.Event,
    ) -> None:
        """Tail /tmp/events.jsonl inside the container and publish events to Redis.

        Runs in a background thread.  Uses ``container.exec_run`` with streaming
        to get real-time output.
        """
        import redis as sync_redis  # local import to keep module-level deps light

        try:
            r = sync_redis.from_url(
                self._redis_url(),
                decode_responses=True,
            )
        except Exception:
            logger.debug("Could not connect to Redis for event streaming")
            return

        channel = f"analysis:{analysis_id}:events"

        try:
            # exec_run with stream=True returns an (exit_code, output_generator) tuple.
            # We use "tail -f" which follows the file as it grows.
            _exit_code, output = container.exec_run(
                ["tail", "-n", "+1", "-f", "/tmp/events.jsonl"],
                stream=True,
                demux=False,
            )
            for chunk in output:
                if stop_event.is_set():
                    break
                lines = chunk.decode(errors="replace").strip().splitlines()
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        # Validate it's JSON before publishing
                        json.loads(line)
                        r.publish(channel, line)
                    except (json.JSONDecodeError, Exception):
                        pass
        except Exception:
            # Container may have been removed, that's expected
            logger.debug("Event streaming stopped for analysis %s", analysis_id)
        finally:
            try:
                r.close()
            except Exception:
                pass

    def _publish_complete(self, analysis_id: UUID | str) -> None:
        """Publish the completion sentinel to the Redis channel."""
        import redis as sync_redis

        channel = f"analysis:{analysis_id}:events"
        try:
            r = sync_redis.from_url(self._redis_url(), decode_responses=True)
            r.publish(channel, json.dumps({"type": "complete"}))
            r.close()
        except Exception:
            logger.debug("Failed to publish complete for analysis %s", analysis_id)

    @staticmethod
    def _redis_url() -> str:
        """Get the Redis URL from settings. Deferred import to avoid circular deps."""
        try:
            from detonate.config import settings
            return settings.redis_url
        except Exception:
            return "redis://localhost:6379/0"

    def _run_pooled_sync(
        self,
        sample_data: bytes,
        filename: str,
        timeout: int,
        container_id: str,
    ) -> dict:
        """Run analysis using a pre-existing pooled container.

        The container was created by the pool in an idle state. We replace it
        with a new one configured for the analysis command, inject the sample,
        start it, and wait. The container is NOT destroyed here -- the pool
        handles that.
        """
        try:
            container = self._client.containers.get(container_id)

            if container.status == "running":
                try:
                    container.kill()
                except Exception:
                    pass
                container.wait(timeout=5)

            labels = container.labels or {}
            container.remove(force=True)

            container = self._client.containers.create(
                SANDBOX_IMAGE,
                command=[f"/sample/{filename}", str(timeout)],
                mem_limit=MEM_LIMIT,
                cpu_quota=CPU_QUOTA,
                network_mode="none",
                security_opt=["no-new-privileges"],
                labels=labels,
            )

            self._inject_file(container, f"/sample/{filename}", sample_data)
            container.start()

            wait_timeout = timeout + 15
            try:
                container.wait(timeout=wait_timeout)
            except Exception:
                logger.warning("Pooled container timed out, killing")
                try:
                    container.kill()
                except Exception:
                    pass

            results = self._extract_results(container)
            results["_container_id"] = container.id
            return results

        except (ContainerError, DockerException) as exc:
            logger.error("Docker machinery error (pooled): %s", exc)
            return self._error_result(str(exc))

    @staticmethod
    def _error_result(error_msg: str) -> dict:
        return {
            "execution": {
                "exit_code": -1,
                "duration_seconds": 0,
                "timed_out": False,
            },
            "error": error_msg,
            "processes": [],
            "network": [],
            "files_created": [],
            "files_modified": [],
            "files_deleted": [],
            "stdout": "",
            "stderr": "",
        }

    def _inject_file(self, container: Any, path: str, data: bytes) -> None:
        """Copy a file into the container via put_archive."""
        tar_stream = io.BytesIO()
        # Extract just the filename from the path
        name = path.rsplit("/", 1)[-1]
        folder = path.rsplit("/", 1)[0] if "/" in path else "/"

        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            info.mode = 0o755
            tar.addfile(info, io.BytesIO(data))

        tar_stream.seek(0)
        container.put_archive(folder, tar_stream)

    def _extract_results(self, container: Any) -> dict:
        """Extract /opt/agent/results.json from the container."""
        try:
            bits, _stat = container.get_archive("/opt/agent/results.json")
            tar_stream = io.BytesIO()
            for chunk in bits:
                tar_stream.write(chunk)
            tar_stream.seek(0)

            with tarfile.open(fileobj=tar_stream, mode="r") as tar:
                member = tar.getmembers()[0]
                f = tar.extractfile(member)
                if f:
                    return json.loads(f.read())
        except Exception as exc:
            logger.error("Failed to extract results: %s", exc)

        # Fallback: try to get container logs
        try:
            logs = container.logs().decode(errors="replace")[:4096]
        except Exception:
            logs = ""

        return {
            "execution": {"exit_code": -1, "duration_seconds": 0, "timed_out": False},
            "error": "Failed to extract results from container",
            "processes": [],
            "network": [],
            "files_created": [],
            "files_modified": [],
            "files_deleted": [],
            "stdout": logs,
            "stderr": "",
        }

    def _extract_screenshots(self, container: Any) -> list[tuple[str, bytes]]:
        """Extract /tmp/screenshots/*.png from the container."""
        screenshots = []
        try:
            bits, _stat = container.get_archive("/tmp/screenshots/")
            tar_stream = io.BytesIO()
            for chunk in bits:
                tar_stream.write(chunk)
            tar_stream.seek(0)

            with tarfile.open(fileobj=tar_stream, mode="r") as tar:
                for member in tar.getmembers():
                    if member.isfile() and member.name.endswith(".png"):
                        f = tar.extractfile(member)
                        if f:
                            name = member.name.rsplit("/", 1)[-1]
                            screenshots.append((name, f.read()))
        except Exception:
            logger.debug("No screenshots to extract")

        return sorted(screenshots, key=lambda x: x[0])

    def _extract_video(self, container: Any) -> bytes | None:
        """Extract /tmp/recording.mp4 from the container."""
        try:
            bits, _stat = container.get_archive("/tmp/recording.mp4")
            tar_stream = io.BytesIO()
            for chunk in bits:
                tar_stream.write(chunk)
            tar_stream.seek(0)

            with tarfile.open(fileobj=tar_stream, mode="r") as tar:
                member = tar.getmembers()[0]
                f = tar.extractfile(member)
                if f:
                    return f.read()
        except Exception:
            logger.debug("No video to extract")
        return None

    def _extract_pcap(self, container: Any) -> bytes | None:
        """Extract /tmp/capture.pcap from the container as raw bytes."""
        try:
            bits, _stat = container.get_archive(PCAP_CONTAINER_PATH)
            tar_stream = io.BytesIO()
            for chunk in bits:
                tar_stream.write(chunk)
            tar_stream.seek(0)

            with tarfile.open(fileobj=tar_stream, mode="r") as tar:
                member = tar.getmembers()[0]
                f = tar.extractfile(member)
                if f:
                    return f.read()
        except Exception as exc:
            logger.warning("Failed to extract PCAP: %s", exc)

        return None
