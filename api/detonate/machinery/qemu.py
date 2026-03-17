"""QEMU/KVM-based machinery for Windows sandbox analysis.

Uses libvirt to manage QEMU VMs with snapshot-restore semantics.
The guest VM runs a Python HTTP server (guest agent) that receives
samples via multipart upload and returns structured analysis results.

Flow:
1. Revert VM to clean snapshot
2. Start VM
3. Wait for guest agent HTTP server to become healthy
4. POST sample binary to guest agent
5. Poll guest agent for completion
6. Collect screenshots via libvirt screendump
7. Stop and restore VM to clean state

Requirements:
- libvirt-python
- A pre-built Windows qcow2 image with guest_agent.py installed
- A clean snapshot created on that image
"""

import asyncio
import json
import logging
import tempfile
import time
from typing import Any
from uuid import UUID

import httpx

from detonate.config import settings
from detonate.machinery.base import BaseMachinery

logger = logging.getLogger("detonate.machinery.qemu")

GUEST_AGENT_PORT = 8080
POLL_INTERVAL = 2.0
HEALTH_TIMEOUT = 120
HEALTH_POLL_INTERVAL = 2.0
HEALTH_BACKOFF_MAX = 10.0
SCREENSHOT_INTERVAL = 15.0
HTTP_TIMEOUT = 30.0


class QEMUMachinery(BaseMachinery):
    """QEMU/KVM-based machinery for Windows sandbox analysis.

    Uses libvirt to manage QEMU VMs. The guest VM runs a Python HTTP
    server (guest agent) that receives samples and returns analysis results.
    """

    def __init__(self) -> None:
        self._conn = None  # lazy libvirt connection

    def _get_connection(self):
        """Get or create libvirt connection.

        Raises RuntimeError if libvirt-python is not installed or the
        connection URI is unreachable.
        """
        if self._conn is None:
            try:
                import libvirt
            except ImportError:
                raise RuntimeError(
                    "libvirt-python is required for QEMU machinery. "
                    "Install with: pip install libvirt-python"
                )
            uri = settings.qemu_connection_uri
            logger.info("Connecting to libvirt at %s", uri)
            self._conn = libvirt.open(uri)
            if self._conn is None:
                raise RuntimeError(f"Failed to open libvirt connection: {uri}")
        return self._conn

    def _close_connection(self) -> None:
        """Close the libvirt connection if open."""
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    async def start(
        self,
        sample_data: bytes,
        filename: str,
        config: dict[str, Any] | None = None,
        analysis_id: UUID | str | None = None,
    ) -> dict:
        """Execute a sample in a Windows QEMU VM and return analysis results.

        Args:
            sample_data: Raw bytes of the sample to execute.
            filename: Original filename of the sample.
            config: Optional dict with keys:
                - timeout (int): Max execution seconds (default 120).
                - vm_name (str): Libvirt domain name to use.
                - screenshots (bool): Whether to capture periodic screenshots.
            analysis_id: Optional analysis UUID for event streaming.

        Returns:
            Structured results dict matching the standard format.
        """
        config = config or {}
        timeout = config.get("timeout", 120)
        vm_name = config.get("vm_name", settings.qemu_base_image)
        capture_screenshots = config.get("screenshots", True)

        return await asyncio.to_thread(
            self._run_sync,
            sample_data,
            filename,
            timeout,
            vm_name,
            capture_screenshots,
            analysis_id,
        )

    def _run_sync(
        self,
        sample_data: bytes,
        filename: str,
        timeout: int,
        vm_name: str,
        capture_screenshots: bool,
        analysis_id: UUID | str | None,
    ) -> dict:
        """Synchronous analysis execution (runs in a thread).

        Orchestrates the full lifecycle: snapshot restore, VM start,
        sample submission, result polling, and cleanup.
        """
        start_time = time.monotonic()
        screenshots: list[bytes] = []
        vm_ip: str | None = None

        try:
            # Step 1: Restore VM to clean snapshot
            logger.info("Restoring VM '%s' to snapshot '%s'", vm_name, settings.qemu_snapshot_name)
            self._restore_snapshot(vm_name)

            # Step 2: Start the VM
            logger.info("Starting VM '%s'", vm_name)
            self._start_vm(vm_name)

            # Step 3: Obtain the VM's IP address
            vm_ip = self._get_vm_ip(vm_name)
            if vm_ip is None:
                raise RuntimeError(
                    f"Could not determine IP address for VM '{vm_name}'. "
                    "Ensure the VM has a DHCP lease or static IP configured."
                )
            logger.info("VM '%s' has IP %s", vm_name, vm_ip)

            # Step 4: Wait for the guest agent to become ready
            logger.info("Waiting for guest agent at %s:%d", vm_ip, GUEST_AGENT_PORT)
            if not self._wait_for_guest_agent(vm_ip, timeout=HEALTH_TIMEOUT):
                raise RuntimeError(
                    f"Guest agent at {vm_ip}:{GUEST_AGENT_PORT} did not become "
                    f"ready within {HEALTH_TIMEOUT}s"
                )
            logger.info("Guest agent is ready")

            # Step 5: Submit the sample for execution
            logger.info("Submitting sample '%s' (%d bytes)", filename, len(sample_data))
            submit_resp = self._submit_sample(vm_ip, sample_data, filename, timeout)
            if not submit_resp.get("accepted"):
                raise RuntimeError(
                    f"Guest agent rejected sample: {submit_resp.get('error', 'unknown')}"
                )
            logger.info("Sample accepted by guest agent")

            # Step 6: Poll for results, optionally capturing screenshots
            logger.info("Polling for results (timeout=%ds)", timeout)
            results = self._poll_results(
                vm_ip,
                timeout,
                vm_name=vm_name if capture_screenshots else None,
                screenshots=screenshots,
            )

            # Step 7: Attach screenshots to results if captured
            if screenshots:
                results["_screenshots"] = screenshots
                logger.info("Captured %d screenshots", len(screenshots))

            # Publish completion event to Redis if streaming
            if analysis_id:
                self._publish_complete(analysis_id)

            elapsed = time.monotonic() - start_time
            logger.info(
                "Analysis complete for '%s' in %.1fs (exit_code=%s)",
                filename,
                elapsed,
                results.get("execution", {}).get("exit_code", "?"),
            )
            return results

        except Exception as exc:
            logger.error("QEMU machinery error: %s", exc)
            elapsed = time.monotonic() - start_time

            if analysis_id:
                self._publish_complete(analysis_id)

            return {
                "execution": {
                    "exit_code": -1,
                    "duration_seconds": round(elapsed, 2),
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
            # Always attempt to stop the VM to avoid resource leaks
            try:
                self._stop_vm(vm_name)
            except Exception as exc:
                logger.warning("Failed to stop VM '%s': %s", vm_name, exc)

    # ------------------------------------------------------------------
    # VM lifecycle helpers
    # ------------------------------------------------------------------

    def _restore_snapshot(self, vm_name: str) -> None:
        """Revert VM to the clean snapshot defined in settings.

        This guarantees each analysis starts from a known-good state.
        """
        conn = self._get_connection()
        try:
            dom = conn.lookupByName(vm_name)
        except Exception as exc:
            raise RuntimeError(f"VM '{vm_name}' not found in libvirt: {exc}") from exc

        snapshot_name = settings.qemu_snapshot_name
        try:
            snap = dom.snapshotLookupByName(snapshot_name)
        except Exception as exc:
            raise RuntimeError(
                f"Snapshot '{snapshot_name}' not found on VM '{vm_name}': {exc}"
            ) from exc

        try:
            dom.revertToSnapshot(snap)
        except Exception as exc:
            raise RuntimeError(
                f"Failed to revert VM '{vm_name}' to snapshot '{snapshot_name}': {exc}"
            ) from exc

        logger.debug("Reverted VM '%s' to snapshot '%s'", vm_name, snapshot_name)

    def _start_vm(self, vm_name: str) -> None:
        """Start (resume) the VM if it is not already running."""
        import libvirt

        conn = self._get_connection()
        dom = conn.lookupByName(vm_name)

        state, _reason = dom.state()
        if state == libvirt.VIR_DOMAIN_RUNNING:
            logger.debug("VM '%s' is already running", vm_name)
            return

        if state == libvirt.VIR_DOMAIN_PAUSED:
            dom.resume()
            logger.debug("Resumed paused VM '%s'", vm_name)
            return

        try:
            dom.create()
        except Exception as exc:
            raise RuntimeError(f"Failed to start VM '{vm_name}': {exc}") from exc

        logger.debug("Started VM '%s'", vm_name)

    def _stop_vm(self, vm_name: str) -> None:
        """Forcefully stop the VM (destroy). Idempotent."""
        import libvirt

        conn = self._get_connection()
        try:
            dom = conn.lookupByName(vm_name)
        except Exception:
            return  # VM doesn't exist, nothing to stop

        state, _reason = dom.state()
        if state in (libvirt.VIR_DOMAIN_SHUTOFF, libvirt.VIR_DOMAIN_CRASHED):
            return

        try:
            dom.destroy()
            logger.debug("Destroyed VM '%s'", vm_name)
        except Exception as exc:
            logger.warning("Failed to destroy VM '%s': %s", vm_name, exc)

    def _get_vm_ip(self, vm_name: str, timeout: int = 60) -> str | None:
        """Obtain the VM's IP address from libvirt DHCP leases or agent.

        Polls with backoff until an IP is found or timeout is reached.
        Tries multiple strategies:
        1. libvirt DHCP leases (virDomainInterfaceAddresses with lease source)
        2. libvirt guest agent query (if qemu-ga is installed)
        3. ARP table lookup as a last resort
        """
        import libvirt

        conn = self._get_connection()
        dom = conn.lookupByName(vm_name)

        deadline = time.monotonic() + timeout
        interval = 2.0

        while time.monotonic() < deadline:
            # Strategy 1: DHCP leases from libvirt's network
            try:
                ifaces = dom.interfaceAddresses(
                    libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_LEASE
                )
                for iface_name, iface_data in ifaces.items():
                    for addr_info in iface_data.get("addrs", []):
                        addr = addr_info.get("addr", "")
                        addr_type = addr_info.get("type", -1)
                        # Type 0 = IPv4
                        if addr_type == 0 and addr and addr != "127.0.0.1":
                            return addr
            except Exception:
                pass

            # Strategy 2: Guest agent (qemu-ga) if available
            try:
                ifaces = dom.interfaceAddresses(
                    libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT
                )
                for iface_name, iface_data in ifaces.items():
                    for addr_info in iface_data.get("addrs", []):
                        addr = addr_info.get("addr", "")
                        addr_type = addr_info.get("type", -1)
                        if addr_type == 0 and addr and addr != "127.0.0.1":
                            return addr
            except Exception:
                pass

            time.sleep(interval)
            interval = min(interval * 1.5, 10.0)

        return None

    # ------------------------------------------------------------------
    # Guest agent HTTP communication
    # ------------------------------------------------------------------

    def _agent_url(self, ip: str, path: str) -> str:
        """Build the full URL for a guest agent endpoint."""
        return f"http://{ip}:{GUEST_AGENT_PORT}{path}"

    def _wait_for_guest_agent(self, ip: str, timeout: int = HEALTH_TIMEOUT) -> bool:
        """Poll the guest agent /health endpoint until it responds.

        Uses exponential backoff to avoid hammering a booting VM.
        Returns True if the agent became ready, False on timeout.
        """
        deadline = time.monotonic() + timeout
        interval = HEALTH_POLL_INTERVAL

        while time.monotonic() < deadline:
            try:
                with httpx.Client(timeout=5.0) as client:
                    resp = client.get(self._agent_url(ip, "/health"))
                    if resp.status_code == 200:
                        data = resp.json()
                        if data.get("status") == "ready":
                            return True
                        logger.debug("Agent not ready yet: %s", data)
            except httpx.ConnectError:
                logger.debug("Guest agent not reachable yet at %s", ip)
            except httpx.TimeoutException:
                logger.debug("Guest agent health check timed out at %s", ip)
            except Exception as exc:
                logger.debug("Guest agent health check error: %s", exc)

            time.sleep(interval)
            interval = min(interval * 1.5, HEALTH_BACKOFF_MAX)

        return False

    def _submit_sample(
        self, ip: str, sample_data: bytes, filename: str, timeout: int
    ) -> dict:
        """POST the sample binary to the guest agent for execution.

        Sends a multipart/form-data request with the file and timeout.
        Returns the JSON response from the agent.
        """
        url = self._agent_url(ip, "/submit")
        try:
            with httpx.Client(timeout=HTTP_TIMEOUT) as client:
                resp = client.post(
                    url,
                    files={"file": (filename, sample_data, "application/octet-stream")},
                    data={"timeout": str(timeout)},
                )
                resp.raise_for_status()
                return resp.json()
        except httpx.HTTPStatusError as exc:
            body = exc.response.text[:500] if exc.response else ""
            raise RuntimeError(
                f"Guest agent rejected submission (HTTP {exc.response.status_code}): {body}"
            ) from exc
        except httpx.ConnectError as exc:
            raise RuntimeError(
                f"Cannot connect to guest agent at {url}: {exc}"
            ) from exc

    def _poll_results(
        self,
        ip: str,
        timeout: int,
        vm_name: str | None = None,
        screenshots: list[bytes] | None = None,
    ) -> dict:
        """Poll the guest agent /status endpoint until analysis completes.

        Optionally captures periodic screenshots while waiting. Returns
        the full results dict from the agent's /results endpoint.

        Args:
            ip: Guest agent IP address.
            timeout: Maximum seconds to wait for results.
            vm_name: If set, capture screenshots from this VM periodically.
            screenshots: Mutable list to append screenshot PNG bytes to.
        """
        # Give extra buffer beyond the sample timeout for overhead
        poll_deadline = time.monotonic() + timeout + 60
        last_screenshot_time = 0.0

        while time.monotonic() < poll_deadline:
            # Capture a screenshot if enough time has passed
            if vm_name and screenshots is not None:
                now = time.monotonic()
                if now - last_screenshot_time >= SCREENSHOT_INTERVAL:
                    shot = self._screendump(vm_name)
                    if shot is not None:
                        screenshots.append(shot)
                    last_screenshot_time = now

            # Check status
            try:
                with httpx.Client(timeout=HTTP_TIMEOUT) as client:
                    resp = client.get(self._agent_url(ip, "/status"))
                    if resp.status_code == 200:
                        status_data = resp.json()
                        status = status_data.get("status", "")

                        if status == "completed":
                            # Fetch full results
                            return self._fetch_results(ip)

                        if status == "failed":
                            error_msg = status_data.get("error", "Unknown execution failure")
                            logger.error("Guest agent reports failure: %s", error_msg)
                            return self._error_result(error_msg)

                        # Still running
                        logger.debug(
                            "Analysis status: %s (elapsed: %.0fs)",
                            status,
                            status_data.get("elapsed", 0),
                        )
            except httpx.ConnectError:
                logger.warning("Lost connection to guest agent at %s", ip)
                # VM may have crashed; give it a moment and retry
            except httpx.TimeoutException:
                logger.debug("Status poll timed out")
            except Exception as exc:
                logger.warning("Status poll error: %s", exc)

            time.sleep(POLL_INTERVAL)

        logger.warning("Result polling timed out after %ds", timeout)
        return self._error_result(f"Analysis timed out after {timeout}s")

    def _fetch_results(self, ip: str) -> dict:
        """GET the full results from the guest agent /results endpoint."""
        url = self._agent_url(ip, "/results")
        try:
            with httpx.Client(timeout=HTTP_TIMEOUT) as client:
                resp = client.get(url)
                resp.raise_for_status()
                results = resp.json()
                # Ensure all required keys are present
                return self._normalize_results(results)
        except Exception as exc:
            logger.error("Failed to fetch results from guest agent: %s", exc)
            return self._error_result(f"Failed to retrieve results: {exc}")

    def _normalize_results(self, results: dict) -> dict:
        """Ensure the results dict has all required keys with correct types.

        The Windows guest agent may return additional keys (registry_changes,
        dns_queries) that the Linux agent doesn't produce; those are kept.
        Missing standard keys get safe defaults.
        """
        defaults = {
            "execution": {
                "exit_code": -1,
                "duration_seconds": 0,
                "timed_out": False,
            },
            "processes": [],
            "network": [],
            "files_created": [],
            "files_modified": [],
            "files_deleted": [],
            "stdout": "",
            "stderr": "",
        }
        for key, default_val in defaults.items():
            if key not in results:
                results[key] = default_val

        # Ensure execution sub-keys exist
        exec_defaults = {"exit_code": -1, "duration_seconds": 0, "timed_out": False}
        if isinstance(results.get("execution"), dict):
            for k, v in exec_defaults.items():
                results["execution"].setdefault(k, v)

        return results

    # ------------------------------------------------------------------
    # Screenshot capture
    # ------------------------------------------------------------------

    def _screendump(self, vm_name: str) -> bytes | None:
        """Capture a screenshot of the VM display as PNG bytes.

        Uses libvirt's screenshot API which writes to a file descriptor.
        Returns the raw PNG data or None on failure.
        """
        conn = self._get_connection()
        try:
            dom = conn.lookupByName(vm_name)

            # libvirt screenshot writes to a stream that we save to a temp file
            stream = conn.newStream()
            mime_type = dom.screenshot(stream, 0)
            logger.debug("Screenshot MIME type: %s", mime_type)

            # Read the stream into a temporary file
            with tempfile.NamedTemporaryFile(suffix=".ppm", delete=True) as tmp:
                def _recv_handler(stream, data, _opaque):
                    return tmp.write(data)

                try:
                    # Use recv to read all data from the stream
                    while True:
                        data = stream.recv(65536)
                        if not data:
                            break
                        tmp.write(data)
                except Exception:
                    pass
                finally:
                    try:
                        stream.finish()
                    except Exception:
                        pass

                tmp.flush()
                tmp.seek(0)
                raw_data = tmp.read()

            if not raw_data:
                return None

            # libvirt screenshots are typically PPM format; try to convert
            # to PNG using PIL if available, otherwise return raw
            try:
                import io

                from PIL import Image

                img = Image.open(io.BytesIO(raw_data))
                png_buf = io.BytesIO()
                img.save(png_buf, format="PNG")
                return png_buf.getvalue()
            except ImportError:
                # PIL not available; return raw PPM data
                logger.debug("PIL not available, returning raw screenshot data")
                return raw_data

        except Exception as exc:
            logger.debug("Screenshot capture failed: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Redis event streaming
    # ------------------------------------------------------------------

    def _publish_complete(self, analysis_id: UUID | str) -> None:
        """Publish the completion sentinel to the Redis channel."""
        channel = f"analysis:{analysis_id}:events"
        try:
            import redis as sync_redis

            r = sync_redis.from_url(self._redis_url(), decode_responses=True)
            r.publish(channel, json.dumps({"type": "complete"}))
            r.close()
        except Exception:
            logger.debug("Failed to publish complete for analysis %s", analysis_id)

    @staticmethod
    def _redis_url() -> str:
        """Get the Redis URL from settings."""
        try:
            from detonate.config import settings as _settings

            return _settings.redis_url
        except Exception:
            return "redis://localhost:6379/0"

    # ------------------------------------------------------------------
    # Error helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _error_result(error_msg: str) -> dict:
        """Build a standard error result dict."""
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
