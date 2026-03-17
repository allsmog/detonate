"""Suricata IDS service for offline PCAP analysis.

Runs Suricata in a Docker container against captured PCAP files
and returns structured alert data.
"""

import asyncio
import io
import json
import logging
import tarfile
from typing import Any

import docker
from docker.errors import DockerException

from detonate.config import settings

logger = logging.getLogger("detonate.services.suricata")


class SuricataService:
    """Analyze PCAP files with Suricata IDS for signature-based detection."""

    def __init__(self) -> None:
        self._client = docker.from_env()

    async def analyze_pcap(self, pcap_data: bytes, analysis_id: str) -> dict:
        """Run Suricata on a PCAP file and return parsed alerts.

        1. Create container from suricata image
        2. Copy PCAP into container at /pcap/capture.pcap
        3. Run: suricata -r /pcap/capture.pcap -l /var/log/suricata/
        4. Extract /var/log/suricata/eve.json
        5. Parse alerts from eve.json
        6. Return structured alert data
        7. Cleanup container
        """
        return await asyncio.to_thread(
            self._analyze_sync, pcap_data, analysis_id
        )

    def _analyze_sync(self, pcap_data: bytes, analysis_id: str) -> dict:
        """Synchronous Suricata analysis (runs in thread pool)."""
        container = None
        try:
            container = self._client.containers.create(
                settings.suricata_image,
                command=[
                    "-r", "/pcap/capture.pcap",
                    "-l", "/var/log/suricata/",
                ],
                mem_limit="512m",
                cpu_quota=50000,
                network_mode="none",
            )

            self._inject_pcap(container, pcap_data)
            container.start()

            # Wait for Suricata to finish processing (generous timeout
            # since rule matching can take a while on large PCAPs)
            try:
                container.wait(timeout=120)
            except Exception:
                logger.warning(
                    "Suricata timed out for analysis %s, killing", analysis_id
                )
                try:
                    container.kill()
                except Exception:
                    pass

            eve_data = self._extract_eve_json(container)
            alerts = self._parse_eve_json(eve_data)
            summary = self._build_summary(alerts)

            return {
                "ids_alerts": alerts,
                "ids_summary": summary,
            }

        except DockerException as exc:
            logger.error("Suricata analysis failed: %s", exc)
            return {
                "ids_alerts": [],
                "ids_summary": self._build_summary([]),
                "ids_error": str(exc),
            }
        finally:
            if container:
                try:
                    container.remove(force=True)
                except Exception:
                    pass

    def _inject_pcap(self, container: Any, pcap_data: bytes) -> None:
        """Copy PCAP data into the container at /pcap/capture.pcap."""
        tar_stream = io.BytesIO()
        with tarfile.open(fileobj=tar_stream, mode="w") as tar:
            info = tarfile.TarInfo(name="capture.pcap")
            info.size = len(pcap_data)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(pcap_data))
        tar_stream.seek(0)
        container.put_archive("/pcap", tar_stream)

    def _extract_eve_json(self, container: Any) -> str:
        """Extract the eve.json log file from the Suricata container."""
        try:
            bits, _stat = container.get_archive("/var/log/suricata/eve.json")
            tar_stream = io.BytesIO()
            for chunk in bits:
                tar_stream.write(chunk)
            tar_stream.seek(0)

            with tarfile.open(fileobj=tar_stream, mode="r") as tar:
                member = tar.getmembers()[0]
                f = tar.extractfile(member)
                if f:
                    return f.read().decode(errors="replace")
        except Exception as exc:
            logger.warning("No eve.json found in Suricata container: %s", exc)
        return ""

    def _parse_eve_json(self, eve_data: str) -> list[dict]:
        """Parse Suricata EVE JSON log into structured alerts.

        Each line in eve.json is a separate JSON object.
        We filter for event_type == "alert" and extract key fields.
        """
        alerts: list[dict] = []
        if not eve_data:
            return alerts

        for line in eve_data.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue

            if event.get("event_type") != "alert":
                continue

            alert_info = event.get("alert", {})
            alerts.append({
                "signature_id": alert_info.get("signature_id", 0),
                "signature": alert_info.get("signature", "Unknown"),
                "severity": alert_info.get("severity", 3),
                "category": alert_info.get("category", "Unknown"),
                "src_ip": event.get("src_ip", ""),
                "src_port": event.get("src_port", 0),
                "dst_ip": event.get("dest_ip", ""),
                "dst_port": event.get("dest_port", 0),
                "protocol": event.get("proto", ""),
                "timestamp": event.get("timestamp", ""),
            })

        return alerts

    def _build_summary(self, alerts: list[dict]) -> dict:
        """Build a summary of IDS alerts by severity and category."""
        high = sum(1 for a in alerts if a.get("severity") == 1)
        medium = sum(1 for a in alerts if a.get("severity") == 2)
        low = sum(1 for a in alerts if a.get("severity", 3) >= 3)
        categories = sorted(set(a.get("category", "Unknown") for a in alerts))

        return {
            "total_alerts": len(alerts),
            "high_severity": high,
            "medium_severity": medium,
            "low_severity": low,
            "categories": categories,
        }
