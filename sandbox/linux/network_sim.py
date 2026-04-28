"""In-container fake network responder.

Two pieces:

1. **fake DNS** on UDP/53 — answers any A query with ``SINKHOLE_IP``
   (default 10.10.10.10). Logs (qname, qtype, client) to
   ``/tmp/network_sim_dns.jsonl``.
2. **fake HTTP** on TCP/80 (and optional TCP/443 with a self-signed
   cert) — answers anything with a 200 OK and a small HTML body.
   Logs request line + headers + body preview to
   ``/tmp/network_sim_http.jsonl``.

Designed to keep C2-checking malware *talking* so we observe the next
beacon, not just the first SYN. Bind addresses default to all
interfaces inside the container; iptables redirection is left to the
host machinery layer.

Run from guest_agent when DETONATE_NETWORK_SIM=1.
"""

from __future__ import annotations

import json
import os
import socket
import socketserver
import struct
import threading
import time
from pathlib import Path

SINKHOLE_IP = os.environ.get("DETONATE_SINKHOLE_IP", "10.10.10.10")
DNS_LOG = Path("/tmp/network_sim_dns.jsonl")
HTTP_LOG = Path("/tmp/network_sim_http.jsonl")


def _log(path: Path, event: dict) -> None:
    try:
        with path.open("a") as f:
            f.write(json.dumps(event) + "\n")
    except OSError:
        pass


# ---------------- DNS ----------------

def _decode_qname(buf: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    while True:
        ln = buf[offset]
        if ln == 0:
            offset += 1
            break
        offset += 1
        labels.append(buf[offset : offset + ln].decode("ascii", errors="replace"))
        offset += ln
    return ".".join(labels), offset


def _dns_response(query: bytes) -> bytes:
    # Echo transaction id, set QR/AA, copy question, append A answer.
    if len(query) < 12:
        return b""
    tid = query[:2]
    qdcount = struct.unpack(">H", query[4:6])[0]
    if qdcount < 1:
        return b""
    qname, end = _decode_qname(query, 12)
    qtype = struct.unpack(">H", query[end : end + 2])[0]
    qclass = struct.unpack(">H", query[end + 2 : end + 4])[0]
    question = query[12 : end + 4]

    # Header: QR=1, AA=1, RD=copy, RA=1; ANCOUNT=1
    flags = 0x8580
    header = tid + struct.pack(">HHHHH", flags, 1, 1, 0, 0)

    # Answer: pointer to qname (0xC00C), type, class, TTL, rdlen, rdata
    answer = struct.pack(">HHHIH", 0xC00C, qtype if qtype in (1,) else 1, qclass, 60, 4)
    try:
        answer += socket.inet_aton(SINKHOLE_IP)
    except OSError:
        answer += b"\x0a\x0a\x0a\x0a"

    _log(DNS_LOG, {"ts": time.time(), "qname": qname, "qtype": qtype, "answer": SINKHOLE_IP})
    return header + question + answer


class _DNSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:  # type: ignore[override]
        data, sock = self.request
        try:
            resp = _dns_response(data)
            if resp:
                sock.sendto(resp, self.client_address)
        except Exception:
            pass


class _ThreadedUDP(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True


def start_dns(host: str = "0.0.0.0", port: int = 53) -> _ThreadedUDP | None:
    try:
        srv = _ThreadedUDP((host, port), _DNSHandler)
    except (PermissionError, OSError):
        return None
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


# ---------------- HTTP ----------------

class _HTTPHandler(socketserver.BaseRequestHandler):
    BODY = b"<html><head><title>OK</title></head><body>OK</body></html>"

    def handle(self) -> None:  # type: ignore[override]
        try:
            self.request.settimeout(2.0)
            data = b""
            while True:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\r\n\r\n" in data or len(data) > 65536:
                    break
        except Exception:
            return

        try:
            head, _, body = data.partition(b"\r\n\r\n")
            lines = head.decode("latin-1", errors="replace").splitlines()
            request_line = lines[0] if lines else ""
            headers = dict(
                (k.strip().lower(), v.strip())
                for k, _, v in (line.partition(":") for line in lines[1:])
                if k.strip()
            )
            _log(HTTP_LOG, {
                "ts": time.time(),
                "request_line": request_line,
                "headers": headers,
                "body_preview": body[:1024].decode("latin-1", errors="replace"),
                "client": self.client_address[0],
            })
            response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/html\r\n"
                b"Content-Length: " + str(len(self.BODY)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n"
            ) + self.BODY
            self.request.sendall(response)
        except Exception:
            pass


class _ThreadedTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True


def start_http(host: str = "0.0.0.0", port: int = 80) -> _ThreadedTCP | None:
    try:
        srv = _ThreadedTCP((host, port), _HTTPHandler)
    except (PermissionError, OSError):
        return None
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv


def start_all() -> dict[str, bool]:
    return {
        "dns": start_dns() is not None,
        "http": start_http() is not None,
    }


if __name__ == "__main__":
    started = start_all()
    print(json.dumps(started))
    while True:
        time.sleep(60)
