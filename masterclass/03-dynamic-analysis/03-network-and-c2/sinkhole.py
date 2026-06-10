#!/usr/bin/env python3
"""sinkhole.py — a tiny local listener for the Module 3.3 offline lab.

Accepts one TCP connection on 127.0.0.1:8888, prints whatever the beacon sends
(so you see the C2 request), and returns a minimal HTTP 200. This stands in for
a controlled C2 sinkhole so the whole lab runs offline and safely.

Usage:  python3 sinkhole.py [port]
"""
import socket
import sys

port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(1)
print(f"[sinkhole] listening on 127.0.0.1:{port} (Ctrl-C to stop)")
try:
    conn, addr = srv.accept()
    data = conn.recv(4096)
    print(f"[sinkhole] connection from {addr}, received {len(data)} bytes:")
    print(data.decode(errors="replace"))
    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
    conn.close()
finally:
    srv.close()
