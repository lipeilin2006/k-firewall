#!/usr/bin/env python3
"""Minimal FTP client: passive mode, connects to learned data port.

Runs in ns1 (client 10.0.5.2). Uses fixed source port 30000 for control
conn (matches the firewall rule). Data conn uses an ephemeral source port
so it can ONLY pass if ALG_EXPECT was learned from the 227 reply.
"""
import socket
import struct
import sys
import time

CTRL_SRC_PORT = 30000
SERVER = "10.0.6.2"


def make_ctrl():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("10.0.5.2", CTRL_SRC_PORT))
    s.settimeout(10)
    s.connect((SERVER, 21))
    print("ctrl: banner =", s.recv(128).decode(errors="replace").strip(), flush=True)
    return s


def cmd(s, c):
    s.sendall(c + b"\r\n")
    time.sleep(0.3)
    try:
        r = s.recv(256)
        print("ctrl: %s -> %r" % (c.decode(), r.decode(errors="replace").strip()), flush=True)
        return r
    except Exception as e:
        print("ctrl: %s recv err %s" % (c.decode(), e), flush=True)
        return b""


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "passive"
    s = make_ctrl()
    cmd(s, b"USER kfw")
    cmd(s, b"PASS x")
    if mode == "passive":
        resp = cmd(s, b"PASV")
        m = resp.decode(errors="replace")
        import re
        mm = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", m)
        if not mm:
            print("PASV reply parse fail:", m, flush=True)
            sys.exit(1)
        host = ".".join(mm.groups()[:4])
        port = int(mm.group(5)) * 256 + int(mm.group(6))
        print("data: connecting %s:%d" % (host, port), flush=True)
        d = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        d.settimeout(10)
        d.connect((host, port))
        print("data: connected (PASSED via ALG_EXPECT)" if host == SERVER else "data: connected (unexpected host)", flush=True)
        d.sendall(b"hello kfw data\n")
        time.sleep(0.5)
        d.close()
        cmd(s, b"QUIT")
    else:
        # active mode: PORT h1,h2,h3,h4,p1,p2 (client's own data listener)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("10.0.5.2", 0))
        listener.listen(1)
        lport = listener.getsockname()[1]
        p1, p2 = lport >> 8, lport & 0xFF
        port_cmd = "PORT 10,0,5,2,%d,%d" % (p1, p2)
        cmd(s, port_cmd.encode())
        print("active: waiting for server data conn on %d" % lport, flush=True)
        listener.settimeout(10)
        try:
            d, _ = listener.accept()
            print("data: server connected (PASSED via ALG_EXPECT)", flush=True)
            d.sendall(b"hello kfw data\n")
            time.sleep(0.5)
            d.close()
        except socket.timeout:
            print("data: TIMEOUT (server never connected)", flush=True)
        cmd(s, b"QUIT")
    print("DONE", flush=True)


if __name__ == "__main__":
    main()
