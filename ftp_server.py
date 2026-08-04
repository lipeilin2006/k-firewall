#!/usr/bin/env python3
"""Minimal passive-mode FTP server for k-firewall ALG test.

Listens on 10.0.6.2:21 in ns2. On PASV, replies
227 Entering Passive Mode (10,0,6,2,p1,p2) and listens on that data port.
On STOR, reads the data connection and ACKs.
"""
import socket
import sys
import threading

DATA_PORT_BASE = 51000
IP = "10.0.6.2"
DATA_PORT_SEQ = [51000]


def next_data_port():
    # 每次递增一个端口，避免 TIME_WAIT 冲突；到 60000 后回绕。
    p = DATA_PORT_SEQ[0]
    DATA_PORT_SEQ[0] = 51001 if p >= 60000 else p + 1
    return p


def handle_data_conn(data_sock):
    try:
        data_sock.settimeout(3)
        data = data_sock.recv(4096)
        print("DATA recv:", data, flush=True)
    except Exception as e:
        print("DATA recv err:", e, flush=True)
    finally:
        try:
            data_sock.close()
        except Exception:
            pass


def handle_client(conn):
    conn.settimeout(15)
    f = conn.makefile("rwb", buffering=0)
    f.write(b"220 kfw test server\r\n")
    while True:
        try:
            line = f.readline()
        except Exception:
            break
        if not line:
            break
        print("CTRL recv:", line.strip(), flush=True)
        cmd = line.strip().upper()
        if cmd.startswith(b"USER"):
            f.write(b"331 ok\r\n")
        elif cmd.startswith(b"PASS"):
            f.write(b"230 ok\r\n")
        elif cmd.startswith(b"PORT"):
            # PORT h1,h2,h3,h4,p1,p2 —— 服务端主动连回客户端数据监听口。
            import re
            m = re.search(r"PORT\s+(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)", line.decode(errors="replace"))
            if m:
                host = ".".join(m.groups()[:4])
                port = int(m.group(5)) * 256 + int(m.group(6))
                print("PORT -> data conn to %s:%d" % (host, port), flush=True)
                f.write(b"200 ok\r\n")
                try:
                    d = socket.create_connection((host, port), timeout=5)
                    threading.Thread(target=handle_data_conn, args=(d,), daemon=True).start()
                except Exception as e:
                    print("PORT connect err:", e, flush=True)
            else:
                f.write(b"500 bad PORT\r\n")
        elif cmd.startswith(b"PASV"):
            data_port = next_data_port()
            d = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            d.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            d.bind((IP, data_port))
            d.listen(1)
            p1, p2 = data_port >> 8, data_port & 0xFF
            resp = f"227 Entering Passive Mode (10,0,6,2,{p1},{p2})\r\n"
            f.write(resp.encode())
            print("PASV ->", resp.strip(), flush=True)
            data_sock, _ = d.accept()
            threading.Thread(target=handle_data_conn, args=(data_sock,), daemon=True).start()
            d.close()
        elif cmd.startswith(b"STOR") or cmd.startswith(b"RETR"):
            f.write(b"150 ok\r\n")
            f.write(b"226 done\r\n")
        elif cmd.startswith(b"QUIT"):
            f.write(b"221 bye\r\n")
            break
        else:
            f.write(b"200 ok\r\n")
    conn.close()


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((IP, 21))
    s.listen(5)
    print("FTP server on %s:21" % IP, flush=True)
    while True:
        conn, _ = s.accept()
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
