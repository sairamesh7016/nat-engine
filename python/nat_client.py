#!/usr/bin/env python3
import socket
import sys

SOCK_PATH = "/tmp/nat-engine.sock"

def send_command(cmd: str, sock_path: str = SOCK_PATH) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(sock_path)
        s.sendall((cmd.strip() + "\n").encode("utf-8"))
        chunks = []
        while True:
            data = s.recv(4096)
            if not data:
                break
            chunks.append(data.decode("utf-8", errors="replace"))
    return "".join(chunks)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 python/nat_client.py <show stats|show conn|show json|flush>")
        sys.exit(1)
    print(send_command(" ".join(sys.argv[1:])), end="")
