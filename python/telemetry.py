#!/usr/bin/env python3
import json
import subprocess
import sys
from nat_client import send_command, SOCK_PATH

def collect_live(sock_path: str = SOCK_PATH) -> dict:
    return json.loads(send_command("show json", sock_path))

def collect_selftest(binary: str = "./nat-engine") -> dict:
    out = subprocess.check_output([binary, "--selftest"], text=True)
    start = out.find("{")
    if start < 0:
        raise RuntimeError("No JSON telemetry found")
    return json.loads(out[start:])

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "--live"
    data = collect_selftest() if mode == "--selftest" else collect_live()
    print(json.dumps(data, indent=2))
