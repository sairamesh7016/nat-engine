#!/usr/bin/env python3
import json
import sys
from pathlib import Path
from telemetry import collect_selftest

def run_checks() -> int:
    binary = Path("./nat-engine")
    if not binary.exists():
        print("[FAIL] ./nat-engine not found. Run 'make' first.")
        return 1

    data = collect_selftest(str(binary.resolve()))
    assert data["active_connections"] == 1
    assert data["packets_translated_out"] == 1
    assert data["packets_translated_in"] == 1
    assert data["bytes_out"] == 28 and data["bytes_in"] == 28
    assert data["drops"]["no_route"] == 0
    assert data["drops"]["invalid"] == 0
    assert data["drops"]["port_exhausted"] == 0

    print(json.dumps(data, indent=2))
    print("\n[PASS] All nat-engine correctness & telemetry checks passed.")
    return 0

if __name__ == "__main__":
    sys.exit(run_checks())
