# nat-engine

A userspace stateful IPv4 Network Address Translation (NAT) engine written in C, paired with a Unix-socket CLI (`natctl`) and a Python test/telemetry harness.

## Overview & Intention

This project was built to implement the core data-plane mechanics of a stateful IPv4 NAT gateway from scratch in C—without relying on `iptables`, `nftables`, or kernel `conntrack`. It focuses on:
* Low-overhead 4-tuple connection tracking and port allocation.
* In-place SNAT/DNAT packet rewriting with RFC 1071 incremental checksum updates.
* Protocol-aware session lifecycles (TCP state machine, UDP/ICMP idle aging).
* Handling IPv4 fragmentation across NAT boundaries.
* Separating the C packet-processing data plane from live inspection and automated verification.

## Architecture

```text
  [LAN TUN: nat-lan0]                                  [WAN TUN: nat-wan0]
           |                                                    ^
           v                                                    |
  +----------------------------------------------------------------------+
  |                       nat-engine (C Data Plane)                      |
  |                                                                      |
  |  nat_frag.c  ->  nat_ct.c           ->  nat_rewrite.c  -> nat_state.c|
  |  (Reassembly)    (FNV-1a Hash +         (SNAT/DNAT +      (TCP/UDP/  |
  |                   64K Port Bitmap)       RFC 1071 Csum)    ICMP FSM) |
  +----------------------------------------------------------------------+
                                    ^
                                    |  Unix Domain Socket (/tmp/nat-engine.sock)
                                    v
              ./natctl (C CLI)  |  python/nat_client.py & telemetry.py
```

## Project Structure

* `include/` & `src/` — C data plane (`main.c`, `nat_ct.c`, `nat_rewrite.c`, `nat_state.c`, `nat_frag.c`, `nat_cli.c`) and CLI (`natctl_main.c`).
* `configs/nat-topo.yaml` — Reference TUN interface and IP configuration.
* `python/nat_client.py` — Python IPC client for querying the running daemon.
* `python/telemetry.py` — Extracts structured JSON telemetry from `nat-engine`.
* `python/nat_test.py` — Automated correctness and assertion test harness.

## Prerequisites

* Linux or WSL2 with `gcc` (C11/GNU11), `make`, and `python3`
* Root privileges (`sudo`) and `/dev/net/tun` support (only required for live TUN forwarding mode)

## Clone & Build

```bash
git clone https://github.com/sairamesh7016/nat-engine.git
cd nat-engine
make
```

This compiles both `nat-engine` and `natctl` with `-O2 -Wall -Wextra -Werror`.

## Testing

Run the built-in C data-plane self-test (verifies outbound SNAT, inbound DNAT, connection tracking, and JSON telemetry):

```bash
./nat-engine --selftest
```

Run the Python verification harness and standalone telemetry check:

```bash
python3 python/nat_test.py
python3 python/telemetry.py --selftest
```

## Running Live (TUN Mode)

Start the NAT engine between two Linux TUN interfaces:

```bash
sudo ./nat-engine nat-lan0 nat-wan0 203.0.113.10
```

In a second terminal, inspect live state or flush the connection table over `/tmp/nat-engine.sock`:

```bash
./natctl show stats
./natctl show conn
./natctl show json
./natctl flush

# Or via Python
python3 python/nat_client.py show json
```

## Sample Telemetry Output

```json
{
  "project": "nat-engine",
  "nat_ip": "203.0.113.10",
  "active_connections": 1,
  "total_connections": 1,
  "expired_connections": 0,
  "packets_translated_out": 1,
  "packets_translated_in": 1,
  "bytes_out": 28,
  "bytes_in": 28,
  "drops": {
    "no_route": 0,
    "port_exhausted": 0,
    "invalid": 0
  },
  "avg_latency_ms": 0.003
}
```
