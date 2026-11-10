# Systems Toolkit

Small tools for Linux diagnostics and performance experiments.

- **cgwhy** — cgroup v2 limits, ancestor constraints, throttling and pressure.
- **ns-diff** — process namespace, filesystem, permissions and environment differences.
- **alloc-bench** — command benchmarks with verified allocator bindings.
- **cacheline-scout** — cache-line contention reports and before/after comparisons using perf c2c.
- **socket-bench** — command benchmarks with observed TCP socket options.
- **pcap-pair** — TCP sequence coverage, retransmissions and ACK observations across two captures.
- **pmtu-check** — bidirectional IPv4 UDP size probes with a temporary cooperating peer.

Run `make` on Linux with Python 3.10+ and a C compiler; commands appear in `bin/`.
Use `--help` for usage and `--json` for structured output.
Allocator auditing requires glibc; cache-line recording requires `perf`, supported hardware and permissions.
