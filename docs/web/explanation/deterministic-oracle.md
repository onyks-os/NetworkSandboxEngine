# Explanation: Deterministic Verdict Oracle

NSE's verdict oracle determines packet pass/drop outcomes deterministically from kernel `nftables` trace events.

---

## How the Oracle Works

1. **Rule Tracing Enablement**: NSE automatically prepends `_TRACE_INIT_RULESET` to set `meta nftrace set 1` on incoming traffic.
2. **Readiness Probe (`wait_ready()`)**: `TraceHarvester` waits for an `asyncio.Event` readiness signal confirming `nft monitor trace` is active.
3. **Sequential Packet Injection**: Packets in a test request are injected sequentially.
4. **Kernel Event Matching**: `nft monitor trace` output is parsed into structured `TraceEvent` objects.
5. **Verdict Extraction**: Verdicts (`ACCEPT`, `DROP`, `REJECT`) are extracted directly from user ruleset matches and chain policy decisions without synthetic padding.
