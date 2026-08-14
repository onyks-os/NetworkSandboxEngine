# Explanation: Namespace Lifecycle & Naming Conventions

NSE guarantees clean teardowns and zero leak of ephemeral network interfaces.

---

## Naming Conventions (`nse.core.naming`)

Namespaces and virtual ethernet pairs follow deterministic prefixing:

| Component | Prefix Pattern | Example |
| :--- | :--- | :--- |
| Simple Netns | `nse_<test_id>` | `nse_a1b2c3d4e5f6` |
| Router Netns | `nse_router_<test_id>` | `nse_router_a1b2c3d4e5f6` |
| Server Netns | `nse_server_<test_id>` | `nse_server_a1b2c3d4e5f6` |
| Host Veth | `vhr-<suffix>` | `vhr-a1b2c3d4e5f6` |
| Router Host Veth | `vrh-<suffix>` | `vrh-a1b2c3d4e5f6` |
| Router Server Veth | `vrs-<suffix>` | `vrs-a1b2c3d4e5f6` |
| Server Veth | `vsr-<suffix>` | `vsr-a1b2c3d4e5f6` |

---

## Automated Startup Sweep & Retry Teardowns

- **Startup Sweep**: When `NetnsController` initializes, it scans `/var/run/netns/` and `ip link` for leftover `nse_*`, `vhr-*`, `vrh-*` links from aborted runs and sweeps them clean.
- **Teardown Retry with Exponential Backoff**: `destroy_netns()` retries namespace deletion up to 3 times (100ms, 500ms, 1s backoff) to handle asynchronous kernel interface unregistration delays.
