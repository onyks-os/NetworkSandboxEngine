# Explanation: Namespace Lifecycle & Naming Conventions

Each controller owns the resources it creates. A new controller can recover a
previous run's abandoned resources, but cannot delete another live controller's
resources merely because their names have an NSE prefix.

## Names identify a family, not ownership

The pipeline derives names from its test ID:

| Component | Pattern | Example |
| --- | --- | --- |
| Simple namespace | `nse_<test_id>` | `nse_a1b2c3d4e5f6` |
| Router namespace | `nsr_<test_id>` | `nsr_a1b2c3d4e5f6` |
| Server namespace | `nss_<test_id>` | `nss_a1b2c3d4e5f6` |
| Host veth | `vhr-<first 8 characters>` | `vhr-a1b2c3d4` |
| Router host veth | `vrh-<first 8 characters>` | `vrh-a1b2c3d4` |
| Router server veth | `vrs-<first 8 characters>` | `vrs-a1b2c3d4` |
| Server veth | `vsr-<first 8 characters>` | `vsr-a1b2c3d4` |

`create_namespace(name)` continues to expose its interface names through
`sandbox.ext_iface` and `sandbox.peer_iface`. Neither these conventions nor
prefixes authorize deletion. Network address/name conflicts between otherwise
independent topologies still need compatible configuration.

## Private ownership journals

Creating a controller does not create network resources. Its first mutation
opens a private lease and writes a versioned journal under
`/run/nse/netns-<device>-<inode>/`, scoped to the calling thread's network
namespace. The runtime directory is mode 0700; journal and lock files are mode
0600, owned by the caller (root for real network operations).

Each controller has a random owner ID. Separate namespaces/experiments within
the controller have distinct run IDs; the router and server of one gateway
share a run ID. Each resource also has a fresh random token. The journal records
namespace identities, veth endpoints and locations, and host routes tied to
their owning link. PID, process start time and boot ID are diagnostics and scope
checks; **a PID is never the activity test**.

Every creation intent is written before the kernel operation. Updates use a
temporary file, flush/fsync, atomic replacement and directory fsync. A journal
is limited to 4 MiB; exceeding that limit refuses the next mutation before its
kernel operation. Symlinks, hard links, non-regular files, unexpected owners,
public permissions, unsupported schemas and inconsistent identities are
rejected. Journals contain resource data, not recovery commands to execute.

Keep the controller alive while using its resources. Its owner lock remains
held even between operations; normal cleanup does not release the controller
for reuse by a different owner. After the controller is discarded or its
process dies, startup recovery can acquire that lease and check the resources.

## Kernel identity checks

Namespace ownership combines the named namespace's device/inode identity with
a marker on its loopback interface. Veth endpoints carry a marker containing
owner ID, run ID and resource token in their interface alias. The lookup checks
the recorded namespace identity before entering it. A matching resource found
under a renamed interface can still be removed by its marker; a different
resource reusing its old name is preserved.

Some kernels ignore interface aliases supplied during veth creation. NSE
therefore assigns both endpoints fresh, locally administered unicast MACs in
the creation request, then applies the aliases explicitly. For a pending
creation interrupted before alias confirmation, recovery requires both
generated MACs and the mutual veth peer relationship in the recorded creation
namespace. One address or one name alone is insufficient. Once creation is
confirmed, the alias marker is required; the temporary MAC check cannot bypass
a missing or altered marker on a completed resource.

## Coordinated cleanup and recovery

`startup_sweep()` keeps its existing signature. Under a coordination lock shared
by all NSE controllers in that runtime scope, it:

1. Finds ownership journals and tries to acquire each owner lock without waiting.
2. Leaves live owners alone, including other controllers in the same process.
3. Validates an inactive owner's metadata and checks the actual kernel resources.
4. Removes verified links first, then namespace names. Routes attached to a
   deleted link disappear with it; unrelated routes are never explicitly deleted.
5. Persists unresolved entries for another attempt, removing the journal and its
   owner lock file only when all entries have been discharged.

The same coordination lock covers ordinary creation, journal changes and
teardown, preventing competing recoverers or new instances from racing through
an NSE mutation. These are cooperative locks: unrelated privileged tools do not
participate in them.

`destroy_netns(name)` now deletes only a namespace recorded by that controller
and still carrying the recorded identity/marker, along with its owned links.
`cleanup_all()` uses the same checks for all of that controller's resources.
Namespace deletion is retried up to three times, with 100 ms and 500 ms waits
between attempts. Failed deletion retains ownership and emits a warning;
`cleanup_all()` can retry it. Unresolved links keep their namespace recorded.

The method signatures and return types are unchanged. Consumers that used
`destroy_netns()` to remove a namespace created externally must manage that
external resource themselves.

## Forks, processes and conservative recovery

Lease descriptors are close-on-exec. After `os.fork()`, NSE closes the child's
inherited registry descriptors without unlocking the parent's shared file
description. An inherited controller cannot mutate ownership state: create a
new controller in the child. Reusing a controller from a different network
namespace is also rejected.

Removing a namespace name does not terminate processes holding that namespace.
This lifecycle manages network resources, not arbitrary applications or their
descendants. Application process ownership and termination are separate work.

Resources without sufficient proof stay untouched, with warnings:

- Legacy prefix matches from versions without journals require manual review.
- A crash between successful namespace creation and application of its first
  loopback marker leaves a recorded, unconfirmed intent. It cannot safely be
  distinguished from a reused name, so automatic recovery preserves it.
- Missing/corrupt metadata, changed markers, unavailable namespace locations or
  exhausted deletion retries preserve the unresolved entries.

Do not remove a journal to force deletion: it removes ownership evidence. Review
the journal and current kernel resources, then clean up only confirmed abandoned
objects. A running version 2.1.2 still has its old prefix sweep and can delete
resources belonging to 2.2.0; upgrade cooperating instances before running them
concurrently.

The regression suite exercises real traffic in two processes, normal teardown,
SIGKILL, recovery before veth alias application, unregistered prefix matches,
reused names, corrupt records, concurrent recoverers and fork inheritance.

For the underlying lock and namespace semantics, see
[flock(2)](https://man7.org/linux/man-pages/man2/flock.2.html) and
[ip-netns(8)](https://man7.org/linux/man-pages/man8/ip-netns.8.html).
