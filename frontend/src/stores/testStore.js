/**
 * Global Svelte stores for NSE test state.
 *
 * Stores are imported by all three main components (RuleEditor, PacketCrafter,
 * Pipeline) so they share a single source of truth without prop drilling.
 */

import { writable, derived } from 'svelte/store'

// --- Packet specification (bound to PacketCrafter form) ---
export const packetSpec = writable({
  protocol: 'tcp',
  src_ip: '10.0.0.1',
  dst_ip: '10.0.0.2',
  src_port: 12345,
  dst_port: 80,
  tcp_flags: ['S'],
})

// --- Rule editor content ---
export const ruleText = writable(
  `table ip filter {
  chain input {
    type filter hook input priority 0; policy drop;
    meta nftrace set 1
    tcp dport 80 accept
    tcp dport 22 accept
  }
}`,
)

// --- Test lifecycle ---
/** @type {import('svelte/store').Writable<string|null>} */
export const testId = writable(null)

/**
 * Connection status: 'idle' | 'submitting' | 'connecting' | 'streaming' | 'done' | 'error'
 * @type {import('svelte/store').Writable<string>}
 */
export const connectionStatus = writable('idle')

/**
 * Array of TraceEvent objects received from the WebSocket.
 * @type {import('svelte/store').Writable<Array>}
 */
export const traceEvents = writable([])

/**
 * Error detail object (if any).
 * @type {import('svelte/store').Writable<Object|null>}
 */
export const lastError = writable(null)

// --- Derived ---

/** True when the daemon is actively streaming events. */
export const isStreaming = derived(
  connectionStatus,
  ($s) => $s === 'streaming' || $s === 'connecting',
)

/** Rule error list (from HTTP 400 response), if any. */
export const ruleErrors = writable([])

/** Reset all test-run state to initial values. */
export function resetTest() {
  testId.set(null)
  connectionStatus.set('idle')
  traceEvents.set([])
  lastError.set(null)
  ruleErrors.set([])
}
