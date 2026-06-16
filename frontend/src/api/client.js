/**
 * NSE API client
 *
 * submitTest(ruleText, packetSpec) → { test_id }
 * openTraceSocket(testId, { onEvent, onDone, onError }) → WebSocket
 */

const API_BASE = '/api'
const WS_BASE = `ws://${location.host}`

/**
 * Submit a new test run.
 *
 * @param {string} ruleText  - Raw nftables ruleset text
 * @param {Object} packetSpec - PacketSpec object
 * @returns {Promise<{test_id: string}>}
 */
export async function submitTest(ruleText, packetSpec) {
  const response = await fetch(`${API_BASE}/test`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      rules: ruleText,
      packet: packetSpec,
    }),
  })

  if (!response.ok) {
    const err = await response.json().catch(() => ({ detail: response.statusText }))
    throw Object.assign(new Error('Test submission failed'), { detail: err.detail })
  }

  return response.json()
}

/**
 * Open a WebSocket connection to stream trace events for a test.
 *
 * @param {string} testId
 * @param {{ onEvent: Function, onDone: Function, onError: Function }} handlers
 * @returns {WebSocket}
 */
export function openTraceSocket(testId, { onEvent, onDone, onError }) {
  // In dev, Vite proxies /ws → ws://127.0.0.1:8000/ws
  // In prod, the URL is on the same origin
  const url = `${WS_BASE}/ws/${testId}`
  const ws = new WebSocket(url)

  ws.addEventListener('message', (ev) => {
    let data
    try {
      data = JSON.parse(ev.data)
    } catch {
      console.warn('[NSE] Received non-JSON WS message:', ev.data)
      return
    }

    if (data.type === 'done') {
      onDone?.()
      ws.close()
    } else if (data.type === 'error') {
      onError?.(data)
    } else if (data.type === 'ping') {
      // keep-alive — ignore
    } else {
      onEvent?.(data)
    }
  })

  ws.addEventListener('error', (ev) => {
    console.error('[NSE] WebSocket error:', ev)
    onError?.({ type: 'error', raw_message: 'WebSocket connection error' })
  })

  ws.addEventListener('close', () => {
    onDone?.()
  })

  return ws
}

/**
 * Fetch the status of a test.
 *
 * @param {string} testId
 * @returns {Promise<{test_id: string, status: string}>}
 */
export async function getTestStatus(testId) {
  const response = await fetch(`${API_BASE}/test/${testId}`)
  if (!response.ok) throw new Error(`Status check failed: ${response.statusText}`)
  return response.json()
}
