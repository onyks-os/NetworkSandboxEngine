<script>
  /**
   * Pipeline — the visualizer showing nftables rule trace and live conntrack table.
   *
   * Displays either the rule trace cascade or the live nf_conntrack state.
   */
  import {
    traceEvents,
    connectionStatus,
    ruleText,
  } from "../stores/testStore.js";

  let activeTab = "trace"; // "trace" | "conntrack"

  // Derive rule lines from the current rule text for display
  $: ruleLines = $ruleText
    .split("\n")
    .map((line, i) => ({ index: i + 1, text: line.trim() }))
    .filter(
      (l) =>
        l.text &&
        !l.text.startsWith("#") &&
        !l.text.startsWith("{") &&
        l.text !== "}",
    );

  // Map of rule_handle → latest verdict for that rule
  $: handleVerdicts = $traceEvents.reduce((acc, ev) => {
    if (ev.rule_handle != null) {
      acc[ev.rule_handle] = ev.verdict ?? "match";
    }
    return acc;
  }, {});

  // Hooks fired (chain names)
  $: firedHooks = new Set(
    $traceEvents.filter((e) => e.type === "hook").map((e) => e.chain),
  );

  // Final verdict (last verdict event)
  $: finalVerdict =
    [...$traceEvents].reverse().find((e) => e.type === "verdict")?.verdict ??
    null;

  function verdictClass(verdict) {
    if (!verdict) return "";
    const v = verdict.toLowerCase();
    if (v === "accept") return "accept";
    if (v === "drop" || v === "reject") return "drop";
    return "match";
  }

  $: isStreaming =
    $connectionStatus === "streaming" || $connectionStatus === "connecting";
  $: isDone = $connectionStatus === "done";

  // Deduplicate and maintain live conntrack table state
  $: conntrackTable = $traceEvents.reduce((acc, ev) => {
    if (ev.type === "conntrack") {
      const key = `${ev.ct_proto}-${ev.ct_src}:${ev.ct_sport}-${ev.ct_dst}:${ev.ct_dport}`;
      acc[key] = {
        proto: ev.ct_proto,
        src: ev.ct_src,
        sport: ev.ct_sport,
        dst: ev.ct_dst,
        dport: ev.ct_dport,
        state: ev.ct_state,
      };
    }
    return acc;
  }, {});

  $: conntrackEntries = Object.values(conntrackTable);

  function conntrackStateClass(state) {
    if (!state) return "ct-unknown";
    const s = state.toUpperCase();
    if (s === "ESTABLISHED" || s === "ASSURED") return "ct-established";
    if (s.startsWith("SYN_") || s.startsWith("SYN")) return "ct-syn";
    if (s.startsWith("FIN_") || s === "CLOSE" || s === "TIME_WAIT") return "ct-closed";
    return "ct-other";
  }
</script>

<div class="pipeline-wrapper">
  <div class="pipeline-header">
    <div class="tabs">
      <button
        class="tab-btn"
        class:active={activeTab === "trace"}
        on:click={() => (activeTab = "trace")}
      >
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
        </svg>
        Trace Log
      </button>
      <button
        class="tab-btn"
        class:active={activeTab === "conntrack"}
        on:click={() => (activeTab = "conntrack")}
      >
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
          <line x1="9" y1="9" x2="15" y2="9"></line>
          <line x1="9" y1="13" x2="15" y2="13"></line>
          <line x1="9" y1="17" x2="13" y2="17"></line>
        </svg>
        Conntrack Table
        {#if conntrackEntries.length > 0}
          <span class="tab-badge">{conntrackEntries.length}</span>
        {/if}
      </button>
    </div>
    <div class="pipeline-status">
      {#if isStreaming}
        <span class="status-dot streaming"></span>
        <span class="status-label">Live</span>
      {:else if isDone && finalVerdict}
        <span class="status-dot {verdictClass(finalVerdict)}"></span>
        <span class="status-label verdict-label">{finalVerdict}</span>
      {:else if isDone}
        <span class="status-dot idle"></span>
        <span class="status-label">Done</span>
      {:else}
        <span class="status-dot idle"></span>
        <span class="status-label">Idle</span>
      {/if}
    </div>
  </div>

  <div class="pipeline-body">
    <!-- TAB 1: TRACE VIEW -->
    {#if activeTab === "trace"}
      {#if $traceEvents.filter(e => e.type !== "conntrack").length === 0}
        <div class="empty-state">
          {#if isStreaming}
            <div class="waiting-spinner"></div>
            <p>Waiting for trace events…</p>
            <span class="empty-hint">Check daemon logs if this hangs</span>
          {:else if isDone}
            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.3">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="8" x2="12" y2="12"></line>
              <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
            <p>No trace events received</p>
            <span class="empty-hint">Make sure rules contain <code>meta nftrace set 1</code></span>
          {:else}
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.3">
              <circle cx="12" cy="12" r="10"></circle>
              <polyline points="8 12 12 16 16 12"></polyline>
              <line x1="12" y1="8" x2="12" y2="16"></line>
            </svg>
            <p>Run a test to see the trace pipeline</p>
          {/if}
        </div>
      {:else}
        <div class="event-list">
          {#each $traceEvents.filter(e => e.type !== "conntrack") as event, i (i)}
            <div
              class="event-node event-{event.type} {event.verdict
                ? verdictClass(event.verdict)
                : ''}"
              class:animate={isStreaming && i === $traceEvents.length - 1}
            >
              {#if i < $traceEvents.filter(e => e.type !== "conntrack").length - 1}
                <div class="connector"></div>
              {/if}

              <div class="event-icon">
                {#if event.type === "hook"}
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
                    <polyline points="5 12 12 5 19 12"></polyline>
                  </svg>
                {:else if event.type === "match"}
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
                    <polyline points="20 6 9 17 4 12"></polyline>
                  </svg>
                {:else if event.type === "verdict"}
                  {#if event.verdict === "ACCEPT"}
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor">
                      <circle cx="12" cy="12" r="9" />
                    </svg>
                  {:else}
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
                      <line x1="18" y1="6" x2="6" y2="18"></line>
                      <line x1="6" y1="6" x2="18" y2="18"></line>
                    </svg>
                  {/if}
                {:else if event.type === "error"}
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="12" y1="8" x2="12" y2="12"></line>
                    <line x1="12" y1="16" x2="12.01" y2="16"></line>
                  </svg>
                {/if}
              </div>

              <div class="event-body">
                <div class="event-type-row">
                  {#if event.type === 'hook'}
                    <span class="event-type">Hook Entered</span>
                    <span class="event-chain">{event.table}/{event.chain}</span>
                  {:else if event.type === 'match'}
                    <span class="event-type">Rule Match</span>
                    <span class="event-chain">{event.table}/{event.chain}</span>
                    {#if event.rule_handle != null}
                      <span class="event-handle">handle {event.rule_handle}</span>
                    {/if}
                    {#if event.verdict}
                      <span class="verdict-badge {verdictClass(event.verdict)}">{event.verdict}</span>
                    {/if}
                  {:else if event.type === 'verdict'}
                    <span class="event-type">Final Verdict</span>
                    <span class="event-chain">{event.table}/{event.chain}</span>
                    <span class="verdict-badge {verdictClass(event.verdict)}">{event.verdict}</span>
                  {:else if event.type === 'error'}
                    <span class="event-type">Pipeline Error</span>
                  {/if}
                </div>

                {#if event.type === 'hook'}
                  <div class="event-desc">
                    Packet entered chain <span class="highlight">{event.chain}</span> (table <span class="highlight">{event.table}</span>)
                  </div>
                {:else if event.type === 'match' && event.rule_text}
                  <div class="event-rule-text">{event.rule_text}</div>
                {:else if event.type === 'verdict'}
                  <div class="event-desc">
                    Ruleset evaluation completed with verdict <span class="highlight verdict-{verdictClass(event.verdict)}">{event.verdict}</span>
                  </div>
                {:else if event.type === 'error' && event.raw_message}
                  <div class="event-error-msg">{event.raw_message}</div>
                {/if}
              </div>
            </div>
          {/each}
        </div>
      {/if}

    <!-- TAB 2: CONNTRACK VIEW -->
    {:else if activeTab === "conntrack"}
      {#if conntrackEntries.length === 0}
        <div class="empty-state">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" opacity="0.3">
            <rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect>
            <circle cx="12" cy="12" r="3"></circle>
          </svg>
          <p>Conntrack table is currently empty</p>
          <span class="empty-hint">Establish TCP flows or UDP packets to track connections</span>
        </div>
      {:else}
        <div class="conntrack-container">
          <table class="ct-table">
            <thead>
              <tr>
                <th>Proto</th>
                <th>Source Address</th>
                <th>Destination Address</th>
                <th>State</th>
              </tr>
            </thead>
            <tbody>
              {#each conntrackEntries as entry}
                <tr>
                  <td>
                    <span class="proto-badge badge-{entry.proto.toLowerCase()}">{entry.proto}</span>
                  </td>
                  <td class="addr-cell">
                    <span class="ip-addr">{entry.src}</span>
                    {#if entry.sport}
                      <span class="port">:{entry.sport}</span>
                    {/if}
                  </td>
                  <td class="addr-cell">
                    <span class="ip-addr">{entry.dst}</span>
                    {#if entry.dport}
                      <span class="port">:{entry.dport}</span>
                    {/if}
                  </td>
                  <td>
                    <span class="ct-state-badge {conntrackStateClass(entry.state)}">{entry.state}</span>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>
      {/if}
    {/if}
  </div>
</div>

<style>
  .pipeline-wrapper {
    display: flex;
    flex-direction: column;
    background: var(--surface-1);
    border-radius: var(--radius-lg);
    border: 1px solid var(--border);
    overflow: hidden;
    height: 100%;
  }

  .pipeline-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.4rem 1rem;
    background: var(--surface-2);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }

  .tabs {
    display: flex;
    gap: 0.25rem;
  }

  .tab-btn {
    display: flex;
    align-items: center;
    gap: 0.35rem;
    background: none;
    border: none;
    border-radius: var(--radius-md);
    padding: 0.35rem 0.65rem;
    font-size: 0.72rem;
    font-weight: 700;
    color: var(--text-muted);
    cursor: pointer;
    transition: all 0.15s ease;
    letter-spacing: 0.02em;
  }

  .tab-btn:hover {
    color: var(--text-secondary);
    background: var(--surface-3);
  }

  .tab-btn.active {
    color: var(--accent);
    background: var(--accent-subtle);
  }

  .tab-badge {
    background: var(--accent);
    color: #000;
    font-size: 0.6rem;
    font-weight: 800;
    border-radius: 10px;
    padding: 0.05rem 0.3rem;
    line-height: 1;
    margin-left: 0.2rem;
  }

  .pipeline-status {
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }

  .status-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    background: var(--text-muted);
  }

  .status-dot.streaming {
    background: #4ade80;
    box-shadow: 0 0 6px #4ade80;
    animation: pulse 1s ease-in-out infinite;
  }

  .status-dot.accept {
    background: #4ade80;
  }
  .status-dot.drop {
    background: #f87171;
  }
  .status-dot.idle {
    background: var(--text-muted);
  }

  .status-label {
    font-size: 0.68rem;
    color: var(--text-muted);
  }

  .verdict-label {
    font-weight: 700;
    letter-spacing: 0.05em;
  }

  @keyframes pulse {
    0%,
    100% {
      opacity: 1;
      transform: scale(1);
    }
    50% {
      opacity: 0.5;
      transform: scale(0.85);
    }
  }

  .pipeline-body {
    flex: 1;
    overflow-y: auto;
    padding: 1rem;
    min-height: 0;
  }

  .empty-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    height: 100%;
    gap: 0.75rem;
    color: var(--text-muted);
    font-size: 0.8rem;
    text-align: center;
    padding: 1rem;
  }

  .empty-hint {
    font-size: 0.68rem;
    color: var(--text-muted);
    opacity: 0.7;
  }

  .empty-hint code {
    font-family: 'JetBrains Mono', monospace;
    background: var(--surface-2);
    padding: 0.1em 0.3em;
    border-radius: 3px;
    color: var(--accent-hover);
  }

  .waiting-spinner {
    width: 24px;
    height: 24px;
    border: 2px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }

  .event-list {
    display: flex;
    flex-direction: column;
    gap: 0.8rem;
  }

  .event-node {
    display: flex;
    align-items: flex-start;
    gap: 1rem;
    padding: 0.9rem 1.2rem;
    border-radius: var(--radius-md);
    border: 1px solid var(--border);
    background: var(--surface-2);
    position: relative;
    transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
    box-shadow: var(--shadow-sm);
  }

  .event-node:hover {
    border-color: rgba(255, 255, 255, 0.15);
    transform: translateY(-1px);
    box-shadow: var(--shadow-md);
  }

  .event-node.event-hook {
    background: linear-gradient(135deg, rgba(6, 182, 212, 0.1), rgba(6, 182, 212, 0.02));
    border-color: rgba(6, 182, 212, 0.35);
    box-shadow: 0 4px 12px rgba(6, 182, 212, 0.04);
  }
  
  .event-node.event-match {
    background: linear-gradient(135deg, rgba(99, 102, 241, 0.1), rgba(99, 102, 241, 0.02));
    border-color: rgba(99, 102, 241, 0.35);
    box-shadow: 0 4px 12px rgba(99, 102, 241, 0.04);
  }
  
  .event-node.accept {
    background: linear-gradient(135deg, rgba(16, 185, 129, 0.12), rgba(16, 185, 129, 0.02));
    border-color: rgba(16, 185, 129, 0.5);
    box-shadow: 0 4px 16px rgba(16, 185, 129, 0.08);
  }
  
  .event-node.drop {
    background: linear-gradient(135deg, rgba(244, 63, 94, 0.12), rgba(244, 63, 94, 0.02));
    border-color: rgba(244, 63, 94, 0.5);
    box-shadow: 0 4px 16px rgba(244, 63, 94, 0.08);
  }
  
  .event-node.event-error {
    background: linear-gradient(135deg, rgba(244, 63, 94, 0.12), rgba(244, 63, 94, 0.02));
    border-color: rgba(244, 63, 94, 0.5);
    box-shadow: 0 4px 16px rgba(244, 63, 94, 0.08);
  }

  .event-node.animate {
    animation: node-pop 0.35s cubic-bezier(0.16, 1, 0.3, 1);
  }

  @keyframes node-pop {
    0% {
      transform: translateY(-8px) scale(0.98);
      opacity: 0;
    }
    100% {
      transform: translateY(0) scale(1);
      opacity: 1;
    }
  }

  .event-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border-radius: 50%;
    flex-shrink: 0;
    z-index: 2;
    box-shadow: 0 2px 6px rgba(0, 0, 0, 0.2);
  }

  .event-node.event-hook .event-icon {
    color: #22d3ee;
    background: rgba(6, 182, 212, 0.22);
    border: 1px solid rgba(6, 182, 212, 0.4);
  }
  .event-node.event-match .event-icon {
    color: #818cf8;
    background: rgba(99, 102, 241, 0.22);
    border: 1px solid rgba(99, 102, 241, 0.4);
  }
  .event-node.accept .event-icon {
    color: #34d399;
    background: rgba(16, 185, 129, 0.22);
    border: 1px solid rgba(16, 185, 129, 0.45);
  }
  .event-node.drop .event-icon {
    color: #fb7185;
    background: rgba(244, 63, 94, 0.22);
    border: 1px solid rgba(244, 63, 94, 0.45);
  }
  .event-node.event-error .event-icon {
    color: #fb7185;
    background: rgba(244, 63, 94, 0.22);
    border: 1px solid rgba(244, 63, 94, 0.45);
  }

  .event-body {
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
    min-width: 0;
    flex: 1;
  }

  .event-type-row {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
  }

  .event-type {
    font-size: 0.72rem;
    font-weight: 800;
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  .event-node.event-hook .event-type { color: #22d3ee; }
  .event-node.event-match .event-type { color: #818cf8; }
  .event-node.accept .event-type { color: #34d399; }
  .event-node.drop .event-type { color: #fb7185; }
  .event-node.event-error .event-type { color: #fb7185; }

  .event-chain,
  .event-handle {
    font-size: 0.72rem;
    font-family: "JetBrains Mono", monospace;
    color: var(--text-primary);
    background: rgba(255, 255, 255, 0.05);
    border: 1px solid var(--border);
    padding: 0.1rem 0.4rem;
    border-radius: 4px;
  }

  .verdict-badge {
    font-size: 0.72rem;
    font-weight: 800;
    letter-spacing: 0.08em;
    padding: 0.1rem 0.5rem;
    border-radius: 4px;
    border: 1px solid transparent;
    display: inline-flex;
    align-items: center;
  }
  .verdict-badge.accept {
    color: #34d399;
    background: rgba(16, 185, 129, 0.15);
    border-color: rgba(16, 185, 129, 0.3);
  }
  .verdict-badge.drop {
    color: #fb7185;
    background: rgba(244, 63, 94, 0.15);
    border-color: rgba(244, 63, 94, 0.3);
  }
  .verdict-badge.match {
    color: #818cf8;
    background: rgba(99, 102, 241, 0.15);
    border-color: rgba(99, 102, 241, 0.3);
  }

  .event-rule-text {
    font-family: "JetBrains Mono", monospace;
    font-size: 0.82rem;
    color: var(--text-primary);
    background: rgba(0, 0, 0, 0.2);
    border-left: 3px solid var(--accent);
    padding: 0.4rem 0.7rem;
    border-radius: 4px;
    margin-top: 0.15rem;
    line-height: 1.4;
    word-break: break-all;
  }

  .event-error-msg {
    font-family: "JetBrains Mono", monospace;
    font-size: 0.82rem;
    color: #fb7185;
    background: rgba(244, 63, 94, 0.06);
    border: 1px solid rgba(244, 63, 94, 0.2);
    padding: 0.4rem 0.7rem;
    border-radius: 4px;
    margin-top: 0.15rem;
    word-break: break-all;
  }

  .event-desc {
    font-size: 0.8rem;
    color: var(--text-secondary);
    line-height: 1.4;
    margin-top: 0.15rem;
  }

  .event-desc .highlight {
    color: var(--text-primary);
    font-weight: 600;
  }

  .event-desc .highlight.verdict-accept {
    color: #34d399;
  }

  .event-desc .highlight.verdict-drop {
    color: #fb7185;
  }

  .connector {
    position: absolute;
    left: calc(1.2rem + 16px - 1px);
    top: calc(0.9rem + 32px);
    height: calc(100% - 32px + 0.8rem);
    width: 2px;
    background: linear-gradient(to bottom, var(--border) 40%, rgba(255, 255, 255, 0.02));
    z-index: 1;
    pointer-events: none;
  }

  /* --- Conntrack Style --- */
  .conntrack-container {
    overflow-x: auto;
    width: 100%;
  }

  .ct-table {
    width: 100%;
    border-collapse: collapse;
    font-family: "Inter", sans-serif;
    font-size: 0.78rem;
    text-align: left;
  }

  .ct-table th {
    color: var(--text-muted);
    font-weight: 600;
    text-transform: uppercase;
    font-size: 0.65rem;
    letter-spacing: 0.05em;
    padding: 0.5rem 0.75rem;
    border-bottom: 1px solid var(--border);
  }

  .ct-table td {
    padding: 0.6rem 0.75rem;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
  }

  .proto-badge {
    padding: 0.1rem 0.35rem;
    border-radius: 4px;
    font-size: 0.6rem;
    font-weight: 700;
    font-family: "JetBrains Mono", monospace;
  }

  .badge-tcp {
    background: rgba(130, 170, 255, 0.15);
    color: #82aaff;
  }

  .badge-udp {
    background: rgba(195, 232, 141, 0.15);
    color: #c3e88d;
  }

  .addr-cell {
    font-family: "JetBrains Mono", monospace;
  }

  .ip-addr {
    color: var(--text-primary);
  }

  .port {
    color: var(--text-muted);
  }

  .ct-state-badge {
    padding: 0.15rem 0.45rem;
    border-radius: 12px;
    font-size: 0.62rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.02em;
    display: inline-block;
  }

  .ct-established {
    background: rgba(74, 222, 128, 0.15);
    color: #4ade80;
  }

  .ct-syn {
    background: rgba(253, 224, 71, 0.15);
    color: #fde047;
  }

  .ct-closed {
    background: rgba(248, 113, 113, 0.15);
    color: #f87171;
  }

  .ct-other {
    background: rgba(255, 255, 255, 0.08);
    color: var(--text-secondary);
  }
</style>
