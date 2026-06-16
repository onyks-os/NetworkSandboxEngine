<script>
  import RuleEditor from "./lib/RuleEditor.svelte";
  import PacketCrafter from "./lib/PacketCrafter.svelte";
  import Pipeline from "./lib/Pipeline.svelte";
  import DocsView from "./lib/DocsView.svelte";

  import {
    packets,
    topology,
    ruleText,
    testId,
    connectionStatus,
    traceEvents,
    lastError,
    ruleErrors,
    resetTest,
  } from "./stores/testStore.js";

  import { submitTest, openTraceSocket } from "./api/client.js";

  let activeSocket = null;
  let currentHash = window.location.hash || '#/';

  window.addEventListener('hashchange', () => {
    currentHash = window.location.hash || '#/';
  });

  async function runTest() {
    if (activeSocket) {
      activeSocket.close();
      activeSocket = null;
    }

    resetTest();
    connectionStatus.set("submitting");

    try {
      const { test_id } = await submitTest($ruleText, $packets, $topology);
      testId.set(test_id);
      connectionStatus.set('connecting');
      console.log('[NSE] Test accepted, id:', test_id);

      activeSocket = openTraceSocket(test_id, {
        onEvent(ev) {
          connectionStatus.set('streaming');
          console.log('[NSE] TraceEvent:', ev);
          traceEvents.update((events) => [...events, ev]);
        },
        onDone() {
          connectionStatus.set('done');
          console.log('[NSE] Test done');
          activeSocket = null;
        },
        onError(err) {
          connectionStatus.set('error');
          console.error('[NSE] WS error:', err);
          lastError.set(_extractMessage(err));
          traceEvents.update((events) => [
            ...events,
            { ...err, type: 'error' },
          ]);
        },
      });
    } catch (err) {
      connectionStatus.set('error');
      console.error('[NSE] Submit error:', err);

      // Extract a human-readable message from the error
      const msg = err.detail?.message
        ?? err.detail?.detail
        ?? (typeof err.detail === 'string' ? err.detail : null)
        ?? err.message
        ?? 'Unknown error';
      lastError.set(msg);

      // If the server returned structured rule errors, surface them in the editor
      if (err.detail?.errors) {
        ruleErrors.set(err.detail.errors);
      }
    }
  }

  $: isRunning =
    $connectionStatus === 'submitting' ||
    $connectionStatus === 'connecting' ||
    $connectionStatus === 'streaming';

  /** Extract a plain-text message from various error shapes. */
  function _extractMessage(err) {
    if (typeof err === 'string') return err;
    return err?.raw_message ?? err?.message ?? JSON.stringify(err);
  }
</script>

<svelte:head>
  <title>NSE — Network Sandbox Engine</title>
  <meta
    name="description"
    content="Visual, deterministic nftables rule tester using ephemeral Linux network namespaces."
  />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link
    href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap"
    rel="stylesheet"
  />
</svelte:head>

<!-- App shell -->
{#if currentHash === '#/docs'}
  <DocsView />
{:else}
  <div class="app">
  <!-- Header -->
  <header class="app-header">
    <div class="header-brand">
      <div class="brand-icon">
        <svg
          width="18"
          height="18"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          stroke-width="2"
        >
          <rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect>
          <line x1="8" y1="21" x2="16" y2="21"></line>
          <line x1="12" y1="17" x2="12" y2="21"></line>
        </svg>
      </div>
      <div>
        <h1 class="brand-name">Network Sandbox Engine</h1>
        <p class="brand-sub">nftables · netns · Scapy</p>
      </div>
    </div>

    <div class="header-actions">
      {#if $connectionStatus === "error"}
        <div class="status-pill error">
          <span class="pill-dot"></span>
          Error
        </div>
      {:else if isRunning}
        <div class="status-pill running">
          <span class="pill-dot pulse"></span>
          Running
        </div>
      {:else if $connectionStatus === "done"}
        <div class="status-pill done">
          <span class="pill-dot"></span>
          Done
        </div>
      {:else}
        <div class="status-pill idle">
          <span class="pill-dot"></span>
          Ready
        </div>
      {/if}

      <a
        href="#/docs"
        target="_blank"
        class="docs-btn"
        title="Open User Guide and interactive examples"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <circle cx="12" cy="12" r="10"></circle>
          <line x1="12" y1="16" x2="12" y2="12"></line>
          <line x1="12" y1="8" x2="12.01" y2="8"></line>
        </svg>
        Docs & Examples
      </a>

      <button
        class="run-btn"
        id="run-test-btn"
        on:click={runTest}
        disabled={isRunning}
        title="Submit test (requires daemon running with sudo)"
      >
        {#if isRunning}
          <svg
            class="spin"
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2.5"
          >
            <path d="M21 12a9 9 0 1 1-6.219-8.56"></path>
          </svg>
          Running…
        {:else}
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2.5"
          >
            <polygon points="5 3 19 12 5 21 5 3"></polygon>
          </svg>
          Run Test
        {/if}
      </button>
    </div>
  </header>

  <!-- Three-panel layout -->
  <main class="app-main">
    <!-- Left: Rule Editor -->
    <section class="panel panel-rules" aria-label="Rule editor">
      <RuleEditor />
    </section>

    <!-- Centre: Packet Crafter -->
    <section class="panel panel-crafter" aria-label="Packet crafter">
      <PacketCrafter />
    </section>

    <!-- Right: Pipeline Trace -->
    <section class="panel panel-pipeline" aria-label="Pipeline trace">
      <Pipeline />
    </section>
  </main>

  <!-- Error banner (shown below header when something goes wrong) -->
  {#if $connectionStatus === 'error' && $lastError}
    <div class="error-banner" role="alert">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" style="flex-shrink:0">
        <circle cx="12" cy="12" r="10"></circle>
        <line x1="12" y1="8" x2="12" y2="12"></line>
        <line x1="12" y1="16" x2="12.01" y2="16"></line>
      </svg>
      <span class="error-banner-msg">{$lastError}</span>
      <button class="error-banner-close" on:click={() => lastError.set(null)} aria-label="Dismiss">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <line x1="18" y1="6" x2="6" y2="18"></line>
          <line x1="6" y1="6" x2="18" y2="18"></line>
        </svg>
      </button>
    </div>
  {/if}

  <!-- Footer -->
  <footer class="app-footer">
    <span>Rules are injected into ephemeral <code>netns</code> — the host firewall is never touched.</span>
    {#if $testId}
      <span class="test-id">test: <code>{$testId}</code></span>
    {/if}
  </footer>
</div>
{/if}

<style>
  /* --- Layout --- */
  .app {
    display: flex;
    flex-direction: column;
    height: 100vh;
    overflow: hidden;
    background: var(--bg);
    color: var(--text-primary);
    font-family: "Inter", sans-serif;
  }

  /* --- Header --- */
  .app-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.75rem 1.5rem;
    background: var(--surface-1);
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
    gap: 1rem;
  }

  .header-brand {
    display: flex;
    align-items: center;
    gap: 0.75rem;
  }

  .brand-icon {
    width: 36px;
    height: 36px;
    border-radius: 8px;
    background: var(--accent-subtle);
    color: var(--accent);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  h1.brand-name {
    font-size: 0.95rem;
    font-weight: 700;
    margin: 0;
    color: var(--text-primary);
    letter-spacing: -0.01em;
  }

  .brand-sub {
    font-size: 0.65rem;
    color: var(--text-muted);
    margin: 0;
    font-family: "JetBrains Mono", monospace;
    letter-spacing: 0.04em;
  }

  /* --- Header actions --- */
  .header-actions {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    flex-shrink: 0;
  }

  .status-pill {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    padding: 0.25rem 0.65rem;
    border-radius: 20px;
    border: 1px solid var(--border);
    color: var(--text-muted);
  }

  .status-pill.running {
    border-color: rgba(74, 222, 128, 0.4);
    color: #4ade80;
    background: rgba(74, 222, 128, 0.08);
  }
  .status-pill.done {
    border-color: rgba(130, 170, 255, 0.4);
    color: #82aaff;
    background: rgba(130, 170, 255, 0.08);
  }
  .status-pill.error {
    border-color: rgba(248, 113, 113, 0.4);
    color: #f87171;
    background: rgba(248, 113, 113, 0.08);
  }
  .status-pill.idle {
    border-color: var(--border);
  }

  .pill-dot {
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: currentColor;
  }

  .pill-dot.pulse {
    animation: pulse 1s ease-in-out infinite;
  }

  @keyframes pulse {
    0%,
    100% {
      opacity: 1;
    }
    50% {
      opacity: 0.4;
    }
  }

  .run-btn {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    background: var(--accent);
    color: #000;
    border: none;
    border-radius: var(--radius-sm);
    padding: 0.5rem 1rem;
    font-size: 0.8rem;
    font-weight: 700;
    letter-spacing: 0.02em;
    cursor: pointer;
    transition: all 0.15s ease;
    font-family: "Inter", sans-serif;
  }

  .run-btn:hover:not(:disabled) {
    background: var(--accent-hover);
    transform: translateY(-1px);
    box-shadow: 0 4px 12px var(--accent-glow);
  }

  .run-btn:active:not(:disabled) {
    transform: translateY(0);
  }

  .run-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .docs-btn {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    background: var(--surface-2);
    color: var(--text-secondary);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 0.5rem 0.9rem;
    font-size: 0.8rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s ease;
    font-family: "Inter", sans-serif;
    text-decoration: none;
  }

  .docs-btn:hover {
    background: var(--surface-3);
    color: var(--text-primary);
    border-color: var(--text-muted);
  }

  .spin {
    animation: spin 0.8s linear infinite;
  }

  @keyframes spin {
    from {
      transform: rotate(0deg);
    }
    to {
      transform: rotate(360deg);
    }
  }

  /* --- Main panel grid --- */
  .app-main {
    display: grid;
    grid-template-columns: 1fr 280px 1fr;
    gap: 0.75rem;
    padding: 0.75rem;
    flex: 1;
    overflow: hidden;
    min-height: 0;
  }

  .panel {
    display: flex;
    flex-direction: column;
    min-height: 0;
    overflow: hidden;
  }

  /* --- Error banner --- */
  .error-banner {
    display: flex;
    align-items: center;
    gap: 0.6rem;
    padding: 0.5rem 1.5rem;
    background: rgba(248, 113, 113, 0.1);
    border-bottom: 1px solid rgba(248, 113, 113, 0.3);
    color: #f87171;
    font-size: 0.78rem;
    font-family: 'JetBrains Mono', monospace;
    flex-shrink: 0;
    animation: banner-slide 0.2s ease-out;
  }

  @keyframes banner-slide {
    from { transform: translateY(-100%); opacity: 0; }
    to   { transform: translateY(0);     opacity: 1; }
  }

  .error-banner-msg {
    flex: 1;
    word-break: break-word;
  }

  .error-banner-close {
    background: none;
    border: none;
    color: #f87171;
    cursor: pointer;
    padding: 0.2rem;
    display: flex;
    align-items: center;
    opacity: 0.7;
    flex-shrink: 0;
  }
  .error-banner-close:hover { opacity: 1; }

  /* --- Footer --- */
  .app-footer {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.4rem 1.5rem;
    font-size: 0.68rem;
    color: var(--text-muted);
    border-top: 1px solid var(--border);
    background: var(--surface-1);
    flex-shrink: 0;
    font-family: 'JetBrains Mono', monospace;
    gap: 1rem;
  }

  .test-id {
    color: var(--text-muted);
    opacity: 0.7;
  }

  /* --- Responsive: collapse centre panel on small screens --- */
  @media (max-width: 900px) {
    .app-main {
      grid-template-columns: 1fr;
      grid-template-rows: 1fr auto 1fr;
    }
  }
</style>
