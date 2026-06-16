<script>
  /**
   * RuleEditor — nftables rule text editor with syntax highlighting overlay.
   *
   * Uses a textarea for input and a <pre> overlay for highlighting.
   * The overlay is positioned absolutely over the textarea and receives
   * pointer-events: none so clicks pass through to the textarea.
   */
  import { ruleText, ruleErrors } from "../stores/testStore.js";

  /** Tokenise a line of nftables text into highlighted HTML. */
  function highlight(text) {
    // Escape HTML first to avoid XSS in the overlay
    const escaped = text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");

    return (
      escaped
        // Comments
        .replace(/(#[^\n]*)/g, '<span class="hl-comment">$1</span>')
        // Keywords
        .replace(
          /\b(table|chain|type|hook|policy|priority|accept|drop|reject|return|jump|goto|add|delete|flush|list|ruleset|meta|nftrace|set|ct|state|established|related|new|invalid)\b/g,
          '<span class="hl-keyword">$1</span>',
        )
        // Families
        .replace(
          /\b(ip|ip6|inet|arp|bridge|netdev)\b/g,
          '<span class="hl-family">$1</span>',
        )
        // Protocols
        .replace(
          /\b(tcp|udp|icmp|icmpv6|udplite|sctp|dccp)\b/g,
          '<span class="hl-protocol">$1</span>',
        )
        // Hooks
        .replace(
          /\b(prerouting|input|forward|output|postrouting|ingress)\b/g,
          '<span class="hl-hook">$1</span>',
        )
        // Numbers (port numbers, priorities)
        .replace(/\b(\d+)\b/g, '<span class="hl-number">$1</span>')
        // IP-like strings
        .replace(
          /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:\/\d{1,2})?)\b/g,
          '<span class="hl-ip">$1</span>',
        )
        // Braces
        .replace(/([{}])/g, '<span class="hl-brace">$1</span>')
    );
  }

  /** Split text into lines and highlight each one. */
  function highlightAll(text) {
    return text
      .split("\n")
      .map((line) => highlight(line))
      .join("\n");
  }

  function handleKeyDown(e) {
    // Insert 2 spaces on Tab
    if (e.key === "Tab") {
      e.preventDefault();
      const el = e.target;
      const start = el.selectionStart;
      const end = el.selectionEnd;
      $ruleText =
        $ruleText.substring(0, start) + "  " + $ruleText.substring(end);
      // Restore cursor position after Svelte re-renders
      requestAnimationFrame(() => {
        el.selectionStart = el.selectionEnd = start + 2;
      });
    }
  }
</script>

<div class="editor-wrapper">
  <div class="editor-header">
    <span class="editor-title">
      <svg
        width="14"
        height="14"
        viewBox="0 0 24 24"
        fill="none"
        stroke="currentColor"
        stroke-width="2"
      >
        <polyline points="16 18 22 12 16 6"></polyline>
        <polyline points="8 6 2 12 8 18"></polyline>
      </svg>
      nftables Ruleset
    </span>
    <span class="editor-badge">nft</span>
  </div>

  <div class="editor-body">
    <!-- Syntax highlight overlay (pointer-events: none) -->
    <pre class="highlight-overlay" aria-hidden="true">{@html highlightAll(
        $ruleText,
      )}<br /></pre>

    <!-- Actual editable textarea — invisible text on top of overlay -->
    <textarea
      class="rule-textarea"
      spellcheck="false"
      autocomplete="off"
      autocorrect="off"
      autocapitalize="off"
      bind:value={$ruleText}
      on:keydown={handleKeyDown}
      placeholder="Enter your nftables ruleset here…"
    ></textarea>
  </div>

  <!-- Inline rule errors from the daemon -->
  {#if $ruleErrors.length > 0}
    <div class="rule-errors">
      {#each $ruleErrors as err}
        <div class="rule-error-item">
          {#if err.line}
            <span class="err-line">Line {err.line}</span>
          {/if}
          <span class="err-msg"
            >{err.message ?? err.raw ?? JSON.stringify(err)}</span
          >
        </div>
      {/each}
    </div>
  {/if}
</div>

<style>
  .editor-wrapper {
    display: flex;
    flex-direction: column;
    height: 100%;
    background: var(--surface-1);
    border-radius: var(--radius-lg);
    border: 1px solid var(--border);
    overflow: hidden;
  }

  .editor-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.6rem 1rem;
    background: var(--surface-2);
    border-bottom: 1px solid var(--border);
    font-size: 0.75rem;
    font-weight: 600;
    color: var(--text-muted);
    letter-spacing: 0.04em;
    text-transform: uppercase;
    flex-shrink: 0;
  }

  .editor-title {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    color: var(--text-secondary);
  }

  .editor-badge {
    background: var(--accent-subtle);
    color: var(--accent);
    padding: 0.15rem 0.5rem;
    border-radius: 4px;
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.08em;
  }

  .editor-body {
    position: relative;
    flex: 1;
    overflow: hidden;
    min-height: 0;
  }

  .highlight-overlay,
  .rule-textarea {
    font-family: "JetBrains Mono", "Fira Code", "Cascadia Code", monospace;
    font-size: 0.82rem;
    line-height: 1.65;
    padding: 1rem;
    margin: 0;
    border: none;
    outline: none;
    white-space: pre;
    overflow: auto;
    tab-size: 2;
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    box-sizing: border-box;
  }

  .highlight-overlay {
    pointer-events: none;
    user-select: none;
    background: transparent;
    color: #e2e8f0; /* Default text color, high contrast */
    z-index: 1;
    overflow: hidden;
  }

  .rule-textarea {
    background: transparent;
    resize: none;
    z-index: 2;
    caret-color: var(--accent);
    /* Make the interactive text transparent so only the overlay color shows */
    color: transparent;
  }

  /* --- High Contrast Syntax Highlight Token Colours --- */
  :global(.hl-keyword) {
    color: #e0b0ff; /* Bright lavender */
    font-weight: 600;
  }
  :global(.hl-protocol) {
    color: #4ba3ff; /* Bright sky blue */
  }
  :global(.hl-family) {
    color: #00ffd0; /* Bright mint cyan */
  }
  :global(.hl-hook) {
    color: #ffd700; /* Vibrant gold */
    font-weight: 600;
  }
  :global(.hl-number) {
    color: #ff8c00; /* Vibrant orange */
  }
  :global(.hl-ip) {
    color: #00e5ff; /* Electric cyan */
  }
  :global(.hl-brace) {
    color: #ffffff; /* Pure white */
    font-weight: bold;
  }
  :global(.hl-comment) {
    color: #94a3b8; /* Lighter slate gray for high contrast */
    font-style: italic;
  }

  /* --- Error panel --- */
  .rule-errors {
    background: rgba(239, 68, 68, 0.08);
    border-top: 1px solid rgba(239, 68, 68, 0.3);
    padding: 0.5rem 1rem;
    max-height: 7rem;
    overflow-y: auto;
    flex-shrink: 0;
  }

  .rule-error-item {
    display: flex;
    align-items: baseline;
    gap: 0.6rem;
    font-size: 0.75rem;
    padding: 0.15rem 0;
    color: #f87171;
    font-family: "JetBrains Mono", monospace;
  }

  .err-line {
    color: #fca5a5;
    font-weight: 700;
    flex-shrink: 0;
  }

  .err-msg {
    color: #f87171;
    word-break: break-all;
  }
</style>
