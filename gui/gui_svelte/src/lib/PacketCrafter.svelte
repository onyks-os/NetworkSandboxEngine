<script>
  /**
   * PacketCrafter — form for defining L3/L4 packet properties and sequences.
   *
   * Bound to the `packets` and `topology` stores.
   */
  import { packets, topology } from "../stores/testStore.js";

  let activeIndex = 0;

  const protocols = ["tcp", "udp", "icmp"];
  const tcpFlagOptions = [
    { label: "SYN", value: "S" },
    { label: "ACK", value: "A" },
    { label: "FIN", value: "F" },
    { label: "RST", value: "R" },
    { label: "PSH", value: "P" },
    { label: "URG", value: "U" },
  ];

  function addPacket() {
    packets.update((list) => {
      const last = list[list.length - 1];
      return [
        ...list,
        {
          protocol: last?.protocol || "tcp",
          src_ip: last?.src_ip || ($topology === "gateway" ? "10.0.1.1" : "10.0.0.1"),
          dst_ip: last?.dst_ip || ($topology === "gateway" ? "10.0.2.2" : "10.0.0.2"),
          src_port: last?.src_port || 12345,
          dst_port: last?.dst_port || 80,
          tcp_flags: last?.tcp_flags ? [...last.tcp_flags] : ["S"],
        },
      ];
    });
    // Set active index to new packet
    packets.subscribe((list) => {
      activeIndex = list.length - 1;
    })();
  }

  function removePacket(index, event) {
    event.stopPropagation();
    packets.update((list) => {
      if (list.length <= 1) return list;
      const newList = list.filter((_, i) => i !== index);
      if (activeIndex >= newList.length) {
        activeIndex = newList.length - 1;
      }
      return newList;
    });
  }

  function toggleFlag(flag) {
    packets.update((list) => {
      const spec = list[activeIndex];
      if (!spec) return list;
      const flags = spec.tcp_flags.includes(flag)
        ? spec.tcp_flags.filter((f) => f !== flag)
        : [...spec.tcp_flags, flag];
      list[activeIndex] = { ...spec, tcp_flags: flags };
      return [...list];
    });
  }

  function setProtocol(proto) {
    packets.update((list) => {
      const spec = list[activeIndex];
      if (!spec) return list;
      list[activeIndex] = { ...spec, protocol: proto };
      return [...list];
    });
  }

  function setTopology(top) {
    topology.set(top);
    // Auto-align IPs to topology defaults
    packets.update((list) => {
      return list.map((spec) => {
        let src = spec.src_ip;
        let dst = spec.dst_ip;
        if (top === "gateway") {
          if (src === "10.0.0.1" || src === "10.0.0.2") src = "10.0.1.1";
          if (dst === "10.0.0.2" || dst === "10.0.0.1") dst = "10.0.2.2";
        } else {
          if (src === "10.0.1.1" || src === "10.0.2.2") src = "10.0.0.1";
          if (dst === "10.0.2.2" || dst === "10.0.1.1") dst = "10.0.0.2";
        }
        return { ...spec, src_ip: src, dst_ip: dst };
      });
    });
  }

  $: currentPacket = $packets[activeIndex] || {};
  $: showPorts = currentPacket.protocol === "tcp" || currentPacket.protocol === "udp";
  $: showFlags = currentPacket.protocol === "tcp";
</script>

<div class="crafter-wrapper">
  <!-- Section 1: Topology -->
  <div class="crafter-header">
    <span class="crafter-title">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <rect x="2" y="2" width="20" height="8" rx="2" ry="2"></rect>
        <rect x="2" y="14" width="20" height="8" rx="2" ry="2"></rect>
        <line x1="6" y1="10" x2="6" y2="14"></line>
        <line x1="18" y1="10" x2="18" y2="14"></line>
      </svg>
      Topology Config
    </span>
  </div>

  <div class="topology-box">
    <div class="topo-buttons">
      <button
        class="topo-btn"
        class:active={$topology === "simple"}
        on:click={() => setTopology("simple")}
      >
        Simple
        <span class="topo-desc">Host ◄─► Netns</span>
      </button>
      <button
        class="topo-btn"
        class:active={$topology === "gateway"}
        on:click={() => setTopology("gateway")}
      >
        Gateway
        <span class="topo-desc">Host ◄─► Router ◄─► Server</span>
      </button>
    </div>
  </div>

  <!-- Section 2: Packet Sequence List -->
  <div class="crafter-header secondary">
    <span class="crafter-title">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <line x1="8" y1="6" x2="21" y2="6"></line>
        <line x1="8" y1="12" x2="21" y2="12"></line>
        <line x1="8" y1="18" x2="21" y2="18"></line>
        <line x1="3" y1="6" x2="3.01" y2="6"></line>
        <line x1="3" y1="12" x2="3.01" y2="12"></line>
        <line x1="3" y1="18" x2="3.01" y2="18"></line>
      </svg>
      Packet Sequence
    </span>
    <button class="add-packet-btn" on:click={addPacket}>+ Add</button>
  </div>

  <div class="packets-list-container">
    {#each $packets as pkt, index}
      <div
        class="packet-item"
        class:active={activeIndex === index}
        on:click={() => (activeIndex = index)}
        on:keydown={(e) => { if (e.key === "Enter" || e.key === " ") { activeIndex = index; } }}
        role="button"
        tabindex="0"
      >
        <div class="packet-info">
          <span class="packet-num">#{index + 1}</span>
          <span class="packet-proto badge-{pkt.protocol}">{pkt.protocol.toUpperCase()}</span>
          <span class="packet-addr-summary">{pkt.src_ip} ➔ {pkt.dst_ip}</span>
        </div>
        {#if $packets.length > 1}
          <button
            class="delete-packet-btn"
            on:click={(e) => removePacket(index, e)}
            title="Delete packet"
          >
            &times;
          </button>
        {/if}
      </div>
    {/each}
  </div>

  <!-- Section 3: Active Packet Editor -->
  <div class="crafter-header secondary">
    <span class="crafter-title">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <path d="M12 20h9"></path>
        <path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"></path>
      </svg>
      Edit Packet #{activeIndex + 1}
    </span>
  </div>

  <div class="crafter-body">
    <!-- Protocol selector -->
    <fieldset class="field-group">
      <legend class="field-legend">Protocol</legend>
      <div class="proto-pills">
        {#each protocols as proto}
          <button
            class="proto-pill"
            class:active={currentPacket.protocol === proto}
            on:click={() => setProtocol(proto)}
            id="proto-{proto}"
          >
            {proto.toUpperCase()}
          </button>
        {/each}
      </div>
    </fieldset>

    <!-- IP addresses -->
    <div class="fields-row">
      <div class="field">
        <label class="field-label" for="src-ip">Source IP</label>
        <input
          id="src-ip"
          class="field-input"
          type="text"
          bind:value={currentPacket.src_ip}
          placeholder="10.0.0.1"
          spellcheck="false"
        />
      </div>
      <div class="field-arrow">
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
          <line x1="5" y1="12" x2="19" y2="12"></line>
          <polyline points="12 5 19 12 12 19"></polyline>
        </svg>
      </div>
      <div class="field">
        <label class="field-label" for="dst-ip">Destination IP</label>
        <input
          id="dst-ip"
          class="field-input"
          type="text"
          bind:value={currentPacket.dst_ip}
          placeholder="10.0.0.2"
          spellcheck="false"
        />
      </div>
    </div>

    <!-- Ports (TCP/UDP only) -->
    {#if showPorts}
      <div class="fields-row">
        <div class="field">
          <label class="field-label" for="src-port">Src Port</label>
          <input
            id="src-port"
            class="field-input"
            type="number"
            min="1"
            max="65535"
            bind:value={currentPacket.src_port}
            placeholder="12345"
          />
        </div>
        <div class="field-arrow">➔</div>
        <div class="field">
          <label class="field-label" for="dst-port">Dst Port</label>
          <input
            id="dst-port"
            class="field-input"
            type="number"
            min="1"
            max="65535"
            bind:value={currentPacket.dst_port}
            placeholder="80"
          />
        </div>
      </div>
    {/if}

    <!-- TCP Flags -->
    {#if showFlags}
      <fieldset class="field-group">
        <legend class="field-legend">TCP Flags</legend>
        <div class="flags-row">
          {#each tcpFlagOptions as { label, value }}
            <button
              class="flag-btn"
              class:active={currentPacket.tcp_flags?.includes(value)}
              on:click={() => toggleFlag(value)}
              id="flag-{value}"
              title="{label} flag"
            >
              {label}
            </button>
          {/each}
        </div>
      </fieldset>
    {/if}
  </div>
</div>

<style>
  .crafter-wrapper {
    display: flex;
    flex-direction: column;
    background: var(--surface-1);
    border-radius: var(--radius-lg);
    border: 1px solid var(--border);
    overflow: hidden;
    height: 100%;
  }

  .crafter-header {
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

  .crafter-header.secondary {
    border-top: 1px solid var(--border);
  }

  .crafter-title {
    display: flex;
    align-items: center;
    gap: 0.4rem;
    color: var(--text-secondary);
  }

  .topology-box {
    padding: 0.75rem;
    background: var(--surface-1);
  }

  .topo-buttons {
    display: flex;
    gap: 0.5rem;
  }

  .topo-btn {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 0.5rem;
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    color: var(--text-secondary);
    font-size: 0.78rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.15s ease;
  }

  .topo-btn:hover {
    border-color: var(--accent);
    background: var(--surface-3);
  }

  .topo-btn.active {
    border-color: var(--accent);
    background: var(--accent-subtle);
    color: var(--accent);
    box-shadow: 0 0 6px var(--accent-glow);
  }

  .topo-desc {
    font-size: 0.62rem;
    color: var(--text-muted);
    font-weight: 400;
    margin-top: 0.15rem;
  }

  .add-packet-btn {
    background: var(--accent);
    color: #000;
    border: none;
    border-radius: var(--radius-sm);
    padding: 0.15rem 0.5rem;
    font-size: 0.68rem;
    font-weight: 700;
    cursor: pointer;
    transition: background 0.15s ease;
  }

  .add-packet-btn:hover {
    background: var(--accent-hover);
  }

  .packets-list-container {
    max-height: 140px;
    overflow-y: auto;
    background: var(--surface-1);
    padding: 0.5rem;
    display: flex;
    flex-direction: column;
    gap: 0.35rem;
  }

  .packet-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0.45rem 0.6rem;
    border-radius: var(--radius-md);
    border: 1px solid var(--border);
    background: var(--surface-2);
    cursor: pointer;
    transition: all 0.15s ease;
  }

  .packet-item:hover {
    border-color: var(--text-muted);
    background: var(--surface-3);
  }

  .packet-item.active {
    border-color: var(--accent);
    background: rgba(0, 229, 255, 0.05);
  }

  .packet-info {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-family: "JetBrains Mono", monospace;
    font-size: 0.72rem;
  }

  .packet-num {
    color: var(--text-muted);
    font-weight: 600;
  }

  .packet-proto {
    padding: 0.1rem 0.35rem;
    border-radius: 4px;
    font-size: 0.6rem;
    font-weight: 700;
  }

  .badge-tcp {
    background: rgba(130, 170, 255, 0.15);
    color: #82aaff;
  }

  .badge-udp {
    background: rgba(195, 232, 141, 0.15);
    color: #c3e88d;
  }

  .badge-icmp {
    background: rgba(255, 203, 107, 0.15);
    color: #ffcb6b;
  }

  .packet-addr-summary {
    color: var(--text-secondary);
  }

  .delete-packet-btn {
    background: none;
    border: none;
    color: var(--text-muted);
    font-size: 1.1rem;
    cursor: pointer;
    line-height: 1;
    padding: 0 0.2rem;
    transition: color 0.15s ease;
  }

  .delete-packet-btn:hover {
    color: #f87171;
  }

  .crafter-body {
    padding: 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    flex: 1;
    overflow-y: auto;
  }

  .field-group {
    border: none;
    padding: 0;
    margin: 0;
  }

  .field-legend {
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    color: var(--text-muted);
    margin-bottom: 0.4rem;
    display: block;
  }

  .proto-pills {
    display: flex;
    gap: 0.4rem;
  }

  .proto-pill {
    flex: 1;
    padding: 0.35rem 0;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--surface-2);
    color: var(--text-muted);
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    cursor: pointer;
    transition: all 0.15s ease;
  }

  .proto-pill:hover {
    border-color: var(--accent);
    color: var(--accent);
  }

  .proto-pill.active {
    background: var(--accent-subtle);
    border-color: var(--accent);
    color: var(--accent);
  }

  .fields-row {
    display: flex;
    align-items: flex-end;
    gap: 0.5rem;
  }

  .field {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
  }

  .field-label {
    font-size: 0.68rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: var(--text-muted);
  }

  .field-input {
    background: var(--surface-2);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font-family: "JetBrains Mono", monospace;
    font-size: 0.82rem;
    padding: 0.4rem 0.55rem;
    outline: none;
    transition: border-color 0.15s ease;
    width: 100%;
    box-sizing: border-box;
  }

  .field-input:focus {
    border-color: var(--accent);
    box-shadow: 0 0 0 2px var(--accent-glow);
  }

  .field-input[type="number"]::-webkit-inner-spin-button,
  .field-input[type="number"]::-webkit-outer-spin-button {
    -webkit-appearance: none;
    margin: 0;
  }
  .field-input[type="number"] {
    -moz-appearance: textfield;
  }

  .field-arrow {
    color: var(--text-muted);
    font-size: 0.8rem;
    padding-bottom: 0.45rem;
    flex-shrink: 0;
    display: flex;
    align-items: center;
  }

  .flags-row {
    display: flex;
    gap: 0.3rem;
    flex-wrap: wrap;
  }

  .flag-btn {
    padding: 0.25rem 0.5rem;
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    background: var(--surface-2);
    color: var(--text-muted);
    font-size: 0.7rem;
    font-weight: 700;
    letter-spacing: 0.05em;
    cursor: pointer;
    transition: all 0.15s ease;
    font-family: inherit;
  }

  .flag-btn:hover {
    border-color: var(--accent);
    color: var(--accent);
  }

  .flag-btn.active {
    background: var(--accent-subtle);
    border-color: var(--accent);
    color: var(--accent);
    box-shadow: 0 0 6px var(--accent-glow);
  }
</style>
