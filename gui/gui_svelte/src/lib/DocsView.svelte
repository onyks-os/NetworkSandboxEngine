<script>
  import { ruleText, packets, topology } from "../stores/testStore.js";

  let activeSection = "overview"; // "overview" | "topologies" | "conntrack" | "cli" | "examples"

  const examplesList = [
    {
      name: "1. Basic Web Server Filter (Simple)",
      desc: "Loads a basic firewall that accepts HTTP (TCP 80) and SSH (TCP 22) traffic, dropping everything else. Tests with a TCP SYN packet to port 80.",
      topology: "simple",
      rules: `table ip filter {
  chain input {
    type filter hook input priority 0; policy drop;
    meta nftrace set 1
    tcp dport 80 accept
    tcp dport 22 accept
  }
}`,
      packets: [
        {
          protocol: "tcp",
          src_ip: "10.0.0.1",
          dst_ip: "10.0.0.2",
          src_port: 12345,
          dst_port: 80,
          tcp_flags: ["S"],
        }
      ]
    },
    {
      name: "2. Stateful TCP Handshake (Simple)",
      desc: "Uses stateful conntrack rules. Allows TCP SYN to port 80, and accepts subsequent packets only if connection state is established. Tests with a sequence: SYN -> ACK.",
      topology: "simple",
      rules: `table ip filter {
  chain input {
    type filter hook input priority 0; policy drop;
    meta nftrace set 1
    ct state established,related accept
    tcp dport 80 accept
  }
}`,
      packets: [
        {
          protocol: "tcp",
          src_ip: "10.0.0.1",
          dst_ip: "10.0.0.2",
          src_port: 54321,
          dst_port: 80,
          tcp_flags: ["S"],
        },
        {
          protocol: "tcp",
          src_ip: "10.0.0.1",
          dst_ip: "10.0.0.2",
          src_port: 54321,
          dst_port: 80,
          tcp_flags: ["A"],
        }
      ]
    },
    {
      name: "3. Gateway Transit Router (Gateway)",
      desc: "Simulates a transit network. Firewall rules live inside the Router. Evaluates transit packets in the forward chain. Tests with UDP dns query passing through.",
      topology: "gateway",
      rules: `table ip filter {
  chain forward {
    type filter hook forward priority 0; policy drop;
    meta nftrace set 1
    udp dport 53 accept
  }
}`,
      packets: [
        {
          protocol: "udp",
          src_ip: "10.0.1.1",
          dst_ip: "10.0.2.2",
          src_port: 33333,
          dst_port: 53,
          tcp_flags: [],
        }
      ]
    }
  ];

  function loadExample(ex) {
    ruleText.set(ex.rules);
    packets.set(ex.packets.map(p => ({...p})));
    topology.set(ex.topology);
    window.location.hash = "#/";
  }
</script>

<div class="docs-page">
  <!-- Top Navigation Header -->
  <header class="docs-header">
    <div class="docs-brand">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
        <circle cx="12" cy="12" r="10"></circle>
        <line x1="12" y1="16" x2="12" y2="12"></line>
        <line x1="12" y1="8" x2="12.01" y2="8"></line>
      </svg>
      <h2>NSE Offline Documentation</h2>
    </div>
    <a href="#/" class="back-btn">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5">
        <line x1="19" y1="12" x2="5" y2="12"></line>
        <polyline points="12 19 5 12 12 5"></polyline>
      </svg>
      Back to Sandbox
    </a>
  </header>

  <!-- Docs Layout -->
  <div class="docs-container">
    <!-- Sidebar -->
    <nav class="docs-sidebar">
      <button class="nav-btn" class:active={activeSection === "overview"} on:click={() => activeSection = "overview"}>
        1. Overview & Mechanics
      </button>
      <button class="nav-btn" class:active={activeSection === "topologies"} on:click={() => activeSection = "topologies"}>
        2. Network Topologies
      </button>
      <button class="nav-btn" class:active={activeSection === "conntrack"} on:click={() => activeSection = "conntrack"}>
        3. Stateful & Conntrack
      </button>
      <button class="nav-btn" class:active={activeSection === "cli"} on:click={() => activeSection = "cli"}>
        4. Headless CLI Runner
      </button>
      <button class="nav-btn" class:active={activeSection === "examples"} on:click={() => activeSection = "examples"}>
        5. Interactive Templates
      </button>
    </nav>

    <!-- Main Content Area -->
    <main class="docs-content">
      {#if activeSection === "overview"}
        <section>
          <h3>1. Overview & Core Mechanics</h3>
          <p>
            The <strong>Network Sandbox Engine (NSE)</strong> is a high-fidelity visual utility for testing and tracing <code>nftables</code> rulesets locally without modifying your host system's firewall configuration.
          </p>
          
          <h4>How it works under the hood:</h4>
          <ul>
            <li><strong>Isolated Sandboxing:</strong> Ephemeral Linux Network Namespaces (<code>netns</code>) are spawned dynamically per test run.</li>
            <li><strong>Virtual Ethernet Wiring:</strong> Virtual Ethernet interfaces (<code>veth</code>) connect the host to the target namespaces.</li>
            <li><strong>Auto-Tracing:</strong> The engine automatically instruments your rules with <code>meta nftrace set 1</code> in all chains to capture traces.</li>
            <li><strong>Packet Injection:</strong> Scapy builds and sends Layer 2/3 packets down the virtual wires.</li>
            <li><strong>Trace Harvesting:</strong> An async subprocess monitors trace reports directly from the kernel and maps matches back to your ruleset.</li>
          </ul>
          
          <div class="note-box">
            <strong>CRITICAL REQUIREMENT:</strong> The daemon must be run with <code>sudo</code> or root privileges since creating namespaces, interfaces, and loading firewall rules are restricted Linux kernel operations.
          </div>
        </section>
      {/if}

      {#if activeSection === "topologies"}
        <section>
          <h3>2. Network Topologies</h3>
          <p>NSE supports two visual topologies depending on what hooks you want to test:</p>
          
          <div class="topo-grid">
            <div class="topo-card">
              <h5>Simple Topology (Host ◄─► Sandbox)</h5>
              <p>Connects your host directly to a single namespace. Ideal for testing <strong>input</strong>, <strong>output</strong>, and local host policies. Link interfaces are configured with both IPv4 (<code>10.0.0.0/24</code>) and IPv6 (<code>fd00::/64</code>) addresses.</p>
            </div>
            <div class="topo-card">
              <h5>Gateway Topology (Host ◄─► Router ◄─► Server)</h5>
              <p>Spawns two namespaces (a Router and a Server) with transit routing. Rules are loaded on the Router. Perfect for testing transit traffic filtering (<strong>forward</strong> chain) and Source/Destination NAT translation rules.</p>
            </div>
          </div>

          <h4>IP Address Layouts:</h4>
          <pre><code># Simple Topology:
Host: 10.0.0.1 / fd00::1  ◄──►  Sandbox: 10.0.0.2 / fd00::2

# Gateway Topology:
Host: 10.0.1.1 / fd00:1::1
Router Host-Facing: 10.0.1.2 / fd00:1::2
Router Server-Facing: 10.0.2.1 / fd00:2::1
Server: 10.0.2.2 / fd00:2::2</code></pre>
        </section>
      {/if}

      {#if activeSection === "conntrack"}
        <section>
          <h3>3. Stateful Connections & Mock Listeners</h3>
          <p>To test stateful rules (such as <code>ct state established accept</code>), packets must be sent in sequence and the network stack must respond with reply packets to build connection tracking entries.</p>
          
          <h4>Active Mock Listeners</h4>
          <p>
            When you define packets destined for a port inside the sandbox (e.g. TCP port 80), the pipeline automatically spawns a background echo socket server (mock listener) inside that namespace.
          </p>
          <p>
            When a TCP SYN packet is injected, the kernel's network stack inside the sandbox responds with SYN-ACK, which completes the three-way handshake, establishing a connection tracked by the kernel's conntrack system.
          </p>

          <h4>Visualizing Conntrack Table</h4>
          <p>
            Select the <strong>Conntrack Table</strong> tab on the Pipeline panel to view live connection tables polled directly from <code>/proc/net/nf_conntrack</code>.
          </p>
        </section>
      {/if}

      {#if activeSection === "cli"}
        <section>
          <h3>4. Headless CLI Test Runner</h3>
          <p>NSE includes a command line runner for headless test suite execution in CI/CD pipelines.</p>
          
          <h4>Command:</h4>
          <pre><code>sudo PYTHONPATH=backend .venv/bin/python -m nse.cli test --file path/to/suite.yaml</code></pre>
          
          <h4>YAML Test Suite Format:</h4>
          <pre><code>tests:
  - name: "Allow HTTP and Block SSH"
    topology: "simple"
    rules: |
      table ip filter &#123;
        chain input &#123;
          type filter hook input priority 0; policy drop;
          tcp dport 80 accept
        &#125;
      &#125;
    packets:
      - protocol: "tcp"
        dst_port: 80
        expected_verdict: "ACCEPT"
      - protocol: "tcp"
        dst_port: 22
        expected_verdict: "DROP"</code></pre>
        </section>
      {/if}

      {#if activeSection === "examples"}
        <section>
          <h3>5. Load Interactive Templates</h3>
          <p>Click any of the examples below to immediately populate the rule editor, packet sequence, and topology configuration, then return back to the sandbox automatically.</p>
          
          <div class="examples-list">
            {#each examplesList as ex}
              <div class="example-card">
                <div class="ex-info">
                  <h5>{ex.name}</h5>
                  <p>{ex.desc}</p>
                </div>
                <button class="load-btn" on:click={() => loadExample(ex)}>Load Template</button>
              </div>
            {/each}
          </div>
        </section>
      {/if}
    </main>
  </div>
</div>

<style>
  /* High Contrast Style Sheet for Offline Docs */
  .docs-page {
    display: flex;
    flex-direction: column;
    height: 100vh;
    background: #090b0f; /* Deep background for rich contrast */
    color: #f3f4f6; /* Off-white for high legibility */
    font-family: "Inter", sans-serif;
  }

  .docs-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 1rem 2rem;
    background: #11151e; /* Distinct dark header */
    border-bottom: 2px solid #242b3b;
    flex-shrink: 0;
  }

  .docs-brand {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    color: #00e5ff; /* High brightness cyan */
  }

  .docs-brand h2 {
    font-size: 1.1rem;
    font-weight: 800;
    margin: 0;
    letter-spacing: -0.01em;
  }

  .back-btn {
    display: flex;
    align-items: center;
    gap: 0.45rem;
    background: #00e5ff;
    color: #000; /* Pure black text on bright background for maximum contrast */
    border: none;
    border-radius: var(--radius-sm);
    padding: 0.5rem 1.1rem;
    font-size: 0.82rem;
    font-weight: 700;
    text-decoration: none;
    transition: all 0.15s ease;
  }

  .back-btn:hover {
    background: #ffffff;
    box-shadow: 0 0 12px rgba(0, 229, 255, 0.4);
    transform: translateY(-1px);
  }

  .docs-container {
    display: flex;
    flex: 1;
    overflow: hidden;
  }

  /* Sidebar Navigation */
  .docs-sidebar {
    width: 260px;
    background: #11151e;
    border-right: 2px solid #242b3b;
    padding: 1.5rem 1rem;
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
    flex-shrink: 0;
  }

  .nav-btn {
    text-align: left;
    background: none;
    border: 1px solid transparent;
    border-radius: var(--radius-md);
    padding: 0.75rem 1rem;
    font-size: 0.85rem;
    font-weight: 700;
    color: #a0aec0; /* Clear contrast gray */
    cursor: pointer;
    transition: all 0.15s ease;
  }

  .nav-btn:hover {
    background: #1a202c;
    color: #ffffff;
  }

  .nav-btn.active {
    background: rgba(0, 229, 255, 0.1);
    border-color: #00e5ff;
    color: #00e5ff;
  }

  /* Content area */
  .docs-content {
    flex: 1;
    padding: 2.5rem;
    overflow-y: auto;
    background: #090b0f;
  }

  .docs-content h3 {
    margin-top: 0;
    font-size: 1.5rem;
    color: #ffffff; /* Pure white title */
    border-bottom: 2px solid #242b3b;
    padding-bottom: 0.75rem;
    margin-bottom: 1.5rem;
    font-weight: 800;
  }

  .docs-content h4 {
    color: #00e5ff; /* High brightness cyan for subheadings */
    margin-top: 1.8rem;
    margin-bottom: 0.75rem;
    font-size: 1.1rem;
    font-weight: 700;
  }

  .docs-content p {
    font-size: 0.92rem;
    line-height: 1.7;
    color: #e2e8f0; /* Clear text color */
    margin-bottom: 1.2rem;
  }

  .docs-content ul {
    padding-left: 1.5rem;
    margin-bottom: 1.5rem;
  }

  .docs-content li {
    font-size: 0.9rem;
    margin-bottom: 0.5rem;
    color: #e2e8f0;
  }

  .note-box {
    background: rgba(0, 229, 255, 0.06);
    border-left: 4px solid #00e5ff;
    padding: 1rem 1.25rem;
    border-radius: 4px;
    margin-top: 1.5rem;
    color: #ffffff;
    font-size: 0.9rem;
  }

  pre {
    background: #0d1117; /* Very dark code block background */
    border: 1px solid #30363d;
    padding: 1rem 1.25rem;
    border-radius: var(--radius-md);
    overflow-x: auto;
    margin-bottom: 1.5rem;
  }

  code {
    font-family: "JetBrains Mono", monospace;
    font-size: 0.82rem;
    color: #ff9e64; /* Vibrant orange code text for high contrast */
  }

  /* Topologies */
  .topo-grid {
    display: flex;
    gap: 1.5rem;
    margin-top: 1.2rem;
    margin-bottom: 1.5rem;
  }

  .topo-card {
    flex: 1;
    background: #11151e;
    border: 1px solid #242b3b;
    border-radius: var(--radius-md);
    padding: 1.2rem;
  }

  .topo-card h5 {
    margin: 0 0 0.6rem 0;
    color: #ffffff;
    font-size: 0.95rem;
    font-weight: 700;
  }

  .topo-card p {
    margin: 0;
    font-size: 0.8rem;
    color: #a0aec0;
    line-height: 1.6;
  }

  /* Examples */
  .examples-list {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    margin-top: 1.2rem;
  }

  .example-card {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: #11151e;
    border: 1px solid #242b3b;
    border-radius: var(--radius-md);
    padding: 1.25rem;
    gap: 1.5rem;
  }

  .ex-info {
    flex: 1;
  }

  .ex-info h5 {
    margin: 0 0 0.4rem 0;
    color: #ffffff;
    font-size: 0.95rem;
    font-weight: 700;
  }

  .ex-info p {
    margin: 0;
    font-size: 0.82rem;
    color: #a0aec0;
    line-height: 1.5;
  }

  .load-btn {
    background: #00e5ff;
    color: #000;
    border: none;
    border-radius: var(--radius-sm);
    padding: 0.6rem 1.25rem;
    font-size: 0.82rem;
    font-weight: 700;
    cursor: pointer;
    transition: all 0.15s ease;
    flex-shrink: 0;
  }

  .load-btn:hover {
    background: #ffffff;
    box-shadow: 0 0 10px rgba(0, 229, 255, 0.5);
  }
</style>
