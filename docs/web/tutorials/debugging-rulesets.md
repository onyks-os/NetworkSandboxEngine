# Debugging Rulesets & Understanding Trace Events

When testing complex `nftables` configurations, understanding how kernel rules evaluate packets is essential.

---

## The Trace Event Stream

NSE executes `nft monitor trace` in the background within isolated network namespaces to collect step-by-step kernel trace events.

Each event generated during packet traversal is categorized into one of three primary types:

| Event Type | Description | Key Fields |
| :--- | :--- | :--- |
| `hook` | Packet enters a netns network interface hook | `family`, `table`, `chain`, `hook` |
| `match` | Packet matches a specific rule expression | `table`, `chain`, `rule_handle`, `rule_text`, `verdict` |
| `verdict` | Final policy or rule verdict reached | `table`, `chain`, `verdict` |
| `conntrack` | Connection tracking state snapshot | `state`, `proto`, `src`, `dst`, `sport`, `dport` |

---

## Inspecting Trace Events in Python

```python
import asyncio
from nse.core.netns_controller import NetnsController
from nse.core.pipeline import run_test_pipeline
from nse.models.test_request import TestRequest, PacketSpec

async def debug_ruleset():
    request = TestRequest(
        rules="""
        table ip filter {
            chain input {
                type filter hook input priority 0; policy drop;
                ip saddr 10.0.0.1 tcp dport 80 accept
            }
        }
        """,
        packets=[
            PacketSpec(protocol="tcp", src_ip="10.0.0.1", dst_ip="10.0.0.2", dst_port=80),
            PacketSpec(protocol="tcp", src_ip="10.0.0.5", dst_ip="10.0.0.2", dst_port=80),
        ],
    )
    
    events = await run_test_pipeline(request=request)
    
    for idx, evt in enumerate(events):
        print(f"[{idx}] {evt.type.upper()} | table={evt.table} chain={evt.chain} verdict={evt.verdict} rule={evt.rule_text}")

asyncio.run(debug_ruleset())
```

---

## Fast-Path Syntax Validation

NSE validates ruleset syntax before spawning network namespaces:

```python
from nse.core.rule_engine import RuleEngine, RuleValidationError

engine = RuleEngine()
try:
    engine.validate("table ip filter { chain bad { type filter hook input priority 0; invalid_keyword } }")
except RuleValidationError as exc:
    print("nftables syntax error:", exc.errors)
```

This raises an immediate error without waiting for namespace setup or kernel injection.
