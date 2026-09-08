# `nft monitor trace` golden corpus

Each `<name>.log` is raw `nft monitor trace` output; `<name>.expected.json` lists
the events `nse.core.trace_harvester._parse_line` must produce for it, in order,
as a subset of fields per event.

`tests/test_trace_parser.py` fails if this directory is empty. That guard exists
because `glob("*.log")` returning nothing makes `parametrize` collect zero tests,
so deleting the corpus used to make the parser's only test disappear silently.

## Provenance

| file | origin |
|---|---|
| `sample_trace.log` | original fixture, hand-authored |
| `hyphenated_names.log` | hand-authored — table/chain identifiers using `-`, `.` and quoting, which `\w+` could not match |
| `ipv6_input.log` | hand-authored — `ip6` family, unquoted `iif` |
| `gateway_forward.log` | hand-authored — prerouting/forward/postrouting chain traversal under one trace id |
| `nse_trace_scaffolding.log` | hand-authored — NSE's own `inet nse_trace` prerouting chain interleaved with a user ruleset |
| `unquoted_iif.log` | hand-authored — the format variant fixed in 1.1.1 |

Hand-authored fixtures follow the output grammar of `nft monitor trace` as
emitted by nftables 1.0.x–1.1.x. They pin the *parser*, and they are cheap.

They are not a substitute for running against a real kernel, which is why
`tests/test_oracle_e2e.py::test_parser_understands_every_line_of_a_real_trace`
asserts, on whatever kernel and nftables version the runner has, that a real run
produced **zero** unparsed trace lines. The CI matrix runs that on more than one
image, so a format change breaks a build instead of silently blinding the oracle.

## Adding a capture from a new kernel

```text
sudo scripts/capture_trace_fixture.sh <name>
```

writes `<name>.log` here; write the matching `.expected.json` by reading the log,
not by dumping what the parser currently produces — a fixture generated from the
parser cannot detect a parser bug.
