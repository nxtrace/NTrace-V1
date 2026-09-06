# CLI Fallback

Use CLI fallback only when MCP is unreachable, the user wants terminal output, or MCP returns an explicit unsupported-capability error.

Fallback must preserve explicit user inputs: `target`, `protocol`, `port`, `source_address`, `source_device`, ASN, location, and IP family. Do not change those values unless the user agrees.

## Local Traceroute

```bash
nexttrace --traceroute example.com
nexttrace --traceroute --tcp -p 443 example.com
nexttrace --traceroute --udp -p 33494 example.com
nexttrace --traceroute --json example.com
```

Full and tiny builds support `-k/--traceroute` and optional MTR. Their default remains traditional traceroute in this release; the default and bare `--raw` will switch to MTR no earlier than 2027, in a separately announced release. Use `--traceroute --raw` to pin traditional RAW (12-column success rows, historical 8-column timeout rows). Detect `--traceroute` in `--help` before using it with older binaries; do not retry failed probes with different mode flags. Explicit traditional mode conflicts with MTR/report/wide and standalone DNS/MTU/speed/nali/deploy modes.

JSON includes optional `StopReason` with lowercase nested fields `hop`, `reason`, `responses`, and `markers`. `responses` contains human-readable descriptions; `markers` contains machine-readable codes. Use `reason` as the reachability conclusion; do not compare the last hop IP with the target.

Normal traceroute output precedence is `--json` > `--table` > `--classic` > `--raw` > `--output` > realtime. A higher-priority mode that overrides an explicit output file emits a warning on stderr.

## MTR

```bash
nexttrace --report example.com
nexttrace --mtr --raw -q 5 example.com
```

When `-q` is omitted, `--mtr --raw` runs continuously, while `--report/--wide` (including with `--raw`) defaults to 10 probes per hop. Set an explicit `-q` for bounded automation. MTR raw stdout remains a fixed 12-column stream. Semantic unreachable diagnostics are written to stderr so stdout parsers remain compatible. In unbounded MTR, an unreachable edge is provisional and later transit evidence can reopen the path; use the final `path_end` from bounded structured output as the authoritative boundary.

## MTU

`--mtu` is available in the `nexttrace` and `nexttrace-tiny` flavors. It is not supported by `ntr`.

```bash
nexttrace --mtu example.com
nexttrace --mtu --json example.com
```

## Globalping

```bash
nexttrace --from "Japan" example.com
nexttrace --from "AS13335" --tcp -p 443 example.com
```

Globalping CLI mode is single-location oriented. For Agent multi-location work, prefer MCP `nexttrace_globalping_trace.locations[]`.

## Deploy MCP

```bash
nexttrace --deploy --mcp
nexttrace --deploy --mcp --listen 0.0.0.0:1080 --deploy-token "$TOKEN"
```
