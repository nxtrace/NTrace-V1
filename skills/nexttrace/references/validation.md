# Validation

## Startup

Loopback tokenless default:

```bash
nexttrace --deploy --mcp
```

External authenticated:

```bash
nexttrace --deploy --mcp --listen 0.0.0.0:1080 --deploy-token "$TOKEN"
```

Expected:

- stdout prints the Web console listen URL.
- stdout prints the MCP endpoint when `--mcp` is enabled.
- external listen without manual token prints a generated token.
- manual token does not echo the token.

## Auth Smoke Checks

```bash
curl -i http://127.0.0.1:1080/api/options
curl -i -H "Authorization: Bearer $TOKEN" http://127.0.0.1:1080/api/options
curl -i -H "X-NextTrace-Token: $TOKEN" http://127.0.0.1:1080/api/options
```

Do not use query token URLs.

## MCP Smoke Checks

Use an MCP client pointed at:

```text
http://127.0.0.1:1080/mcp
```

Then call:

1. `nexttrace_capabilities`
2. `nexttrace_traceroute` with `{"target":"example.com","protocol":"icmp"}`
3. `nexttrace_globalping_limits`
4. `nexttrace_globalping_trace` with a small `locations[]` set

## Repo Tests

```bash
go build ./...
go test ./...
node --test server/web/assets/*.test.cjs
```


## CLI feature regression coverage

| Feature | Local checks | Native CI evidence |
| --- | --- | --- |
| MTR JSON ordering, error stages and ports | `go test ./cmd` | Test full/tiny/ntr; Runtime Regression CI checks finite streams and reports |
| Recording, reducer validation and recovery | `go test ./internal/mtrsession ./trace ./cmd` | Test workflow; recorded sessions and offline replay on PTY/Windows ConPTY |
| Replay sanitation, seek and text columns | `go test ./cmd ./printer` | `scripts/test_mtr_session_pty.py` and `scripts/test_mtr_columns_pty.py` |
| Doctor route/backend checks | `go test ./internal/doctor ./trace/internal ./cmd` | Test workflow loopback route and privileged backend smoke; NO_INSTALL Windows checks |
| Linux fwmark and source constraints | `go test ./internal/routeprobe ./trace ./trace/internal ./cmd` | Linux fwmark workflow: native marks, permission failures, dual-stack dual-egress captures |
| TOS, zero restoration and engine replacement | `go test ./trace ./trace/internal` | TOS packet acceptance: Linux/macOS/Windows amd64 full-byte dual-stack captures |
| Linux legacy socketcall pointer lifetime | Cross-compile and vet `internal/routeprobe` for 386/s390x | Linux fwmark workflow executes route tests on amd64 and 386; s390x compile only |

Privilege-gated tests skip in ordinary `go test` runs. Cross-compilation,
simulated callbacks and successful socket initialization do not prove packet
contents or remote reachability. Inspect the matching commit's workflow logs and
artifacts for native acceptance; do not report a skipped test as passed coverage.
Unix MTR JSON regression failures retain the full Python traceback in
`<case>.json.assert`, with a short failure detail in the summary.
