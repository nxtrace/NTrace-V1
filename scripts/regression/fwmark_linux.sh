#!/usr/bin/env bash
# Run only in an isolated privileged Linux test environment. All network changes
# are confined to uniquely named namespaces; no host routes/firewalls are edited.
set -euo pipefail
BIN="$(realpath "${1:?usage: fwmark_linux.sh /path/to/nexttrace [artifact-dir]}")"
ART="${2:-$(mktemp -d /tmp/nexttrace-fwmark-results.XXXXXX)}"
mkdir -p "$ART"
ART="$(realpath "$ART")"
PREFIX="ntfm-$$"
S="$PREFIX-s"; A="$PREFIX-a"; B="$PREFIX-b"; D="$PREFIX-d"
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done
  for ns in "$S" "$A" "$B" "$D"; do ip netns del "$ns" 2>/dev/null || true; done
}
trap cleanup EXIT
for tool in ip sysctl tcpdump python3 timeout setpriv; do command -v "$tool" >/dev/null; done
for ns in "$S" "$A" "$B" "$D"; do
  ip netns add "$ns"
  ip -n "$ns" link set dev lo up
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 net.ipv6.conf.all.disable_ipv6=0
 done
link() {
  local left="$1" li="$2" right="$3" ri="$4" n="$5"
  ip -n "$left" link add name "$li" type veth peer name "$ri" netns "$right"
  ip -n "$left" addr add "10.201.$n.1/24" dev "$li"
  ip -n "$right" addr add "10.201.$n.2/24" dev "$ri"
  ip -n "$left" -6 addr add "2001:db8:$n::1/64" dev "$li" nodad
  ip -n "$right" -6 addr add "2001:db8:$n::2/64" dev "$ri" nodad
  ip -n "$left" link set dev "$li" up
  ip -n "$right" link set dev "$ri" up
}
link "$A" as "$S" sa 1
link "$B" bs "$S" sb 2
link "$A" ad "$D" da 3
link "$B" bd "$D" db 4
for ns in "$A" "$B"; do ip netns exec "$ns" sysctl -qw net.ipv4.ip_forward=1 net.ipv6.conf.all.forwarding=1; done
ip -n "$D" addr add 203.0.113.9/32 dev lo
ip -n "$D" -6 addr add 2001:db8:99::9/128 dev lo nodad
for spec in "$A 3" "$B 4"; do
  read -r ns n <<< "$spec"
  ip -n "$ns" route add 203.0.113.9/32 via "10.201.$n.2"
  ip -n "$ns" -6 route add 2001:db8:99::9/128 via "2001:db8:$n::2"
done
ip -n "$D" route add 10.201.1.0/24 via 10.201.3.1
ip -n "$D" route add 10.201.2.0/24 via 10.201.4.1
ip -n "$D" -6 route add 2001:db8:1::/64 via 2001:db8:3::1
ip -n "$D" -6 route add 2001:db8:2::/64 via 2001:db8:4::1
ip -n "$S" route add 203.0.113.9/32 via 10.201.1.1
ip -n "$S" -6 route add 2001:db8:99::9/128 via 2001:db8:1::1
ip -n "$S" route add table 200 10.201.2.0/24 dev sb
ip -n "$S" route add table 200 203.0.113.9/32 via 10.201.2.1
ip -n "$S" -6 route add table 200 2001:db8:2::/64 dev sb
ip -n "$S" -6 route add table 200 2001:db8:99::9/128 via 2001:db8:2::1
ip -n "$S" rule add priority 100 fwmark 0x100 lookup 200
ip -n "$S" -6 rule add priority 100 fwmark 0x100 lookup 200

run_case() {
  local label="$1" family="$2" protocol="$3" mode="$4" mark="$5" egress="$6"
  shift 6
  local target=203.0.113.9 source=10.201.1.2
  [[ "$egress" == sb ]] && source=10.201.2.2
  if [[ "$family" == 6 ]]; then
    target=2001:db8:99::9; source=2001:db8:1::2
    [[ "$egress" == sb ]] && source=2001:db8:2::2
  fi
  local args=("-$family" --no-rdns --data-provider disable-geoip --max-hops 4 --queries 2 --timeout 700 --ttl-time 100)
  [[ "$protocol" == tcp ]] && args+=(--tcp)
  [[ "$protocol" == udp ]] && args+=(--udp)
  case "$mode" in
    trace) args+=(--traceroute --json) ;;
    report) args+=(--report --json) ;;
    stream) args+=(--mtr --json) ;;
    raw) args+=(--mtr --raw) ;;
  esac
  [[ "$mark" != none ]] && args+=(--fwmark "$mark")
  local pa pb
  ip netns exec "$S" tcpdump -i sa -n -U -w "$ART/$label-sa.pcap" "dst host $target" >"$ART/$label-sa.capture" 2>&1 & pa=$!
  ip netns exec "$S" tcpdump -i sb -n -U -w "$ART/$label-sb.pcap" "dst host $target" >"$ART/$label-sb.capture" 2>&1 & pb=$!
  PIDS=("$pa" "$pb")
  sleep 0.2
  if ! ip netns exec "$S" timeout 20 "$BIN" "${args[@]}" "$@" "$target" >"$ART/$label.out" 2>"$ART/$label.err"; then
    cat "$ART/$label.err" >&2; cat "$ART/$label.out" >&2; return 1
  fi
  sleep 0.2
  kill -INT "$pa" "$pb"
  wait "$pa"; wait "$pb"; PIDS=()
  tcpdump -nn -r "$ART/$label-sa.pcap" >"$ART/$label-sa.txt" 2>/dev/null
  tcpdump -nn -r "$ART/$label-sb.pcap" >"$ART/$label-sb.txt" 2>/dev/null
  python3 - "$ART" "$label" "$target" "$source" "$egress" "$mode" "$mark" <<'PY'
import json,pathlib,sys
art,label,target,source,egress,mode,mark=sys.argv[1:]
p=pathlib.Path(art)
expected=(p/f'{label}-{egress}.txt').read_text()
other='sb' if egress=='sa' else 'sa'
assert source in expected and target in expected, (label,'missing actual marked egress/source',expected)
assert not (p/f'{label}-{other}.txt').read_text().strip(), (label,'unexpected egress')
output=(p/f'{label}.out').read_text()
assert target in output,(label,'destination did not reply',output)
if mode in ('report','stream'):
 records=[json.loads(output)] if mode=='report' else [json.loads(x) for x in output.splitlines()]
 params=records[0]['effective_parameters']
 assert params['source_address']==source,(label,params)
 if mark=='none': assert 'fwmark' not in params
 else: assert params['fwmark']==int(mark,0),(label,params)
 end=records[-1]
 assert end['end_reason']=='completed',(label,end)
PY
  printf 'PASS %s\n' "$label" | tee -a "$ART/summary.txt"
}
for family in 4 6; do
  for protocol in icmp tcp udp; do
    for mode in trace report; do
      run_case "$family-$protocol-$mode-none" "$family" "$protocol" "$mode" none sa
      run_case "$family-$protocol-$mode-zero" "$family" "$protocol" "$mode" 0 sa
      run_case "$family-$protocol-$mode-hex" "$family" "$protocol" "$mode" 0x100 sb
      run_case "$family-$protocol-$mode-decimal" "$family" "$protocol" "$mode" 256 sb
      run_case "$family-$protocol-$mode-other" "$family" "$protocol" "$mode" 0x200 sa
    done
    run_case "$family-$protocol-source" "$family" "$protocol" report 0x100 sb --source "$([[ "$family" == 4 ]] && echo 10.201.2.2 || echo 2001:db8:2::2)"
    run_case "$family-$protocol-device" "$family" "$protocol" report 0x100 sb --dev sb
    run_case "$family-$protocol-both" "$family" "$protocol" report 0x100 sb --dev sb --source "$([[ "$family" == 4 ]] && echo 10.201.2.2 || echo 2001:db8:2::2)"
    run_case "$family-$protocol-stream" "$family" "$protocol" stream 0x100 sb
    run_case "$family-$protocol-raw" "$family" "$protocol" raw 0x100 sb
  done
 done
# The source resolver must not require an unmarked route to exist.
ip -n "$S" route del 203.0.113.9/32
ip -n "$S" -6 route del 2001:db8:99::9/128
for family in 4 6; do for protocol in icmp tcp udp; do
  run_case "$family-$protocol-mark-only-route" "$family" "$protocol" report 0x100 sb
 done; done
# Explicit constraints are never silently overridden.
if ip netns exec "$S" timeout 10 "$BIN" --report --json --fwmark 0x100 --dev sa -n -d disable-geoip -q 1 203.0.113.9 >"$ART/conflict.out" 2>"$ART/conflict.err"; then
  echo 'incompatible device unexpectedly succeeded' >&2; exit 1
fi
# A process without marking/raw-socket capabilities must fail, not probe unmarked.
if ip netns exec "$S" setpriv --bounding-set=-net_admin,-net_raw --inh-caps=-all --ambient-caps=-all timeout 10 "$BIN" --report --json --fwmark 0x100 -n -d disable-geoip -q 1 203.0.113.9 >"$ART/permission.out" 2>"$ART/permission.err"; then
  echo 'unprivileged marked probe unexpectedly succeeded' >&2; exit 1
fi
python3 - "$ART" <<'PY'
import json,pathlib,sys
p=pathlib.Path(sys.argv[1])
for name in ('conflict','permission'):
 r=json.loads((p/f'{name}.out').read_text())
 assert r['end_reason']=='error' and r['error']['stage']=='initialize',(name,r)
 assert not r['stats'],(name,r)
PY
printf 'PASS constraint and permission failures\n' | tee -a "$ART/summary.txt"
