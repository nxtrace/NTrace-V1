#!/usr/bin/env bash
# Strict policy-routing acceptance. All interfaces, rules and routes live in
# unique network namespaces; this script never changes the host network.
set -euo pipefail
BIN="$(realpath "${1:?usage: tos_linux.sh /path/to/nexttrace [artifact-dir]}")"
ART="${2:-$(mktemp -d /tmp/nexttrace-tos-routing.XXXXXX)}"
CHECK="$(cd "$(dirname "$0")" && pwd)/tos_capture.py"
mkdir -p "$ART"
ART="$(realpath "$ART")"
S="nttos-$$-s"; A="nttos-$$-a"; B="nttos-$$-b"
PIDS=()
cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; wait "$p" 2>/dev/null || true; done
  for ns in "$S" "$A" "$B"; do ip netns del "$ns" 2>/dev/null || true; done
}
trap cleanup EXIT
for tool in ip sysctl tcpdump python3 timeout; do command -v "$tool" >/dev/null; done
[[ "$EUID" == 0 ]]
for ns in "$S" "$A" "$B"; do
  ip netns add "$ns"
  ip -n "$ns" link set dev lo up
  ip netns exec "$ns" sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 net.ipv6.conf.all.disable_ipv6=0 net.ipv4.icmp_ratelimit=0 net.ipv6.icmp.ratelimit=0
 done
link() {
  local peer="$1" dev="$2" n="$3"
  ip -n "$S" link add name "$dev" type veth peer name uplink netns "$peer"
  ip -n "$S" addr add "10.202.$n.2/24" dev "$dev"
  ip -n "$peer" addr add "10.202.$n.1/24" dev uplink
  ip -n "$S" -6 addr add "2001:db8:202:$n::2/64" dev "$dev" nodad
  ip -n "$peer" -6 addr add "2001:db8:202:$n::1/64" dev uplink nodad
  ip -n "$S" link set dev "$dev" up
  ip -n "$peer" link set dev uplink up
  # Both independent destinations own the same test addresses; reaching either
  # requires sending through its distinct source interface and source address.
  ip -n "$peer" addr add 203.0.113.19/32 dev lo
  ip -n "$peer" -6 addr add 2001:db8:202:99::19/128 dev lo nodad
}
link "$A" sa 1
link "$B" sb 2
ip -n "$S" route add 203.0.113.19/32 via 10.202.1.1
ip -n "$S" -6 route add 2001:db8:202:99::19/128 via 2001:db8:202:1::1
ip -n "$S" route add table 200 10.202.2.0/24 dev sb
ip -n "$S" route add table 200 203.0.113.19/32 via 10.202.2.1
ip -n "$S" -6 route add table 200 2001:db8:202:2::/64 dev sb
ip -n "$S" -6 route add table 200 2001:db8:202:99::19/128 via 2001:db8:202:2::1
for family in 4 6; do
  ip -n "$S" "-$family" rule add priority 90 fwmark 0x100 lookup main
  ip -n "$S" "-$family" rule add priority 91 fwmark 0x200 lookup 200
  ip -n "$S" "-$family" rule add priority 100 tos 0x10 lookup 200
  ip -n "$S" "-$family" rule show >"$ART/ipv$family-rules.txt"
  ip -n "$S" "-$family" route show table all >"$ART/ipv$family-routes.txt"
done
uname -a >"$ART/environment.txt"
git rev-parse HEAD >>"$ART/environment.txt"

start_capture() {
  local label="$1" target="$2"
  PIDS=()
  for dev in sa sb; do
    ip netns exec "$S" tcpdump --immediate-mode -i "$dev" -n -U -s 0 -w "$ART/$label-$dev.pcap" "dst host $target" >"$ART/$label-$dev.capture" 2>&1 &
    PIDS+=("$!")
  done
  for attempt in {1..100}; do
    if grep -q 'listening on' "$ART/$label-sa.capture" && grep -q 'listening on' "$ART/$label-sb.capture"; then return; fi
    kill -0 "${PIDS[@]}"
    sleep 0.05
  done
  echo 'capture readiness timeout' >&2; return 1
}
stop_capture() {
  sleep 0.1
  kill -INT "${PIDS[@]}"
  for p in "${PIDS[@]}"; do wait "$p"; done
  PIDS=()
}
run_case() {
  local label="$1" family="$2" protocol="$3" mode="$4" tos="$5" mark="$6" egress="$7"
  shift 7
  local target=203.0.113.19 source=10.202.1.2 other=sb
  [[ "$egress" == sb ]] && source=10.202.2.2 && other=sa
  if [[ "$family" == 6 ]]; then
    target=2001:db8:202:99::19; source=2001:db8:202:1::2
    [[ "$egress" == sb ]] && source=2001:db8:202:2::2
  fi
  local args=("-$family" --no-rdns --data-provider disable-geoip --max-hops 1 --queries 2 --timeout 700 --ttl-time 50 --tos "$tos" --json)
  [[ "$protocol" != icmp ]] && args+=("--$protocol")
  if [[ "$mode" == trace ]]; then args+=(--traceroute); else args+=(--report); fi
  [[ "$mark" != none ]] && args+=(--fwmark "$mark")
  local run_ports=(auto) out_files=() check_args=()
  # TCP/UDP fallback MTR may repeat identical headers. Two source-port sessions
  # make the captured probes distinguishable while each still runs two rounds.
  if [[ "$mode" == report && "$protocol" != icmp ]]; then
    run_ports=(47464 47465)
    check_args+=(--source-ports 47464 47465)
  fi
  start_capture "$label" "$target"
  for source_port in "${run_ports[@]}"; do
    local port_args=() output_label="$label"
    if [[ "$source_port" != auto ]]; then
      port_args=(--source-port "$source_port")
      output_label="$label-port$source_port"
    fi
    out_files+=("$ART/$output_label.out")
    if ! ip netns exec "$S" timeout 15 "$BIN" "${args[@]}" "${port_args[@]}" "$@" "$target" >"$ART/$output_label.out" 2>"$ART/$output_label.err"; then
      cat "$ART/$output_label.err" >&2; cat "$ART/$output_label.out" >&2; return 1
    fi
  done
  stop_capture
  [[ "$label" == *fragment* ]] && check_args+=(--fragmented)
  python3 "$CHECK" check "$ART/$label-$egress.pcap" "$family" "$protocol" "$tos" "$source" "$target" "${check_args[@]}" >"$ART/$label.assert.json"
  tcpdump -nn -r "$ART/$label-$other.pcap" >"$ART/$label-unexpected.txt" 2>/dev/null
  [[ ! -s "$ART/$label-unexpected.txt" ]]
  python3 - "$mode" "$tos" "$mark" "$source" "$target" "${out_files[@]}" <<'PY'
import json,sys
mode,tos,mark,source,target,*paths=sys.argv[1:]
for path in paths:
 r=json.load(open(path))
 if mode=='report':
  assert r['end_reason']=='completed',r
  p=r['effective_parameters']
  assert p['tos']==int(tos) and p['source_address']==source,p
  if mark=='none': assert 'fwmark' not in p,p
  else: assert p['fwmark']==int(mark,0),p
  assert sum(x['snt'] for x in r['stats'])==2,r
  assert any(x.get('ip')==target and x.get('received',0)>0 for x in r['stats']),r
 else:
  assert any(h.get('Success') and h.get('Address',{}).get('IP')==target for row in r['Hops'] for h in row),r
PY
  printf 'PASS %s\n' "$label" | tee -a "$ART/summary.txt"
}
for family in 4 6; do
  for protocol in icmp tcp udp; do
    for mode in trace report; do
      run_case "$family-$protocol-$mode-default" "$family" "$protocol" "$mode" 0 none sa
      run_case "$family-$protocol-$mode-tos" "$family" "$protocol" "$mode" 16 none sb
      run_case "$family-$protocol-$mode-markzero" "$family" "$protocol" "$mode" 16 0 sb
      run_case "$family-$protocol-$mode-markoverride" "$family" "$protocol" "$mode" 16 0x100 sa
      run_case "$family-$protocol-$mode-markonly" "$family" "$protocol" "$mode" 0 0x200 sb
    done
    # Exercise full DSCP/ECN bytes through automatic source lookup as well as
    # packet emission; ECN-only values must not make route lookup fail.
    for tos in 1 2 3 46 184 255; do
      run_case "$family-$protocol-fullbyte-$tos" "$family" "$protocol" report "$tos" none sa
    done
    source=10.202.2.2
    [[ "$family" == 6 ]] && source=2001:db8:202:2::2
    run_case "$family-$protocol-source" "$family" "$protocol" report 16 none sb --source "$source"
    run_case "$family-$protocol-device" "$family" "$protocol" report 16 none sb --dev sb
    run_case "$family-$protocol-both" "$family" "$protocol" report 16 0 sb --source "$source" --dev sb
  done
done
# Linux IPv4 IP_HDRINCL routes as IPPROTO_RAW (255), even when the serialized
# packet is UDP. IPv6 UDP uses the ordinary protocol 17 route lookup.
for family in 4 6; do
  ip -n "$S" "-$family" rule add priority 80 ipproto udp lookup main
  ip -n "$S" "-$family" rule add priority 81 ipproto 255 lookup 200
  ip -n "$S" "-$family" rule show >"$ART/ipv$family-protocol-rules.txt"
done
for mode in trace report; do
  run_case "4-udp-$mode-header-protocol" 4 udp "$mode" 16 none sb
  run_case "6-udp-$mode-header-protocol" 6 udp "$mode" 16 none sa
done
for family in 4 6; do
  ip -n "$S" "-$family" rule del priority 80
  ip -n "$S" "-$family" rule del priority 81
done
# Confirm every IPv4 UDP fragment preserves the complete byte, including ECN.
for mode in trace report; do
  run_case "4-udp-$mode-fragment" 4 udp "$mode" 255 0x200 sb --psize 4000
done
# Unmarked default-route discovery must not be a hidden prerequisite.
ip -n "$S" route del 203.0.113.19/32
ip -n "$S" -6 route del 2001:db8:202:99::19/128
for family in 4 6; do for protocol in icmp tcp udp; do
  run_case "$family-$protocol-tos-only-route" "$family" "$protocol" report 16 none sb
done; done
# An explicit unreachable policy route must fail before any probe is emitted.
for family in 4 6; do
  target=203.0.113.19
  [[ "$family" == 6 ]] && target=2001:db8:202:99::19
  ip -n "$S" "-$family" route replace prohibit "$target" table 200
  label="$family-prohibited"
  start_capture "$label" "$target"
  code=0
  ip netns exec "$S" timeout 10 "$BIN" "-$family" --report --json --tos 16 -n -d disable-geoip -q 1 -m 1 "$target" >"$ART/$label.out" 2>"$ART/$label.err" || code=$?
  [[ "$code" == 1 ]]
  stop_capture
  for dev in sa sb; do
    tcpdump -nn -r "$ART/$label-$dev.pcap" >"$ART/$label-$dev.txt" 2>/dev/null
    [[ ! -s "$ART/$label-$dev.txt" ]]
  done
  python3 - "$ART/$label.out" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))
assert r['end_reason']=='error' and r['error']['stage']=='initialize' and not r['stats'],r
PY
  printf 'PASS %s\n' "$label" | tee -a "$ART/summary.txt"
done
