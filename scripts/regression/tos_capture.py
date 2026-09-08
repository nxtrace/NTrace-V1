#!/usr/bin/env python3
"""Strict on-wire TOS assertions; no packet parsing dependency or SKIP path."""
import argparse
from contextlib import contextmanager
import ipaddress
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import struct
import subprocess
import time

VALUES = (0, 1, 2, 3, 16, 46, 184, 255, 0)


def packets(path):
    data = Path(path).read_bytes()
    if len(data) < 24:
        raise AssertionError(f"missing pcap header: {path}")
    magic = data[:4]
    endian = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">",
              b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}.get(magic)
    if endian is None:
        raise AssertionError(f"unsupported pcap magic: {magic!r}")
    link = struct.unpack_from(endian + "I", data, 20)[0]
    pos = 24
    while pos < len(data):
        assert pos + 16 <= len(data), "truncated pcap record header"
        size = struct.unpack_from(endian + "I", data, pos + 8)[0]
        pos += 16
        frame = data[pos:pos + size]
        assert len(frame) == size, "truncated captured frame"
        pos += size
        if link == 1:  # Ethernet, including Linux loopback.
            offset = 14
            ethertype = struct.unpack_from("!H", frame, 12)[0]
            while ethertype in (0x8100, 0x88A8):
                ethertype = struct.unpack_from("!H", frame, offset + 2)[0]
                offset += 4
            if ethertype not in (0x0800, 0x86DD):
                continue
        elif link in (0, 108):  # BSD NULL / LOOP pseudo-header.
            offset = 4
        elif link == 113:  # Linux cooked v1.
            offset = 16
        elif link == 276:  # Linux cooked v2.
            offset = 20
        elif link in (12, 101, 228, 229):  # Raw IP.
            offset = 0
        else:
            raise AssertionError(f"unsupported pcap link type: {link}")
        ip = frame[offset:]
        assert ip, "empty IP packet"
        version = ip[0] >> 4
        if version == 4:
            assert len(ip) >= 20
            end = struct.unpack_from("!H", ip, 2)[0]
            assert len(ip) >= end, "truncated IPv4 packet"
            frag = struct.unpack_from("!H", ip, 6)[0]
            item = dict(family=4, tos=ip[1], protocol=ip[9],
                        source=str(ipaddress.ip_address(ip[12:16])),
                        target=str(ipaddress.ip_address(ip[16:20])),
                        fragment=frag & 0x1FFF, more_fragments=bool(frag & 0x2000),
                        packet_id=struct.unpack_from("!H", ip, 4)[0])
            body = ip[(ip[0] & 15) * 4:end]
        elif version == 6:
            assert len(ip) >= 40
            end = 40 + struct.unpack_from("!H", ip, 4)[0]
            assert len(ip) >= end, "truncated IPv6 packet"
            item = dict(family=6, tos=((ip[0] & 15) << 4) | (ip[1] >> 4),
                        protocol=ip[6], source=str(ipaddress.ip_address(ip[8:24])),
                        target=str(ipaddress.ip_address(ip[24:40])),
                        fragment=0, more_fragments=False)
            body = ip[40:end]
        else:
            raise AssertionError(f"unexpected IP version {version}")
        item["body"] = body
        yield item


def assert_capture(path, family, protocol, tos, source, target, minimum=2, fragmented=False,
                   source_ports=()):
    number = {"icmp": 1 if family == 4 else 58, "tcp": 6, "udp": 17}[protocol]
    selected, identities = [], set()
    expected_ports, seen_ports = set(source_ports), set()
    for packet in packets(path):
        if (packet["family"] != family or packet["protocol"] != number
                or packet["source"] != source or packet["target"] != target):
            continue
        body = packet["body"]
        if not packet["fragment"] and protocol != "icmp":
            assert len(body) >= 8
            source_port = struct.unpack_from("!H", body)[0]
            if expected_ports and source_port not in expected_ports:
                continue
        if packet["fragment"]:
            # IPv4 fragments have the same IP fields, but no transport header.
            assert protocol == "udp", "unexpected fragmented probe protocol"
        elif protocol == "icmp":
            if not body or body[0] != (8 if family == 4 else 128):
                continue
            assert len(body) >= 8
            identities.add(body[4:8])
        elif protocol == "tcp":
            if len(body) < 14 or body[13] & 0x12 != 0x02:
                continue  # Exclude TCP replies, including loopback RSTs.
            identities.add(body[0:8])
            seen_ports.add(source_port)
        else:
            assert len(body) >= 8
            identities.add((packet.get("packet_id"), body))
            seen_ports.add(source_port)
        assert packet["tos"] == tos, (path, "wrong TOS/Traffic Class", tos, packet["tos"])
        selected.append(packet)
    if expected_ports:
        assert seen_ports == expected_ports, (path, "missing probe sessions", seen_ports, expected_ports)
    assert len(identities) >= minimum, (path, "missing distinct probes", len(identities), minimum)
    if fragmented:
        assert any(p["fragment"] for p in selected), (path, "no noninitial fragment captured")
        assert any(p["more_fragments"] for p in selected), (path, "no first fragment captured")
    return dict(packets=len(selected), distinct_probes=len(identities), tos=tos)


@contextmanager
def capture_packets(tcpdump, interface, target, capture, log):
    with log.open("wb") as capture_log:
        process = subprocess.Popen([tcpdump, "--immediate-mode", "-n", "-U", "-s", "0",
                                    "-i", interface, "-w", str(capture), "dst host " + target],
                                   stdout=capture_log, stderr=capture_log)
        try:
            deadline = time.monotonic() + 5
            while "listening on" not in log.read_text():
                assert process.poll() is None, log.read_text()
                assert time.monotonic() < deadline, "capture failed to become ready"
                time.sleep(0.025)
            yield
            time.sleep(0.1)
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGINT)
            process.wait(timeout=5)
    assert process.returncode == 0, log.read_text()


def assert_rebuild_capture(capture, output, family, target):
    expected = []
    for line in output.splitlines():
        if "TOS_REBUILD " in line:
            expected.append(json.loads(line.split("TOS_REBUILD ", 1)[1]))
    assert len(expected) == 4, ("missing rebuild probe markers", expected)
    identities = {(p["echo_id"], p["sequence"]) for p in expected}
    assert len(identities) == 4 and len({p[0] for p in identities}) == 2, expected
    assert all(p["family"] == family and p["tos"] == 184 for p in expected), expected
    observed = set()
    for packet in packets(capture):
        body = packet["body"]
        if (packet["family"] != family or packet["protocol"] != (1 if family == 4 else 58)
                or packet["source"] != target or packet["target"] != target
                or len(body) < 8 or body[0] != (8 if family == 4 else 128)):
            continue
        identity = struct.unpack_from("!HH", body, 4)
        if identity in identities:
            assert packet["tos"] == 184, (capture, identity, packet["tos"])
            observed.add(identity)
    assert observed == identities, (capture, "missing rebuild probes", identities - observed)
    return dict(distinct_probes=len(observed), generations=2, tos=184)


def run_rebuild(binary, artifacts):
    binary, artifacts = Path(binary).resolve(), Path(artifacts).resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    assert os.geteuid() == 0, "packet capture and raw probes require root"
    tcpdump = shutil.which("tcpdump")
    assert tcpdump, "tcpdump is required; this test must not skip"
    assert binary.is_file(), f"test binary does not exist: {binary}"
    interface = {"Darwin": "lo0", "Linux": "lo"}.get(platform.system())
    assert interface, "this runner supports Linux and macOS"
    for family in (4, 6):
        target = "127.0.0.1" if family == 4 else "::1"
        label = f"ipv{family}-mtr-rebuild-tos184"
        capture, log = artifacts / (label + ".pcap"), artifacts / (label + ".capture.log")
        with capture_packets(tcpdump, interface, target, capture, log):
            result = subprocess.run([str(binary), "-test.v", "-test.run",
                                     f"^TestMTRTOSRebuildIntegration/ipv{family}$"],
                                    env=dict(os.environ, NEXTTRACE_TOS_REBUILD_INTEGRATION="1"),
                                    capture_output=True, text=True, timeout=20)
            (artifacts / (label + ".out")).write_text(result.stdout)
            (artifacts / (label + ".err")).write_text(result.stderr)
            assert result.returncode == 0, (label, result.stdout, result.stderr)
        evidence = assert_rebuild_capture(capture, result.stdout, family, target)
        with (artifacts / "summary.jsonl").open("a") as summary:
            summary.write(json.dumps(dict(case=label, status="PASS", **evidence)) + "\n")
        print("PASS", label, evidence, flush=True)


def run_matrix(binary, artifacts):
    binary, artifacts = Path(binary).resolve(), Path(artifacts).resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    assert os.geteuid() == 0, "packet capture and raw probes require root"
    tcpdump = shutil.which("tcpdump")
    assert tcpdump, "tcpdump is required; this test must not skip"
    assert binary.is_file(), f"binary does not exist: {binary}"
    interface = {"Darwin": "lo0", "Linux": "lo"}.get(platform.system())
    assert interface, "this runner supports Linux and macOS"
    (artifacts / "environment.json").write_text(json.dumps(dict(
        platform=platform.platform(), binary=str(binary), interface=interface,
        revision=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()), indent=2))
    for family in (4, 6):
        target = "127.0.0.1" if family == 4 else "::1"
        for protocol in ("icmp", "tcp", "udp"):
            for mode in ("trace", "report"):
                for index, tos in enumerate(VALUES):
                    label = f"ipv{family}-{protocol}-{mode}-{index:02d}-tos{tos}"
                    capture = artifacts / (label + ".pcap")
                    log = artifacts / (label + ".capture.log")
                    args = [str(binary), f"-{family}", "--no-rdns", "--data-provider", "disable-geoip",
                            "--dev", interface, "--max-hops", "1", "--queries", "2",
                            "--timeout", "500", "--ttl-time", "25", "--send-time", "25", "--tos", str(tos),
                            "--json", "--traceroute" if mode == "trace" else "--report"]
                    if platform.system() == "Darwin":
                        args += ["--source", target]
                    if protocol != "icmp":
                        args += ["--" + protocol]
                    args.append(target)
                    # Fallback MTR repeats the same TCP sequence/UDP payload in
                    # separate one-probe rounds. Distinct session source ports
                    # identify real probes without counting loopback duplicates.
                    source_ports = (47464, 47465) if mode == "report" and protocol != "icmp" else ()
                    commands = [(f"{label}-port{port}", args[:-1] + ["--source-port", str(port), target])
                                for port in source_ports] if source_ports else [(label, args)]
                    with capture_packets(tcpdump, interface, target, capture, log):
                        for run_label, command in commands:
                            result = subprocess.run(command, capture_output=True, timeout=15)
                            (artifacts / (run_label + ".out")).write_bytes(result.stdout)
                            (artifacts / (run_label + ".err")).write_bytes(result.stderr)
                            assert result.returncode == 0, (run_label, result.returncode, result.stderr.decode(errors="replace"))
                            output = json.loads(result.stdout)
                            if mode == "report":
                                assert output["end_reason"] == "completed", (run_label, output)
                                assert output["effective_parameters"]["tos"] == tos, (run_label, output)
                                assert sum(row["snt"] for row in output["stats"]) == 2, (run_label, output)
                    result = assert_capture(capture, family, protocol, tos, target, target,
                                            source_ports=source_ports)
                    with (artifacts / "summary.jsonl").open("a") as summary:
                        summary.write(json.dumps(dict(case=label, status="PASS", **result)) + "\n")
                    print("PASS", label, result, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run = subparsers.add_parser("run")
    run.add_argument("binary")
    run.add_argument("artifacts")
    rebuild = subparsers.add_parser("rebuild")
    rebuild.add_argument("binary")
    rebuild.add_argument("artifacts")
    check = subparsers.add_parser("check")
    check.add_argument("pcap")
    check.add_argument("family", type=int, choices=(4, 6))
    check.add_argument("protocol", choices=("icmp", "tcp", "udp"))
    check.add_argument("tos", type=int)
    check.add_argument("source")
    check.add_argument("target")
    check.add_argument("--minimum", type=int, default=2)
    check.add_argument("--fragmented", action="store_true")
    check.add_argument("--source-ports", type=int, nargs="+", default=())
    args = parser.parse_args()
    if args.command == "run":
        run_matrix(args.binary, args.artifacts)
    elif args.command == "rebuild":
        run_rebuild(args.binary, args.artifacts)
    else:
        print(json.dumps(assert_capture(args.pcap, args.family, args.protocol, args.tos,
                                        args.source, args.target, args.minimum, args.fragmented,
                                        args.source_ports)))


if __name__ == "__main__":
    main()
