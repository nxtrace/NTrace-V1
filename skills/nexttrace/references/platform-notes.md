# Platform Notes

## Source Address and Device

`source_address` and `source_device` are local-stack controls. They apply to local traceroute, MTR, MTU, and speed tools when the OS supports the underlying behavior.

They do not apply to Globalping.

If local source or device selection fails, report the platform or permission error and ask before trying a different source, device, or Globalping. Do not silently replace a requested local source/device run with remote probes.

## TOS / Traffic Class

Use `tos` only with local traceroute/MTR tools. It is the complete 8-bit IPv4 TOS / IPv6 Traffic Class value, from 0 to 255: `DSCP * 4 + ECN`. For DSCP 46 and ECN 0, pass `184`, not `46`.

On Linux, nonzero TOS participates in automatic source selection while preserving explicit source/device constraints. Configuration failures terminate the probe; do not summarize them as packet loss. The JSON `tos` value is the requested configuration, not proof of the emitted packet field.

Linux IPv4 UDP uses a raw socket connection without sending packets to select its source, because netlink does not accept the backend's protocol 255. This confirms the selected source only; doctor cannot confirm the route interface or gateway from this API.

Do not pass `tos` to:

- Globalping tools
- MTU tool

If TOS fails because of platform privileges or socket support, report that limitation. Do not remove `tos` or switch tools unless the user asks for a fallback.

## Linux socket marks

`--fwmark` accepts `0..4294967295` in decimal or hexadecimal for local CLI
traceroute/MTR only. Omission and explicit zero differ: zero still sets SO_MARK
and requires permission. Matching system policy rules must already exist.
Linux requires CAP_NET_ADMIN, or CAP_NET_RAW on Linux 5.17+. Automatic source
selection uses the marked route; explicit source/device constraints are kept.
Doctor, MTU, DNS, speed, deploy/MCP, Globalping, Fast Trace and file targets
reject the option. See the [CLI workflow](cli-fallback.md).

## Packet Size

`packet_size` is local traceroute/MTR input. It means total bytes including IP and active probe protocol headers.

Do not pass `packet_size` to:

- Globalping tools
- MTU tool

## Windows

On Windows amd64, nonzero ICMP TOS requires WinDivert sending and administrator privilege for both IPv4 and IPv6, even with socket reception. Default and zero TOS retain native socket sending. This does not imply WinDivert availability in Windows arm64 builds.

Windows device selection is source-address-based for many paths. Treat `source_device` as a hint unless the returned source path proves otherwise.

Do not summarize Windows `source_device` as guaranteed device binding. Say it is source-address-based behavior unless the result proves otherwise.

## Privileges

Raw socket operations may require elevated privileges or platform-specific packet capture/runtime support. If MCP returns a permission error, ask the user whether to rerun NextTrace with the required privileges.
