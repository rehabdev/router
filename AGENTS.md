# AGENTS.md

## Project purpose

Asira Router is a selective IPv4 tunnel for authorized users who need to send
specific destination networks through a Linux VPS while leaving all other
traffic on the user's normal ISP connection.

The repository contains:

- `crates/protocol`: versioned wire messages and packet validation.
- `crates/tunnel`: shared QUIC, TUN, authentication, and route-management code.
- `apps/server`: the Ubuntu/Linux VPS daemon.
- `apps/client`: a small CLI harness for testing the client engine.
- `apps/tauri-client`: the Windows GUI.

## Working agreements

1. Keep routing selective. Never add a default route (`0.0.0.0/0`) from the
   client UI or client engine.
2. Treat all packets arriving from the network as untrusted. Validate IPv4
   headers, packet sizes, source addresses, and authentication before writing
   anything to a TUN device.
3. Do not invent cryptography. Use QUIC TLS keying material plus the standard
   HMAC channel proof for authentication, and keep authentication changes in
   `crates/protocol` and `crates/tunnel` together.
4. The server passphrase is a shared credential. Do not log it, echo it in
   errors, or commit it in an example configuration.
5. The first supported client platform is Windows and the first server platform
   is Ubuntu. Preserve clean `cfg` boundaries when adding other systems.
6. Any route added by the client must be removed on disconnect, error, or
   shutdown. Test this behavior when changing route code.
7. Enforce the client route policy on the server as well as in the Windows
   route table. A client-controlled route table is not a security boundary.
8. Prefer small, explicit functions over clever abstractions in the packet
   forwarding path. The hot path should avoid allocations where practical,
   but correctness and cleanup come first.
9. Update `DOCS.md` whenever configuration, installation, privileges, firewall
   rules, or the wire protocol changes.
10. Add a regression test for every parsing, authentication, or routing bug.
11. Keep this file current. When a new recurring failure or project convention
    is discovered, add a short rule here with the reason behind it.
12. Store GUI preferences under Tauri's per-user app config directory. Never
    write the shared passphrase as plaintext; use OS-protected storage.
13. Keep release packages reproducible and checksum-verified. Installation
    must not silently change provider-specific forwarding or firewall policy.
14. Bound every client connection attempt and surface a useful error when the
    VPS cannot be reached. A network hang must never leave the GUI in an
    indefinite connecting state.
15. Select the Rustls crypto provider explicitly before building QUIC TLS
    configuration. Dependency feature unification can otherwise leave the
    provider ambiguous and panic inside a GUI command.
16. Treat Wintun as a packaged runtime dependency on Windows. Resolve it from
    the executable's install directory, request administrator elevation, and
    never silently fall back to loading a DLL from the working directory.
17. Bind every selective Windows route to the AsiraRouter interface index
    explicitly. Relying on Windows to infer the interface from the gateway can
    leave a successful tunnel handshake with no usable traffic route.
18. Treat IPv4 packets read from the Windows TUN that do not match the assigned
    source and selected destination CIDRs as drop-only housekeeping traffic.
    Never forward them, but do not tear down the whole selective session.
19. Intentional client disconnects must always finish local route cleanup even
    when the QUIC reader reports the expected connection-closed error.
20. Keep the Windows and Linux TUN MTU below the negotiated QUIC datagram
    ceiling and use back-pressure-aware datagram sends; an oversized or full
    QUIC datagram queue must not silently break the selective tunnel.
21. Configure an explicit QUIC keepalive for the long-lived tunnel. The default
    idle timeout can close an otherwise healthy selective session and leave the
    GUI looking connected without a usable route.
22. Drop malformed, oversized, or policy-invalid client datagrams on the VPS
    without tearing down the authenticated session. A single housekeeping
    packet must not reset an otherwise usable tunnel.
23. Keep an application-level liveness marker separate from tunneled IPv4 data.
    It may preserve a selective session across provider/NAT idle expiry, but it
    must be consumed before either TUN device and never count as user traffic.

## Validation before handing off

Run the formatter and workspace tests. Run a workspace check/build for the
target platform where possible. For the Windows GUI, confirm that the Tauri
frontend builds and that the Rust command layer still compiles. Do not claim
end-to-end network validation unless a real VPS and TUN driver were used.
Run `cargo audit` for the lockfile and record whether any advisory is reachable
in the supported Ubuntu server or Windows client target; do not hide an
advisory only to make the scan green.

## Security notes

The current MVP uses one passphrase for all clients. Anyone who has it can
connect and consume the VPS tunnel. It is intentionally not an account or
per-device authorization system. Future changes should add credential rotation
and revocation before adding public distribution.

## GUI design conventions

The Windows client follows the Asira desktop visual language used by the
companion Asira Keys app. Keep these rules in place when extending the UI:

- Use the neutral dark palette: background `#151515`, surfaces `#202020`,
  outlines `#252525`, primary text/icons `#eeeeee`, secondary text `#a5a5a5`,
  muted text `#808080`, and destructive states `#ab1f1f`.
- Use an 8px spacing and radius base, 1px borders, compact desktop utility
  layouts, and 250ms ease transitions for interactive controls.
- Keep the client frameless with a custom 56px titlebar, a dedicated draggable
  region, centered primary navigation, neutral minimize/close controls, and a
  fixed-size non-resizable window.
- Use visible `:focus-visible` states and preserve hover, active, disabled, and
  error states. Keep scrollbars hidden until scrolling makes them necessary.
- Use `asira_router_logo.svg` as the UI logo source and
  `asira_router_logo.ico` for Windows packaging. Do not modify the separate
  `asira-keys` project while borrowing its visual rules.
- Use the same Iconoir regular glyphs as Asira Keys where the router needs an
  icon: `Home`, `Database`, `StatsUpSquare`, `Check`, `Minus`, and `Xmark`.
  Keep them at 16px with a 1.7px stroke and inherit the surrounding text color.
- Keep `core:window:allow-start-dragging` in the Tauri capability assigned to
  the `main` window whenever the custom titlebar drag handler is used. The
  frontend handler alone is not sufficient under Tauri 2 permissions.

