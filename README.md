# ProxyNightmare (PN)

PN is a C++20 test runner for stateful TCP, UDP, TLS, and QUIC proxy tests. The
controller starts an agent on both the server and client hosts over SSH control
connections. The agents open the sockets under test themselves, so test data
does not pass through an SSH tunnel:

```text
                         control: SSH
                    +---------------------+
                    |                     |
                  server                client
                    ^                     |
                    | tested TCP/UDP/TLS/QUIC |
                    +------ proxy <-------+
```

## Requirements and build

CMake 3.20+, a C++20 compiler, OpenSSL 3.5+ development headers, and `ssh` are
required. For example, on Debian/Ubuntu:

```sh
sudo apt install build-essential cmake libssl-dev openssh-client
```

```sh
cd proxynightmare
cmake -S . -B build
cmake --build build -j
ctest --test-dir build --output-on-failure
```

## Quick start

First, you can check a scenario's syntax without running it:

```sh
./build/pn check docs/examples/client_rx_closed.pn
```

Local examples for all transports:

```sh
# TCP: half-close and complete stream validation
./build/pn run docs/examples/client_rx_closed.pn --trace

# TCP: full-duplex, small buffers, and crossed FINs
./build/pn run docs/examples/buffer_torture.pn --trace

# UDP: three generations of datagrams with source port changes
./build/pn run docs/examples/udp_churn.pn --trace

# TLS: a real OpenSSL TLS 1.3 handshake, one phase at a time
./build/pn run docs/examples/tls_full_handshake.pn --trace

# TLS: an encrypted stamped stream over SSL_write/SSL_read
./build/pn run docs/examples/tls_encrypted_stream.pn --trace

# TLS: ClientHello followed by an immediate TCP FIN
./build/pn run docs/examples/tls_client_hello_eot.pn --trace

# TLS: autonomous completion of the entire handshake
./build/pn run docs/examples/tls_autonomous_handshake.pn --trace

# QUIC: a real QUIC v1/TLS 1.3 stream and STREAM FIN
./build/pn run docs/examples/quic_stream_torture.pn --trace

# QUIC: multiple streams churned on a single connection
./build/pn run docs/examples/quic_stream_churn.pn --trace

# The shortest local smoke test
./build/pn run docs/examples/local_smoke.pn --trace
```

Success returns exit code `0`, failure or timeout `1`, and CLI or syntax errors `2`.

## Remote execution over SSH

Set both control endpoints in the scenario:

```text
server at "tester@origin-host"
client at "tester@client-host"
```

The `pn` binary must be in `PATH` on both hosts:

```sh
./build/pn run test.pn --trace
```

If it is elsewhere, specify a path that is valid on both remote hosts:

```sh
./build/pn run test.pn --remote-pn /opt/pn/bin/pn --trace
```

SSH should be non-interactive. The target after `at` is passed to `ssh`, so it
accepts both `user@host` and SSH configuration aliases. The value `local` starts
an agent locally for smoke testing.
The value `netns:NAME` starts a local agent through `ip netns exec NAME`; the
controller must therefore have permission to enter the namespace. This is
primarily intended for isolated transparent-proxy tests where the client and
origin run in separate namespaces.

PN does not test application payload semantics. `transmit` generates a
deterministic binary stream and inserts a 32-byte stamp every `stamp-every`
bytes, containing the absolute offset, creation timestamp, and checksum.
`drain` independently verifies stamps, offsets, and padding. This detects data
loss, duplication, reordering, and corruption without embedding the payload
in the scenario.

## The `.pn` language

A file requires a `preamble`, a transport body delimited by
`begin using tcp|udp|tls|quic`/`end`, and a final outcome block. A bare `begin`
is not valid:

```text
preamble
name "test name"
description "what the test proves"
timeout 10s
begin using tcp
server at "user@server-host"
client at "user@client-host"
server listen "0.0.0.0:9000"
client connect "proxy.example:443"
client half-close-read
server drain 20KiB stamp-every 1KiB
client transmit 20KiB stamp-every 1KiB chunk 257B
client await-tx
client half-close-write
server await-rx
server receive-eot
server close
client close
end
outcome pass
when server.rx.bytes == 20KiB
and server.rx.integrity == valid
describe "The server received the entire stream without corruption."
outcome fail "The proxy did not deliver the entire stream."
outcome timeout "The proxy still holds the connection after the time limit."
end
```

The preamble accepts arbitrary metadata as `key "value"`; `timeout` controls
the global time limit (`ms`, `s`, `m`). Both roles with `at`, an explicit
`outcome pass` condition, and `outcome timeout` are required. `outcome fail`
is an optional custom description; without it, PN reports the technical cause.

| Operation | Meaning |
|---|---|
| `listen "host:port"` | bind + listen; accept occurs on the first I/O operation |
| `connect "host:port"` | connect to the proxy or destination |
| `receive-eot` | wait for EOF from the peer |
| `close` | close the role's socket |
| `transmit SIZE stamp-every SIZE [chunk SIZE] [delay TIME]` | asynchronously generate and send a stamped stream |
| `drain SIZE stamp-every SIZE` | asynchronously receive and validate a stream |
| `await-tx`, `await-rx` | wait for the corresponding asynchronous task |
| `set-sndbuf SIZE`, `set-rcvbuf SIZE` | set the kernel socket buffer size |
| `half-close-write`, `half-close-read` | independent `shutdown(SHUT_WR/SHUT_RD)` calls |
| `sleep TIME` | a controlled stall of the remote agent |
| `abort` | abortive close with RST (`SO_LINGER=0`) |
| `reconnect` | UDP: the client creates a new socket/source port; the server forgets its peer |
| `hello` | TLS: send ClientHello or ServerHello depending on the role; the peer verifies it |
| `encrypted-extensions` | TLS EncryptedExtensions handshake record |
| `certificate`, `certificate-request`, `certificate-verify` | TLS certificate phases |
| `finished`, `new-session-ticket`, `key-update` | TLS completion and post-handshake phases |
| `change-cipher-spec`, `close-notify` | TLS compatibility CCS and close_notify alert |
| `handshake` | TLS/QUIC: complete the cryptographic handshake of both peers in parallel |
| `next-stream` | QUIC: close the local stream handle; the next TX/RX creates a new stream |

Commands run from top to bottom. The global timeout includes SSH startup,
connection establishment, and I/O. The result is `pass` only when all explicit
`when`/`and` conditions hold. A socket error, corrupted stream, premature EOF,
timeout, or unmet condition means failure. The exit code is `0` only for a pass,
`1` for failure including timeout, and `2` for input or CLI errors.

Sizes accept `B`, `KiB`, `MiB`, and `GiB`; times accept `us`, `ms`, and `s`.
`transmit` and `drain` are asynchronous: you can start both directions, change
socket states, and then use `await-*`. A complete full-duplex example with 4KiB
buffers, asymmetric chunks, and crossed FINs is in `docs/examples/buffer_torture.pn`.
With `--trace`, `await-rx` reports the stamp count and the minimum/average/maximum
difference between the receiver's clock and the sender's timestamp (meaningful
when the peers' clocks are synchronized).

## Transports

```text
begin using tcp   # stream, half-close, FIN/RST, backpressure
begin using udp   # datagrams, reconnect/source-port churn
begin using tls   # TLS records over TCP + all TCP state operations
begin using quic  # QUIC v1 over UDP, TLS 1.3, and independent QUIC streams
```

In UDP mode, `half-close-read`, `half-close-write`/`write-eot`, and `receive-eot`
are intentional no-ops and are identified as such in the trace. `transmit`
splits the generated stream into datagrams according to `chunk`; `drain` checks
for loss, duplication, ordering, and integrity. `reconnect` allows a scenario
to change the client's source port repeatedly.

The TLS backend uses OpenSSL 3 and a real TLS 1.3 state machine. At startup, the
server creates an ephemeral P-256 key and a self-signed certificate; OpenSSL
computes ECDHE, the transcript hash, CertificateVerify, Finished, traffic secrets,
NewSessionTicket, KeyUpdate, and encrypted post-handshake messages. The certificate
is accepted for the test session without checking the public trust store, but
proof of ownership and the CertificateVerify signature are cryptographically
verified. The DSL rejects an invalid phase order based on OpenSSL's actual next
state. TCP operations can be inserted between records:

```text
begin using tls
client at "tester@client"
server at "tester@server"
server listen "0.0.0.0:4433"
client connect "proxy.example:443"
client hello
client write-eot
server receive-eot
...
```

Examples: `docs/examples/udp_churn.pn`, `docs/examples/tls_client_hello_eot.pn`, and
`docs/examples/tls_full_handshake.pn`. After the handshake completes, `transmit`
and `drain` use `SSL_write_ex`/`SSL_read_ex` directly; the stamped torture stream
is therefore protected by real TLS traffic keys and AEAD. See
`docs/examples/tls_encrypted_stream.pn`.

The QUIC backend uses OpenSSL 3.5 server and client APIs, real QUIC v1, TLS 1.3,
and mandatory ALPN `pn/1`. `transmit`/`drain` operate on an encrypted bidirectional
QUIC stream, `half-close-write` sends STREAM FIN, `receive-eot` verifies the remote
STREAM FIN, and `next-stream` enables stream churn on a single connection. `close`
sends QUIC CONNECTION_CLOSE in rapid shutdown mode.

The OpenSSL 3.5 public API does not provide controlled connection migration to a
new local IP/port, so PN does not currently simulate it. Supported churn tests
create new QUIC streams; examples are `docs/examples/quic_stream_torture.pn` and
`docs/examples/quic_stream_churn.pn`.
Likewise, OpenSSL 3.5 does not expose standalone QUIC STOP_SENDING;
`half-close-read` therefore produces an explicit error in QUIC mode instead of
a misleading no-op or an incorrect RESET_STREAM.
