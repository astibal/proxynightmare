# Smithproxy transport scenarios

These scenarios exercise Smithproxy as a black-box transparent TCP/UDP proxy. They
expect an already prepared isolated topology:

```text
sxr-client (198.18.10.2) -> Smithproxy/TProxy -> sxr-origin (198.18.20.2)
```

The namespaces and addresses intentionally match Smithproxy's P3 patch-runner
lab. Run the controller on the same root-capable host after the lab is ready:

```sh
sudo ./build/pn run tests/scenarios/smithproxy/full_duplex_tiny_buffers.pn --trace
```

The scenario files do not create namespaces, start Smithproxy, or alter host
networking. This keeps topology ownership and cleanup in the existing
Smithproxy lab runner. `pn check` is always safe and needs no privileges.

For a complete local run using Smithproxy's existing P3 lab ownership and
cleanup, use:

```sh
sudo tests/scenarios/smithproxy/run-local-p3.sh \
  --source /path/to/smithproxy \
  --binary /path/to/build/smithproxy
```

These are transport/lifecycle tests. They prove byte integrity, ordering,
half-close propagation and freedom from hangs; they do not validate HTTP
semantics, policy selection, or signature generations.

TLS scenarios use the real Smithproxy TLS listener selected by destination
port 443 and its default interception profile. ProxyNightmare runs a complete
OpenSSL TLS 1.3 state machine at both endpoints, so encrypted stream scenarios
exercise Smithproxy's decrypt/inspect/re-encrypt MITM path. The isolated test
profile accepts PN's per-scenario self-signed origin certificate; PN still
cryptographically verifies CertificateVerify, Finished and AEAD records. UDP
scenarios use the generic UDP transparent listener.
