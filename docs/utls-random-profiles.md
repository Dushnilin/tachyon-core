# Random TLS fingerprints

Both `tls.utls.fingerprint: "random"` and `"randomized"` are resolved at
runtime, including when uTLS is used with REALITY. Previously configuration
validation accepted these names but outbound construction rejected them as
unknown browsers, preventing the core from starting.

`random` chooses one of Chrome, Firefox, Edge, Safari or iOS once per process,
matching the reference's browser selection policy. `randomized` creates one
native randomized profile per process from the modern Chrome template:
cipher suites and extensions are shuffled, legacy cipher suites and optional
status-request, SCT, certificate-compression and session-ticket extensions
are randomly retained or removed. The TLS 1.3 cipher suites, SNI, configured
ALPN, signature algorithms, versions, supported groups and key shares remain
available. In particular, the hybrid group and its share remain paired.

The randomized profile is not a byte-for-byte implementation of uTLS's seeded
generation algorithm or probability distribution. Keeping ALPN avoids a draw
that permanently prevents an HTTP/2 transport from negotiating `h2`.

Profile selection stays stable across outbounds, reloads and connections in
the same process. ClientHello random bytes, session IDs, GREASE values and
cryptographic key shares are still generated afresh for each handshake.
Restarting the process selects new profiles. The fixed browser profiles are
unchanged.

Regression tests cover runtime construction, process stability, randomized
profile diversity and negotiation essentials, strict ClientHello parsing,
TLS handshakes and ALPN agreement, and server-side verification of REALITY
session-ID sealing. Session-ID sealing is not a claim of full interoperability
with every deployed REALITY server or target.
