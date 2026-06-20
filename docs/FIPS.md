<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright (c) 2024-2026 CodePros -->

# FIPS-140-3 / PQC mode for `dns`

`dns` supports a build-flag-gated FIPS-140-3 mode that routes every DNSSEC
security primitive through a linked, FIPS-140-3-validated cryptographic module
(the OpenSSL 3.x FIPS provider) and adds post-quantum DNSSEC transaction
signing (ML-DSA-65 SIG(0)). The flag mirrors the existing `-Dwith_otel` seam:
**off by default, zero overhead and zero OpenSSL link when off.**

## The `-Dfips` build flag

| Build | Backend | OpenSSL link | `fips` dependency |
|-------|---------|--------------|-------------------|
| `-Dfips=false` (default) | `std_shim` (`std.crypto`) | none | not fetched |
| `-Dfips=true` | OpenSSL 3.x FIPS provider (`fips` package) | libcrypto + libssl | fetched (lazy) |

The security path always imports the comptime seam `src/crypto_backend.zig`,
never `std.crypto` directly. When `-Dfips=false` the seam selects the local
`std_shim`; when `-Dfips=true` it selects the `fips` OpenSSL backend. The seam
files (`crypto_backend.zig`, `std_shim.zig`, `policy.zig`, `link.zig`) are
**canonical copy-verbatim** files shared with the `fips` foundation package and
must not be edited in `dns`.

### Building / testing under FIPS

```sh
# Default (std shim) — no OpenSSL, no fips dependency:
zig build test

# FIPS backend — requires the OpenSSL FIPS provider (built by `make deps`
# in the fips package, installed under /usr/local/ssl by default):
OPENSSL_CONF=/usr/local/ssl/ssl/openssl.cnf \
  zig build test -Dfips=true -Dopenssl_path=/usr/local/ssl
```

Use `-Dopenssl_path=<prefix>` for a non-standard OpenSSL install (the prefix's
`include`, `lib`, and `lib64` are added; the FIPS-build libcrypto is RPATH'd so
its compiled-in FIPS provider loads at runtime).

## TSIG (transaction authentication)

TSIG HMAC over SHA-2 (HMAC-SHA-256/384/512, RFC 8945) routes through
`crypto_backend.Mac.hmac` in both modes and produces bit-identical MACs
(verified against the RFC 4231 HMAC-SHA-256 KAT).

**Strict-security enforcement under `-Dfips=true`:** the legacy
`hmac_md5` and `hmac_sha1` TSIG algorithms are NOT FIPS-approved. Under
`-Dfips=true` they return `error.UnsupportedAlgorithm`. Under `-Dfips=false`
they remain available (std-backed) for legacy interoperability.

## SIG(0) (transaction signatures)

| SIG(0) algorithm | Codepoint | `-Dfips=false` | `-Dfips=true` |
|------------------|-----------|----------------|---------------|
| ECDSA P-256 / SHA-256 | 13 | supported (std) | supported (OpenSSL) |
| ECDSA P-384 / SHA-384 | 14 | supported (std) | supported (OpenSSL) |
| Ed25519 | 15 | supported (std) | supported (OpenSSL) |
| RSA/SHA-256, RSA/SHA-512 | 8, 10 | **unsupported** | supported at the seam |
| ML-DSA-65 (PQC) | 17 (provisional) | **unsupported** | supported (OpenSSL PQC) |

ECDSA and Ed25519 SIG(0) sign+verify route through `crypto_backend.Sig`
(`KeyPair.fromPrivateBytes` / `fromPublicBytes`) in BOTH modes. Because the
std-shim and OpenSSL-FIPS backends accept different raw key encodings and emit
different ECDSA signature formats, `dns` emits backend-correct bytes via a
comptime `crypto_backend.fips_enabled` branch:

- **Ed25519:** std shim takes the 64-byte std secret / 32-byte point; the FIPS
  backend takes the 32-byte raw seed / 32-byte point.
- **ECDSA:** std shim takes the raw scalar / SEC1 uncompressed point; the FIPS
  backend takes RFC 5915 `ECPrivateKey` DER / X.509 `SubjectPublicKeyInfo` DER,
  which `dns` builds from the raw components using fixed per-curve templates.
- **ECDSA signature format:** the FIPS backend produces DER `ECDSA-Sig-Value`
  signatures; SIG(0)/DNSSEC (RFC 6605) carries raw `r || s`. `dns` converts at
  the seam boundary so the on-wire signature stays RFC-correct.

**RSA SIG(0) boundary:** RSA is FIPS-approved (RFC 3110) and the OpenSSL backend
supports it, so `Algorithm.rsa_sha256/rsa_sha512.isSupported()` returns `true`
under `-Dfips=true` and `false` under `-Dfips=false` (the std shim has no RSA).
`dns` ships **no native RSA implementation** and no RSA key generation, so RSA
SIG(0) key material is not produced by `dns` itself. The consumer-owned-backend
escape hatch (delegating to `std_shim` for std-covered algorithms and to a
custom backend for RSA/PQC in non-fips mode) is documented in the foundation's
`fips/docs/SEAM_CONTRACT.md`; `dns` adopts the seam directly and does not
exercise it.

## ML-DSA-65 SIG(0) DNSSEC signing (post-quantum, FIPS-only)

Under `-Dfips=true`, `dns` adds ML-DSA-65 (FIPS 204) SIG(0) transaction signing
via `MlDsaSig0Signer` and `Sig0Context.signMlDsa` / `verifyMlDsa`, backed
entirely by the OpenSSL FIPS provider's PQC support. The seam-owned EVP keypair
is generated once and held for its lifetime, so no key import is needed. Under
`-Dfips=false` the std shim has no ML-DSA, so `MlDsaSig0Signer.init` returns
`error.UnsupportedAlgorithm` and `Algorithm.ml_dsa_65.isSupported()` is `false`.

### PROVISIONAL DNSSEC codepoint — algorithm 17

`Algorithm.ml_dsa_65 = 17` is a **PROVISIONAL placeholder**, NOT a ratified
IANA assignment. As of 2026-06-20 the IANA "DNSSEC Algorithm Numbers" registry
lists 17 as **Unassigned**:

> <https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml>

The value `17` tracks the working-document allocation for ML-DSA-65 in
`draft-ietf-dnsop-dnssec-pqc`.

**Interop caveat:** ML-DSA-65 SIG(0) records produced by `dns` are
interoperable only with peers that use the same provisional `17` codepoint.
When the draft is ratified and IANA assigns the final value, change the single
`Algorithm.ml_dsa_65 = 17` literal in `src/security/sig0.zig` and this line;
nothing else depends on the numeric value (the wire algorithm byte is derived
via `@intFromEnum`). Tracked in Open Issues #2.

## std-shim `error.Unsupported` boundary

The canonical `std_shim` returns `error.Unsupported` for RSA and for ALL PQC
(ML-DSA / SLH-DSA / ML-KEM). `dns` surfaces this as `error.UnsupportedAlgorithm`
for SIG(0). Consequently RSA and ML-DSA SIG(0) are fips-only; classical ECDSA
and Ed25519 SIG(0) and SHA-2 TSIG work in both modes.

## Dual-mode test gate

Spec section 7 requires `dns` to be green with BOTH `-Dfips=false` (default,
std shim, zero OpenSSL) AND `-Dfips=true` (OpenSSL FIPS backend). The Makefile
encodes this gate:

```sh
# std shim only (no OpenSSL):
make test-unit

# FIPS backend only (-Dfips=true). Override the OpenSSL prefix with
# OPENSSL_PREFIX=<prefix>; defaults to /usr/local/ssl:
OPENSSL_CONF=/usr/local/ssl/ssl/openssl.cnf make test-fips

# BOTH modes (the gate):
OPENSSL_CONF=/usr/local/ssl/ssl/openssl.cnf make test-dual
```

`make test-fips` / `make test-dual` require the OpenSSL FIPS provider to be
installed first. It is built by the `fips` package's `make deps`
(`install-openssl-fips.sh`), which compiles the latest OpenSSL 3.x with
`enable-fips` and installs it under `/usr/local/ssl` (override with
`OPENSSL_PREFIX=`). In CI the `test-fips` job provisions the provider before
running `make test-dual` (see `.gitlab-ci.yml`).
