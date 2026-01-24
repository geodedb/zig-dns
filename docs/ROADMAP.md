# zigdns Roadmap

This document tracks the implementation status of zigdns features. Each item links to a GitLab issue for detailed requirements and progress tracking.

**Project URL:** https://gitlab.com/devnw/zig/dns

## Phase 1: Core Recursion ✅ COMPLETE

**Milestone:** [Phase 1: Core Recursion](https://gitlab.com/devnw/zig/dns/-/milestones/1)

Foundation for full recursive DNS resolution.

| Feature | Issue | Priority | Status | Notes |
|---------|-------|----------|--------|-------|
| Iterative recursion algorithm | [#1](https://gitlab.com/devnw/zig/dns/-/issues/1) | Critical | **Complete** | Full CNAME/referral handling |
| QNAME minimization (RFC 7816) | [#2](https://gitlab.com/devnw/zig/dns/-/issues/2) | High | **Complete** | Privacy-preserving queries |
| 0x20 case randomization | [#3](https://gitlab.com/devnw/zig/dns/-/issues/3) | Medium | **Complete** | Cache poisoning protection |
| SRV record parser (RFC 2782) | [#5](https://gitlab.com/devnw/zig/dns/-/issues/5) | Medium | **Complete** | Service discovery |
| CAA record parser (RFC 8659) | [#6](https://gitlab.com/devnw/zig/dns/-/issues/6) | Medium | **Complete** | CA authorization |
| TLSA record parser (RFC 6698) | [#7](https://gitlab.com/devnw/zig/dns/-/issues/7) | Medium | **Complete** | DANE/TLS auth |
| SVCB/HTTPS parsers (RFC 9460) | [#8](https://gitlab.com/devnw/zig/dns/-/issues/8) | Medium | **Complete** | Service binding |

### Dependencies
- None (uses existing UDP/TCP transports)

### Deliverables
- Full recursive resolution from root servers
- Improved privacy with QNAME minimization
- Cache poisoning protection via 0x20
- Modern record type support

---

## Phase 2: Production Ready ✅ COMPLETE

**Milestone:** [Phase 2: Production Ready](https://gitlab.com/devnw/zig/dns/-/milestones/2)

Features required for production deployment.

| Feature | Issue | Priority | Status | Notes |
|---------|-------|----------|--------|-------|
| DoT transport (RFC 7858) | [#9](https://gitlab.com/devnw/zig/dns/-/issues/9) | Critical | **Complete** | TLS backend abstraction |
| Negative caching (RFC 2308) | [#10](https://gitlab.com/devnw/zig/dns/-/issues/10) | Medium | **Complete** | SOA minimum extraction |
| Cache poisoning protection | [#11](https://gitlab.com/devnw/zig/dns/-/issues/11) | Medium | **Complete** | Bailiwick checks, TTL capping |
| Zone transfers (AXFR/IXFR) | [#12](https://gitlab.com/devnw/zig/dns/-/issues/12) | Medium | **Complete** | Full zone transfer support |

### Dependencies
- Phase 1 completion ✓

### External Dependencies
DoT transport provides a pluggable TLS backend interface. Implementations can use:
- BoringSSL bindings
- mbedTLS bindings
- bearssl
- Any other TLS library via the TlsBackend interface

### Deliverables
- Encrypted DNS queries via DoT with TLS backend abstraction
- RFC 2308 compliant negative caching with SOA minimum TTL extraction
- Hardened cache against poisoning attacks (bailiwick checks, TTL capping)
- Zone synchronization capability (AXFR/IXFR)

---

## Phase 3: DNSSEC ✅ COMPLETE

**Milestone:** [Phase 3: DNSSEC](https://gitlab.com/devnw/zig/dns/-/milestones/3)

Full DNSSEC validation for authenticated DNS.

| Feature | Issue | Priority | Status | Notes |
|---------|-------|----------|--------|-------|
| RRSIG/DNSKEY parsers | [#13](https://gitlab.com/devnw/zig/dns/-/issues/13) | Critical | **Complete** | Full parsing with key tag calculation |
| DS record validation | [#14](https://gitlab.com/devnw/zig/dns/-/issues/14) | Critical | **Complete** | SHA-1/SHA-256/SHA-384 digests |
| NSEC/NSEC3 validation | [#15](https://gitlab.com/devnw/zig/dns/-/issues/15) | High | **Complete** | NXDOMAIN/NODATA proofs |
| Signature validation | [#16](https://gitlab.com/devnw/zig/dns/-/issues/16) | Critical | **Complete** | Ed25519, ECDSA P-256/P-384 |
| Chain-of-trust validation | [#17](https://gitlab.com/devnw/zig/dns/-/issues/17) | Critical | **Complete** | Trust anchor to leaf |

### Dependencies
- Phase 2 completion ✓

### Algorithm Support
| Algorithm | ID | Status | Notes |
|-----------|-----|--------|-------|
| ECDSAP256SHA256 | 13 | **Complete** | std.crypto.sign.ecdsa |
| ED25519 | 15 | **Complete** | std.crypto.sign.Ed25519 |
| ECDSAP384SHA384 | 14 | **Complete** | std.crypto.sign.ecdsa |
| RSASHA256 | 8 | Stub | Requires external crypto lib |
| RSASHA512 | 10 | Stub | Requires external crypto lib |
| RSASHA1 | 5 | Stub | Requires external crypto lib |

Note: RSA algorithms require external cryptographic library (e.g., BoringSSL, mbedTLS).
Ed25519 and ECDSA algorithms are fully supported via Zig's std.crypto.

### Deliverables
- ✅ Cryptographic signature validation (Ed25519, ECDSA)
- ✅ Authenticated denial of existence (NSEC/NSEC3)
- ✅ Full chain-of-trust from root to leaf
- ✅ DNSSEC record parsers (DNSKEY, RRSIG, DS, NSEC, NSEC3, NSEC3PARAM)

---

## Phase 4: Modern Features ✅ COMPLETE

**Milestone:** [Phase 4: Modern Features](https://gitlab.com/devnw/zig/dns/-/milestones/4)

Modern transport protocols and advanced features.

| Feature | Issue | Priority | Status | Notes |
|---------|-------|----------|--------|-------|
| DoH transport (RFC 8484) | [#18](https://gitlab.com/devnw/zig/dns/-/issues/18) | Critical | **Complete** | Pluggable HTTP backend |
| DoQ transport (RFC 9250) | [#19](https://gitlab.com/devnw/zig/dns/-/issues/19) | High | **Complete** | Pluggable QUIC backend |
| EDNS Client Subnet (RFC 7871) | [#20](https://gitlab.com/devnw/zig/dns/-/issues/20) | Low | **Complete** | Full ECS support |
| DNS Cookies (RFC 7873) | [#21](https://gitlab.com/devnw/zig/dns/-/issues/21) | Low | **Complete** | SipHash cookie computation |
| Cache prefetching | [#22](https://gitlab.com/devnw/zig/dns/-/issues/22) | Low | **Complete** | Configurable threshold |

### Dependencies
- Phase 3 completion ✓

### External Dependencies

DoH and DoQ transports provide pluggable backend interfaces. Implementations can use:

**DoH (HTTP Backend):**
- Zig standard library HTTP client
- curl bindings
- nghttp2 bindings
- Any HTTP/2 library via HttpBackend interface

**DoQ (QUIC Backend):**
- quiche (Cloudflare)
- ngtcp2
- msquic
- Any QUIC library via QuicBackend interface

### Deliverables
- ✅ HTTP-based DNS queries (DoH with pluggable backend)
- ✅ QUIC-based DNS queries (DoQ with pluggable backend)
- ✅ Geo-aware queries (EDNS Client Subnet)
- ✅ Replay protection (DNS Cookies)
- ✅ Proactive cache refresh (Cache Prefetching)

---

## Current Implementation Status

### Fully Implemented (Phase 1 + Phase 2 + Phase 3 + Phase 4)
- Core DNS message parsing (RFC 1035)
- Name compression/decompression
- A, AAAA, CNAME, MX, NS, PTR, SOA, TXT, DNAME records
- Modern record types: SRV, CAA, TLSA, SVCB, HTTPS
- DNSSEC record types: DNSKEY, RRSIG, DS, NSEC, NSEC3, NSEC3PARAM
- UDP and TCP transports
- EDNS(0) with DO flag (RFC 6891)
- Full recursive resolution with iterative algorithm
- QNAME minimization (RFC 7816)
- 0x20 case randomization for cache poisoning protection
- LRU caching with TTL clamping
- Negative caching (RFC 2308) with SOA minimum extraction
- DoT transport with pluggable TLS backend (RFC 7858)
- Cache poisoning protection (bailiwick checks, TTL capping)
- Zone transfers (AXFR/IXFR) via RFC 5936/1995
- Stub resolver with TCP fallback
- DNSSEC validation (Ed25519, ECDSA P-256/P-384)
- Chain-of-trust validation from root to leaf
- Authenticated denial of existence (NSEC/NSEC3)
- DoH transport with pluggable HTTP backend (RFC 8484)
- DoQ transport with pluggable QUIC backend (RFC 9250)
- EDNS Client Subnet (RFC 7871)
- DNS Cookies (RFC 7873)
- Cache prefetching with configurable threshold

### Partially Implemented
- DNSSEC RSA algorithms (requires external crypto library)

### Requires External Libraries
- DoH: Requires HTTP/2 library (provides HttpBackend interface)
- DoQ: Requires QUIC library (provides QuicBackend interface)

---

## Effort Estimates

| Phase | Estimated Duration |
|-------|-------------------|
| Phase 1 | 4-6 weeks |
| Phase 2 | 6-8 weeks |
| Phase 3 | 8-12 weeks |
| Phase 4 | 6-10 weeks |
| **Total** | **24-36 weeks** |

Note: Phases can overlap. Phase 1 and Phase 2 can proceed in parallel once recursion algorithm is stable.

---

## Contributing

Pick an issue from any phase! Start with Phase 1 items for the biggest impact.

1. Check the issue for detailed requirements
2. Fork the repository
3. Create a feature branch
4. Submit a merge request

See [CONTRIBUTING.md](../CONTRIBUTING.md) for detailed guidelines.
