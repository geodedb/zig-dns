# zigdns Architecture

This document describes the architecture and design of the zigdns library.

## Overview

zigdns is organized into layered modules following DNS protocol structure:

```text
┌─────────────────────────────────────────────────────────┐
│                     Client API                          │
│                   (src/client.zig)                      │
├─────────────────────────────────────────────────────────┤
│     Stub Resolver      │      Recursive Resolver        │
│    (src/stub.zig)      │    (src/recursive.zig)         │
├─────────────────────────────────────────────────────────┤
│        Cache Layer     │      DNSSEC Validation         │
│  (src/cache.zig,       │   (src/resolver/dnssec.zig)    │
│   resolver/dns_cache)  │                                │
├─────────────────────────────────────────────────────────┤
│                   Transport Layer                        │
│  (src/transports/udp, tcp, dot, doh, doq, pool, ...)   │
├─────────────────────────────────────────────────────────┤
│               Security / Policy Layer                    │
│  (tsig, sig0, rpz, split_dns, failover, logging, ...)  │
├─────────────────────────────────────────────────────────┤
│                   Message Layer                          │
│  (src/message.zig, header.zig, question.zig, record.zig)│
├─────────────────────────────────────────────────────────┤
│                   Core Types                             │
│           (src/types.zig, src/name.zig)                 │
└─────────────────────────────────────────────────────────┘
```

## Module Descriptions

### Core Types (`src/types.zig`)

Defines all DNS constants, enums, and basic types:

- `Type` - Record types (A, AAAA, CNAME, etc.)
- `Class` - Query classes (IN, CH, HS, etc.)
- `ResponseCode` - RCODE values (NOERROR, NXDOMAIN, etc.)
- `Opcode` - Query opcodes (QUERY, IQUERY, STATUS, etc.)

### Name Handling (`src/name.zig`)

DNS name encoding and compression per RFC 1035 Section 4.1.4:

- Label parsing and validation
- Compression pointer handling
- Allocation-free label-by-label comparison
- Case-insensitive comparison
- Wire format encoding

### Message Layer

#### Header (`src/header.zig`)

DNS message header (12 bytes):

- Transaction ID
- Flags (QR, Opcode, AA, TC, RD, RA, Z, RCODE)
- Section counts (QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

#### Question (`src/question.zig`)

Question section handling:

- QNAME parsing
- QTYPE and QCLASS
- Wire format encoding

#### Record (`src/record.zig`)

Resource record parsing:

- Common RR header (name, type, class, TTL, RDLENGTH)
- RDATA parsing for each type
- Type-specific parsers (parseA, parseAAAA, parseMX, etc.)
- `rdataOffset()` helper for wire format offset calculations

#### Message (`src/message.zig`)

Complete message handling:

- Section iteration (question, answer, authority, additional)
- Cached section offsets for O(1) access
- Message building
- Response validation helpers

### EDNS (`src/edns.zig`)

EDNS(0) OPT record handling per RFC 6891:

- UDP payload size negotiation
- Extended RCODE
- DNSSEC OK (DO) flag
- Option parsing (ECS, cookies, etc.)

### Cache Layer

#### Basic Cache (`src/cache.zig`)

Simple response caching:

- TTL-aware expiration
- Name-based lookup

#### Advanced Cache (`src/resolver/dns_cache.zig`)

Enhanced caching with:

- LRU eviction policy
- TTL clamping (min/max)
- Negative caching (NXDOMAIN, NODATA)
- Clock abstraction for testing

#### Cache Prefetching (`src/resolver/cache_prefetch.zig`)

Proactive cache refresh:

- Configurable TTL threshold for triggering prefetch
- Integrates with DnsCache for entry monitoring

### Resolver Layer

#### Channel Abstraction (`src/resolver/channel.zig`)

Unified transport interface:

```zig
pub const Channel = struct {
    kind: ChannelKind,  // udp, tcp, dot, doh, doq
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        query: *const fn(*anyopaque, []const u8, u32) anyerror![]u8,
        close: *const fn(*anyopaque) void,
    };
};
```

Mock implementation for testing:

```zig
var mock = MockChannel.init(allocator, .udp);
try mock.addResponse(response_bytes);
const resp = try mock.channel().query(query, 1000);
```

#### Stub Resolver (`src/stub.zig`)

Simple forwarding resolver:

- Configurable upstream servers
- UDP with TCP fallback on truncation
- Timeout and retry handling
- EDNS negotiation

#### Recursive Resolver (`src/recursive.zig`)

Full iterative resolution from root servers:

- Root server list (13 servers, IPv4 and IPv6)
- QNAME minimization (RFC 7816)
- 0x20 case randomization for cache poisoning protection
- NS record following with single-pass referral extraction
- Bailiwick checks for glue records
- CNAME chain following (up to 8 records) with outer-loop restart
- Configurable depth limit and query budget
- Response caching with TTL awareness
- Owned server/zone lifecycle management for referral chains

#### Convenience APIs (`src/resolver/convenience.zig`)

High-level resolution helpers:

- IPv4/IPv6 address formatting with bounded stack buffers
- Simplified query construction

#### Configuration (`src/resolver/config.zig`)

Configuration file support for resolver settings.

### Transport Layer (`src/transports/`)

#### UDP Transport (`src/transports/udp.zig`)

- Standard UDP DNS queries (RFC 1035)
- Configurable timeout via SO_RCVTIMEO
- Source address validation
- 4096-byte receive buffer (EDNS default, RFC 6891)

#### TCP Transport (`src/transports/tcp.zig`)

- 2-byte length prefix per RFC 1035
- Connection timeout enforcement
- Exact-read loop for partial read handling
- For truncated responses and zone transfers

#### DoT Transport (`src/transports/dot.zig`)

DNS over TLS (RFC 7858) -- pluggable TLS backend interface:

- ALPN: "dot"
- Port 853 default
- Requires external TLS library (BoringSSL, mbedTLS, bearssl) via `TlsBackend` vtable

#### DoH Transport (`src/transports/doh.zig`)

DNS over HTTPS (RFC 8484) -- pluggable HTTP backend interface:

- GET with base64url query parameter
- POST with application/dns-message
- HTTPS scheme and Content-Type validation
- Requires external HTTP/2 library via `HttpBackend` vtable

#### DoQ Transport (`src/transports/doq.zig`)

DNS over QUIC (RFC 9250) -- pluggable QUIC backend interface:

- ALPN: "doq"
- 2-byte length prefix
- Message ID = 0
- Feature-gated via `-Dfeature_doq=true`
- Requires external QUIC library (quiche, ngtcp2, msquic) via `QuicBackend` vtable

#### Connection Pool (`src/transports/connection_pool.zig`)

TCP connection pooling (RFC 7766/7828):

- Reusable connections to reduce socket overhead
- Idle connection management

#### Happy Eyeballs (`src/transports/happy_eyeballs.zig`)

Dual-stack connection racing (RFC 8305):

- Parallel IPv4/IPv6 connection attempts
- Configurable race delay

### Security Modules

#### TSIG (`src/security/tsig.zig`)

Transaction Signatures (RFC 2845):

- HMAC-based message authentication
- Request/response signing and verification

#### SIG(0) (`src/security/sig0.zig`)

DNS Request and Transaction Signatures (RFC 2931):

- Public key-based message signing
- Algorithm support detection (Ed25519, ECDSA)

#### Shared DNS Name Utilities (`src/security/dns_name.zig`)

Shared name parsing for security modules:

- `parseName`, `skipName`, `skipRR` for wire format traversal
- `encodeName`, `encodeNameLower` for wire format encoding

### DNSSEC (`src/resolver/dnssec.zig`)

> ⚠️ **Not wired into resolution.** The validator below is a standalone module
> with no callers in `recursive.zig`/`stub.zig`/`client.zig`, and outgoing
> queries do not set the EDNS DO bit. Resolved answers are therefore **not**
> DNSSEC-validated and the validator must not be relied on for an integrity
> guarantee. Tracked by [#207](https://gitlab.com/devnw/zig/dns/-/issues/207)
> (wiring) and [#255](https://gitlab.com/devnw/zig/dns/-/issues/255).

DNSSEC validation primitives (RFC 4033/4034/4035):

- RRSIG signature verification (Ed25519, ECDSA P-256/P-384)
- DS record validation (SHA-1/SHA-256/SHA-384 digests)
- NSEC/NSEC3 authenticated denial of existence
- Chain-of-trust validation from root to leaf
- RSA algorithms (8/10/5) return UnsupportedAlgorithm (requires external crypto library)

### Zone Transfer (`src/resolver/zone_transfer.zig`)

Zone transfer support:

- AXFR full zone transfer (RFC 5936)
- IXFR incremental zone transfer (RFC 1995)

### Policy and Routing

#### Server Failover (`src/resolver/failover.zig`)

Server failover and load balancing:

- Health tracking per server
- Automatic failover on server failure

#### Split DNS (`src/resolver/split_dns.zig`)

Policy-based DNS routing:

- Domain-based routing rules
- Per-policy server configuration

#### Response Policy Zones (`src/resolver/rpz.zig`)

RPZ support (RFC 8646):

- Policy-based response filtering
- Domain blocking and redirection

### Logging (`src/resolver/logging.zig`)

Query/response logging:

- Structured log output
- JSON string escaping for safe output
- Log string sanitization
- Buffer bounds checking

### Cache Protection (`src/resolver/cache_protection.zig`)

Cache poisoning protection (RFC 5452):

- Bailiwick checks
- TTL capping

### Utilities (`src/util/`)

#### Clock (`src/util/clock.zig`)

Mockable time source for deterministic testing.

#### Random (`src/util/random.zig`)

Mockable RNG for deterministic testing.

#### LRU Cache (`src/util/lru.zig`)

Generic LRU cache with O(1) operations:

- HashMap for O(1) lookup
- Doubly-linked list for LRU ordering

#### Metrics (`src/util/metrics.zig`)

Prometheus-style counters:

- queries_total, cache_hits_total, cache_misses_total
- tcp_fallback_total, timeouts_total, servfail_total

#### Enhanced Metrics (`src/util/enhanced_metrics.zig`)

Extended metrics collection:

- Histograms and gauges
- Per-server statistics

#### Backoff (`src/util/backoff.zig`)

Exponential backoff with jitter for retry logic.

### Zone File Parser (`src/zone_file.zig`)

RFC 1035 Section 5 zone file parsing:

- Standard zone file format support

### Parallel Operations (`src/parallel.zig`)

Spice-based parallelism for concurrent DNS operations:

- Thread pool management (GPA-backed)
- Parallel query dispatch
- Feature-gated via `-Dspice=true` (enabled by default)

### Resolver EDNS (`src/resolver/edns.zig`)

EDNS(0) handling specific to the resolver layer.

### Public API Entry Point (`src/lib.zig`)

Re-exports all public modules via `@import("dns")`:

- Core protocol, resolution, transports, security, utilities
- Convenience type aliases (Name, Header, Message, Client, etc.)

## Design Principles

### 1. Zero Runtime Allocations in Hot Path

Message parsing uses slices into the original buffer rather than copying.

### 2. Explicit Error Handling

All fallible operations return errors rather than using defaults.

### 3. Testability

- Mock implementations for all external dependencies
- Fixed clock and RNG for deterministic tests
- Acceptance tests with controlled I/O

### 4. RFC Compliance

- Comments reference specific RFC sections
- Wire format matches specifications exactly
- Test vectors from RFCs where available

### 5. Modular Design

- Each module has single responsibility
- Dependencies flow downward
- Circular dependencies avoided

### 6. Pluggable Backends

- DoT, DoH, DoQ use vtable interfaces for backend injection
- No bundled TLS/HTTP/QUIC implementations; users provide their own
- Enables integration with any crypto/network library

## DNSSEC Architecture

```text
┌─────────────────────────────────────────────────────────┐
│                     Client API                          │
├─────────────────────────────────────────────────────────┤
│                  DNSSEC Validator                       │
│        (Ed25519, ECDSA P-256/P-384 supported)          │
│      (RSA: requires external crypto library)            │
├─────────────────────────────────────────────────────────┤
│                  Recursive Resolver                     │
│              (fetches DNSKEY/DS/RRSIG)                 │
├─────────────────────────────────────────────────────────┤
│                    Trust Anchors                        │
│                  (root DNSKEY)                         │
└─────────────────────────────────────────────────────────┘
```

## Connection Pooling Architecture

```text
┌─────────────────────────────────────────────────────────┐
│                   Connection Pool                       │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐       │
│  │   TCP Conn  │ │   TCP Conn  │ │   TCP Conn  │  ...  │
│  │  (idle)     │ │  (active)   │ │  (idle)     │       │
│  └─────────────┘ └─────────────┘ └─────────────┘       │
└─────────────────────────────────────────────────────────┘
```

## Module Index

| File | Description |
|------|-------------|
| `src/types.zig` | Core DNS types, enums, and constants |
| `src/name.zig` | DNS name encoding, compression, comparison |
| `src/header.zig` | DNS message header parsing |
| `src/question.zig` | DNS question section handling |
| `src/record.zig` | DNS resource record parsing and encoding |
| `src/message.zig` | Complete DNS message handling with cached offsets |
| `src/edns.zig` | EDNS(0) extensions (RFC 6891) |
| `src/cache.zig` | Basic TTL-aware response cache |
| `src/stub.zig` | Stub resolver with TCP fallback |
| `src/recursive.zig` | Full recursive resolver from root servers |
| `src/client.zig` | High-level client API |
| `src/lib.zig` | Public API entry point (re-exports all modules) |
| `src/parallel.zig` | Spice-based parallel query support |
| `src/zone_file.zig` | Zone file parser (RFC 1035 Section 5) |
| `src/resolver/channel.zig` | Transport vtable abstraction |
| `src/resolver/dns_cache.zig` | Advanced LRU cache with negative caching |
| `src/resolver/dnssec.zig` | DNSSEC validation (RFC 4033/4034/4035) |
| `src/resolver/zone_transfer.zig` | AXFR/IXFR zone transfer (RFC 5936/1995) |
| `src/resolver/cache_prefetch.zig` | Proactive cache refresh |
| `src/resolver/cache_protection.zig` | Cache poisoning protection (RFC 5452) |
| `src/resolver/failover.zig` | Server failover and load balancing |
| `src/resolver/split_dns.zig` | Policy-based DNS routing |
| `src/resolver/rpz.zig` | Response Policy Zones (RFC 8646) |
| `src/resolver/logging.zig` | Query/response logging |
| `src/resolver/config.zig` | Configuration file support |
| `src/resolver/convenience.zig` | High-level convenience APIs |
| `src/resolver/edns.zig` | Resolver-layer EDNS handling |
| `src/security/tsig.zig` | TSIG transaction signatures (RFC 2845) |
| `src/security/sig0.zig` | SIG(0) request signatures (RFC 2931) |
| `src/security/dns_name.zig` | Shared DNS name utilities for security modules |
| `src/transports/udp.zig` | UDP transport with source validation |
| `src/transports/tcp.zig` | TCP transport with length-prefix framing |
| `src/transports/dot.zig` | DoT interface (RFC 7858, pluggable TLS backend) |
| `src/transports/doh.zig` | DoH interface (RFC 8484, pluggable HTTP backend) |
| `src/transports/doq.zig` | DoQ interface (RFC 9250, pluggable QUIC backend) |
| `src/transports/connection_pool.zig` | TCP connection pooling (RFC 7766/7828) |
| `src/transports/happy_eyeballs.zig` | Dual-stack connection racing (RFC 8305) |
| `src/util/clock.zig` | Mockable clock for testing |
| `src/util/random.zig` | Mockable RNG for testing |
| `src/util/lru.zig` | Generic O(1) LRU cache |
| `src/util/metrics.zig` | Prometheus-style counters |
| `src/util/enhanced_metrics.zig` | Extended metrics (histograms, gauges) |
| `src/util/backoff.zig` | Exponential backoff with jitter |
