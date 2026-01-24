# zigdns Architecture

This document describes the architecture and design of the zigdns library.

## Overview

zigdns is organized into layered modules following DNS protocol structure:

```
┌─────────────────────────────────────────────────────────┐
│                     Client API                          │
│                   (src/client.zig)                      │
├─────────────────────────────────────────────────────────┤
│     Stub Resolver      │      Recursive Resolver        │
│    (src/stub.zig)      │    (src/recursive.zig)         │
├─────────────────────────────────────────────────────────┤
│                      Cache Layer                         │
│         (src/cache.zig, src/resolver/dns_cache.zig)     │
├─────────────────────────────────────────────────────────┤
│                   Transport Layer                        │
│     (src/transports/udp.zig, tcp.zig, dot.zig, ...)    │
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

#### Message (`src/message.zig`)
Complete message handling:
- Section iteration (question, answer, authority, additional)
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

#### Stub Resolver (`src/stub.zig`, `src/resolver/stub.zig`)

Simple forwarding resolver:
- Configurable upstream servers
- UDP with TCP fallback on truncation
- Timeout and retry handling
- EDNS negotiation

#### Recursive Resolver (`src/recursive.zig`, `src/resolver/recursive.zig`)

Full iterative resolution (WIP):
- Root server list (13 servers)
- NS record following
- Bailiwick checks for glue
- Configurable depth limit

### Transport Layer (`src/transports/`)

#### UDP Transport (`udp.zig`)
- Standard UDP DNS queries
- Configurable timeout via SO_RCVTIMEO
- Single-query-per-socket model

#### TCP Transport (`tcp.zig`)
- 2-byte length prefix per RFC 1035
- Connection per query (no pooling yet)
- For truncated responses and zone transfers

#### DoT Transport (`dot.zig`) - STUB
- ALPN: "dot"
- Port 853 default
- TLS 1.3 (when implemented)

#### DoH Transport (`doh.zig`) - STUB
- GET with base64url query parameter
- POST with application/dns-message
- HTTP/2 (when implemented)

#### DoQ Transport (`doq.zig`) - STUB
- ALPN: "doq"
- 2-byte length prefix
- Message ID = 0
- Feature-gated

### Utilities (`src/util/`)

#### Clock (`clock.zig`)
Mockable time source:
```zig
pub const MockClock = struct {
    // Fixed time: 2025-01-02T03:04:05Z
    pub fn init() Self { ... }
    pub fn advance(self: *Self, seconds: i64) void { ... }
};
```

#### Random (`random.zig`)
Mockable RNG:
```zig
pub const MockRandom = struct {
    pub const default_seed: u64 = 0x123456789ABCDEF0;
    pub fn init() Self { ... }
};
```

#### LRU Cache (`lru.zig`)
Generic LRU cache with O(1) operations:
- HashMap for O(1) lookup
- Doubly-linked list for LRU ordering

#### Metrics (`metrics.zig`)
Prometheus-style counters:
- queries_total
- cache_hits_total
- cache_misses_total
- tcp_fallback_total
- timeouts_total
- servfail_total

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

## Future Architecture

### DNSSEC Integration

```
┌─────────────────────────────────────────────────────────┐
│                     Client API                          │
├─────────────────────────────────────────────────────────┤
│                  DNSSEC Validator                       │
│              (validates signatures)                     │
├─────────────────────────────────────────────────────────┤
│                  Recursive Resolver                     │
│              (fetches DNSKEY/DS/RRSIG)                 │
├─────────────────────────────────────────────────────────┤
│                    Trust Anchors                        │
│                  (root DNSKEY)                         │
└─────────────────────────────────────────────────────────┘
```

### Connection Pooling

```
┌─────────────────────────────────────────────────────────┐
│                   Connection Pool                       │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐       │
│  │   DoT Conn  │ │   DoT Conn  │ │   DoH Conn  │  ...  │
│  │  (idle)     │ │  (active)   │ │  (idle)     │       │
│  └─────────────┘ └─────────────┘ └─────────────┘       │
└─────────────────────────────────────────────────────────┘
```

## File Index

| File | Lines | Description |
|------|-------|-------------|
| `src/types.zig` | ~250 | Core types and constants |
| `src/name.zig` | ~300 | Name handling |
| `src/header.zig` | ~300 | Header parsing |
| `src/question.zig` | ~150 | Question section |
| `src/record.zig` | ~400 | Resource records |
| `src/message.zig` | ~400 | Message handling |
| `src/edns.zig` | ~250 | EDNS(0) |
| `src/cache.zig` | ~200 | Basic cache |
| `src/stub.zig` | ~300 | Stub resolver |
| `src/recursive.zig` | ~300 | Recursive resolver |
| `src/client.zig` | ~350 | Client API |
| `src/resolver/*.zig` | ~800 | Enhanced resolver |
| `src/transports/*.zig` | ~600 | Transports |
| `src/util/*.zig` | ~400 | Utilities |
| **Total** | ~5000 | |
