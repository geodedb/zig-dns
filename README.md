# zigdns - Zig DNS Library

A comprehensive pure Zig implementation of the Domain Name System (DNS) protocol. Supports both stub and recursive resolution with modern transport protocols.

## Status

| Aspect | Info |
|--------|------|
| API Stability | Beta |
| Zig Version | 0.15.1+ |
| Platforms | Linux, macOS, Windows |

## Features

### Implemented
- **RFC 1035 Compliant**: Full DNS message parsing and encoding
- **Full Recursive Resolution**: Iterative resolution from root servers
- **QNAME Minimization**: RFC 7816 privacy-preserving queries
- **0x20 Case Randomization**: Cache poisoning protection
- **Stub Resolver**: Simple forwarding to upstream DNS servers (UDP/TCP)
- **EDNS0 Support**: Extended DNS with larger UDP payloads (RFC 6891)
- **Response Caching**: TTL-aware LRU caching with negative caching (RFC 2308)
- **DoT Transport**: DNS over TLS with pluggable TLS backend (RFC 7858)
- **DoH Transport**: DNS over HTTPS with pluggable HTTP backend (RFC 8484)
- **DoQ Transport**: DNS over QUIC with pluggable QUIC backend (RFC 9250)
- **Zone Transfers**: Full AXFR/IXFR support (RFC 5936, RFC 1995)
- **Cache Protection**: Bailiwick checking, TTL capping (RFC 5452)
- **Cache Prefetching**: Proactive cache refresh before TTL expiration
- **DNSSEC Validation**: Ed25519, ECDSA P-256/P-384 signature verification (RFC 4033/4034/4035)
- **EDNS Client Subnet**: Geo-aware DNS queries (RFC 7871)
- **DNS Cookies**: Lightweight transaction security (RFC 7873)
- **Cross-Platform**: Linux, macOS, Windows, and more
- **Minimal Dependencies**: Pure Zig implementation using the standard library (optional `spice` dependency for parallelism)
- **Record Types**: A, AAAA, CNAME, MX, NS, PTR, SOA, TXT, DNAME, SRV, CAA, TLSA, SVCB, HTTPS, DNSKEY, RRSIG, DS, NSEC, NSEC3

### Project Status

See [ROADMAP.md](docs/ROADMAP.md) and [GitLab Issues](https://gitlab.com/devnw/zig/dns/-/issues) for detailed status.

| Phase | Description | Status |
|-------|-------------|--------|
| Phase 1 | Core Recursion | **Complete** |
| Phase 2 | Production Ready (DoT, caching, zone transfers) | **Complete** |
| Phase 3 | DNSSEC Validation | **Partial** (Ed25519/ECDSA complete, RSA pending) |
| Phase 4 | Modern Features (DoH, DoQ, ECS, Cookies, Prefetch) | **Complete** |

## Requirements

- Zig 0.15.1 or later

## Installation

Add `dns` as a dependency in your `build.zig.zon`:

```zig
.dependencies = .{
    .dns = .{
        .url = "https://gitlab.com/devnw/zig/dns/-/archive/main/dns-main.tar.gz",
        .hash = "...",
    },
},
```

Then in your `build.zig`:

```zig
const dns_dep = b.dependency("dns", .{
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("dns", dns_dep.module("dns"));
```

## Quick Start

### Basic DNS Query (Stub Resolver)

```zig
const std = @import("std");
const dns = @import("dns");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a DNS client (uses system DNS servers by default)
    var client = try dns.Client.init(allocator);
    defer client.deinit();

    // Resolve a hostname
    var result = try client.resolveA("example.com");
    defer result.deinit(allocator);

    for (result.addresses) |addr| {
        std.debug.print("IP: {s}\n", .{addr});
    }
}
```

### Custom DNS Server

```zig
var client = try dns.Client.initWithConfig(allocator, .{
    .servers = &[_][]const u8{ "8.8.8.8", "8.8.4.4" },
    .timeout_ms = 3000,
});
```

### Low-Level Message Parsing

```zig
const dns = @import("dns");

// Parse a DNS response
const msg = try dns.Message.parse(response_bytes);

// Check if successful
if (msg.isSuccess()) {
    var iter = try msg.answers();
    while (try iter.next()) |rr| {
        if (rr.rtype == .a) {
            const ip = try rr.parseA();
            // Use ip[0..4] as IPv4 address bytes
        }
    }
}
```

## Building

```bash
# Build the library
zig build

# Run all tests
zig build test --summary all

# Run specific test suites
zig build test-accept      # Acceptance tests
zig build test-util        # Utility module tests
zig build test-transport   # Transport tests
zig build test-resolver    # Resolver tests
zig build test-rfc1035     # RFC 1035 compliance
zig build test-rfc6891     # EDNS0 tests

# With optimization
zig build test -Doptimize=ReleaseFast
```

## Project Structure

```
src/
├── lib.zig              # Public API entry point
├── types.zig            # DNS types, enums, constants
├── name.zig             # DNS name handling, compression, 0x20
├── header.zig           # DNS header parsing/encoding
├── question.zig         # Question section handling
├── record.zig           # Resource record parsing (all types)
├── message.zig          # Complete message handling
├── edns.zig             # EDNS(0) OPT record, Client Subnet, Cookies
├── cache.zig            # Basic caching
├── stub.zig             # Stub resolver
├── recursive.zig        # Recursive resolver with QNAME min
├── client.zig           # High-level client API
├── resolver/            # Enhanced resolver components
│   ├── channel.zig      # Transport abstraction
│   ├── dns_cache.zig    # RFC 2308 negative caching
│   ├── cache_protection.zig  # RFC 5452 poisoning protection
│   ├── cache_prefetch.zig   # Proactive cache refresh
│   ├── zone_transfer.zig    # RFC 5936/1995 AXFR/IXFR
│   ├── dnssec.zig       # RFC 4033/4034/4035 DNSSEC validation
│   └── edns.zig         # EDNS handling
├── transports/          # Transport implementations
│   ├── udp.zig          # UDP transport
│   ├── tcp.zig          # TCP transport
│   ├── dot.zig          # DoT with TLS backend (RFC 7858)
│   ├── doh.zig          # DoH with HTTP backend (RFC 8484)
│   └── doq.zig          # DoQ with QUIC backend (RFC 9250)
└── util/                # Utilities
    ├── clock.zig        # Mockable clock
    ├── random.zig       # Mockable RNG
    ├── lru.zig          # LRU cache
    └── metrics.zig      # Prometheus metrics
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) - System design and module overview
- [Roadmap](docs/ROADMAP.md) - Implementation status and GitLab issues
- [RFC Compliance](docs/RFC_COMPLIANCE.md) - RFC implementation status

## Cross-Compilation

Zig's cross-compilation support allows building for any target:

```bash
# Linux ARM64
zig build -Dtarget=aarch64-linux-gnu

# Windows x64
zig build -Dtarget=x86_64-windows-msvc

# macOS ARM64
zig build -Dtarget=aarch64-macos

# RISC-V 64
zig build -Dtarget=riscv64-linux-gnu
```

## Contributing

See [GitLab Issues](https://gitlab.com/devnw/zig/dns/-/issues) for open tasks.

1. Code passes `zig fmt`
2. All tests pass
3. New features include tests
4. RFC compliance is maintained

## RFC References

| RFC | Description | Status |
|-----|-------------|--------|
| [RFC 1034](https://tools.ietf.org/html/rfc1034) | Domain Names - Concepts | Complete |
| [RFC 1035](https://tools.ietf.org/html/rfc1035) | Domain Names - Implementation | Complete |
| [RFC 2308](https://tools.ietf.org/html/rfc2308) | Negative Caching | Complete |
| [RFC 3596](https://tools.ietf.org/html/rfc3596) | IPv6 (AAAA) | Complete |
| [RFC 4033](https://tools.ietf.org/html/rfc4033) | DNSSEC Introduction | Partial** |
| [RFC 4034](https://tools.ietf.org/html/rfc4034) | DNSSEC Resource Records | Partial** |
| [RFC 4035](https://tools.ietf.org/html/rfc4035) | DNSSEC Protocol | Partial** |
| [RFC 5155](https://tools.ietf.org/html/rfc5155) | NSEC3 | Complete |
| [RFC 6891](https://tools.ietf.org/html/rfc6891) | EDNS(0) | Complete |
| [RFC 7816](https://tools.ietf.org/html/rfc7816) | QNAME Minimization | Complete |
| [RFC 7858](https://tools.ietf.org/html/rfc7858) | DNS over TLS | Complete*** |
| [RFC 7871](https://tools.ietf.org/html/rfc7871) | Client Subnet | Complete |
| [RFC 7873](https://tools.ietf.org/html/rfc7873) | DNS Cookies | Complete |
| [RFC 8484](https://tools.ietf.org/html/rfc8484) | DNS over HTTPS | Complete* |
| [RFC 9250](https://tools.ietf.org/html/rfc9250) | DNS over QUIC | Complete* |

\* Requires external HTTP/QUIC library via pluggable backend interface

\*\* Ed25519 and ECDSA (P-256/P-384) signature verification is implemented; RSA signature verification is not yet implemented

\*\*\* DoT transport interface exists with pluggable TLS backend; a TLS implementation must be provided by the consumer

## License

Apache-2.0 License - see [LICENSE](LICENSE) for details.
