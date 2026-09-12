# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.19] - 2026-09-12

### Changed

- Converge thread_pool v0.2.7, fips v0.1.1, protobuf v0.1.5, config v0.1.13 (GAP-0838 diamond sync).

## [0.1.18] - 2026-09-12

### Changed

- Converge thread_pool v0.2.7, fips v0.1.1, protobuf v0.1.5 (GAP-0838 diamond sync).

## [0.1.0] - 2026-01-24

Initial public release under Apache-2.0 license.

### Added
- Merge request template for standardized contributions
- Issue templates for bug reports, features, and questions

### Changed
- Updated CI catalog components to v1.7.1
- Updated cli dependency to use GitLab archive URL

### Security
- Fixed gitleaks allowlist for test data and implementation details
- Added GitLab native Secret Detection
- Enabled Advanced SAST and Dependency Scanning

### Features

#### Core DNS Library
- RFC 1035 compliant DNS message parsing and encoding
- Complete DNS header, question, and resource record handling
- DNS name compression and decompression support
- Support for 20+ record types: A, AAAA, CNAME, MX, NS, PTR, SOA, TXT, DNAME, SRV, CAA, TLSA, SVCB, HTTPS, DNSKEY, RRSIG, DS, NSEC, NSEC3

#### Phase 1 - Core Recursion
- Full recursive resolution from root servers
- Iterative query support
- Basic stub resolver for forwarding to upstream DNS servers

#### Phase 2 - Production Ready
- DNS over TLS (DoT) transport with pluggable TLS backend (RFC 7858)
- TTL-aware LRU caching with negative caching (RFC 2308)
- Zone transfers with full AXFR/IXFR support (RFC 5936, RFC 1995)
- Cache protection with bailiwick checking and TTL capping (RFC 5452)

#### Phase 3 - DNSSEC Validation
- DNSSEC signature verification (RFC 4033/4034/4035)
- Ed25519 algorithm support
- ECDSA P-256/P-384 algorithm support
- NSEC and NSEC3 authenticated denial of existence (RFC 5155)

#### Phase 4 - Modern Features
- DNS over HTTPS (DoH) with pluggable HTTP backend (RFC 8484)
- DNS over QUIC (DoQ) with pluggable QUIC backend (RFC 9250)
- EDNS Client Subnet for geo-aware DNS queries (RFC 7871)
- DNS Cookies for lightweight transaction security (RFC 7873)
- Cache prefetching for proactive cache refresh before TTL expiration
- QNAME Minimization for privacy-preserving queries (RFC 7816)
- 0x20 Case Randomization for cache poisoning protection

#### CLI Tool (zdig)
- Command-line DNS lookup utility for testing
- Proper integration with Zig CLI library
- Multi-platform support

#### Infrastructure
- EDNS0 support with extended UDP payloads (RFC 6891)
- Cross-platform support: Linux, macOS, Windows
- Zero external dependencies (pure Zig standard library)
- GoReleaser integration for multi-platform release pipeline
- SBOM generation
- DevNW CI Catalog integration

### Fixed
- Windows compatibility for fd_t in tests and connection handling
- Cross-platform stdout handling in zdig
- Zig 0.15 I/O API compatibility

### Changed
- Requires Zig 0.15.1 or later

[Unreleased]: https://gitlab.com/devnw/zig/dns/-/compare/v0.1.0...HEAD
[0.1.0]: https://gitlab.com/devnw/zig/dns/-/releases/v0.1.0
