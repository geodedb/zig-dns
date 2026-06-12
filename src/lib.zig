// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DNS Library for Zig
//!
//! A pure Zig implementation of the Domain Name System (DNS) protocol.
//! Supports full recursive resolution and standard stub resolution.
//!
//! ## Features
//!
//! - RFC 1035 compliant DNS message parsing and encoding
//! - Stub resolver for simple DNS queries
//! - Full recursive resolver for complete name resolution
//! - EDNS0 support (RFC 6891)
//! - Linux (primary); macOS/Windows not yet supported (socket layer is Linux-only)
//! - Minimal dependencies (optional thread pool for parallelism)
//!
//! ## Quick Start
//!
//! ```zig
//! const dns = @import("dns");
//!
//! // Create a client (init is fallible: it probes OS entropy)
//! var client = try dns.Client.init(allocator);
//! defer client.deinit();
//!
//! // Resolve a hostname; the caller owns the result
//! var result = try client.resolve("example.com", .a);
//! defer result.deinit(allocator);
//! ```
//!
//! ## Module Organization
//!
//! ### Core Protocol
//! - `types`: DNS record types, classes, and opcodes
//! - `name`: DNS name encoding and compression
//! - `header`: DNS message header
//! - `question`: DNS question section
//! - `record`: DNS resource records
//! - `message`: Complete DNS message handling
//! - `edns`: EDNS0 extensions
//!
//! ### Resolution
//! - `cache`: DNS response caching
//! - `parallel`: Parallel DNS operations (thread-pool-based)
//! - `stub`: Stub resolver (forwards to upstream)
//! - `recursive`: Full recursive resolver
//! - `client`: High-level resolution interface
//! - `dnssec`: DNSSEC validation (RFC 4033/4034/4035)
//! - `zone_transfer`: Zone transfer support (RFC 5936 AXFR, RFC 1995 IXFR)
//! - `failover`: Server failover and load balancing
//! - `split_dns`: Split DNS / policy routing
//! - `rpz`: Response Policy Zones (RFC 8646)
//! - `logging`: Query/response logging
//! - `config`: Configuration file support
//! - `convenience`: High-level convenience APIs
//! - `cache_prefetch`: Cache prefetching
//!
//! ### Transports
//! - `transport_udp`: UDP transport
//! - `transport_tcp`: TCP transport
//! - `transport_dot`: DNS over TLS (RFC 7858)
//! - `transport_doh`: DNS over HTTPS (RFC 8484)
//! - `transport_doq`: DNS over QUIC (RFC 9250, feature-gated)
//! - `connection_pool`: Connection pooling (RFC 7766/7828)
//! - `happy_eyeballs`: Dual-stack connection racing (RFC 8305)
//!
//! ### Security
//! - `tsig`: Transaction Signatures (RFC 2845)
//! - `sig0`: DNS Request/Transaction Signatures (RFC 2931)
//!
//! ### Utilities
//! - `enhanced_metrics`: Histograms, gauges, per-server stats
//! - `backoff`: Exponential backoff with jitter
//! - `zone_file`: Zone file parser (RFC 1035 Section 5)

const std = @import("std");

// Core protocol modules
pub const name = @import("name");
pub const header = @import("header");
pub const types = @import("types");
pub const question = @import("question");
pub const record = @import("record");
pub const message = @import("message");

// Extensions
pub const edns = @import("edns");

// Parallelism
pub const parallel = @import("parallel");

// Resolution
pub const cache = @import("cache");
pub const stub = @import("stub");
pub const recursive = @import("recursive");
pub const client = @import("client");

// Resolver extensions
pub const dnssec = @import("dnssec");
pub const zone_transfer = @import("zone_transfer");
pub const failover = @import("failover");
pub const split_dns = @import("split_dns");
pub const rpz = @import("rpz"); // Public API: no internal callers; kept for external consumers
pub const logging = @import("logging");
pub const config = @import("config"); // Public API: no internal callers; kept for external consumers
pub const convenience = @import("convenience"); // Public API: no internal callers; kept for external consumers
pub const cache_prefetch = @import("cache_prefetch"); // Public API: no internal callers; kept for external consumers

// Transports
pub const transport_udp = @import("transport_udp");
pub const transport_tcp = @import("transport_tcp");
pub const transport_dot = @import("transport_dot");
pub const transport_doh = @import("transport_doh");
pub const transport_doq = @import("transport_doq");
pub const connection_pool = @import("connection_pool");
pub const happy_eyeballs = @import("happy_eyeballs");

// Security
pub const tsig = @import("tsig");
pub const sig0 = @import("sig0");

// Utilities
pub const enhanced_metrics = @import("enhanced_metrics");
pub const backoff = @import("backoff");
pub const zone_file = @import("zone_file");

// Observability seam (otel). The seam is always compiled, but its
// `enabled` flag tracks `-Dwith_otel`; when off, every call collapses
// to a comptime-known no-op (verified by the disabled-mode test under
// tests/observability_disabled_test.zig). Imported as a named module
// so it lives in a single module tree across all consumers.
pub const observability = @import("observability");

/// Bootstrap helper: builds OTEL TracerProvider/MeterProvider/LoggerProvider
/// from OTEL_* env vars and publishes Tracer/Meter handles to
/// `observability.global`. Application entry-point code calls
/// `observability_init.Otel.init` then `installGlobals()` to publish
/// providers; when `-Dwith_otel=false` this collapses to an empty
/// struct so the import never resolves the otel namespace.
pub const observability_init = if (observability.enabled)
    @import("observability_init")
else
    struct {};

// Re-export commonly used types for convenience
pub const Name = name.Name;
pub const Header = header.Header;
pub const Message = message.Message;
pub const Question = question.Question;
pub const ResourceRecord = record.ResourceRecord;
pub const Client = client.Client;

// Type aliases
pub const Type = types.Type;
pub const Class = types.Class;
pub const Opcode = types.Opcode;
pub const ResponseCode = types.ResponseCode;

test {
    // Run all module tests
    std.testing.refAllDecls(@This());
}

test "parallel re-export is reachable" {
    // Smoke test: verify parallel.zig is reachable through the public
    // dns root module. Parallel DNS ops need wire-format records or
    // live network state which are impractical in a unit test, so we
    // assert the pool lifecycle entry points are exposed and call
    // `deinitPool()` (always safe as a no-op when the pool was never
    // initialized).
    _ = @TypeOf(parallel.getPool);
    _ = @TypeOf(parallel.parallelZoneRecordParse);
    parallel.deinitPool();
}
