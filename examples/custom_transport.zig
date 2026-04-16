// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Custom Transport Example
//!
//! Demonstrates how to work with different DNS transport protocols:
//! - UDP (default, fast, 512 byte limit without EDNS)
//! - TCP (reliable, unlimited message size)
//! - DNS over TLS (DoT, RFC 7858, encrypted)
//!
//! This example shows:
//! - Understanding transport tradeoffs
//! - TCP fallback when UDP responses are truncated
//! - EDNS0 for larger UDP payloads
//!
//! Run with: zig build run-custom-transport
//! Or: zig build examples && ./zig-out/bin/custom_transport

const std = @import("std");
const dns = @import("dns");

inline fn timeMilli() i64 {
    const io_inst = std.Io.Threaded.global_single_threaded.io();
    return std.Io.Clock.Timestamp.now(io_inst, .real).raw.toMilliseconds();
}

pub fn main() !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n=== DNS Transport Protocols Example ===\n\n", .{});

    // =========================================================================
    // Introduction: DNS Transport Options
    // =========================================================================

    std.debug.print("DNS Transport Protocols:\n\n", .{});
    std.debug.print("  UDP (Port 53) - Default:\n", .{});
    std.debug.print("    + Fast (single packet, no connection)\n", .{});
    std.debug.print("    + Low overhead\n", .{});
    std.debug.print("    - 512 byte limit (without EDNS0)\n", .{});
    std.debug.print("    - No encryption\n", .{});
    std.debug.print("    - Spoofing vulnerable\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("  TCP (Port 53) - Fallback:\n", .{});
    std.debug.print("    + Reliable delivery\n", .{});
    std.debug.print("    + No message size limit\n", .{});
    std.debug.print("    + Connection prevents spoofing\n", .{});
    std.debug.print("    - Higher latency (connection setup)\n", .{});
    std.debug.print("    - More server resources\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("  DNS over TLS (DoT, Port 853) - Encrypted:\n", .{});
    std.debug.print("    + Encrypted transport\n", .{});
    std.debug.print("    + Privacy from eavesdroppers\n", .{});
    std.debug.print("    + Server authentication\n", .{});
    std.debug.print("    - Higher latency (TLS handshake)\n", .{});
    std.debug.print("    - Blocked by some networks\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("  DNS over HTTPS (DoH, Port 443) - Web-based:\n", .{});
    std.debug.print("    + Encrypted\n", .{});
    std.debug.print("    + Bypasses DNS blocking (looks like HTTPS)\n", .{});
    std.debug.print("    - Highest latency\n", .{});
    std.debug.print("    - Requires HTTP/2 client\n", .{});
    std.debug.print("\n", .{});

    // =========================================================================
    // Example 1: UDP Query (Default)
    // =========================================================================

    std.debug.print("[1] UDP Query (Default Transport)\n", .{});
    {
        var client = dns.Client.initWithConfig(allocator, .{
            .servers = &[_][]const u8{"8.8.8.8"},
            .timeout_ms = 3000,
        }) catch |err| {
            std.debug.print("    Failed to create client: {}\n", .{err});
            return;
        };
        defer client.deinit();

        std.debug.print("    Sending UDP query to 8.8.8.8:53...\n", .{});
        const start = timeMilli();

        var result = client.resolveA("example.com") catch |err| {
            std.debug.print("    Error: {}\n", .{err});
            return;
        };
        defer result.deinit(allocator);

        const elapsed = timeMilli() - start;
        std.debug.print("    Response in {d}ms\n", .{elapsed});

        for (result.addresses) |addr| {
            std.debug.print("    Address: {s}\n", .{addr});
        }
    }

    std.debug.print("\n", .{});

    // =========================================================================
    // Example 2: TCP Fallback for Truncated Responses
    // =========================================================================

    std.debug.print("[2] TCP Fallback (for large responses)\n", .{});
    std.debug.print("    When a UDP response has TC (truncated) bit set:\n", .{});
    std.debug.print("    1. Client receives partial response over UDP\n", .{});
    std.debug.print("    2. Client detects TC=1 in header\n", .{});
    std.debug.print("    3. Client retries query over TCP\n", .{});
    std.debug.print("    4. Full response received\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("    The StubResolver handles this automatically:\n", .{});
    std.debug.print("      use_tcp_on_truncation: true (default)\n", .{});

    std.debug.print("\n", .{});

    // =========================================================================
    // Example 3: EDNS0 for Larger UDP Payloads
    // =========================================================================

    std.debug.print("[3] EDNS0 - Extended DNS\n", .{});
    std.debug.print("    EDNS0 (RFC 6891) extends UDP payload size:\n", .{});
    std.debug.print("    - Original DNS:  512 bytes max UDP payload\n", .{});
    std.debug.print("    - With EDNS0:    4096+ bytes UDP payload\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("    EDNS0 is signaled via OPT pseudo-record:\n", .{});
    std.debug.print("    - Added to Additional section\n", .{});
    std.debug.print("    - Contains UDP payload size offer\n", .{});
    std.debug.print("    - Can carry extensions (DNSSEC OK, cookies, etc.)\n", .{});
    std.debug.print("\n", .{});

    // Show EDNS configuration
    std.debug.print("    Client EDNS configuration:\n", .{});
    std.debug.print("      use_edns: true (default)\n", .{});
    std.debug.print("      edns_payload_size: 4096 bytes\n", .{});

    std.debug.print("\n", .{});

    // =========================================================================
    // Example 4: Well-Known DNS Services
    // =========================================================================

    std.debug.print("[4] Well-Known Public DNS Services\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("    Google Public DNS:\n", .{});
    std.debug.print("      UDP/TCP: 8.8.8.8, 8.8.4.4\n", .{});
    std.debug.print("      DoT:     dns.google (port 853)\n", .{});
    std.debug.print("      DoH:     https://dns.google/dns-query\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("    Cloudflare DNS:\n", .{});
    std.debug.print("      UDP/TCP: 1.1.1.1, 1.0.0.1\n", .{});
    std.debug.print("      DoT:     cloudflare-dns.com (port 853)\n", .{});
    std.debug.print("      DoH:     https://cloudflare-dns.com/dns-query\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("    Quad9 (Security-focused):\n", .{});
    std.debug.print("      UDP/TCP: 9.9.9.9\n", .{});
    std.debug.print("      DoT:     dns.quad9.net (port 853)\n", .{});
    std.debug.print("      DoH:     https://dns.quad9.net/dns-query\n", .{});

    std.debug.print("\n", .{});

    // =========================================================================
    // Example 5: Comparing Transport Performance
    // =========================================================================

    std.debug.print("[5] Comparing Transport Performance\n", .{});
    {
        const servers = &[_][]const u8{"8.8.8.8"};
        const domain = "google.com";
        const iterations: usize = 3;

        var client = dns.Client.initWithConfig(allocator, .{
            .servers = servers,
            .timeout_ms = 5000,
            .cache_size = 0, // Disable cache for accurate timing
        }) catch |err| {
            std.debug.print("    Failed to create client: {}\n", .{err});
            return;
        };
        defer client.deinit();

        std.debug.print("    Timing {d} queries to {s}...\n", .{ iterations, domain });

        var total_time: i64 = 0;
        var successful: usize = 0;

        for (0..iterations) |i| {
            const start = timeMilli();
            var result = client.resolveA(domain) catch |err| {
                std.debug.print("    Query {d} failed: {}\n", .{ i + 1, err });
                continue;
            };
            result.deinit(allocator);

            const elapsed = timeMilli() - start;
            total_time += elapsed;
            successful += 1;
            std.debug.print("    Query {d}: {d}ms\n", .{ i + 1, elapsed });
        }

        if (successful > 0) {
            const avg = @divFloor(total_time, @as(i64, @intCast(successful)));
            std.debug.print("    Average: {d}ms ({d}/{d} successful)\n", .{
                avg, successful, iterations,
            });
        }
    }

    std.debug.print("\n", .{});

    // =========================================================================
    // Example 6: Transport-Related Configuration
    // =========================================================================

    std.debug.print("[6] Transport Configuration Options\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("    StubConfig (for StubResolver):\n", .{});
    std.debug.print("      timeout_ms:            Query timeout\n", .{});
    std.debug.print("      retries:               Per-server retry count\n", .{});
    std.debug.print("      use_tcp_on_truncation: Auto TCP fallback\n", .{});
    std.debug.print("      udp_payload_size:      EDNS0 buffer size\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("    ClientConfig (for high-level Client):\n", .{});
    std.debug.print("      mode:      .stub or .recursive\n", .{});
    std.debug.print("      servers:   Upstream DNS servers\n", .{});
    std.debug.print("      timeout_ms: Query timeout\n", .{});
    std.debug.print("      use_edns:  Enable EDNS0\n", .{});
    std.debug.print("      edns_payload_size: Advertised UDP size\n", .{});

    std.debug.print("\n=== Example Complete ===\n\n", .{});
}
