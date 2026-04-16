// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Recursive DNS Resolution Example
//!
//! Demonstrates full recursive resolution starting from DNS root servers,
//! following referrals through the DNS hierarchy (root -> TLD -> authoritative).
//!
//! This example shows:
//! - Using the recursive resolver instead of stub resolver
//! - QNAME minimization for privacy (RFC 7816)
//! - 0x20 case randomization for cache poisoning protection
//! - Comparing stub vs recursive resolution modes
//!
//! Run with: zig build run-recursive
//! Or: zig build examples && ./zig-out/bin/recursive_resolution

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

    std.debug.print("\n=== Recursive DNS Resolution Example ===\n\n", .{});

    // =========================================================================
    // Introduction: How DNS Resolution Works
    // =========================================================================
    //
    // DNS resolution can happen in two ways:
    //
    // 1. Stub Resolution (default mode):
    //    Your query -> Upstream resolver (e.g., 8.8.8.8) -> Answer
    //    The upstream server does all the work.
    //
    // 2. Recursive Resolution:
    //    Your query -> Root servers -> TLD servers -> Authoritative servers -> Answer
    //    You follow the DNS hierarchy yourself.
    //
    // Recursive resolution gives you:
    // - Full control over the resolution process
    // - No dependence on third-party resolvers
    // - Ability to implement DNSSEC validation
    // - Privacy (no single party sees all your queries)

    std.debug.print("DNS Root Servers:\n", .{});
    const roots = dns.recursive.RootServers.all();
    for (roots[0..3]) |root_ip| {
        std.debug.print("  - {s}\n", .{root_ip});
    }
    std.debug.print("  ... and {d} more\n\n", .{roots.len - 3});

    // =========================================================================
    // Example 1: Basic Recursive Resolution
    // =========================================================================
    //
    // Create a client in recursive mode. This will start from root servers
    // and follow referrals through the DNS hierarchy.

    std.debug.print("[1] Recursive resolution of example.com\n", .{});
    {
        var client = dns.Client.initWithConfig(allocator, .{
            .mode = .recursive,
            .timeout_ms = 5000,
            .cache_size = 1000,
        }) catch |err| {
            std.debug.print("    Failed to create recursive client: {}\n", .{err});
            std.debug.print("    (Recursive resolution requires outbound UDP port 53)\n\n", .{});
            return;
        };
        defer client.deinit();

        std.debug.print("    Starting resolution from root servers...\n", .{});
        std.debug.print("    Path: . -> com -> example.com\n", .{});

        const start_time = timeMilli();
        var result = client.resolveA("example.com") catch |err| {
            std.debug.print("    Error: {}\n", .{err});
            std.debug.print("    (This may fail if you cannot send UDP to port 53)\n\n", .{});
            return;
        };
        defer result.deinit(allocator);
        const elapsed = timeMilli() - start_time;

        std.debug.print("    Resolved in {d}ms:\n", .{elapsed});
        for (result.addresses) |addr| {
            std.debug.print("      - {s}\n", .{addr});
        }
    }

    std.debug.print("\n", .{});

    // =========================================================================
    // Example 2: Using the RecursiveResolver Directly
    // =========================================================================
    //
    // For more control, you can use the RecursiveResolver directly.
    // This gives access to the full resolution result including status codes.

    std.debug.print("[2] Direct RecursiveResolver usage\n", .{});
    {
        var resolver = dns.recursive.RecursiveResolver.init(allocator, .{
            .max_depth = 32,
            .max_queries = 64,
            .timeout_ms = 5000,
            .cache_size = 10000,
            .qname_minimization = true, // RFC 7816 privacy feature
            .case_randomization = true, // 0x20 encoding for security
        }) catch |err| {
            std.debug.print("    Failed to create resolver: {}\n", .{err});
            return;
        };
        defer resolver.deinit();

        std.debug.print("    Resolving www.google.com...\n", .{});
        const result = resolver.resolve("www.google.com", .a) catch |err| {
            std.debug.print("    Error: {}\n", .{err});
            return;
        };
        defer if (result.answer) |a| allocator.free(a);

        std.debug.print("    Status: {s}\n", .{@tagName(result.status)});
        std.debug.print("    From cache: {}\n", .{result.from_cache});

        if (result.answer) |answer| {
            const msg = dns.Message.parse(answer) catch {
                std.debug.print("    Failed to parse response\n", .{});
                return;
            };

            std.debug.print("    Response:\n", .{});
            std.debug.print("      - Questions: {d}\n", .{msg.header.qdcount});
            std.debug.print("      - Answers: {d}\n", .{msg.header.ancount});
            std.debug.print("      - Authority: {d}\n", .{msg.header.nscount});
            std.debug.print("      - Additional: {d}\n", .{msg.header.arcount});

            // Extract A records
            var ans_iter = msg.answers();
            while (ans_iter.next() catch null) |rr| {
                if (rr.rtype == .a) {
                    const addr = rr.parseA() catch continue;
                    std.debug.print("      A: {d}.{d}.{d}.{d}\n", .{
                        addr[0], addr[1], addr[2], addr[3],
                    });
                }
            }
        }
    }

    std.debug.print("\n", .{});

    // =========================================================================
    // Example 3: QNAME Minimization (RFC 7816)
    // =========================================================================
    //
    // QNAME minimization is a privacy feature that minimizes the data sent
    // to each DNS server during resolution.
    //
    // Without QNAME minimization:
    //   Root server sees: www.secret.example.com
    //   TLD server sees:  www.secret.example.com
    //   Auth server sees: www.secret.example.com
    //
    // With QNAME minimization:
    //   Root server sees: com
    //   TLD server sees:  example.com
    //   Auth server sees: www.secret.example.com
    //
    // This prevents upper-level servers from learning your full queries.

    std.debug.print("[3] QNAME Minimization for Privacy\n", .{});
    std.debug.print("    With QNAME minimization enabled:\n", .{});
    std.debug.print("      Query to root:      'com' (not full domain)\n", .{});
    std.debug.print("      Query to .com TLD:  'example.com'\n", .{});
    std.debug.print("      Query to auth:      'www.example.com'\n", .{});
    std.debug.print("    Each server only sees what it needs!\n", .{});

    std.debug.print("\n", .{});

    // =========================================================================
    // Example 4: Resolution Status Codes
    // =========================================================================
    //
    // Recursive resolution can return different status codes:
    // - success:  Found the requested records
    // - nxdomain: Domain does not exist
    // - nodata:   Domain exists but no records of requested type
    // - servfail: Server error during resolution

    std.debug.print("[4] Understanding Resolution Status\n", .{});
    {
        var resolver = dns.recursive.RecursiveResolver.init(allocator, .{}) catch |err| {
            std.debug.print("    Failed to create resolver: {}\n", .{err});
            return;
        };
        defer resolver.deinit();

        // Try resolving a domain that should exist
        std.debug.print("    Trying example.com (should succeed)...\n", .{});
        const result1 = resolver.resolve("example.com", .a) catch |err| {
            std.debug.print("    Error: {}\n", .{err});
            return;
        };
        defer if (result1.answer) |a| allocator.free(a);
        std.debug.print("    Status: {s}\n", .{@tagName(result1.status)});

        // Try resolving a type that might not exist
        std.debug.print("    Trying example.com AAAA (may return nodata)...\n", .{});
        const result2 = resolver.resolve("example.com", .aaaa) catch |err| {
            std.debug.print("    Error: {}\n", .{err});
            return;
        };
        defer if (result2.answer) |a| allocator.free(a);
        std.debug.print("    Status: {s}\n", .{@tagName(result2.status)});
    }

    std.debug.print("\n", .{});

    // =========================================================================
    // Example 5: Comparing Stub vs Recursive Mode
    // =========================================================================

    std.debug.print("[5] Stub vs Recursive Mode Comparison\n", .{});
    std.debug.print("    Stub resolver:\n", .{});
    std.debug.print("      + Faster (single query to upstream)\n", .{});
    std.debug.print("      + Works behind NAT/firewalls\n", .{});
    std.debug.print("      + Less network traffic\n", .{});
    std.debug.print("      - Depends on upstream resolver\n", .{});
    std.debug.print("      - Privacy concerns (upstream sees all queries)\n", .{});
    std.debug.print("\n", .{});
    std.debug.print("    Recursive resolver:\n", .{});
    std.debug.print("      + Full control over resolution\n", .{});
    std.debug.print("      + No third-party dependency\n", .{});
    std.debug.print("      + Can implement DNSSEC validation\n", .{});
    std.debug.print("      + Privacy with QNAME minimization\n", .{});
    std.debug.print("      - Slower (multiple queries)\n", .{});
    std.debug.print("      - Requires outbound UDP port 53\n", .{});

    std.debug.print("\n=== Example Complete ===\n\n", .{});
}
