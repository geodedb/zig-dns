// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Basic DNS Query Example
//!
//! Demonstrates the simplest way to resolve DNS names using the high-level
//! Client API with the stub resolver (forwards queries to upstream DNS servers).
//!
//! This example shows:
//! - Creating a DNS client with default configuration
//! - Resolving IPv4 (A) and IPv6 (AAAA) addresses
//! - Looking up MX records for email routing
//! - Using custom DNS servers (e.g., Google, Cloudflare)
//! - Error handling for DNS queries
//!
//! Run with: zig build run-basic-query
//! Or: zig build examples && ./zig-out/bin/basic_query

const std = @import("std");
const dns = @import("dns");

pub fn main() !void {
    // Use a general purpose allocator for this example
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n=== Basic DNS Query Example ===\n\n", .{});

    // =========================================================================
    // Example 1: Simple DNS resolution using system DNS servers
    // =========================================================================
    //
    // The default Client configuration uses stub resolver mode, which forwards
    // queries to your system's configured DNS servers (from /etc/resolv.conf
    // on Unix systems).

    std.debug.print("[1] Resolving with system DNS servers\n", .{});
    {
        var client = dns.Client.init(allocator) catch |err| {
            std.debug.print("    Failed to create client: {}\n", .{err});
            std.debug.print("    (This may fail if network is unavailable)\n\n", .{});
            return;
        };
        defer client.deinit();

        // Resolve IPv4 address (A record)
        std.debug.print("    Resolving example.com (A record)...\n", .{});
        var result_a = client.resolveA("example.com") catch |err| {
            std.debug.print("    Error: {}\n", .{err});
            return;
        };
        defer result_a.deinit(allocator);

        std.debug.print("    IPv4 addresses:\n", .{});
        for (result_a.addresses) |addr| {
            std.debug.print("      - {s}\n", .{addr});
        }
        if (result_a.from_cache) {
            std.debug.print("    (from cache)\n", .{});
        }
    }

    std.debug.print("\n", .{});

    // =========================================================================
    // Example 2: Resolve IPv6 addresses (AAAA records)
    // =========================================================================

    std.debug.print("[2] Resolving IPv6 addresses\n", .{});
    {
        var client = dns.Client.init(allocator) catch |err| {
            std.debug.print("    Failed to create client: {}\n", .{err});
            return;
        };
        defer client.deinit();

        std.debug.print("    Resolving google.com (AAAA record)...\n", .{});
        var result = client.resolveAAAA("google.com") catch |err| {
            std.debug.print("    Error: {} (IPv6 may not be available)\n", .{err});
            return;
        };
        defer result.deinit(allocator);

        std.debug.print("    IPv6 addresses:\n", .{});
        for (result.addresses) |addr| {
            std.debug.print("      - {s}\n", .{addr});
        }
    }

    std.debug.print("\n", .{});

    // =========================================================================
    // Example 3: Using custom DNS servers
    // =========================================================================
    //
    // You can configure specific DNS servers instead of using system defaults.
    // This is useful for:
    // - Using privacy-focused DNS (Cloudflare 1.1.1.1, Quad9 9.9.9.9)
    // - Bypassing DNS-based content filtering
    // - Testing against specific resolvers

    std.debug.print("[3] Using custom DNS servers (Google 8.8.8.8)\n", .{});
    {
        var client = dns.Client.initWithConfig(allocator, .{
            .servers = &[_][]const u8{ "8.8.8.8", "8.8.4.4" },
            .timeout_ms = 3000, // 3 second timeout
            .cache_size = 100, // Cache up to 100 entries
        }) catch |err| {
            std.debug.print("    Failed to create client: {}\n", .{err});
            return;
        };
        defer client.deinit();

        std.debug.print("    Resolving cloudflare.com via Google DNS...\n", .{});
        var result = client.resolveA("cloudflare.com") catch |err| {
            std.debug.print("    Error: {}\n", .{err});
            return;
        };
        defer result.deinit(allocator);

        std.debug.print("    IPv4 addresses:\n", .{});
        for (result.addresses) |addr| {
            std.debug.print("      - {s}\n", .{addr});
        }
    }

    std.debug.print("\n", .{});

    // =========================================================================
    // Example 4: MX record lookup (email routing)
    // =========================================================================
    //
    // MX records specify which mail servers handle email for a domain.
    // Each MX record has a preference value (lower = higher priority).

    std.debug.print("[4] Looking up MX records (mail servers)\n", .{});
    {
        var client = dns.Client.init(allocator) catch |err| {
            std.debug.print("    Failed to create client: {}\n", .{err});
            return;
        };
        defer client.deinit();

        std.debug.print("    Looking up MX for gmail.com...\n", .{});
        const mx_records = client.lookupMX("gmail.com") catch |err| {
            std.debug.print("    Error: {}\n", .{err});
            return;
        };
        defer allocator.free(mx_records);

        std.debug.print("    Mail servers (lower preference = higher priority):\n", .{});
        for (mx_records) |mx| {
            std.debug.print("      - {d}: {s}\n", .{ mx.preference, mx.exchange });
            allocator.free(mx.exchange);
        }
    }

    std.debug.print("\n", .{});

    // =========================================================================
    // Example 5: Generic record lookup
    // =========================================================================
    //
    // The resolve() method allows querying for any record type.

    std.debug.print("[5] Generic record lookup (TXT, NS, etc.)\n", .{});
    {
        var client = dns.Client.init(allocator) catch |err| {
            std.debug.print("    Failed to create client: {}\n", .{err});
            return;
        };
        defer client.deinit();

        // Query for NS (nameserver) records
        std.debug.print("    Looking up NS records for example.com...\n", .{});
        // Note: resolve() returns formatted addresses for A/AAAA records
        // For other record types, you would use lower-level APIs
        var result = client.resolve("example.com", .a) catch |err| {
            std.debug.print("    Error: {}\n", .{err});
            return;
        };
        defer result.deinit(allocator);

        std.debug.print("    Found {d} address(es)\n", .{result.addresses.len});
    }

    std.debug.print("\n", .{});

    // =========================================================================
    // Example 6: Error handling
    // =========================================================================
    //
    // DNS queries can fail for various reasons:
    // - NameNotFound (NXDOMAIN): Domain does not exist
    // - NoResponse: Network timeout or server unreachable
    // - NoAnswer: Domain exists but no records of requested type

    std.debug.print("[6] Error handling examples\n", .{});
    {
        var client = dns.Client.initWithConfig(allocator, .{
            .servers = &[_][]const u8{"8.8.8.8"},
            .timeout_ms = 2000,
        }) catch |err| {
            std.debug.print("    Failed to create client: {}\n", .{err});
            return;
        };
        defer client.deinit();

        // Try to resolve a non-existent domain
        std.debug.print("    Resolving nonexistent.invalid...\n", .{});
        _ = client.resolveA("nonexistent.invalid") catch |err| {
            std.debug.print("    Expected error: {}\n", .{err});
        };
    }

    std.debug.print("\n=== Example Complete ===\n\n", .{});
}
