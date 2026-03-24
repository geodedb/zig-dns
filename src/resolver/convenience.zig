// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! High-Level Convenience APIs
//!
//! Provides simple, easy-to-use interfaces for common DNS operations:
//! - One-liner lookups
//! - Hostname resolution
//! - Reverse DNS lookups
//! - Service discovery (SRV)
//! - Mail server lookup (MX)
//! - Text record lookup (TXT)

const std = @import("std");
const types_mod = @import("types");

/// DNS Resource Record Type (canonical definition in types.zig).
/// Re-exported here for convenience API users.
pub const Type = types_mod.Type;

/// IPv4 address
pub const IPv4 = struct {
    bytes: [4]u8,

    pub const Formatted = struct {
        buf: [15]u8,
        len: u8,

        /// Return the formatted IP address as a string slice.
        pub fn slice(self: *const Formatted) []const u8 {
            return self.buf[0..self.len];
        }
    };

    pub fn format(self: IPv4) Formatted {
        var buf: [15]u8 = .{0} ** 15;
        const result = std.fmt.bufPrint(&buf, "{d}.{d}.{d}.{d}", .{
            self.bytes[0],
            self.bytes[1],
            self.bytes[2],
            self.bytes[3],
        }) catch unreachable;
        return .{
            .buf = buf,
            .len = @intCast(result.len),
        };
    }

    pub fn toSlice(self: *const IPv4) []const u8 {
        return &self.bytes;
    }
};

/// IPv6 address
pub const IPv6 = struct {
    bytes: [16]u8,

    pub fn toSlice(self: *const IPv6) []const u8 {
        return &self.bytes;
    }
};

/// Resolved address (can be IPv4 or IPv6)
pub const Address = union(enum) {
    ipv4: IPv4,
    ipv6: IPv6,

    pub fn isIPv4(self: Address) bool {
        return self == .ipv4;
    }

    pub fn isIPv6(self: Address) bool {
        return self == .ipv6;
    }
};

// MX record type lives in client.zig as MXRecord.
// Removed duplicate MxRecord definition (RM-04).

/// SRV record result
pub const SrvRecord = struct {
    priority: u16,
    weight: u16,
    port: u16,
    target: []const u8,
};

/// SOA record result
pub const SoaRecord = struct {
    mname: []const u8,
    rname: []const u8,
    serial: u32,
    refresh: u32,
    retry: u32,
    expire: u32,
    minimum: u32,
};

/// Lookup result
pub const LookupResult = struct {
    /// Addresses found
    addresses: std.ArrayList(Address),
    /// Allocator used for addresses
    allocator: std.mem.Allocator,
    /// Canonical name (if CNAME was followed)
    cname: ?[]const u8 = null,
    /// TTL of the records
    ttl: u32 = 0,
    /// Response time (ms)
    response_time_ms: u32 = 0,

    pub fn deinit(self: *LookupResult) void {
        self.addresses.deinit(self.allocator);
    }

    pub fn hasIPv4(self: *const LookupResult) bool {
        for (self.addresses.items) |addr| {
            if (addr.isIPv4()) return true;
        }
        return false;
    }

    pub fn hasIPv6(self: *const LookupResult) bool {
        for (self.addresses.items) |addr| {
            if (addr.isIPv6()) return true;
        }
        return false;
    }

    pub fn firstIPv4(self: *const LookupResult) ?IPv4 {
        for (self.addresses.items) |addr| {
            if (addr == .ipv4) return addr.ipv4;
        }
        return null;
    }

    pub fn firstIPv6(self: *const LookupResult) ?IPv6 {
        for (self.addresses.items) |addr| {
            if (addr == .ipv6) return addr.ipv6;
        }
        return null;
    }
};

/// Simple DNS resolver
pub const SimpleResolver = struct {
    allocator: std.mem.Allocator,
    /// Upstream servers
    servers: []const []const u8,
    /// Default timeout (ms)
    timeout_ms: u32,
    /// Statistics
    stats: Stats,

    const Self = @This();

    pub const Stats = struct {
        /// Total lookups
        total_lookups: u64 = 0,
        /// Successful lookups
        successful: u64 = 0,
        /// Failed lookups
        failed: u64 = 0,
        /// IPv4 lookups
        ipv4_lookups: u64 = 0,
        /// IPv6 lookups
        ipv6_lookups: u64 = 0,
        /// Average response time (ms)
        avg_response_time_ms: u32 = 0,
    };

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .servers = &[_][]const u8{ "8.8.8.8", "8.8.4.4" },
            .timeout_ms = 5000,
            .stats = .{},
        };
    }

    /// Lookup IPv4 addresses for a hostname.
    ///
    /// Not yet implemented -- returns `error.NotImplemented` so callers
    /// get a clear signal instead of silently empty results (QH-NEW-01).
    /// Use `client.Client.resolveA` for working A-record resolution.
    pub fn lookupA(self: *Self, hostname: []const u8) !LookupResult {
        _ = self;
        _ = hostname;
        return error.NotImplemented;
    }

    /// Lookup IPv6 addresses for a hostname.
    ///
    /// Not yet implemented -- returns `error.NotImplemented` so callers
    /// get a clear signal instead of silently empty results (QH-NEW-01).
    /// Use `client.Client.resolveAAAA` for working AAAA-record resolution.
    pub fn lookupAAAA(self: *Self, hostname: []const u8) !LookupResult {
        _ = self;
        _ = hostname;
        return error.NotImplemented;
    }

    /// Lookup both IPv4 and IPv6 addresses.
    ///
    /// Not yet implemented -- returns `error.NotImplemented` so callers
    /// get a clear signal instead of silently empty results (QH-NEW-01).
    /// Use `client.Client.resolve` for working dual-stack resolution.
    pub fn lookup(self: *Self, hostname: []const u8) !LookupResult {
        _ = self;
        _ = hostname;
        return error.NotImplemented;
    }

    /// Get statistics
    pub fn getStats(self: *const Self) Stats {
        return self.stats;
    }
};

/// Resolve hostname to list of addresses (convenience function)
pub fn resolveHost(allocator: std.mem.Allocator, hostname: []const u8) ![]Address {
    var resolver = SimpleResolver.init(allocator);
    var result = try resolver.lookup(hostname);
    defer result.deinit();

    return try allocator.dupe(Address, result.addresses.items);
}

/// Resolve hostname to first IPv4 address
pub fn resolveHostIPv4(allocator: std.mem.Allocator, hostname: []const u8) !?IPv4 {
    var resolver = SimpleResolver.init(allocator);
    var result = try resolver.lookupA(hostname);
    defer result.deinit();

    return result.firstIPv4();
}

/// Resolve hostname to first IPv6 address
pub fn resolveHostIPv6(allocator: std.mem.Allocator, hostname: []const u8) !?IPv6 {
    var resolver = SimpleResolver.init(allocator);
    var result = try resolver.lookupAAAA(hostname);
    defer result.deinit();

    return result.firstIPv6();
}

/// Build a reverse DNS name from an IPv4 address
pub fn reverseIPv4Name(allocator: std.mem.Allocator, ip: IPv4) ![]u8 {
    return try std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}.in-addr.arpa", .{
        ip.bytes[3],
        ip.bytes[2],
        ip.bytes[1],
        ip.bytes[0],
    });
}

/// Build a reverse DNS name from an IPv6 address
pub fn reverseIPv6Name(allocator: std.mem.Allocator, ip: IPv6) ![]u8 {
    var result = std.ArrayList(u8).empty;
    errdefer result.deinit(allocator);

    // Pre-allocate exact capacity: 32 nibbles * 2 (nibble + dot) + "ip6.arpa" (8) = 72 bytes
    try result.ensureTotalCapacity(allocator, 72);

    // Add each nibble in reverse order
    var i: usize = 16;
    while (i > 0) {
        i -= 1;
        const byte = ip.bytes[i];
        const low = byte & 0x0F;
        const high = (byte >> 4) & 0x0F;

        const hex_chars = "0123456789abcdef";
        try result.append(allocator, hex_chars[low]);
        try result.append(allocator, '.');
        try result.append(allocator, hex_chars[high]);
        try result.append(allocator, '.');
    }

    try result.appendSlice(allocator, "ip6.arpa");

    return try result.toOwnedSlice(allocator);
}

/// Parse an IPv4 address string
pub fn parseIPv4(str: []const u8) !IPv4 {
    var bytes: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, str, '.');
    var i: usize = 0;

    while (parts.next()) |part| {
        if (i >= 4) return error.InvalidIPv4;
        bytes[i] = try std.fmt.parseInt(u8, part, 10);
        i += 1;
    }

    if (i != 4) return error.InvalidIPv4;

    return IPv4{ .bytes = bytes };
}

/// Check if a string is a valid domain name
pub fn isValidDomain(name: []const u8) bool {
    if (name.len == 0 or name.len > 253) return false;

    var labels = std.mem.splitScalar(u8, name, '.');
    var label_count: usize = 0;

    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63) return false;

        // Check first and last character
        if (!std.ascii.isAlphanumeric(label[0])) return false;
        if (label.len > 1 and !std.ascii.isAlphanumeric(label[label.len - 1])) return false;

        // Check all characters
        for (label) |c| {
            if (!std.ascii.isAlphanumeric(c) and c != '-') return false;
        }

        label_count += 1;
    }

    return label_count >= 1;
}

/// Normalize a domain name (lowercase, remove trailing dot)
pub fn normalizeDomain(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    if (name.len == 0) return try allocator.dupe(u8, name);

    var end = name.len;
    if (name[end - 1] == '.') end -= 1;

    const result = try allocator.alloc(u8, end);
    for (name[0..end], 0..) |c, i| {
        result[i] = std.ascii.toLower(c);
    }

    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "IPv4 format" {
    const ip = IPv4{ .bytes = .{ 192, 168, 1, 1 } };
    const formatted = ip.format();
    try std.testing.expectEqualStrings("192.168.1.1", formatted.slice());
}

test "IPv4 format max length" {
    // Maximum length IP: 255.255.255.255 = 15 chars
    const ip = IPv4{ .bytes = .{ 255, 255, 255, 255 } };
    const formatted = ip.format();
    try std.testing.expectEqualStrings("255.255.255.255", formatted.slice());
    try std.testing.expectEqual(@as(u8, 15), formatted.len);
}

test "IPv4 format min length" {
    // Minimum length IP: 0.0.0.0 = 7 chars
    const ip = IPv4{ .bytes = .{ 0, 0, 0, 0 } };
    const formatted = ip.format();
    try std.testing.expectEqualStrings("0.0.0.0", formatted.slice());
    try std.testing.expectEqual(@as(u8, 7), formatted.len);
    // Trailing bytes should be zero
    for (formatted.buf[formatted.len..]) |b| {
        try std.testing.expectEqual(@as(u8, 0), b);
    }
}

test "parseIPv4" {
    const ip = try parseIPv4("192.168.1.1");
    try std.testing.expectEqual([4]u8{ 192, 168, 1, 1 }, ip.bytes);

    const ip2 = try parseIPv4("8.8.8.8");
    try std.testing.expectEqual([4]u8{ 8, 8, 8, 8 }, ip2.bytes);

    // Invalid
    try std.testing.expectError(error.InvalidIPv4, parseIPv4("192.168.1"));
    try std.testing.expectError(error.Overflow, parseIPv4("256.1.1.1"));
}

test "Address union" {
    const ipv4_addr = Address{ .ipv4 = .{ .bytes = .{ 127, 0, 0, 1 } } };
    try std.testing.expect(ipv4_addr.isIPv4());
    try std.testing.expect(!ipv4_addr.isIPv6());

    const ipv6_addr = Address{ .ipv6 = .{ .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } } };
    try std.testing.expect(ipv6_addr.isIPv6());
    try std.testing.expect(!ipv6_addr.isIPv4());
}

test "reverseIPv4Name" {
    const allocator = std.testing.allocator;

    const ip = IPv4{ .bytes = .{ 192, 168, 1, 1 } };
    const name = try reverseIPv4Name(allocator, ip);
    defer allocator.free(name);

    try std.testing.expectEqualStrings("1.1.168.192.in-addr.arpa", name);
}

test "reverseIPv6Name" {
    const allocator = std.testing.allocator;

    // ::1 (loopback)
    const ip = IPv6{ .bytes = .{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 } };
    const name = try reverseIPv6Name(allocator, ip);
    defer allocator.free(name);

    try std.testing.expect(std.mem.endsWith(u8, name, "ip6.arpa"));
    try std.testing.expect(std.mem.startsWith(u8, name, "1.0."));
}

test "isValidDomain" {
    try std.testing.expect(isValidDomain("example.com"));
    try std.testing.expect(isValidDomain("sub.example.com"));
    try std.testing.expect(isValidDomain("example-site.com"));
    try std.testing.expect(isValidDomain("a.b.c.d.e.f"));

    try std.testing.expect(!isValidDomain(""));
    try std.testing.expect(!isValidDomain("-example.com"));
    try std.testing.expect(!isValidDomain("example-.com"));
    try std.testing.expect(!isValidDomain("example..com"));
}

test "normalizeDomain" {
    const allocator = std.testing.allocator;

    const n1 = try normalizeDomain(allocator, "Example.COM");
    defer allocator.free(n1);
    try std.testing.expectEqualStrings("example.com", n1);

    const n2 = try normalizeDomain(allocator, "WWW.Example.COM.");
    defer allocator.free(n2);
    try std.testing.expectEqualStrings("www.example.com", n2);
}

test "SimpleResolver init" {
    const allocator = std.testing.allocator;

    const resolver = SimpleResolver.init(allocator);
    _ = resolver;

    // Just test initialization
    try std.testing.expect(true);
}

test "LookupResult methods" {
    const allocator = std.testing.allocator;

    var result = LookupResult{
        .addresses = .empty,
        .allocator = allocator,
    };
    defer result.deinit();

    try result.addresses.append(allocator, .{ .ipv4 = .{ .bytes = .{ 1, 2, 3, 4 } } });
    try result.addresses.append(allocator, .{ .ipv6 = .{ .bytes = .{0} ** 16 } });

    try std.testing.expect(result.hasIPv4());
    try std.testing.expect(result.hasIPv6());
    try std.testing.expect(result.firstIPv4() != null);
    try std.testing.expect(result.firstIPv6() != null);
}

test "SimpleResolver lookup stubs return NotImplemented" {
    const allocator = std.testing.allocator;
    var resolver = SimpleResolver.init(allocator);

    try std.testing.expectError(error.NotImplemented, resolver.lookupA("example.com"));
    try std.testing.expectError(error.NotImplemented, resolver.lookupAAAA("example.com"));
    try std.testing.expectError(error.NotImplemented, resolver.lookup("example.com"));
}

test "resolveHost returns NotImplemented" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.NotImplemented, resolveHost(allocator, "example.com"));
    try std.testing.expectError(error.NotImplemented, resolveHostIPv4(allocator, "example.com"));
    try std.testing.expectError(error.NotImplemented, resolveHostIPv6(allocator, "example.com"));
}

test "Type enum re-export matches canonical values" {
    // Verify that the re-exported Type from types.zig has the expected
    // wire-format values for common query types (QM-NEW-01).
    try std.testing.expectEqual(@as(u16, 1), @intFromEnum(Type.a));
    try std.testing.expectEqual(@as(u16, 28), @intFromEnum(Type.aaaa));
    try std.testing.expectEqual(@as(u16, 15), @intFromEnum(Type.mx));
    try std.testing.expectEqual(@as(u16, 33), @intFromEnum(Type.srv));
    try std.testing.expectEqual(@as(u16, 255), @intFromEnum(Type.any));
}
