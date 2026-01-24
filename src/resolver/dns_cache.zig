// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DNS Cache
//!
//! RFC 1035 Section 7.4: Using the cache
//! RFC 2308: Negative Caching of DNS Queries
//!
//! This module implements TTL-aware caching with full RFC 2308 negative
//! caching support including:
//! - NXDOMAIN caching with SOA minimum TTL extraction
//! - NODATA caching (empty answer, but name exists)
//! - Zone-level NXDOMAIN caching
//! - Proper TTL calculation: min(SOA TTL, SOA MINIMUM field)

const std = @import("std");
const types = @import("types");
const lru = @import("lru");
const clock_mod = @import("clock");
const record_mod = @import("record");
const message_mod = @import("message");
const name_mod = @import("name");

pub const Type = types.Type;
pub const Class = types.Class;
pub const Clock = clock_mod.Clock;
pub const ResourceRecord = record_mod.ResourceRecord;
pub const Message = message_mod.Message;
pub const Name = name_mod.Name;

/// Cache configuration
pub const CacheOptions = struct {
    /// Maximum number of cache entries
    max_entries: usize = 65536,
    /// Minimum TTL to enforce (prevents very short TTLs)
    min_ttl_s: u32 = 0,
    /// Maximum TTL to enforce (prevents cache pollution)
    max_ttl_s: u32 = 86400,
    /// Default negative TTL when SOA is not available
    negative_ttl_s: u32 = 300,
    /// Maximum negative TTL (RFC 2308 recommends 1-3 hours)
    max_negative_ttl_s: u32 = 10800,
    /// Enable zone-level NXDOMAIN caching
    zone_nxdomain: bool = true,
};

/// Cache entry type
pub const EntryType = enum {
    /// Positive response with RDATA
    positive,
    /// NXDOMAIN (name does not exist)
    nxdomain,
    /// NODATA (name exists but no records of requested type)
    nodata,
};

/// SOA record data for negative caching
pub const SoaCacheData = struct {
    /// SOA record TTL
    soa_ttl: u32,
    /// SOA MINIMUM field (RFC 2308: negative cache TTL)
    minimum: u32,
    /// Zone name this SOA applies to
    zone: []const u8,

    /// Calculate the effective negative TTL per RFC 2308 Section 5
    /// TTL = min(SOA TTL, SOA MINIMUM)
    pub fn negativeTtl(self: SoaCacheData) u32 {
        return @min(self.soa_ttl, self.minimum);
    }
};

/// Cached DNS entry
pub const CacheEntry = struct {
    entry_type: EntryType,
    rdata: []const u8,
    cached_at: i64,
    original_ttl: u32,
    /// Zone name for NXDOMAIN entries (for zone-level caching)
    zone_name: ?[]const u8 = null,

    const Self = @This();

    pub fn isExpired(self: Self, now: i64) bool {
        const age = now - self.cached_at;
        return age < 0 or age >= self.original_ttl;
    }

    pub fn remainingTtl(self: Self, now: i64) u32 {
        const age = now - self.cached_at;
        if (age < 0 or age >= self.original_ttl) return 0;
        return self.original_ttl - @as(u32, @intCast(age));
    }
};

/// DNS Response Cache
pub const DnsCache = struct {
    allocator: std.mem.Allocator,
    options: CacheOptions,
    entries: lru.LruCache(CacheEntry),
    clock: Clock,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, options: CacheOptions, clk: Clock) Self {
        return Self{
            .allocator = allocator,
            .options = options,
            .entries = lru.LruCache(CacheEntry).init(allocator, options.max_entries),
            .clock = clk,
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.entries.map.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.value.rdata.len > 0) {
                self.allocator.free(kv.value_ptr.value.rdata);
            }
        }
        self.entries.deinit();
    }

    pub fn get(self: *Self, name: []const u8, qtype: Type, qclass: Class) ?CacheEntry {
        const key = self.makeKey(name, qtype, qclass) catch return null;
        defer self.allocator.free(key);

        const now = self.clock.now();

        if (self.entries.get(key)) |entry| {
            if (entry.isExpired(now)) {
                _ = self.entries.remove(key);
                return null;
            }
            return entry;
        }
        return null;
    }

    pub fn putPositive(self: *Self, name: []const u8, qtype: Type, qclass: Class, rdata: []const u8, ttl: u32) !void {
        const clamped_ttl = self.clampTtl(ttl);
        if (clamped_ttl == 0) return;

        const key = try self.makeKey(name, qtype, qclass);
        defer self.allocator.free(key);

        const rdata_copy = try self.allocator.dupe(u8, rdata);
        errdefer self.allocator.free(rdata_copy);

        try self.entries.put(key, CacheEntry{
            .entry_type = .positive,
            .rdata = rdata_copy,
            .cached_at = self.clock.now(),
            .original_ttl = clamped_ttl,
        });
    }

    /// Cache an NXDOMAIN response (RFC 2308 Section 3)
    /// Uses SOA minimum field for TTL calculation
    pub fn putNxdomain(self: *Self, name: []const u8, qtype: Type, qclass: Class, soa_ttl: ?u32) !void {
        const ttl = self.clampNegativeTtl(soa_ttl orelse self.options.negative_ttl_s);
        if (ttl == 0) return;

        const key = try self.makeKey(name, qtype, qclass);
        defer self.allocator.free(key);

        try self.entries.put(key, CacheEntry{
            .entry_type = .nxdomain,
            .rdata = &[_]u8{},
            .cached_at = self.clock.now(),
            .original_ttl = ttl,
        });
    }

    /// Cache an NXDOMAIN response from a raw DNS message (RFC 2308)
    /// Extracts SOA minimum field automatically
    pub fn putNxdomainFromResponse(self: *Self, name: []const u8, qtype: Type, qclass: Class, response: []const u8) !void {
        const soa_data = self.extractSoaFromResponse(response);
        const ttl = if (soa_data) |soa|
            self.clampNegativeTtl(soa.negativeTtl())
        else
            self.clampNegativeTtl(self.options.negative_ttl_s);

        if (ttl == 0) return;

        const key = try self.makeKey(name, qtype, qclass);
        defer self.allocator.free(key);

        // For zone-level caching, also cache at the zone level
        if (self.options.zone_nxdomain) {
            if (soa_data) |soa| {
                const zone_key = try self.makeNxdomainZoneKey(soa.zone);
                defer self.allocator.free(zone_key);

                // Don't overwrite existing zone entry with shorter TTL
                if (self.entries.get(zone_key)) |existing| {
                    if (!existing.isExpired(self.clock.now())) {
                        // Zone already cached, just cache specific name
                    }
                } else {
                    try self.entries.put(zone_key, CacheEntry{
                        .entry_type = .nxdomain,
                        .rdata = &[_]u8{},
                        .cached_at = self.clock.now(),
                        .original_ttl = ttl,
                        .zone_name = try self.allocator.dupe(u8, soa.zone),
                    });
                }
            }
        }

        try self.entries.put(key, CacheEntry{
            .entry_type = .nxdomain,
            .rdata = &[_]u8{},
            .cached_at = self.clock.now(),
            .original_ttl = ttl,
        });
    }

    /// Cache a NODATA response (RFC 2308 Section 2.2)
    /// NODATA = name exists but no records of requested type
    pub fn putNodata(self: *Self, name: []const u8, qtype: Type, qclass: Class, soa_ttl: ?u32) !void {
        const ttl = self.clampNegativeTtl(soa_ttl orelse self.options.negative_ttl_s);
        if (ttl == 0) return;

        const key = try self.makeKey(name, qtype, qclass);
        defer self.allocator.free(key);

        try self.entries.put(key, CacheEntry{
            .entry_type = .nodata,
            .rdata = &[_]u8{},
            .cached_at = self.clock.now(),
            .original_ttl = ttl,
        });
    }

    /// Cache a NODATA response from a raw DNS message (RFC 2308)
    /// Extracts SOA minimum field automatically
    pub fn putNodataFromResponse(self: *Self, name: []const u8, qtype: Type, qclass: Class, response: []const u8) !void {
        const soa_data = self.extractSoaFromResponse(response);
        const ttl = if (soa_data) |soa|
            self.clampNegativeTtl(soa.negativeTtl())
        else
            self.clampNegativeTtl(self.options.negative_ttl_s);

        if (ttl == 0) return;

        const key = try self.makeKey(name, qtype, qclass);
        defer self.allocator.free(key);

        try self.entries.put(key, CacheEntry{
            .entry_type = .nodata,
            .rdata = &[_]u8{},
            .cached_at = self.clock.now(),
            .original_ttl = ttl,
        });
    }

    /// Extract SOA record data from a DNS response (RFC 2308)
    /// Returns null if no SOA is found in authority section
    pub fn extractSoaFromResponse(self: *Self, response: []const u8) ?SoaCacheData {
        const msg = Message.parse(response) catch return null;

        // SOA should be in authority section for negative responses
        var auth_iter = msg.authority() catch return null;
        while (auth_iter.next() catch null) |rr| {
            if (rr.rtype == .soa) {
                const soa = rr.parseSOA(response) catch continue;
                const zone_name = rr.getName(self.allocator, response) catch continue;
                defer self.allocator.free(zone_name);

                return SoaCacheData{
                    .soa_ttl = rr.ttl,
                    .minimum = soa.minimum,
                    .zone = zone_name,
                };
            }
        }

        return null;
    }

    /// Check if a name is under a cached NXDOMAIN zone
    pub fn isUnderNxdomainZone(self: *Self, name: []const u8) bool {
        if (!self.options.zone_nxdomain) return false;

        const now = self.clock.now();

        // Check each parent zone
        var current = name;
        while (current.len > 0) {
            const zone_key = self.makeNxdomainZoneKey(current) catch continue;
            defer self.allocator.free(zone_key);

            if (self.entries.get(zone_key)) |entry| {
                if (entry.entry_type == .nxdomain and !entry.isExpired(now)) {
                    return true;
                }
            }

            // Move to parent zone
            if (std.mem.indexOf(u8, current, ".")) |dot_idx| {
                current = current[dot_idx + 1 ..];
            } else {
                break;
            }
        }

        return false;
    }

    fn makeNxdomainZoneKey(self: *Self, zone: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "NXZONE:{s}", .{zone});
    }

    pub fn clear(self: *Self) void {
        var it = self.entries.map.iterator();
        while (it.next()) |kv| {
            if (kv.value_ptr.value.rdata.len > 0) {
                self.allocator.free(kv.value_ptr.value.rdata);
            }
        }
        self.entries.clear();
    }

    pub fn len(self: *Self) usize {
        return self.entries.len();
    }

    fn makeKey(self: *Self, name: []const u8, qtype: Type, qclass: Class) ![]u8 {
        // Lowercase for case-insensitive matching
        const lower = try self.allocator.alloc(u8, name.len);
        defer self.allocator.free(lower);
        for (name, 0..) |c, i| {
            lower[i] = std.ascii.toLower(c);
        }

        return std.fmt.allocPrint(self.allocator, "{s}:{d}:{d}", .{
            lower,
            @intFromEnum(qtype),
            @intFromEnum(qclass),
        });
    }

    fn clampTtl(self: *Self, ttl: u32) u32 {
        return @min(self.options.max_ttl_s, @max(self.options.min_ttl_s, ttl));
    }

    /// Clamp TTL for negative cache entries (RFC 2308)
    fn clampNegativeTtl(self: *Self, ttl: u32) u32 {
        return @min(self.options.max_negative_ttl_s, @max(self.options.min_ttl_s, ttl));
    }
};

test "DnsCache basic" {
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();

    var cache = DnsCache.init(allocator, .{}, mock_clock.clock());
    defer cache.deinit();

    try cache.putPositive("example.com.", .a, .in, &[_]u8{ 1, 2, 3, 4 }, 300);

    const entry = cache.get("example.com.", .a, .in);
    try std.testing.expect(entry != null);
    try std.testing.expectEqual(EntryType.positive, entry.?.entry_type);
}

test "DnsCache expiration" {
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();

    var cache = DnsCache.init(allocator, .{}, mock_clock.clock());
    defer cache.deinit();

    try cache.putPositive("test.com.", .a, .in, &[_]u8{ 1, 2, 3, 4 }, 60);

    try std.testing.expect(cache.get("test.com.", .a, .in) != null);

    mock_clock.advance(61);

    try std.testing.expect(cache.get("test.com.", .a, .in) == null);
}

test "DnsCache NXDOMAIN caching" {
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();

    var cache = DnsCache.init(allocator, .{}, mock_clock.clock());
    defer cache.deinit();

    try cache.putNxdomain("nonexistent.com.", .a, .in, 300);

    const entry = cache.get("nonexistent.com.", .a, .in);
    try std.testing.expect(entry != null);
    try std.testing.expectEqual(EntryType.nxdomain, entry.?.entry_type);
}

test "DnsCache NODATA caching" {
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();

    var cache = DnsCache.init(allocator, .{}, mock_clock.clock());
    defer cache.deinit();

    try cache.putNodata("example.com.", .aaaa, .in, 600);

    const entry = cache.get("example.com.", .aaaa, .in);
    try std.testing.expect(entry != null);
    try std.testing.expectEqual(EntryType.nodata, entry.?.entry_type);
}

test "DnsCache negative TTL clamping" {
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();

    // Set max_negative_ttl_s to 1 hour (3600s)
    var cache = DnsCache.init(allocator, .{
        .max_negative_ttl_s = 3600,
    }, mock_clock.clock());
    defer cache.deinit();

    // Try to cache with very long TTL
    try cache.putNxdomain("nonexistent.com.", .a, .in, 86400);

    const entry = cache.get("nonexistent.com.", .a, .in);
    try std.testing.expect(entry != null);
    // TTL should be clamped to max_negative_ttl_s
    try std.testing.expectEqual(@as(u32, 3600), entry.?.original_ttl);
}

test "SoaCacheData negativeTtl calculation" {
    // RFC 2308: TTL = min(SOA TTL, SOA MINIMUM)
    const soa1 = SoaCacheData{
        .soa_ttl = 300,
        .minimum = 600,
        .zone = "example.com.",
    };
    try std.testing.expectEqual(@as(u32, 300), soa1.negativeTtl());

    const soa2 = SoaCacheData{
        .soa_ttl = 600,
        .minimum = 300,
        .zone = "example.com.",
    };
    try std.testing.expectEqual(@as(u32, 300), soa2.negativeTtl());
}
