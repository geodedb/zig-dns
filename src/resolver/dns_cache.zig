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
const cache_protection = @import("cache_protection");

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

    pub inline fn isExpired(self: Self, now: i64) bool {
        const age = now - self.cached_at;
        return age < 0 or age >= self.original_ttl;
    }

    pub inline fn remainingTtl(self: Self, now: i64) u32 {
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
        var entries = lru.LruCache(CacheEntry).init(allocator, options.max_entries);
        entries.on_evict = &freeCacheEntry;
        return Self{
            .allocator = allocator,
            .options = options,
            .entries = entries,
            .clock = clk,
        };
    }

    /// Free owned memory inside a CacheEntry (rdata and zone_name).
    /// Used as the LRU on_evict callback so that eviction, removal,
    /// overwrite, clear, and deinit all release entry-owned memory.
    fn freeCacheEntry(allocator: std.mem.Allocator, entry: CacheEntry) void {
        if (entry.rdata.len > 0) {
            allocator.free(entry.rdata);
        }
        if (entry.zone_name) |zn| {
            allocator.free(zn);
        }
    }

    pub fn deinit(self: *Self) void {
        // The LRU deinit calls on_evict for each entry, which frees
        // rdata and zone_name via freeCacheEntry.
        self.entries.deinit();
    }

    pub fn get(self: *Self, name: []const u8, qtype: Type, qclass: Class) ?CacheEntry {
        // PF-21: Use a stack buffer for the key to avoid a heap allocation
        // on every lookup.  PF-26: Use getWithHandle + removeByHandle to
        // avoid re-hashing the key when removing expired entries.
        var key_buf: [max_key_len]u8 = undefined;
        const key = self.makeKeyBuf(name, qtype, qclass, &key_buf) orelse {
            // Name exceeded stack buffer -- fall back to heap allocation.
            const heap_key = self.makeKey(name, qtype, qclass) catch return null;
            defer self.allocator.free(heap_key);
            return self.getWithKey(heap_key);
        };

        return self.getWithKey(key);
    }

    /// Internal helper: look up a pre-formatted key and handle expiry.
    fn getWithKey(self: *Self, key: []const u8) ?CacheEntry {
        const now = self.clock.now();

        // PF-26: getWithHandle returns an internal handle so that, if the
        // entry is expired, we can remove it via removeByHandle without
        // re-hashing the key string.
        if (self.entries.getWithHandle(key)) |handle| {
            if (handle.value.isExpired(now)) {
                self.entries.removeByHandle(handle);
                return null;
            }
            return handle.value;
        }
        return null;
    }

    pub fn putPositive(self: *Self, name: []const u8, qtype: Type, qclass: Class, rdata: []const u8, ttl: u32) !void {
        const clamped_ttl = self.clampTtl(ttl);
        if (clamped_ttl == 0) return;

        const rdata_copy = try self.allocator.dupe(u8, rdata);
        errdefer self.allocator.free(rdata_copy);

        const entry = CacheEntry{
            .entry_type = .positive,
            .rdata = rdata_copy,
            .cached_at = self.clock.now(),
            .original_ttl = clamped_ttl,
        };

        // PF-NEW-15: Use stack buffer for key to avoid heap allocation on hot path.
        var key_buf: [max_key_len]u8 = undefined;
        if (self.makeKeyBuf(name, qtype, qclass, &key_buf)) |key| {
            try self.entries.put(key, entry);
        } else {
            const heap_key = try self.makeKey(name, qtype, qclass);
            defer self.allocator.free(heap_key);
            try self.entries.put(heap_key, entry);
        }
    }

    /// Cache an NXDOMAIN response (RFC 2308 Section 3)
    /// Uses SOA minimum field for TTL calculation
    pub fn putNxdomain(self: *Self, name: []const u8, qtype: Type, qclass: Class, soa_ttl: ?u32) !void {
        const ttl = self.clampNegativeTtl(soa_ttl orelse self.options.negative_ttl_s);
        if (ttl == 0) return;

        const entry = CacheEntry{
            .entry_type = .nxdomain,
            .rdata = &[_]u8{},
            .cached_at = self.clock.now(),
            .original_ttl = ttl,
        };

        // PF-NEW-15: Use stack buffer for key to avoid heap allocation on hot path.
        var key_buf: [max_key_len]u8 = undefined;
        if (self.makeKeyBuf(name, qtype, qclass, &key_buf)) |key| {
            try self.entries.put(key, entry);
        } else {
            const heap_key = try self.makeKey(name, qtype, qclass);
            defer self.allocator.free(heap_key);
            try self.entries.put(heap_key, entry);
        }
    }

    /// Cache an NXDOMAIN response from a raw DNS message (RFC 2308)
    /// Extracts SOA minimum field automatically
    pub fn putNxdomainFromResponse(self: *Self, name: []const u8, qtype: Type, qclass: Class, response: []const u8) !void {
        const soa_data = self.extractSoaFromResponse(response);
        defer if (soa_data) |soa| self.allocator.free(soa.zone);

        const ttl = if (soa_data) |soa|
            self.clampNegativeTtl(soa.negativeTtl())
        else
            self.clampNegativeTtl(self.options.negative_ttl_s);

        if (ttl == 0) return;

        // For zone-level caching, also cache at the zone level
        if (self.options.zone_nxdomain) {
            if (soa_data) |soa| {
                // PF-NEW-15: Use stack buffer for zone key.
                var zone_key_buf: [max_key_len]u8 = undefined;
                if (self.makeNxdomainZoneKeyBuf(soa.zone, &zone_key_buf)) |zone_key| {
                    try self.putNxdomainZoneEntry(zone_key, soa.zone, ttl);
                } else {
                    const heap_zone_key = try self.makeNxdomainZoneKey(soa.zone);
                    defer self.allocator.free(heap_zone_key);
                    try self.putNxdomainZoneEntry(heap_zone_key, soa.zone, ttl);
                }
            }
        }

        const entry = CacheEntry{
            .entry_type = .nxdomain,
            .rdata = &[_]u8{},
            .cached_at = self.clock.now(),
            .original_ttl = ttl,
        };

        // PF-NEW-15: Use stack buffer for key to avoid heap allocation on hot path.
        var key_buf: [max_key_len]u8 = undefined;
        if (self.makeKeyBuf(name, qtype, qclass, &key_buf)) |key| {
            try self.entries.put(key, entry);
        } else {
            const heap_key = try self.makeKey(name, qtype, qclass);
            defer self.allocator.free(heap_key);
            try self.entries.put(heap_key, entry);
        }
    }

    /// Cache a NODATA response (RFC 2308 Section 2.2)
    /// NODATA = name exists but no records of requested type
    pub fn putNodata(self: *Self, name: []const u8, qtype: Type, qclass: Class, soa_ttl: ?u32) !void {
        const ttl = self.clampNegativeTtl(soa_ttl orelse self.options.negative_ttl_s);
        if (ttl == 0) return;

        const entry = CacheEntry{
            .entry_type = .nodata,
            .rdata = &[_]u8{},
            .cached_at = self.clock.now(),
            .original_ttl = ttl,
        };

        // PF-NEW-15: Use stack buffer for key to avoid heap allocation on hot path.
        var key_buf: [max_key_len]u8 = undefined;
        if (self.makeKeyBuf(name, qtype, qclass, &key_buf)) |key| {
            try self.entries.put(key, entry);
        } else {
            const heap_key = try self.makeKey(name, qtype, qclass);
            defer self.allocator.free(heap_key);
            try self.entries.put(heap_key, entry);
        }
    }

    /// Cache a NODATA response from a raw DNS message (RFC 2308)
    /// Extracts SOA minimum field automatically
    pub fn putNodataFromResponse(self: *Self, name: []const u8, qtype: Type, qclass: Class, response: []const u8) !void {
        const soa_data = self.extractSoaFromResponse(response);
        defer if (soa_data) |soa| self.allocator.free(soa.zone);

        const ttl = if (soa_data) |soa|
            self.clampNegativeTtl(soa.negativeTtl())
        else
            self.clampNegativeTtl(self.options.negative_ttl_s);

        if (ttl == 0) return;

        const entry = CacheEntry{
            .entry_type = .nodata,
            .rdata = &[_]u8{},
            .cached_at = self.clock.now(),
            .original_ttl = ttl,
        };

        // PF-NEW-15: Use stack buffer for key to avoid heap allocation on hot path.
        var key_buf: [max_key_len]u8 = undefined;
        if (self.makeKeyBuf(name, qtype, qclass, &key_buf)) |key| {
            try self.entries.put(key, entry);
        } else {
            const heap_key = try self.makeKey(name, qtype, qclass);
            defer self.allocator.free(heap_key);
            try self.entries.put(heap_key, entry);
        }
    }

    /// Extract SOA record data from a DNS response (RFC 2308)
    /// Returns null if no SOA is found in authority section.
    /// Caller must free the returned SoaCacheData.zone slice when done.
    pub fn extractSoaFromResponse(self: *Self, response: []const u8) ?SoaCacheData {
        const msg = Message.parse(response) catch return null;

        // SOA should be in authority section for negative responses
        var auth_iter = msg.authority();
        while (auth_iter.next() catch null) |rr| {
            if (rr.rtype == .soa) {
                const soa = rr.parseSOA(response) catch continue;
                const zone_name = rr.getName(self.allocator, response) catch continue;

                return SoaCacheData{
                    .soa_ttl = rr.ttl,
                    .minimum = soa.minimum,
                    .zone = zone_name,
                };
            }
        }

        return null;
    }

    /// Helper: insert an NXDOMAIN zone entry if one does not already exist.
    /// Accepts a pre-formatted zone key (may live on the stack or heap).
    fn putNxdomainZoneEntry(self: *Self, zone_key: []const u8, zone: []const u8, ttl: u32) !void {
        // Don't overwrite existing zone entry with shorter TTL
        if (self.entries.get(zone_key)) |existing| {
            if (!existing.isExpired(self.clock.now())) {
                // Zone already cached, just cache specific name
                return;
            }
        }
        try self.entries.put(zone_key, CacheEntry{
            .entry_type = .nxdomain,
            .rdata = &[_]u8{},
            .cached_at = self.clock.now(),
            .original_ttl = ttl,
            .zone_name = try self.allocator.dupe(u8, zone),
        });
    }

    /// Check if a name is under a cached NXDOMAIN zone
    pub fn isUnderNxdomainZone(self: *Self, name: []const u8) bool {
        if (!self.options.zone_nxdomain) return false;

        const now = self.clock.now();
        // PF-25: Use a stack buffer for the zone key to avoid a heap
        // allocation on every iteration of the parent-zone loop.
        var key_buf: [max_key_len]u8 = undefined;

        // Check each parent zone
        var current = name;
        while (current.len > 0) {
            if (self.checkNxdomainZone(current, &key_buf, now)) return true;

            // Move to parent zone
            if (std.mem.indexOf(u8, current, ".")) |dot_idx| {
                current = current[dot_idx + 1 ..];
            } else {
                break;
            }
        }

        return false;
    }

    /// Check whether a single zone name is cached as NXDOMAIN.
    /// Uses the stack buffer first; falls back to heap if needed.
    fn checkNxdomainZone(self: *Self, zone: []const u8, key_buf: []u8, now: i64) bool {
        if (self.makeNxdomainZoneKeyBuf(zone, key_buf)) |zone_key| {
            if (self.entries.get(zone_key)) |entry| {
                return entry.entry_type == .nxdomain and !entry.isExpired(now);
            }
            return false;
        }
        // Fallback: heap-allocate for extremely long zone names.
        const heap_key = self.makeNxdomainZoneKey(zone) catch return false;
        defer self.allocator.free(heap_key);
        if (self.entries.get(heap_key)) |entry| {
            return entry.entry_type == .nxdomain and !entry.isExpired(now);
        }
        return false;
    }

    fn makeNxdomainZoneKey(self: *Self, zone: []const u8) ![]u8 {
        return std.fmt.allocPrint(self.allocator, "NXZONE:{s}", .{zone});
    }

    /// Format an NXDOMAIN zone key into a caller-owned stack buffer.
    /// Returns null if the formatted key exceeds the buffer.
    fn makeNxdomainZoneKeyBuf(_: *Self, zone: []const u8, buf: []u8) ?[]const u8 {
        return std.fmt.bufPrint(buf, "NXZONE:{s}", .{zone}) catch null;
    }

    pub fn clear(self: *Self) void {
        // The LRU clear calls on_evict for each entry, which frees
        // rdata and zone_name via freeCacheEntry.
        self.entries.clear();
    }

    pub fn len(self: *Self) usize {
        return self.entries.len();
    }

    /// Maximum formatted key length: 255 (name) + 1 (:) + 5 (type) + 1 (:) + 5 (class) = 267.
    /// Rounded up for safety.  Also covers NXZONE: prefix (7) + 255 = 262.
    const max_key_len = 280;

    /// Format a lookup key into a caller-owned stack buffer without any
    /// heap allocation.  Returns null if the formatted key would not fit
    /// (extremely unlikely given RFC 1035 name limits).
    fn makeKeyBuf(_: *Self, name: []const u8, qtype: Type, qclass: Class, buf: []u8) ?[]const u8 {
        // Lowercase the name in-place into the beginning of buf, then
        // append ":<type>:<class>".
        var lower_buf: [name_mod.max_name_length]u8 = undefined;
        const clamped_len = @min(name.len, lower_buf.len);
        for (name[0..clamped_len], 0..) |c, i| {
            lower_buf[i] = std.ascii.toLower(c);
        }

        return std.fmt.bufPrint(buf, "{s}:{d}:{d}", .{
            lower_buf[0..clamped_len],
            @intFromEnum(qtype),
            @intFromEnum(qclass),
        }) catch null;
    }

    fn makeKey(self: *Self, name: []const u8, qtype: Type, qclass: Class) ![]u8 {
        // Lowercase into a stack buffer for case-insensitive matching.
        // DNS names are at most 255 bytes (RFC 1035 Section 2.3.4).
        var lower_buf: [name_mod.max_name_length]u8 = undefined;
        const clamped_len = @min(name.len, lower_buf.len);
        for (name[0..clamped_len], 0..) |c, i| {
            lower_buf[i] = std.ascii.toLower(c);
        }

        // Single heap allocation for the final key string
        return std.fmt.allocPrint(self.allocator, "{s}:{d}:{d}", .{
            lower_buf[0..clamped_len],
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

    // ================================================================
    // Multi-record support (PF-24-dual-cache)
    // ================================================================
    //
    // Positive entries may contain multiple resource records packed as:
    //   [u16 len1][rdata1][u16 len2][rdata2]...
    // putRecord appends to an existing positive entry for the same key.
    // PackedRdataIterator walks the segments.

    /// Store a single resource record, appending to existing records for
    /// the same (name, type, class). Records are packed with 2-byte
    /// big-endian length prefixes so PackedRdataIterator can walk them.
    pub fn putRecord(self: *Self, name: []const u8, qtype: Type, qclass: Class, rdata: []const u8, ttl: u32) !void {
        const clamped_ttl = self.clampTtl(ttl);
        if (clamped_ttl == 0) return;

        var key_buf: [max_key_len]u8 = undefined;
        if (self.makeKeyBuf(name, qtype, qclass, &key_buf)) |key| {
            return self.putRecordWithKey(key, rdata, clamped_ttl);
        }
        const heap_key = try self.makeKey(name, qtype, qclass);
        defer self.allocator.free(heap_key);
        return self.putRecordWithKey(heap_key, rdata, clamped_ttl);
    }

    /// putRecord with bailiwick validation (RFC 5452).
    pub fn putRecordWithBailiwick(
        self: *Self,
        name: []const u8,
        qtype: Type,
        qclass: Class,
        rdata: []const u8,
        ttl: u32,
        query_zone: []const u8,
    ) !void {
        if (cache_protection.checkBailiwick(name, query_zone) == .out_of_bailiwick) return;
        return self.putRecord(name, qtype, qclass, rdata, ttl);
    }

    fn putRecordWithKey(self: *Self, key: []const u8, rdata: []const u8, ttl: u32) !void {
        const now = self.clock.now();

        // Append to existing positive entry if present and not expired.
        if (self.entries.getWithHandle(key)) |handle| {
            if (handle.value.entry_type == .positive and !handle.value.isExpired(now)) {
                const old = handle.value.rdata;
                const seg_len = 2 + rdata.len;
                const buf = try self.allocator.alloc(u8, old.len + seg_len);
                errdefer self.allocator.free(buf);
                @memcpy(buf[0..old.len], old);
                std.mem.writeInt(u16, buf[old.len..][0..2], @intCast(rdata.len), .big);
                @memcpy(buf[old.len + 2 ..][0..rdata.len], rdata);

                // put evicts old entry (freeing old rdata via on_evict)
                try self.entries.put(key, CacheEntry{
                    .entry_type = .positive,
                    .rdata = buf,
                    .cached_at = handle.value.cached_at,
                    .original_ttl = ttl,
                });
                return;
            }
        }

        // New entry: single segment [u16 len][rdata]
        const buf = try self.allocator.alloc(u8, 2 + rdata.len);
        errdefer self.allocator.free(buf);
        std.mem.writeInt(u16, buf[0..2], @intCast(rdata.len), .big);
        @memcpy(buf[2..][0..rdata.len], rdata);

        try self.entries.put(key, CacheEntry{
            .entry_type = .positive,
            .rdata = buf,
            .cached_at = now,
            .original_ttl = ttl,
        });
    }
};

/// Iterator over length-prefixed packed rdata segments.
/// Each segment is: [u16 big-endian length][rdata bytes].
pub const PackedRdataIterator = struct {
    data: []const u8,
    pos: usize = 0,

    pub fn init(data: []const u8) PackedRdataIterator {
        return .{ .data = data };
    }

    pub fn next(self: *PackedRdataIterator) ?[]const u8 {
        if (self.pos + 2 > self.data.len) return null;
        const len = std.mem.readInt(u16, self.data[self.pos..][0..2], .big);
        self.pos += 2;
        if (self.pos + len > self.data.len) return null;
        const segment = self.data[self.pos..][0..len];
        self.pos += len;
        return segment;
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

test "DnsCache NXDOMAIN with zone_name freed on deinit" {
    // Regression test for PF-12: zone_name must be freed on deinit.
    // The testing allocator will detect any leak.
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();

    var cache = DnsCache.init(allocator, .{}, mock_clock.clock());
    defer cache.deinit();

    // Manually insert an entry with an allocated zone_name
    const zone = try allocator.dupe(u8, "example.com.");
    const key = try cache.makeKey("nonexistent.example.com.", .a, .in);
    defer allocator.free(key);

    try cache.entries.put(key, CacheEntry{
        .entry_type = .nxdomain,
        .rdata = &[_]u8{},
        .cached_at = mock_clock.clock().now(),
        .original_ttl = 300,
        .zone_name = zone,
    });
}

test "DnsCache zone_name freed on clear" {
    // Regression test for PF-12: zone_name must be freed on clear.
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();

    var cache = DnsCache.init(allocator, .{}, mock_clock.clock());
    defer cache.deinit();

    const zone = try allocator.dupe(u8, "test.org.");
    const key = try cache.makeKey("gone.test.org.", .a, .in);
    defer allocator.free(key);

    try cache.entries.put(key, CacheEntry{
        .entry_type = .nxdomain,
        .rdata = &[_]u8{},
        .cached_at = mock_clock.clock().now(),
        .original_ttl = 300,
        .zone_name = zone,
    });

    cache.clear();
    // After clear, no leak should be detected by testing allocator
}

test "DnsCache zone_name freed on eviction" {
    // Regression test for PF-12: zone_name must be freed when LRU evicts.
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();

    // Cache with capacity of 2 to trigger eviction
    var cache = DnsCache.init(allocator, .{ .max_entries = 2 }, mock_clock.clock());
    defer cache.deinit();

    // Insert entry with zone_name
    const zone = try allocator.dupe(u8, "evict.zone.");
    const key1 = try cache.makeKey("a.evict.zone.", .a, .in);
    defer allocator.free(key1);

    try cache.entries.put(key1, CacheEntry{
        .entry_type = .nxdomain,
        .rdata = &[_]u8{},
        .cached_at = mock_clock.clock().now(),
        .original_ttl = 300,
        .zone_name = zone,
    });

    // Fill up the cache to trigger eviction of the first entry
    try cache.putPositive("b.evict.zone.", .a, .in, &[_]u8{ 1, 2, 3, 4 }, 300);
    try cache.putPositive("c.evict.zone.", .a, .in, &[_]u8{ 5, 6, 7, 8 }, 300);

    // The first entry (with zone_name) should have been evicted.
    // Testing allocator will catch any leak.
}

test "DnsCache zone_name freed on expired removal" {
    // Regression test for PF-12: zone_name freed when expired entries are removed via get().
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();

    var cache = DnsCache.init(allocator, .{}, mock_clock.clock());
    defer cache.deinit();

    const zone = try allocator.dupe(u8, "expired.zone.");
    const key = try cache.makeKey("old.expired.zone.", .a, .in);
    defer allocator.free(key);

    try cache.entries.put(key, CacheEntry{
        .entry_type = .nxdomain,
        .rdata = &[_]u8{},
        .cached_at = mock_clock.clock().now(),
        .original_ttl = 10,
        .zone_name = zone,
    });

    // Advance time past TTL
    mock_clock.advance(11);

    // get() removes expired entries -- zone_name must be freed
    const result = cache.get("old.expired.zone.", .a, .in);
    try std.testing.expect(result == null);
}

test "DnsCache makeKey uses stack buffer for lowercase" {
    // Regression test for PF-15: makeKey must use a stack buffer for lowercase
    // conversion instead of a heap allocation + free. Verified by code review:
    // the implementation uses a [max_name_length]u8 stack buffer.
    // Here we verify correctness of the key format and case-insensitivity.
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();

    var cache = DnsCache.init(allocator, .{}, mock_clock.clock());
    defer cache.deinit();

    // Verify the key value is correct and lowercase
    const key = try cache.makeKey("Example.COM.", .a, .in);
    defer allocator.free(key);
    try std.testing.expect(std.mem.startsWith(u8, key, "example.com.:"));

    // Verify with max-length name (255 bytes)
    var max_name: [255]u8 = undefined;
    @memset(&max_name, 'A');
    const max_key = try cache.makeKey(&max_name, .a, .in);
    defer allocator.free(max_key);

    // Should be all lowercase
    var expected_lower: [255]u8 = undefined;
    @memset(&expected_lower, 'a');
    try std.testing.expect(std.mem.startsWith(u8, max_key, &expected_lower));
}

test "DnsCache makeKey case insensitive" {
    // Verify case-insensitive key generation still works after PF-15 optimization.
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();

    var cache = DnsCache.init(allocator, .{}, mock_clock.clock());
    defer cache.deinit();

    const key1 = try cache.makeKey("Example.COM.", .a, .in);
    defer allocator.free(key1);

    const key2 = try cache.makeKey("example.com.", .a, .in);
    defer allocator.free(key2);

    const key3 = try cache.makeKey("EXAMPLE.COM.", .a, .in);
    defer allocator.free(key3);

    try std.testing.expectEqualStrings(key1, key2);
    try std.testing.expectEqualStrings(key2, key3);
}

test "DnsCache get uses stack buffer (PF-21)" {
    // Verify that get() produces the same results as the heap-allocated
    // makeKey path by exercising various name lengths and case mixtures.
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();

    var cache = DnsCache.init(allocator, .{}, mock_clock.clock());
    defer cache.deinit();

    // Insert with various cases, retrieve with different cases
    try cache.putPositive("Mixed.CASE.Example.COM.", .a, .in, &[_]u8{ 10, 20, 30, 40 }, 300);

    // get() should find the entry regardless of case (stack-buffered path)
    const entry1 = cache.get("mixed.case.example.com.", .a, .in);
    try std.testing.expect(entry1 != null);
    try std.testing.expectEqual(EntryType.positive, entry1.?.entry_type);

    const entry2 = cache.get("MIXED.CASE.EXAMPLE.COM.", .a, .in);
    try std.testing.expect(entry2 != null);

    // Different type should not match
    try std.testing.expect(cache.get("mixed.case.example.com.", .aaaa, .in) == null);
}

test "DnsCache makeKeyBuf matches makeKey output" {
    // Verify makeKeyBuf produces identical output to makeKey.
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();

    var cache = DnsCache.init(allocator, .{}, mock_clock.clock());
    defer cache.deinit();

    const test_names = [_][]const u8{
        "example.com.",
        "UPPER.CASE.",
        "MiXeD.cAsE.123.",
        "a.",
    };

    for (test_names) |name| {
        const heap_key = try cache.makeKey(name, .a, .in);
        defer allocator.free(heap_key);

        var buf: [DnsCache.max_key_len]u8 = undefined;
        const stack_key = cache.makeKeyBuf(name, .a, .in, &buf);
        try std.testing.expect(stack_key != null);
        try std.testing.expectEqualStrings(heap_key, stack_key.?);
    }
}

test "DnsCache isUnderNxdomainZone stack buffer (PF-25)" {
    // Verify isUnderNxdomainZone works correctly with the stack-buffered
    // zone key path instead of the heap-allocating path.
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();

    var cache = DnsCache.init(allocator, .{}, mock_clock.clock());
    defer cache.deinit();

    // Manually insert an NXDOMAIN zone entry for "example.com."
    const zone = try allocator.dupe(u8, "example.com.");
    const zone_key = try cache.makeNxdomainZoneKey("example.com.");
    defer allocator.free(zone_key);

    try cache.entries.put(zone_key, CacheEntry{
        .entry_type = .nxdomain,
        .rdata = &[_]u8{},
        .cached_at = mock_clock.clock().now(),
        .original_ttl = 300,
        .zone_name = zone,
    });

    // Subdomains should be detected as under the NXDOMAIN zone
    try std.testing.expect(cache.isUnderNxdomainZone("foo.example.com."));
    try std.testing.expect(cache.isUnderNxdomainZone("bar.baz.example.com."));

    // Unrelated zone should not match
    try std.testing.expect(!cache.isUnderNxdomainZone("other.net."));
}

test "DnsCache expired removal uses removeByHandle (PF-26)" {
    // Verify that expired entries are correctly removed via the
    // handle-based path (no re-hash).  The testing allocator will
    // detect any leaked memory from zone_name or rdata.
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();

    var cache = DnsCache.init(allocator, .{}, mock_clock.clock());
    defer cache.deinit();

    // Insert an entry with allocated rdata that will expire
    try cache.putPositive("expire-me.test.", .a, .in, &[_]u8{ 1, 2, 3, 4 }, 5);

    // Should be present initially
    try std.testing.expect(cache.get("expire-me.test.", .a, .in) != null);

    // Advance past expiry
    mock_clock.advance(6);

    // get() should return null and remove the expired entry
    try std.testing.expect(cache.get("expire-me.test.", .a, .in) == null);

    // Entry should be gone from the cache
    try std.testing.expectEqual(@as(usize, 0), cache.len());
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

test "DnsCache putRecord packs multiple records" {
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();

    var cache = DnsCache.init(allocator, .{}, mock_clock.clock());
    defer cache.deinit();

    // Put two A records for the same domain
    try cache.putRecord("example.com.", .a, .in, &[_]u8{ 1, 2, 3, 4 }, 300);
    try cache.putRecord("example.com.", .a, .in, &[_]u8{ 5, 6, 7, 8 }, 300);

    const entry = cache.get("example.com.", .a, .in).?;
    try std.testing.expectEqual(EntryType.positive, entry.entry_type);

    // Iterate packed segments
    var iter = PackedRdataIterator.init(entry.rdata);
    const first = iter.next().?;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, first);
    const second = iter.next().?;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 5, 6, 7, 8 }, second);
    try std.testing.expect(iter.next() == null);
}

test "PackedRdataIterator empty and single" {
    // Empty data
    var empty_iter = PackedRdataIterator.init(&[_]u8{});
    try std.testing.expect(empty_iter.next() == null);

    // Single segment: [0x00, 0x02, 0xAA, 0xBB]
    var single_iter = PackedRdataIterator.init(&[_]u8{ 0x00, 0x02, 0xAA, 0xBB });
    const seg = single_iter.next().?;
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xAA, 0xBB }, seg);
    try std.testing.expect(single_iter.next() == null);
}
