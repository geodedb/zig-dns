// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DNS Response Cache
//!
//! RFC 1035 Section 7.4: Using the cache
//!
//! Implements TTL-based caching for DNS responses to reduce
//! network traffic and improve resolution latency.

const std = @import("std");
const name_mod = @import("name");
const types_mod = @import("types");
const record_mod = @import("record");
const cache_protection = @import("cache_protection");

pub const Name = name_mod.Name;
pub const Type = types_mod.Type;
pub const Class = types_mod.Class;
pub const ResourceRecord = record_mod.ResourceRecord;
pub const CacheProtectionConfig = cache_protection.CacheProtectionConfig;

/// Cache configuration
pub const CacheConfig = struct {
    max_entries: usize,
    protection: CacheProtectionConfig = .{},
};

/// Cache entry for a DNS record
pub const CacheEntry = struct {
    /// Domain name (owned by cache)
    name: []const u8,

    /// Record type
    rtype: Type,

    /// Record class
    class: Class,

    /// Cached RDATA (owned by cache)
    rdata: []const u8,

    /// Original TTL from the record
    original_ttl: u32,

    /// Timestamp when this entry was cached (in seconds since epoch)
    cached_at: i64,

    const Self = @This();

    /// Check if this entry has expired
    pub inline fn isExpired(self: Self, now: i64) bool {
        const age = now - self.cached_at;
        return age < 0 or age >= self.original_ttl;
    }

    /// Get remaining TTL
    pub inline fn remainingTtl(self: Self, now: i64) u32 {
        const age = now - self.cached_at;
        if (age < 0 or age >= self.original_ttl) {
            return 0;
        }
        return self.original_ttl - @as(u32, @intCast(age));
    }
};

/// DNS Response Cache - Simple array-based implementation
pub const Cache = struct {
    allocator: std.mem.Allocator,
    entries: []CacheEntry,
    count: usize,
    max_entries: usize,
    protection: CacheProtectionConfig,

    const Self = @This();

    /// Create a new cache with the given maximum number of entries
    pub fn init(allocator: std.mem.Allocator, max_entries: usize) Self {
        return initWithConfig(allocator, .{ .max_entries = max_entries });
    }

    /// Create a new cache with custom configuration
    pub fn initWithConfig(allocator: std.mem.Allocator, config: CacheConfig) Self {
        return Self{
            .allocator = allocator,
            .entries = &[_]CacheEntry{},
            .count = 0,
            .max_entries = config.max_entries,
            .protection = config.protection,
        };
    }

    /// Free all cache resources
    pub fn deinit(self: *Self) void {
        for (self.entries[0..self.count]) |entry| {
            self.allocator.free(entry.name);
            self.allocator.free(entry.rdata);
        }
        if (self.entries.len > 0) {
            self.allocator.free(self.entries);
        }
    }

    /// Add a record to the cache
    pub fn put(self: *Self, domain: []const u8, rr: ResourceRecord) !void {
        // Don't cache records with TTL of 0
        if (rr.ttl == 0) {
            return;
        }

        const clamped_ttl = cache_protection.clampTtl(rr.ttl, self.protection, false);
        if (clamped_ttl == 0) {
            return;
        }

        const now = std.time.timestamp();

        // Check if we need to evict entries
        if (self.count >= self.max_entries) {
            self.evictExpired(now);
        }

        // Still full? Evict oldest
        if (self.count >= self.max_entries and self.count > 0) {
            self.evictOldest();
        }

        // Grow entries array if needed
        if (self.count >= self.entries.len) {
            const new_cap = if (self.entries.len == 0) 16 else self.entries.len * 2;
            const capped = @min(new_cap, self.max_entries);
            const new_entries = try self.allocator.alloc(CacheEntry, capped);
            if (self.entries.len > 0) {
                @memcpy(new_entries[0..self.count], self.entries[0..self.count]);
                self.allocator.free(self.entries);
            }
            self.entries = new_entries;
        }

        const name_copy = try self.allocator.dupe(u8, domain);
        errdefer self.allocator.free(name_copy);

        const rdata_copy = try self.allocator.dupe(u8, rr.rdata);
        errdefer self.allocator.free(rdata_copy);

        self.entries[self.count] = CacheEntry{
            .name = name_copy,
            .rtype = rr.rtype,
            .class = rr.class,
            .rdata = rdata_copy,
            .original_ttl = clamped_ttl,
            .cached_at = now,
        };
        self.count += 1;
    }

    /// Add a record to the cache with bailiwick validation
    pub fn putWithBailiwick(self: *Self, domain: []const u8, rr: ResourceRecord, query_zone: []const u8) !void {
        if (cache_protection.checkBailiwick(domain, query_zone) == .out_of_bailiwick) {
            return;
        }
        try self.put(domain, rr);
    }

    /// Get cached records for a domain and type.
    /// Compacts matching entries so the returned slice is contiguous and
    /// contains only records that match (domain, rtype, class) and are
    /// not expired. Returns null if no matching records exist.
    pub fn get(self: *Self, domain: []const u8, rtype: Type, class: Class) ?[]const CacheEntry {
        const now = std.time.timestamp();

        // Compact matching entries to the front of a contiguous run.
        // We swap each matching entry forward so all matches are adjacent.
        var match_count: usize = 0;
        var first_match: ?usize = null;

        for (0..self.count) |i| {
            const entry = self.entries[i];
            if (entry.rtype == rtype and entry.class == class and
                std.ascii.eqlIgnoreCase(entry.name, domain) and
                !entry.isExpired(now))
            {
                if (first_match == null) {
                    first_match = i;
                }
                const target = first_match.? + match_count;
                if (i != target) {
                    // Swap so matching entries are contiguous
                    const tmp = self.entries[target];
                    self.entries[target] = self.entries[i];
                    self.entries[i] = tmp;
                }
                match_count += 1;
            }
        }

        if (first_match) |s| {
            return self.entries[s .. s + match_count];
        }

        return null;
    }

    /// Remove expired entries from the cache
    pub fn evictExpired(self: *Self, now: i64) void {
        var write_idx: usize = 0;
        for (self.entries[0..self.count]) |entry| {
            if (!entry.isExpired(now)) {
                self.entries[write_idx] = entry;
                write_idx += 1;
            } else {
                self.allocator.free(entry.name);
                self.allocator.free(entry.rdata);
            }
        }
        self.count = write_idx;
    }

    /// Evict the oldest entry
    fn evictOldest(self: *Self) void {
        if (self.count == 0) return;

        var oldest_idx: usize = 0;
        var oldest_time: i64 = self.entries[0].cached_at;

        for (self.entries[1..self.count], 1..) |entry, i| {
            if (entry.cached_at < oldest_time) {
                oldest_time = entry.cached_at;
                oldest_idx = i;
            }
        }

        // Free the oldest entry
        self.allocator.free(self.entries[oldest_idx].name);
        self.allocator.free(self.entries[oldest_idx].rdata);

        // Move last entry to fill the gap
        if (oldest_idx < self.count - 1) {
            self.entries[oldest_idx] = self.entries[self.count - 1];
        }
        self.count -= 1;
    }

    /// Clear all entries from the cache
    pub fn clear(self: *Self) void {
        for (self.entries[0..self.count]) |entry| {
            self.allocator.free(entry.name);
            self.allocator.free(entry.rdata);
        }
        self.count = 0;
    }
};

test "Cache basic operations" {
    const allocator = std.testing.allocator;
    var cache = Cache.init(allocator, 1000);
    defer cache.deinit();

    // Create a mock resource record
    const rdata = [_]u8{ 93, 184, 216, 34 };
    const rr = ResourceRecord{
        .name = undefined,
        .rtype = .a,
        .class = .in,
        .ttl = 300,
        .rdlength = 4,
        .rdata = &rdata,
        .wire_length = 0,
    };

    try cache.put("example.com", rr);
    try std.testing.expectEqual(@as(usize, 1), cache.count);

    const entries = cache.get("example.com", .a, .in);
    try std.testing.expect(entries != null);
    try std.testing.expectEqualSlices(u8, &rdata, entries.?[0].rdata);
}

test "Cache case insensitive lookup" {
    const allocator = std.testing.allocator;
    var cache = Cache.init(allocator, 1000);
    defer cache.deinit();

    const rdata = [_]u8{ 93, 184, 216, 34 };
    const rr = ResourceRecord{
        .name = undefined,
        .rtype = .a,
        .class = .in,
        .ttl = 300,
        .rdlength = 4,
        .rdata = &rdata,
        .wire_length = 0,
    };

    try cache.put("Example.COM", rr);

    // Should find with different case
    const entries = cache.get("example.com", .a, .in);
    try std.testing.expect(entries != null);
}

test "Cache clear" {
    const allocator = std.testing.allocator;
    var cache = Cache.init(allocator, 1000);
    defer cache.deinit();

    const rdata = [_]u8{ 93, 184, 216, 34 };
    const rr = ResourceRecord{
        .name = undefined,
        .rtype = .a,
        .class = .in,
        .ttl = 300,
        .rdlength = 4,
        .rdata = &rdata,
        .wire_length = 0,
    };

    try cache.put("example.com", rr);
    try std.testing.expectEqual(@as(usize, 1), cache.count);

    cache.clear();
    try std.testing.expectEqual(@as(usize, 0), cache.count);
}

test "Cache TTL clamping" {
    const allocator = std.testing.allocator;
    var cache = Cache.initWithConfig(allocator, .{
        .max_entries = 10,
        .protection = .{
            .max_positive_ttl_s = 60,
            .min_ttl_s = 0,
        },
    });
    defer cache.deinit();

    const rdata = [_]u8{ 1, 2, 3, 4 };
    const rr = ResourceRecord{
        .name = undefined,
        .rtype = .a,
        .class = .in,
        .ttl = 3600,
        .rdlength = 4,
        .rdata = &rdata,
        .wire_length = 0,
    };

    try cache.put("example.com", rr);
    const entries_opt = cache.get("example.com", .a, .in);
    try std.testing.expect(entries_opt != null);
    try std.testing.expectEqual(@as(u32, 60), entries_opt.?[0].original_ttl);
}

test "Cache bailiwick validation" {
    const allocator = std.testing.allocator;
    var cache = Cache.init(allocator, 10);
    defer cache.deinit();

    const rdata = [_]u8{ 5, 6, 7, 8 };
    const rr = ResourceRecord{
        .name = undefined,
        .rtype = .a,
        .class = .in,
        .ttl = 300,
        .rdlength = 4,
        .rdata = &rdata,
        .wire_length = 0,
    };

    try cache.putWithBailiwick("evil.com", rr, "example.com");
    try std.testing.expect(cache.get("evil.com", .a, .in) == null);

    try cache.putWithBailiwick("www.example.com", rr, "example.com");
    try std.testing.expect(cache.get("www.example.com", .a, .in) != null);
}

test "Cache get returns only matching entries (non-contiguous fix)" {
    // Regression test for PF-02b: Cache.get used to return entries[start..end]
    // which could include unrelated records between the first and last match.
    const allocator = std.testing.allocator;
    var cache = Cache.init(allocator, 100);
    defer cache.deinit();

    const rdata_a = [_]u8{ 1, 2, 3, 4 };
    const rdata_b = [_]u8{ 5, 6, 7, 8 };
    const rdata_c = [_]u8{ 9, 10, 11, 12 };

    // Insert: example.com A, other.com A, example.com A
    // This creates a non-contiguous pattern for "example.com A"
    const rr_a = ResourceRecord{
        .name = undefined,
        .rtype = .a,
        .class = .in,
        .ttl = 300,
        .rdlength = 4,
        .rdata = &rdata_a,
        .wire_length = 0,
    };
    const rr_b = ResourceRecord{
        .name = undefined,
        .rtype = .a,
        .class = .in,
        .ttl = 300,
        .rdlength = 4,
        .rdata = &rdata_b,
        .wire_length = 0,
    };
    const rr_c = ResourceRecord{
        .name = undefined,
        .rtype = .a,
        .class = .in,
        .ttl = 300,
        .rdlength = 4,
        .rdata = &rdata_c,
        .wire_length = 0,
    };

    try cache.put("example.com", rr_a); // index 0: match
    try cache.put("other.com", rr_b); // index 1: non-match
    try cache.put("example.com", rr_c); // index 2: match

    const entries = cache.get("example.com", .a, .in);
    try std.testing.expect(entries != null);

    // The returned slice must contain exactly 2 entries, both for example.com.
    // Before the fix, entries[start..end] would be entries[0..3] which
    // included the "other.com" record in the middle.
    try std.testing.expectEqual(@as(usize, 2), entries.?.len);

    // Verify every entry in the slice actually matches
    for (entries.?) |entry| {
        try std.testing.expect(std.ascii.eqlIgnoreCase(entry.name, "example.com"));
        try std.testing.expectEqual(Type.a, entry.rtype);
        try std.testing.expectEqual(Class.in, entry.class);
    }
}

test "Cache get with interleaved types returns only requested type" {
    const allocator = std.testing.allocator;
    var cache = Cache.init(allocator, 100);
    defer cache.deinit();

    const rdata_v4 = [_]u8{ 1, 2, 3, 4 };
    const rdata_v6 = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };

    const rr_a = ResourceRecord{
        .name = undefined,
        .rtype = .a,
        .class = .in,
        .ttl = 300,
        .rdlength = 4,
        .rdata = &rdata_v4,
        .wire_length = 0,
    };
    const rr_aaaa = ResourceRecord{
        .name = undefined,
        .rtype = .aaaa,
        .class = .in,
        .ttl = 300,
        .rdlength = 16,
        .rdata = &rdata_v6,
        .wire_length = 0,
    };

    // Interleave A and AAAA records for same domain
    try cache.put("example.com", rr_a);
    try cache.put("example.com", rr_aaaa);
    try cache.put("example.com", rr_a);

    // Query for A records only
    const a_entries = cache.get("example.com", .a, .in);
    try std.testing.expect(a_entries != null);
    try std.testing.expectEqual(@as(usize, 2), a_entries.?.len);

    // Every returned entry must be an A record
    for (a_entries.?) |entry| {
        try std.testing.expectEqual(Type.a, entry.rtype);
    }

    // Query for AAAA records only
    const aaaa_entries = cache.get("example.com", .aaaa, .in);
    try std.testing.expect(aaaa_entries != null);
    try std.testing.expectEqual(@as(usize, 1), aaaa_entries.?.len);
    try std.testing.expectEqual(Type.aaaa, aaaa_entries.?[0].rtype);
}
