// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DNS Cache Prefetching
//!
//! Proactive cache refresh to improve response latency by refreshing
//! cached records before they expire.
//!
//! When a cached record's TTL falls below a configurable threshold
//! (typically 10% of original TTL), the resolver can trigger a
//! background refresh to update the cache before expiration.

const std = @import("std");
const types = @import("types");
const dns_cache = @import("dns_cache");
const clock_mod = @import("clock");

pub const Type = types.Type;
pub const Class = types.Class;
pub const DnsCache = dns_cache.DnsCache;
pub const CacheEntry = dns_cache.CacheEntry;
pub const Clock = clock_mod.Clock;

/// Prefetch configuration options
pub const PrefetchOptions = struct {
    /// Enable prefetching
    enabled: bool = true,
    /// Prefetch threshold as percentage of original TTL (0-100)
    /// Default: 10% (prefetch when TTL drops below 10% of original)
    threshold_percent: u8 = 10,
    /// Minimum remaining TTL to trigger prefetch (seconds)
    /// Avoids prefetching for very short TTLs
    min_remaining_ttl: u32 = 5,
    /// Maximum number of pending prefetch requests
    max_pending: usize = 1024,
    /// Minimum original TTL for prefetch eligibility
    /// Records with shorter TTLs are not prefetched
    min_original_ttl: u32 = 30,
};

/// Prefetch request representing a cache entry that needs refreshing
pub const PrefetchRequest = struct {
    /// Queried name
    name: []const u8,
    /// Query type
    qtype: Type,
    /// Query class
    qclass: Class,
    /// Timestamp when request was created
    created_at: i64,
};

/// Cache prefetch manager
///
/// Tracks which entries need refreshing and provides a queue
/// of prefetch requests for the resolver to process.
pub const CachePrefetcher = struct {
    allocator: std.mem.Allocator,
    options: PrefetchOptions,
    clock: Clock,

    /// Pending prefetch requests
    pending: std.StringHashMap(PrefetchRequest),

    /// Set of keys currently being prefetched (to avoid duplicates)
    in_flight: std.StringHashMap(void),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, options: PrefetchOptions, clk: Clock) Self {
        return Self{
            .allocator = allocator,
            .options = options,
            .clock = clk,
            .pending = std.StringHashMap(PrefetchRequest).init(allocator),
            .in_flight = std.StringHashMap(void).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        // Free all pending request names and keys
        var pending_it = self.pending.iterator();
        while (pending_it.next()) |kv| {
            self.allocator.free(kv.value_ptr.name);
            self.allocator.free(kv.key_ptr.*);
        }
        self.pending.deinit();

        // Free in_flight keys
        var flight_it = self.in_flight.iterator();
        while (flight_it.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
        }
        self.in_flight.deinit();
    }

    /// Check if a cache entry needs prefetching
    ///
    /// Returns true if:
    /// - Prefetching is enabled
    /// - Entry is not expired
    /// - Remaining TTL is below threshold percentage
    /// - Original TTL meets minimum requirement
    /// - Entry is not already being prefetched
    pub fn needsPrefetch(self: *Self, entry: CacheEntry, name: []const u8, qtype: Type, qclass: Class) bool {
        if (!self.options.enabled) return false;

        // Only prefetch positive entries
        if (entry.entry_type != .positive) return false;

        // Check minimum original TTL
        if (entry.original_ttl < self.options.min_original_ttl) return false;

        const now = self.clock.now();
        const remaining = entry.remainingTtl(now);

        // Don't prefetch if already expired or below minimum
        if (remaining < self.options.min_remaining_ttl) return false;

        // Calculate threshold
        const threshold = (entry.original_ttl * self.options.threshold_percent) / 100;

        // Check if remaining TTL is below threshold
        if (remaining >= threshold) return false;

        // Check if already in flight
        const key = self.makeKey(name, qtype, qclass) catch return false;
        defer self.allocator.free(key);

        if (self.in_flight.contains(key)) return false;
        if (self.pending.contains(key)) return false;

        return true;
    }

    /// Schedule a prefetch request
    ///
    /// Adds the entry to the pending queue if not already scheduled.
    /// Returns true if added, false if already pending or queue is full.
    pub fn schedulePrefetch(self: *Self, name: []const u8, qtype: Type, qclass: Class) !bool {
        if (!self.options.enabled) return false;

        // Check queue limit
        if (self.pending.count() >= self.options.max_pending) return false;

        const key = try self.makeKey(name, qtype, qclass);
        errdefer self.allocator.free(key);

        // Already scheduled?
        if (self.pending.contains(key)) {
            self.allocator.free(key);
            return false;
        }

        // Already in flight?
        if (self.in_flight.contains(key)) {
            self.allocator.free(key);
            return false;
        }

        const name_copy = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(name_copy);

        try self.pending.put(key, PrefetchRequest{
            .name = name_copy,
            .qtype = qtype,
            .qclass = qclass,
            .created_at = self.clock.now(),
        });

        return true;
    }

    /// Get the next prefetch request from the queue
    ///
    /// Returns null if queue is empty.
    /// The caller is responsible for calling `completePrefetch` when done.
    pub fn nextPrefetch(self: *Self) ?PrefetchRequest {
        var it = self.pending.iterator();
        if (it.next()) |kv| {
            const key = kv.key_ptr.*;
            const request = kv.value_ptr.*;

            // Move to in_flight
            const key_copy = self.allocator.dupe(u8, key) catch return null;
            self.in_flight.put(key_copy, {}) catch {
                self.allocator.free(key_copy);
                return null;
            };

            // Remove from pending (don't free key yet - it's in in_flight)
            _ = self.pending.remove(key);
            self.allocator.free(key);

            return request;
        }
        return null;
    }

    /// Mark a prefetch as complete
    ///
    /// Removes the entry from the in_flight set.
    /// The name memory is freed.
    pub fn completePrefetch(self: *Self, name: []const u8, qtype: Type, qclass: Class) void {
        const key = self.makeKey(name, qtype, qclass) catch return;
        defer self.allocator.free(key);

        if (self.in_flight.fetchRemove(key)) |kv| {
            self.allocator.free(kv.key);
        }

        // Free the name that was allocated in schedulePrefetch
        self.allocator.free(name);
    }

    /// Cancel a pending prefetch request
    pub fn cancelPrefetch(self: *Self, name: []const u8, qtype: Type, qclass: Class) void {
        const key = self.makeKey(name, qtype, qclass) catch return;
        defer self.allocator.free(key);

        if (self.pending.fetchRemove(key)) |kv| {
            self.allocator.free(kv.value.name);
            self.allocator.free(kv.key);
        }
    }

    /// Get number of pending prefetch requests
    pub fn pendingCount(self: *Self) usize {
        return self.pending.count();
    }

    /// Get number of in-flight prefetch requests
    pub fn inFlightCount(self: *Self) usize {
        return self.in_flight.count();
    }

    /// Clear all pending and in-flight requests
    pub fn clear(self: *Self) void {
        // Free pending
        var pending_it = self.pending.iterator();
        while (pending_it.next()) |kv| {
            self.allocator.free(kv.value_ptr.name);
            self.allocator.free(kv.key_ptr.*);
        }
        self.pending.clearRetainingCapacity();

        // Free in_flight
        var flight_it = self.in_flight.iterator();
        while (flight_it.next()) |kv| {
            self.allocator.free(kv.key_ptr.*);
        }
        self.in_flight.clearRetainingCapacity();
    }

    /// Check if a key is in the prefetch queue or in flight
    pub fn isPending(self: *Self, name: []const u8, qtype: Type, qclass: Class) bool {
        const key = self.makeKey(name, qtype, qclass) catch return false;
        defer self.allocator.free(key);
        return self.pending.contains(key) or self.in_flight.contains(key);
    }

    fn makeKey(self: *Self, name: []const u8, qtype: Type, qclass: Class) ![]u8 {
        // Lowercase for case-insensitive matching
        const lower = try self.allocator.alloc(u8, name.len);
        defer self.allocator.free(lower);
        for (name, 0..) |c, i| {
            lower[i] = std.ascii.toLower(c);
        }

        return std.fmt.allocPrint(self.allocator, "PF:{s}:{d}:{d}", .{
            lower,
            @intFromEnum(qtype),
            @intFromEnum(qclass),
        });
    }
};

/// Helper to check cache entry and schedule prefetch if needed
///
/// Call this after getting a cache hit. If the entry needs prefetching,
/// it will be added to the prefetch queue.
pub fn checkAndSchedulePrefetch(
    prefetcher: *CachePrefetcher,
    entry: CacheEntry,
    name: []const u8,
    qtype: Type,
    qclass: Class,
) void {
    if (prefetcher.needsPrefetch(entry, name, qtype, qclass)) {
        _ = prefetcher.schedulePrefetch(name, qtype, qclass) catch {};
    }
}

// ============================================================================
// Tests
// ============================================================================

test "CachePrefetcher init/deinit" {
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();

    var prefetcher = CachePrefetcher.init(allocator, .{}, mock_clock.clock());
    defer prefetcher.deinit();

    try std.testing.expectEqual(@as(usize, 0), prefetcher.pendingCount());
    try std.testing.expectEqual(@as(usize, 0), prefetcher.inFlightCount());
}

test "CachePrefetcher needsPrefetch" {
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();
    const start_time = mock_clock.clock().now();

    var prefetcher = CachePrefetcher.init(allocator, .{
        .threshold_percent = 10,
        .min_original_ttl = 30,
    }, mock_clock.clock());
    defer prefetcher.deinit();

    // Entry with 100s TTL, just cached at current time
    const entry = CacheEntry{
        .entry_type = .positive,
        .rdata = &[_]u8{},
        .cached_at = start_time,
        .original_ttl = 100,
    };

    // At start, remaining TTL is 100s (100%), should not prefetch
    try std.testing.expect(!prefetcher.needsPrefetch(entry, "example.com.", .a, .in));

    // After 85s, remaining TTL is 15s (15%), still above 10%
    mock_clock.advance(85);
    try std.testing.expect(!prefetcher.needsPrefetch(entry, "example.com.", .a, .in));

    // After 92s total, remaining TTL is 8s (8%), below 10%, should prefetch
    mock_clock.advance(7);
    try std.testing.expect(prefetcher.needsPrefetch(entry, "example.com.", .a, .in));
}

test "CachePrefetcher schedulePrefetch" {
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();

    var prefetcher = CachePrefetcher.init(allocator, .{}, mock_clock.clock());
    defer prefetcher.deinit();

    // Schedule a prefetch
    const scheduled = try prefetcher.schedulePrefetch("example.com.", .a, .in);
    try std.testing.expect(scheduled);
    try std.testing.expectEqual(@as(usize, 1), prefetcher.pendingCount());

    // Try to schedule same again - should return false
    const duplicate = try prefetcher.schedulePrefetch("example.com.", .a, .in);
    try std.testing.expect(!duplicate);
    try std.testing.expectEqual(@as(usize, 1), prefetcher.pendingCount());
}

test "CachePrefetcher nextPrefetch" {
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();

    var prefetcher = CachePrefetcher.init(allocator, .{}, mock_clock.clock());
    defer prefetcher.deinit();

    // Schedule a prefetch
    _ = try prefetcher.schedulePrefetch("example.com.", .a, .in);

    // Get it
    const request = prefetcher.nextPrefetch();
    try std.testing.expect(request != null);
    try std.testing.expectEqualStrings("example.com.", request.?.name);
    try std.testing.expectEqual(Type.a, request.?.qtype);

    // Should be in flight now
    try std.testing.expectEqual(@as(usize, 0), prefetcher.pendingCount());
    try std.testing.expectEqual(@as(usize, 1), prefetcher.inFlightCount());

    // Complete it
    prefetcher.completePrefetch(request.?.name, request.?.qtype, request.?.qclass);
    try std.testing.expectEqual(@as(usize, 0), prefetcher.inFlightCount());
}

test "CachePrefetcher queue limit" {
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();

    var prefetcher = CachePrefetcher.init(allocator, .{
        .max_pending = 2,
    }, mock_clock.clock());
    defer prefetcher.deinit();

    // Schedule up to limit
    _ = try prefetcher.schedulePrefetch("a.com.", .a, .in);
    _ = try prefetcher.schedulePrefetch("b.com.", .a, .in);
    try std.testing.expectEqual(@as(usize, 2), prefetcher.pendingCount());

    // Third should fail
    const third = try prefetcher.schedulePrefetch("c.com.", .a, .in);
    try std.testing.expect(!third);
    try std.testing.expectEqual(@as(usize, 2), prefetcher.pendingCount());
}

test "CachePrefetcher disabled" {
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();

    var prefetcher = CachePrefetcher.init(allocator, .{
        .enabled = false,
    }, mock_clock.clock());
    defer prefetcher.deinit();

    // Should not schedule when disabled
    const scheduled = try prefetcher.schedulePrefetch("example.com.", .a, .in);
    try std.testing.expect(!scheduled);
}

test "CachePrefetcher negative entries not prefetched" {
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();
    const start_time = mock_clock.clock().now();

    var prefetcher = CachePrefetcher.init(allocator, .{
        .threshold_percent = 10,
        .min_original_ttl = 30,
    }, mock_clock.clock());
    defer prefetcher.deinit();

    // NXDOMAIN entry
    const entry = CacheEntry{
        .entry_type = .nxdomain,
        .rdata = &[_]u8{},
        .cached_at = start_time,
        .original_ttl = 100,
    };

    // Advance time to trigger prefetch threshold
    mock_clock.advance(95);

    // Should not prefetch negative entries
    try std.testing.expect(!prefetcher.needsPrefetch(entry, "nonexistent.com.", .a, .in));
}

test "CachePrefetcher short TTL not prefetched" {
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();
    const start_time = mock_clock.clock().now();

    var prefetcher = CachePrefetcher.init(allocator, .{
        .threshold_percent = 10,
        .min_original_ttl = 30,
    }, mock_clock.clock());
    defer prefetcher.deinit();

    // Entry with 20s TTL (below min_original_ttl of 30)
    const entry = CacheEntry{
        .entry_type = .positive,
        .rdata = &[_]u8{},
        .cached_at = start_time,
        .original_ttl = 20,
    };

    // Even at 2s remaining (10%), should not prefetch
    mock_clock.advance(18);
    try std.testing.expect(!prefetcher.needsPrefetch(entry, "short.com.", .a, .in));
}

test "checkAndSchedulePrefetch" {
    const allocator = std.testing.allocator;
    var mock_clock = clock_mod.MockClock.init();
    const start_time = mock_clock.clock().now();

    var prefetcher = CachePrefetcher.init(allocator, .{
        .threshold_percent = 10,
        .min_original_ttl = 30,
    }, mock_clock.clock());
    defer prefetcher.deinit();

    const entry = CacheEntry{
        .entry_type = .positive,
        .rdata = &[_]u8{},
        .cached_at = start_time,
        .original_ttl = 100,
    };

    // After 92s, remaining TTL is 8s (8%), should schedule prefetch
    mock_clock.advance(92);

    checkAndSchedulePrefetch(&prefetcher, entry, "example.com.", .a, .in);
    try std.testing.expectEqual(@as(usize, 1), prefetcher.pendingCount());
}
