// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Prometheus-style Metrics
//!
//! Provides counters for DNS resolver monitoring.

const std = @import("std");

/// Metrics snapshot
pub const MetricsSnapshot = struct {
    queries_total: u64,
    cache_hits_total: u64,
    cache_misses_total: u64,
    tcp_fallback_total: u64,
    timeouts_total: u64,
    servfail_total: u64,
    nxdomain_total: u64,
    formerr_total: u64,
    edns_retries_total: u64,

    /// Render as Prometheus text format
    pub fn render(self: MetricsSnapshot, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator,
            \\zigdns_queries_total {d}
            \\zigdns_cache_hits_total {d}
            \\zigdns_cache_misses_total {d}
            \\zigdns_tcp_fallback_total {d}
            \\zigdns_timeouts_total {d}
            \\zigdns_servfail_total {d}
            \\zigdns_nxdomain_total {d}
            \\zigdns_formerr_total {d}
            \\zigdns_edns_retries_total {d}
            \\
        , .{
            self.queries_total,
            self.cache_hits_total,
            self.cache_misses_total,
            self.tcp_fallback_total,
            self.timeouts_total,
            self.servfail_total,
            self.nxdomain_total,
            self.formerr_total,
            self.edns_retries_total,
        });
    }
};

/// Thread-safe metrics collector
pub const Metrics = struct {
    queries_total: std.atomic.Value(u64),
    cache_hits_total: std.atomic.Value(u64),
    cache_misses_total: std.atomic.Value(u64),
    tcp_fallback_total: std.atomic.Value(u64),
    timeouts_total: std.atomic.Value(u64),
    servfail_total: std.atomic.Value(u64),
    nxdomain_total: std.atomic.Value(u64),
    formerr_total: std.atomic.Value(u64),
    edns_retries_total: std.atomic.Value(u64),

    const Self = @This();

    pub fn init() Self {
        return Self{
            .queries_total = std.atomic.Value(u64).init(0),
            .cache_hits_total = std.atomic.Value(u64).init(0),
            .cache_misses_total = std.atomic.Value(u64).init(0),
            .tcp_fallback_total = std.atomic.Value(u64).init(0),
            .timeouts_total = std.atomic.Value(u64).init(0),
            .servfail_total = std.atomic.Value(u64).init(0),
            .nxdomain_total = std.atomic.Value(u64).init(0),
            .formerr_total = std.atomic.Value(u64).init(0),
            .edns_retries_total = std.atomic.Value(u64).init(0),
        };
    }

    pub fn incQueries(self: *Self) void {
        _ = self.queries_total.fetchAdd(1, .monotonic);
    }

    pub fn incCacheHits(self: *Self) void {
        _ = self.cache_hits_total.fetchAdd(1, .monotonic);
    }

    pub fn incCacheMisses(self: *Self) void {
        _ = self.cache_misses_total.fetchAdd(1, .monotonic);
    }

    pub fn incTcpFallback(self: *Self) void {
        _ = self.tcp_fallback_total.fetchAdd(1, .monotonic);
    }

    pub fn incTimeouts(self: *Self) void {
        _ = self.timeouts_total.fetchAdd(1, .monotonic);
    }

    pub fn incServfail(self: *Self) void {
        _ = self.servfail_total.fetchAdd(1, .monotonic);
    }

    pub fn incNxdomain(self: *Self) void {
        _ = self.nxdomain_total.fetchAdd(1, .monotonic);
    }

    pub fn incFormerr(self: *Self) void {
        _ = self.formerr_total.fetchAdd(1, .monotonic);
    }

    pub fn incEdnsRetries(self: *Self) void {
        _ = self.edns_retries_total.fetchAdd(1, .monotonic);
    }

    pub fn snapshot(self: *Self) MetricsSnapshot {
        return MetricsSnapshot{
            .queries_total = self.queries_total.load(.monotonic),
            .cache_hits_total = self.cache_hits_total.load(.monotonic),
            .cache_misses_total = self.cache_misses_total.load(.monotonic),
            .tcp_fallback_total = self.tcp_fallback_total.load(.monotonic),
            .timeouts_total = self.timeouts_total.load(.monotonic),
            .servfail_total = self.servfail_total.load(.monotonic),
            .nxdomain_total = self.nxdomain_total.load(.monotonic),
            .formerr_total = self.formerr_total.load(.monotonic),
            .edns_retries_total = self.edns_retries_total.load(.monotonic),
        };
    }

    pub fn reset(self: *Self) void {
        self.queries_total.store(0, .monotonic);
        self.cache_hits_total.store(0, .monotonic);
        self.cache_misses_total.store(0, .monotonic);
        self.tcp_fallback_total.store(0, .monotonic);
        self.timeouts_total.store(0, .monotonic);
        self.servfail_total.store(0, .monotonic);
        self.nxdomain_total.store(0, .monotonic);
        self.formerr_total.store(0, .monotonic);
        self.edns_retries_total.store(0, .monotonic);
    }
};

test "Metrics basic" {
    var m = Metrics.init();
    m.incQueries();
    m.incQueries();
    m.incCacheHits();

    const s = m.snapshot();
    try std.testing.expectEqual(@as(u64, 2), s.queries_total);
    try std.testing.expectEqual(@as(u64, 1), s.cache_hits_total);
}
