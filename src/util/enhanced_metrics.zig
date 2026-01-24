// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Enhanced DNS Metrics
//!
//! Provides comprehensive metrics collection including:
//! - Counters with labels (per-server, per-query-type)
//! - Histograms for latency tracking
//! - Gauges for current state
//! - Percentile calculations
//! - Rate calculations

const std = @import("std");

/// Histogram bucket boundaries (in microseconds for latency)
pub const LatencyBuckets = struct {
    /// Default latency buckets in microseconds
    pub const default = [_]u64{
        1_000, // 1ms
        5_000, // 5ms
        10_000, // 10ms
        25_000, // 25ms
        50_000, // 50ms
        100_000, // 100ms
        250_000, // 250ms
        500_000, // 500ms
        1_000_000, // 1s
        2_500_000, // 2.5s
        5_000_000, // 5s
        10_000_000, // 10s
    };
};

/// Histogram for tracking distribution of values
pub fn Histogram(comptime num_buckets: usize) type {
    return struct {
        /// Bucket boundaries (exclusive upper bounds)
        boundaries: [num_buckets]u64,
        /// Bucket counts
        buckets: [num_buckets + 1]std.atomic.Value(u64),
        /// Sum of all observed values
        sum: std.atomic.Value(u64),
        /// Count of all observations
        count: std.atomic.Value(u64),
        /// Minimum observed value
        min: std.atomic.Value(u64),
        /// Maximum observed value
        max: std.atomic.Value(u64),

        const Self = @This();

        pub fn init(boundaries: [num_buckets]u64) Self {
            var self = Self{
                .boundaries = boundaries,
                .buckets = undefined,
                .sum = std.atomic.Value(u64).init(0),
                .count = std.atomic.Value(u64).init(0),
                .min = std.atomic.Value(u64).init(std.math.maxInt(u64)),
                .max = std.atomic.Value(u64).init(0),
            };

            for (&self.buckets) |*bucket| {
                bucket.* = std.atomic.Value(u64).init(0);
            }

            return self;
        }

        pub fn observe(self: *Self, value: u64) void {
            // Update sum and count
            _ = self.sum.fetchAdd(value, .monotonic);
            _ = self.count.fetchAdd(1, .monotonic);

            // Update min
            var current_min = self.min.load(.monotonic);
            while (value < current_min) {
                const result = self.min.cmpxchgWeak(current_min, value, .monotonic, .monotonic);
                if (result) |new_val| {
                    current_min = new_val;
                } else {
                    break;
                }
            }

            // Update max
            var current_max = self.max.load(.monotonic);
            while (value > current_max) {
                const result = self.max.cmpxchgWeak(current_max, value, .monotonic, .monotonic);
                if (result) |new_val| {
                    current_max = new_val;
                } else {
                    break;
                }
            }

            // Find bucket and increment
            var bucket_idx: usize = num_buckets;
            for (self.boundaries, 0..) |boundary, i| {
                if (value <= boundary) {
                    bucket_idx = i;
                    break;
                }
            }
            _ = self.buckets[bucket_idx].fetchAdd(1, .monotonic);
        }

        pub fn getSnapshot(self: *const Self) HistogramSnapshot(num_buckets) {
            var bucket_counts: [num_buckets + 1]u64 = undefined;
            for (&self.buckets, 0..) |*bucket, i| {
                bucket_counts[i] = bucket.load(.monotonic);
            }

            const count = self.count.load(.monotonic);
            const sum = self.sum.load(.monotonic);
            const min_val = self.min.load(.monotonic);
            const max_val = self.max.load(.monotonic);

            return HistogramSnapshot(num_buckets){
                .boundaries = self.boundaries,
                .bucket_counts = bucket_counts,
                .sum = sum,
                .count = count,
                .min = if (count > 0) min_val else 0,
                .max = max_val,
            };
        }

        pub fn reset(self: *Self) void {
            self.sum.store(0, .monotonic);
            self.count.store(0, .monotonic);
            self.min.store(std.math.maxInt(u64), .monotonic);
            self.max.store(0, .monotonic);
            for (&self.buckets) |*bucket| {
                bucket.store(0, .monotonic);
            }
        }
    };
}

/// Snapshot of histogram data
pub fn HistogramSnapshot(comptime num_buckets: usize) type {
    return struct {
        boundaries: [num_buckets]u64,
        bucket_counts: [num_buckets + 1]u64,
        sum: u64,
        count: u64,
        min: u64,
        max: u64,

        const Self = @This();

        pub fn mean(self: Self) f64 {
            if (self.count == 0) return 0;
            return @as(f64, @floatFromInt(self.sum)) / @as(f64, @floatFromInt(self.count));
        }

        /// Calculate approximate percentile (0.0 - 1.0)
        pub fn percentile(self: Self, p: f64) u64 {
            if (self.count == 0) return 0;

            const target_count = @as(u64, @intFromFloat(@as(f64, @floatFromInt(self.count)) * p));
            var cumulative: u64 = 0;

            for (self.bucket_counts, 0..) |bucket_count, i| {
                cumulative += bucket_count;
                if (cumulative >= target_count) {
                    if (i < num_buckets) {
                        return self.boundaries[i];
                    }
                    return self.max;
                }
            }

            return self.max;
        }

        pub fn p50(self: Self) u64 {
            return self.percentile(0.5);
        }

        pub fn p90(self: Self) u64 {
            return self.percentile(0.9);
        }

        pub fn p95(self: Self) u64 {
            return self.percentile(0.95);
        }

        pub fn p99(self: Self) u64 {
            return self.percentile(0.99);
        }
    };
}

/// Default latency histogram type
pub const LatencyHistogram = Histogram(LatencyBuckets.default.len);

/// Gauge for current value tracking
pub const Gauge = struct {
    value: std.atomic.Value(i64),

    const Self = @This();

    pub fn init(initial: i64) Self {
        return Self{
            .value = std.atomic.Value(i64).init(initial),
        };
    }

    pub fn set(self: *Self, val: i64) void {
        self.value.store(val, .monotonic);
    }

    pub fn inc(self: *Self) void {
        _ = self.value.fetchAdd(1, .monotonic);
    }

    pub fn dec(self: *Self) void {
        _ = self.value.fetchSub(1, .monotonic);
    }

    pub fn add(self: *Self, val: i64) void {
        _ = self.value.fetchAdd(val, .monotonic);
    }

    pub fn get(self: *const Self) i64 {
        return self.value.load(.monotonic);
    }
};

/// Counter with atomic operations
pub const Counter = struct {
    value: std.atomic.Value(u64),

    const Self = @This();

    pub fn init() Self {
        return Self{
            .value = std.atomic.Value(u64).init(0),
        };
    }

    pub fn inc(self: *Self) void {
        _ = self.value.fetchAdd(1, .monotonic);
    }

    pub fn add(self: *Self, val: u64) void {
        _ = self.value.fetchAdd(val, .monotonic);
    }

    pub fn get(self: *const Self) u64 {
        return self.value.load(.monotonic);
    }

    pub fn reset(self: *Self) void {
        self.value.store(0, .monotonic);
    }
};

/// Query type statistics
pub const QueryTypeStats = struct {
    /// A record queries
    a: Counter,
    /// AAAA record queries
    aaaa: Counter,
    /// CNAME queries
    cname: Counter,
    /// MX queries
    mx: Counter,
    /// TXT queries
    txt: Counter,
    /// SRV queries
    srv: Counter,
    /// PTR queries
    ptr: Counter,
    /// SOA queries
    soa: Counter,
    /// NS queries
    ns: Counter,
    /// Other query types
    other: Counter,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .a = Counter.init(),
            .aaaa = Counter.init(),
            .cname = Counter.init(),
            .mx = Counter.init(),
            .txt = Counter.init(),
            .srv = Counter.init(),
            .ptr = Counter.init(),
            .soa = Counter.init(),
            .ns = Counter.init(),
            .other = Counter.init(),
        };
    }

    pub fn recordQuery(self: *Self, query_type: u16) void {
        switch (query_type) {
            1 => self.a.inc(), // A
            28 => self.aaaa.inc(), // AAAA
            5 => self.cname.inc(), // CNAME
            15 => self.mx.inc(), // MX
            16 => self.txt.inc(), // TXT
            33 => self.srv.inc(), // SRV
            12 => self.ptr.inc(), // PTR
            6 => self.soa.inc(), // SOA
            2 => self.ns.inc(), // NS
            else => self.other.inc(),
        }
    }

    pub fn total(self: *const Self) u64 {
        return self.a.get() +
            self.aaaa.get() +
            self.cname.get() +
            self.mx.get() +
            self.txt.get() +
            self.srv.get() +
            self.ptr.get() +
            self.soa.get() +
            self.ns.get() +
            self.other.get();
    }
};

/// Response code statistics
pub const ResponseCodeStats = struct {
    /// NOERROR (0)
    noerror: Counter,
    /// FORMERR (1)
    formerr: Counter,
    /// SERVFAIL (2)
    servfail: Counter,
    /// NXDOMAIN (3)
    nxdomain: Counter,
    /// NOTIMP (4)
    notimp: Counter,
    /// REFUSED (5)
    refused: Counter,
    /// Other response codes
    other: Counter,

    const Self = @This();

    pub fn init() Self {
        return Self{
            .noerror = Counter.init(),
            .formerr = Counter.init(),
            .servfail = Counter.init(),
            .nxdomain = Counter.init(),
            .notimp = Counter.init(),
            .refused = Counter.init(),
            .other = Counter.init(),
        };
    }

    pub fn recordResponse(self: *Self, rcode: u4) void {
        switch (rcode) {
            0 => self.noerror.inc(),
            1 => self.formerr.inc(),
            2 => self.servfail.inc(),
            3 => self.nxdomain.inc(),
            4 => self.notimp.inc(),
            5 => self.refused.inc(),
            else => self.other.inc(),
        }
    }
};

/// Per-server statistics
pub const ServerStats = struct {
    allocator: std.mem.Allocator,
    /// Server address (key)
    address: []const u8,
    /// Total queries sent
    queries: Counter,
    /// Successful responses
    successes: Counter,
    /// Failures (timeouts, errors)
    failures: Counter,
    /// Latency histogram
    latency: LatencyHistogram,
    /// Currently in-flight queries
    in_flight: Gauge,
    /// Is server currently healthy
    healthy: std.atomic.Value(bool),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, address: []const u8) !Self {
        return Self{
            .allocator = allocator,
            .address = try allocator.dupe(u8, address),
            .queries = Counter.init(),
            .successes = Counter.init(),
            .failures = Counter.init(),
            .latency = LatencyHistogram.init(LatencyBuckets.default),
            .in_flight = Gauge.init(0),
            .healthy = std.atomic.Value(bool).init(true),
        };
    }

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.address);
    }

    pub fn recordQuery(self: *Self) void {
        self.queries.inc();
        self.in_flight.inc();
    }

    pub fn recordSuccess(self: *Self, latency_us: u64) void {
        self.successes.inc();
        self.in_flight.dec();
        self.latency.observe(latency_us);
        self.healthy.store(true, .monotonic);
    }

    pub fn recordFailure(self: *Self) void {
        self.failures.inc();
        self.in_flight.dec();
    }

    pub fn getSuccessRate(self: *const Self) f64 {
        const total = self.queries.get();
        if (total == 0) return 1.0;
        return @as(f64, @floatFromInt(self.successes.get())) / @as(f64, @floatFromInt(total));
    }
};

/// Rate calculator for calculating rates over time windows
pub const RateCalculator = struct {
    /// Ring buffer of (timestamp, count) pairs
    samples: [60]Sample,
    /// Current index in ring buffer
    index: usize,
    /// Counter reference
    last_count: u64,
    /// Last sample timestamp
    last_timestamp: i64,

    const Sample = struct {
        timestamp: i64,
        count: u64,
    };

    const Self = @This();

    pub fn init() Self {
        return Self{
            .samples = [_]Sample{.{ .timestamp = 0, .count = 0 }} ** 60,
            .index = 0,
            .last_count = 0,
            .last_timestamp = 0,
        };
    }

    /// Record a sample at the current time
    pub fn recordSample(self: *Self, count: u64, timestamp: i64) void {
        self.samples[self.index] = Sample{
            .timestamp = timestamp,
            .count = count,
        };
        self.index = (self.index + 1) % 60;
        self.last_count = count;
        self.last_timestamp = timestamp;
    }

    /// Calculate rate per second over the given window (in seconds)
    pub fn getRate(self: *const Self, window_seconds: u32, current_timestamp: i64) f64 {
        const window_start = current_timestamp - @as(i64, @intCast(window_seconds));

        var oldest_valid: ?Sample = null;
        var newest_valid: ?Sample = null;

        for (self.samples) |sample| {
            if (sample.timestamp >= window_start and sample.timestamp <= current_timestamp) {
                if (oldest_valid == null or sample.timestamp < oldest_valid.?.timestamp) {
                    oldest_valid = sample;
                }
                if (newest_valid == null or sample.timestamp > newest_valid.?.timestamp) {
                    newest_valid = sample;
                }
            }
        }

        if (oldest_valid == null or newest_valid == null) return 0;
        if (oldest_valid.?.timestamp == newest_valid.?.timestamp) return 0;

        const count_diff = newest_valid.?.count - oldest_valid.?.count;
        const time_diff = newest_valid.?.timestamp - oldest_valid.?.timestamp;

        return @as(f64, @floatFromInt(count_diff)) / @as(f64, @floatFromInt(time_diff));
    }
};

/// Comprehensive enhanced metrics collector
pub const EnhancedMetrics = struct {
    allocator: std.mem.Allocator,

    // Counters
    queries_total: Counter,
    responses_total: Counter,
    cache_hits: Counter,
    cache_misses: Counter,
    tcp_connections: Counter,
    udp_queries: Counter,
    tcp_queries: Counter,
    dot_queries: Counter,
    doh_queries: Counter,
    truncated_responses: Counter,
    dnssec_validations: Counter,
    dnssec_failures: Counter,

    // Gauges
    cache_size: Gauge,
    active_connections: Gauge,
    pending_queries: Gauge,

    // Histograms
    query_latency: LatencyHistogram,
    response_size: Histogram(10),

    // Detailed stats
    query_types: QueryTypeStats,
    response_codes: ResponseCodeStats,

    // Per-server stats
    server_stats: std.StringHashMap(ServerStats),

    // Rate calculators
    query_rate: RateCalculator,

    // Uptime tracking
    start_time: i64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .queries_total = Counter.init(),
            .responses_total = Counter.init(),
            .cache_hits = Counter.init(),
            .cache_misses = Counter.init(),
            .tcp_connections = Counter.init(),
            .udp_queries = Counter.init(),
            .tcp_queries = Counter.init(),
            .dot_queries = Counter.init(),
            .doh_queries = Counter.init(),
            .truncated_responses = Counter.init(),
            .dnssec_validations = Counter.init(),
            .dnssec_failures = Counter.init(),
            .cache_size = Gauge.init(0),
            .active_connections = Gauge.init(0),
            .pending_queries = Gauge.init(0),
            .query_latency = LatencyHistogram.init(LatencyBuckets.default),
            .response_size = Histogram(10).init([_]u64{
                64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768,
            }),
            .query_types = QueryTypeStats.init(),
            .response_codes = ResponseCodeStats.init(),
            .server_stats = std.StringHashMap(ServerStats).init(allocator),
            .query_rate = RateCalculator.init(),
            .start_time = std.time.timestamp(),
        };
    }

    pub fn deinit(self: *Self) void {
        var iter = self.server_stats.valueIterator();
        while (iter.next()) |stats| {
            stats.deinit();
        }
        self.server_stats.deinit();
    }

    /// Record a query
    pub fn recordQuery(self: *Self, query_type: u16, transport: Transport) void {
        self.queries_total.inc();
        self.pending_queries.inc();
        self.query_types.recordQuery(query_type);

        switch (transport) {
            .udp => self.udp_queries.inc(),
            .tcp => self.tcp_queries.inc(),
            .dot => self.dot_queries.inc(),
            .doh => self.doh_queries.inc(),
        }
    }

    /// Record a response
    pub fn recordResponse(self: *Self, rcode: u4, latency_us: u64, response_size: u64) void {
        self.responses_total.inc();
        self.pending_queries.dec();
        self.response_codes.recordResponse(rcode);
        self.query_latency.observe(latency_us);
        self.response_size.observe(response_size);
    }

    /// Record cache hit
    pub fn recordCacheHit(self: *Self) void {
        self.cache_hits.inc();
    }

    /// Record cache miss
    pub fn recordCacheMiss(self: *Self) void {
        self.cache_misses.inc();
    }

    /// Update cache size
    pub fn setCacheSize(self: *Self, size: i64) void {
        self.cache_size.set(size);
    }

    /// Get or create server stats
    pub fn getServerStats(self: *Self, address: []const u8) !*ServerStats {
        if (self.server_stats.getPtr(address)) |stats| {
            return stats;
        }

        const stats = try ServerStats.init(self.allocator, address);
        try self.server_stats.put(stats.address, stats);
        return self.server_stats.getPtr(stats.address).?;
    }

    /// Calculate cache hit rate
    pub fn getCacheHitRate(self: *const Self) f64 {
        const hits = self.cache_hits.get();
        const misses = self.cache_misses.get();
        const total = hits + misses;
        if (total == 0) return 0;
        return @as(f64, @floatFromInt(hits)) / @as(f64, @floatFromInt(total));
    }

    /// Get uptime in seconds
    pub fn getUptime(self: *const Self) i64 {
        return std.time.timestamp() - self.start_time;
    }

    /// Render metrics in Prometheus text format
    pub fn renderPrometheus(self: *Self, allocator: std.mem.Allocator) ![]u8 {
        var result: std.ArrayList(u8) = .empty;
        errdefer result.deinit(allocator);
        const writer = result.writer(allocator);

        // Counters
        try writer.print("# HELP zigdns_queries_total Total DNS queries\n", .{});
        try writer.print("# TYPE zigdns_queries_total counter\n", .{});
        try writer.print("zigdns_queries_total {d}\n\n", .{self.queries_total.get()});

        try writer.print("# HELP zigdns_responses_total Total DNS responses\n", .{});
        try writer.print("# TYPE zigdns_responses_total counter\n", .{});
        try writer.print("zigdns_responses_total {d}\n\n", .{self.responses_total.get()});

        // Cache metrics
        try writer.print("# HELP zigdns_cache_hits_total Cache hits\n", .{});
        try writer.print("# TYPE zigdns_cache_hits_total counter\n", .{});
        try writer.print("zigdns_cache_hits_total {d}\n\n", .{self.cache_hits.get()});

        try writer.print("# HELP zigdns_cache_misses_total Cache misses\n", .{});
        try writer.print("# TYPE zigdns_cache_misses_total counter\n", .{});
        try writer.print("zigdns_cache_misses_total {d}\n\n", .{self.cache_misses.get()});

        try writer.print("# HELP zigdns_cache_size Current cache size\n", .{});
        try writer.print("# TYPE zigdns_cache_size gauge\n", .{});
        try writer.print("zigdns_cache_size {d}\n\n", .{self.cache_size.get()});

        // Query types
        try writer.print("# HELP zigdns_queries_by_type Queries by type\n", .{});
        try writer.print("# TYPE zigdns_queries_by_type counter\n", .{});
        try writer.print("zigdns_queries_by_type{{type=\"A\"}} {d}\n", .{self.query_types.a.get()});
        try writer.print("zigdns_queries_by_type{{type=\"AAAA\"}} {d}\n", .{self.query_types.aaaa.get()});
        try writer.print("zigdns_queries_by_type{{type=\"CNAME\"}} {d}\n", .{self.query_types.cname.get()});
        try writer.print("zigdns_queries_by_type{{type=\"MX\"}} {d}\n", .{self.query_types.mx.get()});
        try writer.print("zigdns_queries_by_type{{type=\"TXT\"}} {d}\n", .{self.query_types.txt.get()});
        try writer.print("zigdns_queries_by_type{{type=\"SRV\"}} {d}\n", .{self.query_types.srv.get()});
        try writer.print("zigdns_queries_by_type{{type=\"OTHER\"}} {d}\n\n", .{self.query_types.other.get()});

        // Response codes
        try writer.print("# HELP zigdns_responses_by_rcode Responses by RCODE\n", .{});
        try writer.print("# TYPE zigdns_responses_by_rcode counter\n", .{});
        try writer.print("zigdns_responses_by_rcode{{rcode=\"NOERROR\"}} {d}\n", .{self.response_codes.noerror.get()});
        try writer.print("zigdns_responses_by_rcode{{rcode=\"SERVFAIL\"}} {d}\n", .{self.response_codes.servfail.get()});
        try writer.print("zigdns_responses_by_rcode{{rcode=\"NXDOMAIN\"}} {d}\n", .{self.response_codes.nxdomain.get()});
        try writer.print("zigdns_responses_by_rcode{{rcode=\"REFUSED\"}} {d}\n\n", .{self.response_codes.refused.get()});

        // Latency histogram
        const latency_snapshot = self.query_latency.getSnapshot();
        try writer.print("# HELP zigdns_query_latency_seconds Query latency in seconds\n", .{});
        try writer.print("# TYPE zigdns_query_latency_seconds histogram\n", .{});

        var cumulative: u64 = 0;
        for (latency_snapshot.bucket_counts, 0..) |count, i| {
            cumulative += count;
            if (i < LatencyBuckets.default.len) {
                const boundary_sec = @as(f64, @floatFromInt(latency_snapshot.boundaries[i])) / 1_000_000.0;
                try writer.print("zigdns_query_latency_seconds_bucket{{le=\"{d:.6}\"}} {d}\n", .{ boundary_sec, cumulative });
            }
        }
        try writer.print("zigdns_query_latency_seconds_bucket{{le=\"+Inf\"}} {d}\n", .{cumulative});
        try writer.print("zigdns_query_latency_seconds_sum {d:.6}\n", .{@as(f64, @floatFromInt(latency_snapshot.sum)) / 1_000_000.0});
        try writer.print("zigdns_query_latency_seconds_count {d}\n\n", .{latency_snapshot.count});

        // Transport metrics
        try writer.print("# HELP zigdns_queries_by_transport Queries by transport\n", .{});
        try writer.print("# TYPE zigdns_queries_by_transport counter\n", .{});
        try writer.print("zigdns_queries_by_transport{{transport=\"udp\"}} {d}\n", .{self.udp_queries.get()});
        try writer.print("zigdns_queries_by_transport{{transport=\"tcp\"}} {d}\n", .{self.tcp_queries.get()});
        try writer.print("zigdns_queries_by_transport{{transport=\"dot\"}} {d}\n", .{self.dot_queries.get()});
        try writer.print("zigdns_queries_by_transport{{transport=\"doh\"}} {d}\n\n", .{self.doh_queries.get()});

        // Uptime
        try writer.print("# HELP zigdns_uptime_seconds Uptime in seconds\n", .{});
        try writer.print("# TYPE zigdns_uptime_seconds gauge\n", .{});
        try writer.print("zigdns_uptime_seconds {d}\n", .{self.getUptime()});

        return result.toOwnedSlice(allocator);
    }

    /// Transport type for metrics
    pub const Transport = enum {
        udp,
        tcp,
        dot,
        doh,
    };
};

// ============================================================================
// Tests
// ============================================================================

test "Counter basic" {
    var counter = Counter.init();
    try std.testing.expectEqual(@as(u64, 0), counter.get());

    counter.inc();
    try std.testing.expectEqual(@as(u64, 1), counter.get());

    counter.add(5);
    try std.testing.expectEqual(@as(u64, 6), counter.get());

    counter.reset();
    try std.testing.expectEqual(@as(u64, 0), counter.get());
}

test "Gauge basic" {
    var gauge = Gauge.init(0);
    try std.testing.expectEqual(@as(i64, 0), gauge.get());

    gauge.set(10);
    try std.testing.expectEqual(@as(i64, 10), gauge.get());

    gauge.inc();
    try std.testing.expectEqual(@as(i64, 11), gauge.get());

    gauge.dec();
    try std.testing.expectEqual(@as(i64, 10), gauge.get());

    gauge.add(-5);
    try std.testing.expectEqual(@as(i64, 5), gauge.get());
}

test "Histogram basic" {
    var hist = Histogram(5).init([_]u64{ 10, 50, 100, 500, 1000 });

    hist.observe(5);
    hist.observe(25);
    hist.observe(75);
    hist.observe(200);
    hist.observe(2000);

    const snapshot = hist.getSnapshot();
    try std.testing.expectEqual(@as(u64, 5), snapshot.count);
    try std.testing.expectEqual(@as(u64, 5 + 25 + 75 + 200 + 2000), snapshot.sum);
    try std.testing.expectEqual(@as(u64, 5), snapshot.min);
    try std.testing.expectEqual(@as(u64, 2000), snapshot.max);

    // Check buckets: [<=10, <=50, <=100, <=500, <=1000, >1000]
    try std.testing.expectEqual(@as(u64, 1), snapshot.bucket_counts[0]); // 5
    try std.testing.expectEqual(@as(u64, 1), snapshot.bucket_counts[1]); // 25
    try std.testing.expectEqual(@as(u64, 1), snapshot.bucket_counts[2]); // 75
    try std.testing.expectEqual(@as(u64, 1), snapshot.bucket_counts[3]); // 200
    try std.testing.expectEqual(@as(u64, 0), snapshot.bucket_counts[4]); // none
    try std.testing.expectEqual(@as(u64, 1), snapshot.bucket_counts[5]); // 2000
}

test "Histogram percentiles" {
    var hist = Histogram(5).init([_]u64{ 10, 50, 100, 500, 1000 });

    // Add 100 observations: 10 in each of first 10 buckets
    var i: u64 = 0;
    while (i < 100) : (i += 1) {
        hist.observe(5); // All in first bucket
    }

    const snapshot = hist.getSnapshot();
    try std.testing.expectEqual(@as(u64, 100), snapshot.count);

    // All values in first bucket, so p50, p90, p99 should all be <=10
    try std.testing.expectEqual(@as(u64, 10), snapshot.p50());
    try std.testing.expectEqual(@as(u64, 10), snapshot.p90());
    try std.testing.expectEqual(@as(u64, 10), snapshot.p99());
}

test "QueryTypeStats" {
    var stats = QueryTypeStats.init();

    stats.recordQuery(1); // A
    stats.recordQuery(28); // AAAA
    stats.recordQuery(28); // AAAA
    stats.recordQuery(15); // MX

    try std.testing.expectEqual(@as(u64, 1), stats.a.get());
    try std.testing.expectEqual(@as(u64, 2), stats.aaaa.get());
    try std.testing.expectEqual(@as(u64, 1), stats.mx.get());
    try std.testing.expectEqual(@as(u64, 4), stats.total());
}

test "ResponseCodeStats" {
    var stats = ResponseCodeStats.init();

    stats.recordResponse(0); // NOERROR
    stats.recordResponse(0);
    stats.recordResponse(3); // NXDOMAIN
    stats.recordResponse(2); // SERVFAIL

    try std.testing.expectEqual(@as(u64, 2), stats.noerror.get());
    try std.testing.expectEqual(@as(u64, 1), stats.nxdomain.get());
    try std.testing.expectEqual(@as(u64, 1), stats.servfail.get());
}

test "EnhancedMetrics init/deinit" {
    const allocator = std.testing.allocator;
    var metrics = EnhancedMetrics.init(allocator);
    defer metrics.deinit();

    metrics.recordQuery(1, .udp);
    metrics.recordResponse(0, 10000, 512);
    metrics.recordCacheHit();

    try std.testing.expectEqual(@as(u64, 1), metrics.queries_total.get());
    try std.testing.expectEqual(@as(u64, 1), metrics.responses_total.get());
    try std.testing.expectEqual(@as(u64, 1), metrics.cache_hits.get());
}

test "EnhancedMetrics Prometheus output" {
    const allocator = std.testing.allocator;
    var metrics = EnhancedMetrics.init(allocator);
    defer metrics.deinit();

    metrics.recordQuery(1, .udp);
    metrics.recordResponse(0, 50000, 256);

    const output = try metrics.renderPrometheus(allocator);
    defer allocator.free(output);

    try std.testing.expect(std.mem.indexOf(u8, output, "zigdns_queries_total 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "zigdns_responses_total 1") != null);
}

test "LatencyHistogram with default buckets" {
    var hist = LatencyHistogram.init(LatencyBuckets.default);

    // Observe some latencies in microseconds
    hist.observe(500); // 0.5ms
    hist.observe(5000); // 5ms
    hist.observe(50000); // 50ms
    hist.observe(500000); // 500ms
    hist.observe(5000000); // 5s

    const snapshot = hist.getSnapshot();
    try std.testing.expectEqual(@as(u64, 5), snapshot.count);
    try std.testing.expectEqual(@as(u64, 500), snapshot.min);
    try std.testing.expectEqual(@as(u64, 5000000), snapshot.max);
}
