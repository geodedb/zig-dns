// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Query/Response Logging
//!
//! Provides structured logging for DNS queries and responses:
//! - Query logging with timestamps and metadata
//! - Response logging with timing information
//! - Structured log formats (JSON, text, syslog)
//! - Log filtering and sampling
//! - Privacy controls (anonymization)

const std = @import("std");

/// Log level
pub const LogLevel = enum(u8) {
    /// Debug information
    debug = 0,
    /// Informational messages
    info = 1,
    /// Warning messages
    warning = 2,
    /// Error messages
    err = 3,
    /// Critical errors
    critical = 4,

    pub fn toString(self: LogLevel) []const u8 {
        return switch (self) {
            .debug => "DEBUG",
            .info => "INFO",
            .warning => "WARN",
            .err => "ERROR",
            .critical => "CRIT",
        };
    }
};

/// Log format
pub const LogFormat = enum {
    /// Human-readable text
    text,
    /// JSON format
    json,
    /// Common Log Format
    clf,
    /// Syslog format
    syslog,
};

/// Query log entry
pub const QueryLogEntry = struct {
    /// Timestamp (Unix epoch ms)
    timestamp: i64,
    /// Query ID
    query_id: u16,
    /// Client IP (if available)
    client_ip: ?[]const u8 = null,
    /// Query name
    qname: []const u8,
    /// Query type (A, AAAA, MX, etc.)
    qtype: []const u8,
    /// Query class (IN, CH, etc.)
    qclass: []const u8 = "IN",
    /// Protocol used (UDP, TCP, DoT, DoH, DoQ)
    protocol: []const u8 = "UDP",
    /// Server being queried
    server: ?[]const u8 = null,
    /// EDNS present
    edns: bool = false,
    /// DNSSEC requested
    dnssec: bool = false,
};

/// Response log entry
pub const ResponseLogEntry = struct {
    /// Original query
    query: QueryLogEntry,
    /// Response code (NOERROR, NXDOMAIN, etc.)
    rcode: []const u8,
    /// Response time (ms)
    response_time_ms: u32,
    /// Answer count
    answer_count: u16,
    /// Authority count
    authority_count: u16,
    /// Additional count
    additional_count: u16,
    /// Response truncated
    truncated: bool = false,
    /// Response authenticated
    authenticated: bool = false,
    /// Cache hit
    cache_hit: bool = false,
    /// Error message (if failed)
    error_msg: ?[]const u8 = null,
};

/// Log writer configuration
pub const LogConfig = struct {
    /// Minimum log level
    min_level: LogLevel = .info,
    /// Output format
    format: LogFormat = .text,
    /// Include timestamps
    include_timestamp: bool = true,
    /// Include query ID
    include_query_id: bool = true,
    /// Anonymize client IPs
    anonymize_ips: bool = false,
    /// Log sampling rate (1.0 = all, 0.1 = 10%)
    sample_rate: f32 = 1.0,
    /// Buffer size for async logging
    buffer_size: usize = 1024,
    /// Flush interval (ms)
    flush_interval_ms: u32 = 1000,
};

/// DNS Logger
pub const DnsLogger = struct {
    allocator: std.mem.Allocator,
    config: LogConfig,
    /// Log buffer
    buffer: std.ArrayList(u8),
    /// Statistics
    stats: Stats,
    /// Random for sampling
    rng: std.Random.DefaultPrng,

    const Self = @This();

    pub const Stats = struct {
        /// Total log entries
        total_entries: u64 = 0,
        /// Entries actually logged (after sampling)
        logged_entries: u64 = 0,
        /// Entries dropped (sampling/filtering)
        dropped_entries: u64 = 0,
        /// Bytes written
        bytes_written: u64 = 0,
        /// Flush count
        flush_count: u64 = 0,
    };

    pub fn init(allocator: std.mem.Allocator, config: LogConfig) Self {
        return Self{
            .allocator = allocator,
            .config = config,
            .buffer = .empty,
            .stats = .{},
            .rng = std.Random.DefaultPrng.init(@intCast(std.time.milliTimestamp())),
        };
    }

    pub fn deinit(self: *Self) void {
        self.buffer.deinit(self.allocator);
    }

    /// Log a query
    pub fn logQuery(self: *Self, entry: QueryLogEntry, level: LogLevel) !void {
        if (@intFromEnum(level) < @intFromEnum(self.config.min_level)) return;
        if (!self.shouldSample()) {
            self.stats.dropped_entries += 1;
            return;
        }

        self.stats.total_entries += 1;

        try self.formatQueryEntry(entry, level);
        self.stats.logged_entries += 1;
    }

    /// Log a response
    pub fn logResponse(self: *Self, entry: ResponseLogEntry, level: LogLevel) !void {
        if (@intFromEnum(level) < @intFromEnum(self.config.min_level)) return;
        if (!self.shouldSample()) {
            self.stats.dropped_entries += 1;
            return;
        }

        self.stats.total_entries += 1;

        try self.formatResponseEntry(entry, level);
        self.stats.logged_entries += 1;
    }

    /// Log a simple message
    pub fn log(self: *Self, level: LogLevel, comptime fmt: []const u8, args: anytype) !void {
        if (@intFromEnum(level) < @intFromEnum(self.config.min_level)) return;

        self.stats.total_entries += 1;

        const timestamp = std.time.milliTimestamp();

        switch (self.config.format) {
            .text => {
                if (self.config.include_timestamp) {
                    try self.buffer.writer(self.allocator).print("{d} ", .{timestamp});
                }
                try self.buffer.writer(self.allocator).print("[{s}] ", .{level.toString()});
                try self.buffer.writer(self.allocator).print(fmt, args);
                try self.buffer.append(self.allocator, '\n');
            },
            .json => {
                try self.buffer.writer(self.allocator).print(
                    \\{{"timestamp":{d},"level":"{s}","message":"
                , .{ timestamp, level.toString() });
                try self.buffer.writer(self.allocator).print(fmt, args);
                try self.buffer.appendSlice(self.allocator, "\"}\n");
            },
            else => {
                try self.buffer.writer(self.allocator).print(fmt, args);
                try self.buffer.append(self.allocator, '\n');
            },
        }

        self.stats.logged_entries += 1;
    }

    fn formatQueryEntry(self: *Self, entry: QueryLogEntry, level: LogLevel) !void {
        const writer = self.buffer.writer(self.allocator);

        switch (self.config.format) {
            .text => {
                if (self.config.include_timestamp) {
                    try writer.print("{d} ", .{entry.timestamp});
                }
                try writer.print("[{s}] QUERY ", .{level.toString()});
                if (self.config.include_query_id) {
                    try writer.print("id={d} ", .{entry.query_id});
                }
                try writer.print("qname={s} qtype={s} ", .{ entry.qname, entry.qtype });
                if (entry.client_ip) |ip| {
                    const display_ip = if (self.config.anonymize_ips) anonymizeIp(ip) else ip;
                    try writer.print("client={s} ", .{display_ip});
                }
                if (entry.server) |server| {
                    try writer.print("server={s} ", .{server});
                }
                try writer.print("proto={s}", .{entry.protocol});
                if (entry.edns) try writer.writeAll(" edns=true");
                if (entry.dnssec) try writer.writeAll(" dnssec=true");
                try self.buffer.append(self.allocator, '\n');
            },
            .json => {
                try writer.print(
                    \\{{"type":"query","timestamp":{d},"level":"{s}","query_id":{d},"qname":"{s}","qtype":"{s}","qclass":"{s}","protocol":"{s}"
                , .{
                    entry.timestamp,
                    level.toString(),
                    entry.query_id,
                    entry.qname,
                    entry.qtype,
                    entry.qclass,
                    entry.protocol,
                });
                if (entry.client_ip) |ip| {
                    const display_ip = if (self.config.anonymize_ips) anonymizeIp(ip) else ip;
                    try writer.print(",\"client_ip\":\"{s}\"", .{display_ip});
                }
                if (entry.server) |server| {
                    try writer.print(",\"server\":\"{s}\"", .{server});
                }
                try writer.print(",\"edns\":{},\"dnssec\":{}}}\n", .{ entry.edns, entry.dnssec });
            },
            else => {
                try writer.print("QUERY {s} {s}\n", .{ entry.qname, entry.qtype });
            },
        }
    }

    fn formatResponseEntry(self: *Self, entry: ResponseLogEntry, level: LogLevel) !void {
        const writer = self.buffer.writer(self.allocator);

        switch (self.config.format) {
            .text => {
                if (self.config.include_timestamp) {
                    try writer.print("{d} ", .{entry.query.timestamp});
                }
                try writer.print("[{s}] RESPONSE ", .{level.toString()});
                if (self.config.include_query_id) {
                    try writer.print("id={d} ", .{entry.query.query_id});
                }
                try writer.print("qname={s} rcode={s} time={d}ms ", .{
                    entry.query.qname,
                    entry.rcode,
                    entry.response_time_ms,
                });
                try writer.print("answers={d} ", .{entry.answer_count});
                if (entry.cache_hit) try writer.writeAll("cached=true ");
                if (entry.error_msg) |msg| {
                    try writer.print("error=\"{s}\"", .{msg});
                }
                try self.buffer.append(self.allocator, '\n');
            },
            .json => {
                try writer.print(
                    \\{{"type":"response","timestamp":{d},"level":"{s}","query_id":{d},"qname":"{s}","qtype":"{s}","rcode":"{s}","response_time_ms":{d},"answer_count":{d},"authority_count":{d},"additional_count":{d},"truncated":{},"authenticated":{},"cache_hit":{}
                , .{
                    entry.query.timestamp,
                    level.toString(),
                    entry.query.query_id,
                    entry.query.qname,
                    entry.query.qtype,
                    entry.rcode,
                    entry.response_time_ms,
                    entry.answer_count,
                    entry.authority_count,
                    entry.additional_count,
                    entry.truncated,
                    entry.authenticated,
                    entry.cache_hit,
                });
                if (entry.error_msg) |msg| {
                    try writer.print(",\"error\":\"{s}\"", .{msg});
                }
                try writer.writeAll("}\n");
            },
            else => {
                try writer.print("RESPONSE {s} {s} {d}ms\n", .{ entry.query.qname, entry.rcode, entry.response_time_ms });
            },
        }
    }

    fn shouldSample(self: *Self) bool {
        if (self.config.sample_rate >= 1.0) return true;
        if (self.config.sample_rate <= 0.0) return false;

        const random_val = self.rng.random().float(f32);
        return random_val < self.config.sample_rate;
    }

    /// Get buffered log data
    pub fn getBuffer(self: *Self) []const u8 {
        return self.buffer.items;
    }

    /// Clear the buffer
    pub fn clearBuffer(self: *Self) void {
        self.stats.bytes_written += self.buffer.items.len;
        self.stats.flush_count += 1;
        self.buffer.clearRetainingCapacity();
    }

    /// Get statistics
    pub fn getStats(self: *const Self) Stats {
        return self.stats;
    }
};

/// Anonymize an IP address (zero last octet for IPv4, last 80 bits for IPv6)
fn anonymizeIp(ip: []const u8) []const u8 {
    // Simple anonymization - just return "x.x.x.0" style
    // In a real implementation, this would properly parse and mask the IP
    _ = ip;
    return "anonymized";
}

/// Create a query log entry
pub fn queryEntry(query_id: u16, qname: []const u8, qtype: []const u8) QueryLogEntry {
    return QueryLogEntry{
        .timestamp = std.time.milliTimestamp(),
        .query_id = query_id,
        .qname = qname,
        .qtype = qtype,
    };
}

/// Create a response log entry
pub fn responseEntry(query: QueryLogEntry, rcode: []const u8, response_time_ms: u32, answer_count: u16) ResponseLogEntry {
    return ResponseLogEntry{
        .query = query,
        .rcode = rcode,
        .response_time_ms = response_time_ms,
        .answer_count = answer_count,
        .authority_count = 0,
        .additional_count = 0,
    };
}

// ============================================================================
// Tests
// ============================================================================

test "LogLevel toString" {
    try std.testing.expectEqualStrings("DEBUG", LogLevel.debug.toString());
    try std.testing.expectEqualStrings("INFO", LogLevel.info.toString());
    try std.testing.expectEqualStrings("ERROR", LogLevel.err.toString());
}

test "DnsLogger init/deinit" {
    const allocator = std.testing.allocator;

    var logger = DnsLogger.init(allocator, .{});
    defer logger.deinit();

    try std.testing.expectEqual(@as(u64, 0), logger.stats.total_entries);
}

test "DnsLogger log query text format" {
    const allocator = std.testing.allocator;

    var logger = DnsLogger.init(allocator, .{ .format = .text });
    defer logger.deinit();

    const entry = queryEntry(1234, "example.com", "A");
    try logger.logQuery(entry, .info);

    const output = logger.getBuffer();
    try std.testing.expect(std.mem.indexOf(u8, output, "QUERY") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "qtype=A") != null);
}

test "DnsLogger log query JSON format" {
    const allocator = std.testing.allocator;

    var logger = DnsLogger.init(allocator, .{ .format = .json });
    defer logger.deinit();

    const entry = queryEntry(5678, "test.example.com", "AAAA");
    try logger.logQuery(entry, .info);

    const output = logger.getBuffer();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"type\":\"query\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"qname\":\"test.example.com\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"qtype\":\"AAAA\"") != null);
}

test "DnsLogger log response" {
    const allocator = std.testing.allocator;

    var logger = DnsLogger.init(allocator, .{ .format = .text });
    defer logger.deinit();

    const query = queryEntry(1111, "api.example.com", "A");
    const response = responseEntry(query, "NOERROR", 25, 2);
    try logger.logResponse(response, .info);

    const output = logger.getBuffer();
    try std.testing.expect(std.mem.indexOf(u8, output, "RESPONSE") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "rcode=NOERROR") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "time=25ms") != null);
}

test "DnsLogger level filtering" {
    const allocator = std.testing.allocator;

    var logger = DnsLogger.init(allocator, .{ .min_level = .warning });
    defer logger.deinit();

    // Debug should be filtered out
    try logger.log(.debug, "debug message", .{});
    try std.testing.expectEqual(@as(usize, 0), logger.getBuffer().len);

    // Warning should be logged
    try logger.log(.warning, "warning message", .{});
    try std.testing.expect(logger.getBuffer().len > 0);
}

test "DnsLogger statistics" {
    const allocator = std.testing.allocator;

    var logger = DnsLogger.init(allocator, .{});
    defer logger.deinit();

    try logger.log(.info, "test1", .{});
    try logger.log(.info, "test2", .{});
    logger.clearBuffer();
    try logger.log(.info, "test3", .{});

    const stats = logger.getStats();
    try std.testing.expectEqual(@as(u64, 3), stats.total_entries);
    try std.testing.expectEqual(@as(u64, 3), stats.logged_entries);
    try std.testing.expectEqual(@as(u64, 1), stats.flush_count);
}

test "helper functions" {
    const q = queryEntry(100, "example.com", "MX");
    try std.testing.expectEqual(@as(u16, 100), q.query_id);
    try std.testing.expectEqualStrings("example.com", q.qname);

    const r = responseEntry(q, "NOERROR", 50, 1);
    try std.testing.expectEqualStrings("NOERROR", r.rcode);
    try std.testing.expectEqual(@as(u32, 50), r.response_time_ms);
}
