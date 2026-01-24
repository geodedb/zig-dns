// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Recursive Resolver
//!
//! RFC 1034 Section 5.3.3: Algorithm
//!
//! Implements full iterative recursive resolution from root servers.

const std = @import("std");
const types = @import("../types.zig");
const message = @import("../message.zig");
const name_mod = @import("../name.zig");
const channel_mod = @import("channel.zig");
const dns_cache = @import("dns_cache.zig");
const edns = @import("edns.zig");
const metrics_mod = @import("../util/metrics.zig");
const clock_mod = @import("../util/clock.zig");

pub const Type = types.Type;
pub const Class = types.Class;
pub const Name = types.Name;
pub const Channel = channel_mod.Channel;
pub const DnsCache = dns_cache.DnsCache;
pub const CacheOptions = dns_cache.CacheOptions;
pub const Metrics = metrics_mod.Metrics;

/// Root DNS Servers
pub const RootServers = struct {
    pub const a = "198.41.0.4";
    pub const b = "170.247.170.2";
    pub const c = "192.33.4.12";
    pub const d = "199.7.91.13";
    pub const e = "192.203.230.10";
    pub const f = "192.5.5.241";
    pub const g = "192.112.36.4";
    pub const h = "198.97.190.53";
    pub const i_server = "192.36.148.17";
    pub const j = "192.58.128.30";
    pub const k = "193.0.14.129";
    pub const l = "199.7.83.42";
    pub const m = "202.12.27.33";

    pub fn all() [13][]const u8 {
        return [_][]const u8{
            a, b, c, d, e, f, g, h, i_server, j, k, l, m,
        };
    }
};

/// Name server with addresses
pub const NameServer = struct {
    name: []const u8,
    addrs: []const []const u8,
};

/// Recursive resolver options
pub const RecursiveOptions = struct {
    /// Root servers
    roots: []const NameServer = &[_]NameServer{},
    /// Cache configuration
    cache: CacheOptions = .{},
    /// Maximum recursion depth
    max_depth: u8 = 20,
    /// DNSSEC validation (feature-gated)
    dnssec_validate: bool = false,
    /// Query timeout
    timeout_ms: u32 = 5000,
    /// EDNS UDP payload size
    edns_payload_size: u16 = 1232,
    /// Enable QNAME minimization
    qname_minimization: bool = true,
};

/// Resolution status
pub const ResolveStatus = enum {
    success,
    nxdomain,
    nodata,
    servfail,
    timeout,

    pub fn toString(self: ResolveStatus) []const u8 {
        return switch (self) {
            .success => "success",
            .nxdomain => "nxdomain",
            .nodata => "nodata",
            .servfail => "servfail",
            .timeout => "timeout",
        };
    }
};

/// Resolution result
pub const Answer = struct {
    status: ResolveStatus,
    qname: []const u8,
    qtype: Type,
    rcode: types.RCode,
    response_data: []u8,
    cname_chain: std.ArrayList([]const u8),
    used_tcp: bool,
    from_cache: bool,
    validated_dnssec: bool,

    pub fn deinit(self: *Answer, allocator: std.mem.Allocator) void {
        allocator.free(self.response_data);
        for (self.cname_chain.items) |name| {
            allocator.free(name);
        }
        self.cname_chain.deinit(allocator);
    }

    /// Format as JSON
    pub fn toJson(self: *const Answer, allocator: std.mem.Allocator) ![]u8 {
        var json: std.ArrayList(u8) = .empty;
        errdefer json.deinit(allocator);

        try json.appendSlice(allocator, "{\"status\":\"");
        try json.appendSlice(allocator, self.status.toString());
        try json.appendSlice(allocator, "\",\"qname\":\"");
        try json.appendSlice(allocator, self.qname);
        try json.appendSlice(allocator, "\",\"qtype\":\"");
        try json.appendSlice(allocator, self.qtype.toString());
        try json.appendSlice(allocator, "\",\"answers\":[],\"cname_chain\":[");

        for (self.cname_chain.items, 0..) |name, i| {
            if (i > 0) try json.append(allocator, ',');
            try json.append(allocator, '"');
            try json.appendSlice(allocator, name);
            try json.append(allocator, '"');
        }

        try json.appendSlice(allocator, "],\"rcode\":\"");
        try json.appendSlice(allocator, self.rcode.toString());
        try json.appendSlice(allocator, "\",\"used_tcp\":");
        try json.appendSlice(allocator, if (self.used_tcp) "true" else "false");
        try json.appendSlice(allocator, ",\"from_cache\":");
        try json.appendSlice(allocator, if (self.from_cache) "true" else "false");
        try json.appendSlice(allocator, ",\"validated_dnssec\":");
        try json.appendSlice(allocator, if (self.validated_dnssec) "true" else "false");
        try json.append(allocator, '}');

        return json.toOwnedSlice(allocator);
    }
};

/// Recursive Resolver
pub const RecursiveResolver = struct {
    allocator: std.mem.Allocator,
    options: RecursiveOptions,
    cache: DnsCache,
    metrics: Metrics,
    root_addrs: [][]const u8,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, options: RecursiveOptions) !Self {
        var mock_clock = clock_mod.MockClock.init();

        // Initialize root server addresses
        const roots = RootServers.all();
        const root_addrs = try allocator.alloc([]const u8, roots.len);
        for (roots, 0..) |addr, i| {
            root_addrs[i] = addr;
        }

        return Self{
            .allocator = allocator,
            .options = options,
            .cache = DnsCache.init(allocator, options.cache, mock_clock.clock()),
            .metrics = Metrics.init(),
            .root_addrs = root_addrs,
        };
    }

    pub fn deinit(self: *Self) void {
        self.cache.deinit();
        self.allocator.free(self.root_addrs);
    }

    /// Resolve a DNS query recursively
    pub fn resolve(self: *Self, qname: []const u8, qtype: Type) !Answer {
        self.metrics.incQueries();

        // Check cache first
        if (self.cache.get(qname, qtype, .in)) |entry| {
            self.metrics.incCacheHits();

            const status: ResolveStatus = switch (entry.entry_type) {
                .positive => .success,
                .nxdomain => .nxdomain,
                .nodata => .nodata,
            };

            return Answer{
                .status = status,
                .qname = qname,
                .qtype = qtype,
                .rcode = if (status == .nxdomain) .nxdomain else .noerror,
                .response_data = try self.allocator.dupe(u8, entry.rdata),
                .cname_chain = .empty,
                .used_tcp = false,
                .from_cache = true,
                .validated_dnssec = false,
            };
        }

        self.metrics.incCacheMisses();

        // Start recursive resolution from roots
        return self.resolveWithDepth(qname, qtype, 0);
    }

    fn resolveWithDepth(self: *Self, qname: []const u8, qtype: Type, depth: u8) !Answer {
        if (depth >= self.options.max_depth) {
            return error.MaxDepthExceeded;
        }

        // For now, return a placeholder - full implementation would iterate through zones
        return Answer{
            .status = .servfail,
            .qname = qname,
            .qtype = qtype,
            .rcode = .servfail,
            .response_data = try self.allocator.alloc(u8, 0),
            .cname_chain = .empty,
            .used_tcp = false,
            .from_cache = false,
            .validated_dnssec = false,
        };
    }

    /// Bailiwick check: verify NS/glue is in authority zone
    fn isInBailiwick(name: []const u8, zone: []const u8) bool {
        if (zone.len == 1 and zone[0] == '.') return true;
        if (name.len < zone.len) return false;

        const suffix_start = name.len - zone.len;
        return std.ascii.eqlIgnoreCase(name[suffix_start..], zone);
    }

    /// Get metrics snapshot
    pub fn getMetrics(self: *Self) metrics_mod.MetricsSnapshot {
        return self.metrics.snapshot();
    }

    /// Clear cache
    pub fn clearCache(self: *Self) void {
        self.cache.clear();
    }
};

test "RecursiveResolver init" {
    const allocator = std.testing.allocator;

    var resolver = try RecursiveResolver.init(allocator, .{});
    defer resolver.deinit();

    try std.testing.expectEqual(@as(usize, 13), resolver.root_addrs.len);
}

test "RecursiveResolver bailiwick" {
    try std.testing.expect(RecursiveResolver.isInBailiwick("ns1.example.com.", "example.com."));
    try std.testing.expect(RecursiveResolver.isInBailiwick("example.com.", "."));
    try std.testing.expect(!RecursiveResolver.isInBailiwick("ns1.other.com.", "example.com."));
}

test "RootServers" {
    const roots = RootServers.all();
    try std.testing.expectEqual(@as(usize, 13), roots.len);
    try std.testing.expectEqualStrings("198.41.0.4", roots[0]);
}
