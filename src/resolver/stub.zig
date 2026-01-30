// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Stub Resolver
//!
//! RFC 1034 Section 5.3.1: Stub Resolvers
//!
//! Forwards queries to configured upstream servers using various transports.

const std = @import("std");
const types = @import("../types.zig");
const message = @import("../message.zig");
const channel_mod = @import("channel.zig");
const edns = @import("edns.zig");
const metrics_mod = @import("../util/metrics.zig");

pub const Type = types.Type;
pub const Class = types.Class;
pub const Channel = channel_mod.Channel;
pub const ChannelKind = channel_mod.ChannelKind;
pub const Metrics = metrics_mod.Metrics;

/// Stub resolver options
pub const StubOptions = struct {
    /// Channels to use for queries
    channels: []const Channel,
    /// Number of parallel queries to send
    parallel: u2 = 2,
    /// Whether to rotate through channels
    rotate: bool = true,
    /// Query timeout in milliseconds
    timeout_ms: u32 = 1500,
    /// Number of retries per query
    retries: u3 = 2,
    /// EDNS UDP payload size
    edns_payload_size: u16 = 1232,
    /// Enable EDNS
    use_edns: bool = true,
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
    used_tcp: bool,
    from_cache: bool,
    validated_dnssec: bool,

    pub fn deinit(self: *Answer, allocator: std.mem.Allocator) void {
        allocator.free(self.response_data);
    }
};

/// Stub Resolver
pub const StubResolver = struct {
    allocator: std.mem.Allocator,
    options: StubOptions,
    metrics: Metrics,
    next_channel: usize,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, options: StubOptions) Self {
        return Self{
            .allocator = allocator,
            .options = options,
            .metrics = Metrics.init(),
            .next_channel = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        _ = self;
    }

    /// Resolve a DNS query
    pub fn resolve(self: *Self, qname: []const u8, qtype: Type) !Answer {
        self.metrics.incQueries();

        var attempt: u8 = 0;
        const max_attempts = self.options.retries + 1;

        while (attempt < max_attempts) : (attempt += 1) {
            const channel = self.selectChannel();

            const id = try getSecureRandomId();

            // Build query
            const query = try self.buildQuery(id, qname, qtype);
            defer self.allocator.free(query);

            // Send query
            const response = channel.query(query, self.options.timeout_ms) catch |err| {
                if (err == error.Timeout) {
                    self.metrics.incTimeouts();
                    continue;
                }
                return err;
            };
            const msg = message.Message.parse(response) catch {
                self.allocator.free(response);
                continue;
            };

            if (msg.header.id != id or !responseMatchesQuery(self.allocator, msg, qname, qtype, .in)) {
                self.allocator.free(response);
                continue;
            }

            // Check for truncation - retry over TCP
            if (msg.header.tc and channel.kind == .udp) {
                self.allocator.free(response);
                self.metrics.incTcpFallback();

                // Find TCP channel
                for (self.options.channels) |ch| {
                    if (ch.kind == .tcp) {
                        const tcp_response = ch.query(query, self.options.timeout_ms) catch continue;
                        return Answer{
                            .status = .success,
                            .qname = qname,
                            .qtype = qtype,
                            .rcode = msg.header.rcode,
                            .response_data = tcp_response,
                            .used_tcp = true,
                            .from_cache = false,
                            .validated_dnssec = false,
                        };
                    }
                }
                continue;
            }

            // Check for EDNS FORMERR - retry without EDNS
            if (msg.header.rcode == .formerr and self.options.use_edns) {
                self.allocator.free(response);
                self.metrics.incFormerr();
                self.metrics.incEdnsRetries();

                const retry_id = try getSecureRandomId();
                const query_no_edns = try self.buildQueryNoEdns(retry_id, qname, qtype);
                defer self.allocator.free(query_no_edns);

                const retry_response = channel.query(query_no_edns, self.options.timeout_ms) catch continue;
                const retry_msg = message.Message.parse(retry_response) catch {
                    self.allocator.free(retry_response);
                    continue;
                };
                if (retry_msg.header.id != retry_id or !responseMatchesQuery(self.allocator, retry_msg, qname, qtype, .in)) {
                    self.allocator.free(retry_response);
                    continue;
                }
                return Answer{
                    .status = .success,
                    .qname = qname,
                    .qtype = qtype,
                    .rcode = retry_msg.header.rcode,
                    .response_data = retry_response,
                    .used_tcp = false,
                    .from_cache = false,
                    .validated_dnssec = false,
                };
            }

            // Determine status
            const status: ResolveStatus = switch (msg.header.rcode) {
                .noerror => if (msg.header.ancount > 0) .success else .nodata,
                .nxdomain => blk: {
                    self.metrics.incNxdomain();
                    break :blk .nxdomain;
                },
                .servfail => blk: {
                    self.metrics.incServfail();
                    break :blk .servfail;
                },
                else => .servfail,
            };

            return Answer{
                .status = status,
                .qname = qname,
                .qtype = qtype,
                .rcode = msg.header.rcode,
                .response_data = response,
                .used_tcp = channel.kind == .tcp,
                .from_cache = false,
                .validated_dnssec = false,
            };
        }

        return error.Timeout;
    }

    /// Get metrics snapshot
    pub fn getMetrics(self: *Self) metrics_mod.MetricsSnapshot {
        return self.metrics.snapshot();
    }

    /// Error returned when no channels are configured
    pub const SelectChannelError = error{NoChannelsConfigured};

    fn selectChannel(self: *Self) SelectChannelError!Channel {
        if (self.options.channels.len == 0) {
            return error.NoChannelsConfigured;
        }

        const idx = if (self.options.rotate) blk: {
            const i = self.next_channel;
            self.next_channel = (self.next_channel + 1) % self.options.channels.len;
            break :blk i;
        } else 0;

        return self.options.channels[idx];
    }

    /// Error for entropy unavailability
    pub const EntropyError = error{EntropyUnavailable};

    fn getSecureRandomId() EntropyError!u16 {
        var seed: u64 = undefined;
        std.posix.getrandom(std.mem.asBytes(&seed)) catch {
            return error.EntropyUnavailable;
        };
        var prng = std.Random.DefaultPrng.init(seed);
        return prng.random().int(u16);
    }

    fn buildQuery(self: *Self, id: u16, qname: []const u8, qtype: Type) ![]u8 {
        // Build basic query
        const query = try message.buildQuery(self.allocator, id, qname, qtype, .in, true);
        errdefer self.allocator.free(query);

        if (!self.options.use_edns) {
            return query;
        }

        // Append EDNS OPT record
        const opt = edns.EdnsOpt{
            .udp_payload_size = self.options.edns_payload_size,
        };
        const opt_wire = try opt.encode(self.allocator);
        defer self.allocator.free(opt_wire);

        const full_query = try self.allocator.alloc(u8, query.len + opt_wire.len);
        @memcpy(full_query[0..query.len], query);
        @memcpy(full_query[query.len..], opt_wire);

        // Update ARCOUNT
        const new_arcount = std.mem.readInt(u16, full_query[10..12], .big) + 1;
        std.mem.writeInt(u16, full_query[10..12], new_arcount, .big);

        self.allocator.free(query);
        return full_query;
    }

    fn buildQueryNoEdns(self: *Self, id: u16, qname: []const u8, qtype: Type) ![]u8 {
        return message.buildQuery(self.allocator, id, qname, qtype, .in, true);
    }
};

fn trimTrailingDot(name: []const u8) []const u8 {
    if (name.len > 0 and name[name.len - 1] == '.') {
        return name[0 .. name.len - 1];
    }
    return name;
}

fn namesEqual(a: []const u8, b: []const u8) bool {
    return std.ascii.eqlIgnoreCase(trimTrailingDot(a), trimTrailingDot(b));
}

fn responseMatchesQuery(
    allocator: std.mem.Allocator,
    msg: message.Message,
    expected_name: []const u8,
    expected_type: Type,
    expected_class: Class,
) bool {
    if (!msg.header.qr) return false;
    if (msg.header.opcode != .query) return false;
    if (msg.header.qdcount == 0) return false;

    var q_iter = msg.questions();
    const q = (q_iter.next() catch null) orelse return false;
    if (q.qtype != expected_type or q.qclass != expected_class) return false;

    const qname = q.getName(allocator, msg.data) catch return false;
    defer allocator.free(qname);

    return namesEqual(qname, expected_name);
}

test "StubResolver basic" {
    const allocator = std.testing.allocator;

    var mock = channel_mod.MockChannel.init(allocator, .udp);
    defer mock.deinit();

    // Add a simple DNS response
    const response = [_]u8{
        0x00, 0x01, // ID
        0x81, 0x80, // Flags
        0x00, 0x01, // QDCOUNT
        0x00, 0x01, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
        // Question
        7,    'e',
        'x',  'a',
        'm',  'p',
        'l',  'e',
        3,    'c',
        'o',  'm',
        0,    0x00,
        0x01, 0x00,
        0x01,
        // Answer
        0xC0,
        0x0C, 0x00,
        0x01, 0x00,
        0x01, 0x00,
        0x00, 0x01,
        0x2C, 0x00,
        0x04, 93,
        184,  216,
        34,
    };
    try mock.addResponse(&response);

    const channels = [_]Channel{mock.channel()};
    var resolver = StubResolver.init(allocator, .{
        .channels = &channels,
        .use_edns = false,
    });
    defer resolver.deinit();

    var answer = try resolver.resolve("example.com.", .a);
    defer answer.deinit(allocator);

    try std.testing.expectEqual(ResolveStatus.success, answer.status);
}
