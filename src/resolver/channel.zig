// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Channel Abstraction for DNS Transports
//!
//! Provides a unified interface for UDP, TCP, DoT, DoH, and DoQ transports.

const std = @import("std");

/// Channel transport type
pub const ChannelKind = enum {
    udp,
    tcp,
    dot,
    doh,
    doq,

    pub fn toString(self: ChannelKind) []const u8 {
        return switch (self) {
            .udp => "UDP",
            .tcp => "TCP",
            .dot => "DoT",
            .doh => "DoH",
            .doq => "DoQ",
        };
    }

    pub fn defaultPort(self: ChannelKind) u16 {
        return switch (self) {
            .udp, .tcp => 53,
            .dot, .doq => 853,
            .doh => 443,
        };
    }
};

/// DNS transport channel
pub const Channel = struct {
    kind: ChannelKind,
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        query: *const fn (ctx: *anyopaque, wire_req: []const u8, timeout_ms: u32) anyerror![]u8,
        close: *const fn (ctx: *anyopaque) void,
    };

    const Self = @This();

    /// Send a DNS query and receive response
    pub fn query(self: Self, wire_req: []const u8, timeout_ms: u32) ![]u8 {
        return self.vtable.query(self.ctx, wire_req, timeout_ms);
    }

    /// Close the channel
    pub fn close(self: Self) void {
        self.vtable.close(self.ctx);
    }
};

/// Socket Address
pub const SocketAddress = struct {
    host: []const u8,
    port: u16,

    pub fn init(host: []const u8, port: u16) SocketAddress {
        return .{ .host = host, .port = port };
    }
};

/// DNS over TLS options
pub const DoTOptions = struct {
    server_name: []const u8,
    addr: SocketAddress,
    ca_pem: []const u8,
    alpn_dot: []const u8 = "dot",
    /// Explicitly use system CA trust store (SEC-GAP-057: CWE-295)
    /// If false and ca_pem is empty, connection will fail
    use_system_ca: bool = false,
};

/// DNS over HTTPS options
pub const DoHOptions = struct {
    uri: []const u8,
    ca_pem: []const u8,
    bootstrap_ip: ?SocketAddress = null,
    prefer_get: bool = true,
};

/// DNS over QUIC options
pub const DoQOptions = struct {
    server_name: []const u8,
    addr: SocketAddress,
    ca_pem: []const u8,
    alpn_doq: []const u8 = "doq",
};

/// Mock channel for testing
pub const MockChannel = struct {
    allocator: std.mem.Allocator,
    kind: ChannelKind,
    responses: std.ArrayList([]const u8),
    response_index: usize,
    queries: std.ArrayList([]u8),
    closed: bool,
    // Mock TLS handshake info
    handshake_alpn: ?[]const u8,
    handshake_sni: ?[]const u8,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, kind: ChannelKind) Self {
        return Self{
            .allocator = allocator,
            .kind = kind,
            .responses = .empty,
            .response_index = 0,
            .queries = .empty,
            .closed = false,
            .handshake_alpn = null,
            .handshake_sni = null,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.responses.items) |r| {
            self.allocator.free(r);
        }
        self.responses.deinit(self.allocator);

        for (self.queries.items) |q| {
            self.allocator.free(q);
        }
        self.queries.deinit(self.allocator);
    }

    pub fn addResponse(self: *Self, response: []const u8) !void {
        const copy = try self.allocator.dupe(u8, response);
        try self.responses.append(self.allocator, copy);
    }

    pub fn setHandshakeInfo(self: *Self, alpn: []const u8, sni: []const u8) void {
        self.handshake_alpn = alpn;
        self.handshake_sni = sni;
    }

    pub fn channel(self: *Self) Channel {
        return Channel{
            .kind = self.kind,
            .ctx = self,
            .vtable = &vtable,
        };
    }

    pub fn getQueries(self: *Self) []const []u8 {
        return self.queries.items;
    }

    /// Get handshake info as JSON for testing
    pub fn handshakeInfoJson(self: *Self, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator,
            \\{{"alpn":["{s}"],"sni":"{s}","tls_version":"1.3"}}
        , .{
            self.handshake_alpn orelse "",
            self.handshake_sni orelse "",
        });
    }

    fn queryImpl(ctx: *anyopaque, wire_req: []const u8, timeout_ms: u32) anyerror![]u8 {
        _ = timeout_ms;
        const self: *Self = @ptrCast(@alignCast(ctx));

        const query_copy = try self.allocator.dupe(u8, wire_req);
        try self.queries.append(self.allocator, query_copy);

        if (self.response_index >= self.responses.items.len) {
            return error.Timeout;
        }

        const response = self.responses.items[self.response_index];
        self.response_index += 1;

        return try self.allocator.dupe(u8, response);
    }

    fn closeImpl(ctx: *anyopaque) void {
        const self: *Self = @ptrCast(@alignCast(ctx));
        self.closed = true;
    }

    const vtable = Channel.VTable{
        .query = queryImpl,
        .close = closeImpl,
    };
};

test "MockChannel basic" {
    const allocator = std.testing.allocator;

    var mock = MockChannel.init(allocator, .udp);
    defer mock.deinit();

    try mock.addResponse(&[_]u8{ 0x00, 0x01, 0x02 });

    const ch = mock.channel();
    const response = try ch.query(&[_]u8{ 0xAA, 0xBB }, 1000);
    defer allocator.free(response);

    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x01, 0x02 }, response);
}

test "ChannelKind" {
    try std.testing.expectEqual(@as(u16, 53), ChannelKind.udp.defaultPort());
    try std.testing.expectEqual(@as(u16, 853), ChannelKind.dot.defaultPort());
    try std.testing.expectEqualStrings("DoT", ChannelKind.dot.toString());
}
