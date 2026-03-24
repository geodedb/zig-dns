// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! TCP Transport for DNS
//!
//! RFC 1035 Section 4.2.2: TCP Usage

const std = @import("std");
const channel = @import("channel");
const io = @import("transport_io");

pub const Channel = channel.Channel;
pub const ChannelKind = channel.ChannelKind;

/// TCP Transport
pub const TcpTransport = struct {
    allocator: std.mem.Allocator,
    address: std.net.Address,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, host: []const u8, port: u16) !Self {
        return Self{
            .allocator = allocator,
            .address = try std.net.Address.parseIp4(host, port),
        };
    }

    pub fn channel(self: *Self) Channel {
        return Channel{
            .kind = .tcp,
            .ctx = self,
            .vtable = &vtable,
        };
    }

    fn queryImpl(ctx: *anyopaque, wire_req: []const u8, timeout_ms: u32) anyerror![]u8 {
        const self: *Self = @ptrCast(@alignCast(ctx));

        const sock = try std.posix.socket(
            self.address.any.family,
            std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
            std.posix.IPPROTO.TCP,
        );
        defer std.posix.close(sock);

        // Connect
        try io.connectWithTimeout(sock, self.address, timeout_ms);

        // TCP DNS: 2-byte length prefix
        // SECURITY (SEC-SCAN-04): Bounds check before @intCast to u16 (CWE-681)
        if (wire_req.len > std.math.maxInt(u16)) return error.MessageTooLong;
        var length_prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &length_prefix, @intCast(wire_req.len), .big);

        try io.writeAllWithTimeout(sock, &length_prefix, timeout_ms);
        try io.writeAllWithTimeout(sock, wire_req, timeout_ms);

        // Read response length
        var resp_len_buf: [2]u8 = undefined;
        try io.readExactWithTimeout(sock, &resp_len_buf, timeout_ms);
        const resp_len = std.mem.readInt(u16, &resp_len_buf, .big);
        if (resp_len == 0 or resp_len > max_message_size) {
            return error.MessageTooLarge;
        }

        // Read response
        const response = try self.allocator.alloc(u8, resp_len);
        errdefer self.allocator.free(response);

        var total_read: usize = 0;
        while (total_read < resp_len) {
            const n = try io.readWithTimeout(sock, response[total_read..], timeout_ms);
            if (n == 0) return error.ConnectionClosed;
            total_read += n;
        }

        return response;
    }

    fn closeImpl(_: *anyopaque) void {
        // Connection closed after each query
    }

    const vtable = Channel.VTable{
        .query = queryImpl,
        .close = closeImpl,
    };
};

const max_message_size: usize = 65535;

test "TcpTransport init" {
    const allocator = std.testing.allocator;
    var transport = try TcpTransport.init(allocator, "8.8.8.8", 53);
    _ = transport.channel();
}
