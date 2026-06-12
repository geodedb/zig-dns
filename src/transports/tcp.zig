// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! TCP Transport for DNS
//!
//! RFC 1035 Section 4.2.2: TCP Usage

const std = @import("std");
const channel = @import("channel");
const io = @import("transport_io");
const net = @import("net_compat");

pub const Channel = channel.Channel;
pub const ChannelKind = channel.ChannelKind;

/// TCP Transport
pub const TcpTransport = struct {
    allocator: std.mem.Allocator,
    address: net.Address,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, host: []const u8, port: u16) !Self {
        return Self{
            .allocator = allocator,
            .address = try net.Address.parseIp4(host, port),
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

        const sock = try net.socket(
            self.address.any.family,
            std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
            std.os.linux.IPPROTO.TCP,
        );
        defer net.close(sock);

        // Connect
        try io.connectWithTimeout(sock, self.address, timeout_ms);

        // TCP DNS: 2-byte length prefix + payload as one write (GAP-0888).
        // Bounds check (SEC-SCAN-04, CWE-681) lives in writeFramedWithTimeout.
        try io.writeFramedWithTimeout(self.allocator, sock, wire_req, timeout_ms);

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
