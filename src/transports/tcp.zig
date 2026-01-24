// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! TCP Transport for DNS
//!
//! RFC 1035 Section 4.2.2: TCP Usage

const std = @import("std");
const channel = @import("channel");

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
        _ = timeout_ms;

        const sock = try std.posix.socket(
            self.address.any.family,
            std.posix.SOCK.STREAM,
            std.posix.IPPROTO.TCP,
        );
        defer std.posix.close(sock);

        // Connect
        try std.posix.connect(sock, &self.address.any, self.address.getOsSockLen());

        // TCP DNS: 2-byte length prefix
        var length_prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &length_prefix, @intCast(wire_req.len), .big);

        _ = try std.posix.write(sock, &length_prefix);
        _ = try std.posix.write(sock, wire_req);

        // Read response length
        var resp_len_buf: [2]u8 = undefined;
        _ = try std.posix.read(sock, &resp_len_buf);
        const resp_len = std.mem.readInt(u16, &resp_len_buf, .big);

        // Read response
        const response = try self.allocator.alloc(u8, resp_len);
        errdefer self.allocator.free(response);

        var total_read: usize = 0;
        while (total_read < resp_len) {
            const n = try std.posix.read(sock, response[total_read..]);
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

test "TcpTransport init" {
    const allocator = std.testing.allocator;
    var transport = try TcpTransport.init(allocator, "8.8.8.8", 53);
    _ = transport.channel();
}
