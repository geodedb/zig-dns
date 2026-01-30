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

        const sock = try std.posix.socket(
            self.address.any.family,
            std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK,
            std.posix.IPPROTO.TCP,
        );
        defer std.posix.close(sock);

        // Connect
        try connectWithTimeout(sock, self.address, timeout_ms);

        // TCP DNS: 2-byte length prefix
        var length_prefix: [2]u8 = undefined;
        std.mem.writeInt(u16, &length_prefix, @intCast(wire_req.len), .big);

        try writeAllWithTimeout(sock, &length_prefix, timeout_ms);
        try writeAllWithTimeout(sock, wire_req, timeout_ms);

        // Read response length
        var resp_len_buf: [2]u8 = undefined;
        try readExactWithTimeout(sock, &resp_len_buf, timeout_ms);
        const resp_len = std.mem.readInt(u16, &resp_len_buf, .big);
        if (resp_len == 0 or resp_len > max_message_size) {
            return error.MessageTooLarge;
        }

        // Read response
        const response = try self.allocator.alloc(u8, resp_len);
        errdefer self.allocator.free(response);

        var total_read: usize = 0;
        while (total_read < resp_len) {
            const n = try readWithTimeout(sock, response[total_read..], timeout_ms);
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

fn connectWithTimeout(sock: std.posix.socket_t, address: std.net.Address, timeout_ms: u32) !void {
    std.posix.connect(sock, &address.any, address.getOsSockLen()) catch |err| switch (err) {
        error.WouldBlock, error.InProgress => {},
        else => return err,
    };

    var poll_fds = [_]std.posix.pollfd{.{
        .fd = sock,
        .events = std.posix.POLL.OUT,
        .revents = 0,
    }};
    const rc = try std.posix.poll(&poll_fds, @intCast(timeout_ms));
    if (rc == 0) return error.Timeout;
    if ((poll_fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP)) != 0) {
        return error.ConnectionClosed;
    }
    try std.posix.getsockoptError(sock);
}

fn writeAllWithTimeout(sock: std.posix.socket_t, data: []const u8, timeout_ms: u32) !void {
    var sent: usize = 0;
    const deadline = std.time.milliTimestamp() + timeout_ms;
    while (sent < data.len) {
        const now = std.time.milliTimestamp();
        if (now >= deadline) return error.Timeout;
        const remaining: i32 = @intCast(@max(@as(i64, 0), deadline - now));

        var poll_fds = [_]std.posix.pollfd{.{
            .fd = sock,
            .events = std.posix.POLL.OUT,
            .revents = 0,
        }};
        const rc = try std.posix.poll(&poll_fds, remaining);
        if (rc == 0) return error.Timeout;
        if ((poll_fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP)) != 0) {
            return error.ConnectionClosed;
        }

        const n = std.posix.write(sock, data[sent..]) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        sent += n;
    }
}

fn readWithTimeout(sock: std.posix.socket_t, buffer: []u8, timeout_ms: u32) !usize {
    const deadline = std.time.milliTimestamp() + timeout_ms;
    while (true) {
        const now = std.time.milliTimestamp();
        if (now >= deadline) return error.Timeout;
        const remaining: i32 = @intCast(@max(@as(i64, 0), deadline - now));

        var poll_fds = [_]std.posix.pollfd{.{
            .fd = sock,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const rc = try std.posix.poll(&poll_fds, remaining);
        if (rc == 0) return error.Timeout;
        if ((poll_fds[0].revents & (std.posix.POLL.ERR | std.posix.POLL.HUP)) != 0) {
            return error.ConnectionClosed;
        }

        return std.posix.read(sock, buffer) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
    }
}

fn readExactWithTimeout(sock: std.posix.socket_t, buffer: []u8, timeout_ms: u32) !void {
    var read_total: usize = 0;
    while (read_total < buffer.len) {
        const n = try readWithTimeout(sock, buffer[read_total..], timeout_ms);
        if (n == 0) return error.ConnectionClosed;
        read_total += n;
    }
}

test "TcpTransport init" {
    const allocator = std.testing.allocator;
    var transport = try TcpTransport.init(allocator, "8.8.8.8", 53);
    _ = transport.channel();
}
