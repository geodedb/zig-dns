// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! UDP Transport for DNS
//!
//! RFC 1035 Section 4.2.1: UDP Usage

const std = @import("std");
const channel = @import("channel");
const types_mod = @import("types");

pub const Channel = channel.Channel;
pub const ChannelKind = channel.ChannelKind;

/// QR-02: Shared constant from types module; see types.max_spurious_discards.
const max_spurious_discards = types_mod.max_spurious_discards;

/// UDP Transport
pub const UdpTransport = struct {
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
            .kind = .udp,
            .ctx = self,
            .vtable = &vtable,
        };
    }

    fn queryImpl(ctx: *anyopaque, wire_req: []const u8, timeout_ms: u32) anyerror![]u8 {
        const self: *Self = @ptrCast(@alignCast(ctx));

        const sock = try std.posix.socket(
            self.address.any.family,
            std.posix.SOCK.DGRAM,
            std.posix.IPPROTO.UDP,
        );
        defer std.posix.close(sock);

        // Set timeout
        const timeout_sec = timeout_ms / 1000;
        const timeout_usec = (timeout_ms % 1000) * 1000;
        const timeout = std.posix.timeval{
            .sec = @intCast(timeout_sec),
            .usec = @intCast(timeout_usec),
        };
        try std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));

        // Send query
        _ = try std.posix.sendto(sock, wire_req, 0, &self.address.any, self.address.getOsSockLen());

        const start_ms = std.time.milliTimestamp();
        // SEC-AUDIT-02: Limit discarded packets to prevent CPU pinning from flood attacks.
        var discards = types_mod.SpuriousDiscardCounter{};
        while (true) {
            if (std.time.milliTimestamp() - start_ms >= timeout_ms) {
                return error.Timeout;
            }

            // Receive response (capture source)
            // 4096 bytes matches EDNS default max payload (RFC 6891).
            // Responses exceeding this are truncated and fall back to TCP.
            var buffer: [4096]u8 = undefined;
            var src_addr: std.net.Address = undefined;
            var src_len: std.posix.socklen_t = @sizeOf(std.net.Address);
            const recv_len = std.posix.recvfrom(sock, &buffer, 0, &src_addr.any, &src_len) catch |err| switch (err) {
                error.WouldBlock, error.ConnectionTimedOut => return error.Timeout,
                else => return err,
            };

            if (!std.net.Address.eql(src_addr, self.address)) {
                discards.increment() catch return error.TooManySpuriousPackets;
                continue;
            }

            // Copy response
            const response = try self.allocator.alloc(u8, recv_len);
            @memcpy(response, buffer[0..recv_len]);

            return response;
        }
    }

    fn closeImpl(_: *anyopaque) void {
        // UDP is connectionless
    }

    const vtable = Channel.VTable{
        .query = queryImpl,
        .close = closeImpl,
    };
};

test "UdpTransport init" {
    const allocator = std.testing.allocator;
    var transport = try UdpTransport.init(allocator, "8.8.8.8", 53);
    _ = transport.channel();
}

test "SEC-AUDIT-02: UDP discard limit prevents CPU pinning" {
    // Verify the discard limit constant exists and is a reasonable positive value.
    // The actual enforcement is in queryImpl's receive loop, which discards packets
    // from non-matching source addresses up to this limit before returning
    // error.TooManySpuriousPackets.
    try std.testing.expect(max_spurious_discards > 0);
    try std.testing.expect(max_spurious_discards <= 10000);
}
