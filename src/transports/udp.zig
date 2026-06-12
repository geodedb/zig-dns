// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! UDP Transport for DNS
//!
//! RFC 1035 Section 4.2.1: UDP Usage

const std = @import("std");
const channel = @import("channel");
const types_mod = @import("types");
const net = @import("net_compat");

inline fn timeMilli() i64 {
    const io = std.Io.Threaded.global_single_threaded.io();
    return std.Io.Clock.Timestamp.now(io, .real).raw.toMilliseconds();
}

/// Remaining receive budget in milliseconds, or null when the deadline has
/// already passed. Used to shrink SO_RCVTIMEO after each discarded spurious
/// packet so a late off-source packet cannot reset the full timeout (REL-3).
fn remainingBudgetMs(start_ms: i64, now_ms: i64, timeout_ms: u32) ?u32 {
    const elapsed = now_ms - start_ms;
    if (elapsed >= @as(i64, timeout_ms)) return null;
    return @intCast(@as(i64, timeout_ms) - elapsed);
}

pub const Channel = channel.Channel;
pub const ChannelKind = channel.ChannelKind;

/// QR-02: Shared constant from types module; see types.max_spurious_discards.
const max_spurious_discards = types_mod.max_spurious_discards;

/// UDP Transport
pub const UdpTransport = struct {
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
            .kind = .udp,
            .ctx = self,
            .vtable = &vtable,
        };
    }

    fn queryImpl(ctx: *anyopaque, wire_req: []const u8, timeout_ms: u32) anyerror![]u8 {
        const self: *Self = @ptrCast(@alignCast(ctx));

        const sock = try net.socket(
            self.address.any.family,
            std.posix.SOCK.DGRAM,
            std.os.linux.IPPROTO.UDP,
        );
        defer net.close(sock);

        // Send query
        _ = try net.sendto(sock, wire_req, 0, &self.address.any, self.address.getOsSockLen());

        const start_ms = timeMilli();
        // SEC-AUDIT-02: Limit discarded packets to prevent CPU pinning from flood attacks.
        var discards = types_mod.SpuriousDiscardCounter{};
        while (true) {
            // REL-3: bound each recvfrom by the REMAINING budget, not the full
            // timeout. Otherwise a spurious off-source packet arriving just
            // before the deadline lets the next recvfrom block for another full
            // timeout (~2x the requested budget).
            const remaining_ms = remainingBudgetMs(start_ms, timeMilli(), timeout_ms) orelse
                return error.Timeout;
            const timeout = std.os.linux.timeval{
                .sec = @intCast(remaining_ms / 1000),
                .usec = @intCast((remaining_ms % 1000) * 1000),
            };
            try std.posix.setsockopt(sock, std.os.linux.SOL.SOCKET, std.os.linux.SO.RCVTIMEO, std.mem.asBytes(&timeout));

            // Receive response (capture source)
            // 4096 bytes matches EDNS default max payload (RFC 6891).
            // Responses exceeding this are truncated and fall back to TCP.
            var buffer: [4096]u8 = undefined;
            var src_addr: net.Address = undefined;
            var src_len: std.posix.socklen_t = @sizeOf(net.Address);
            const recv_len = net.recvfrom(sock, &buffer, 0, &src_addr.any, &src_len) catch |err| switch (err) {
                error.WouldBlock, error.ConnectionTimedOut => return error.Timeout,
                else => return err,
            };

            if (!net.Address.eql(src_addr, self.address)) {
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

test "REL-3: remainingBudgetMs shrinks toward the deadline and then expires" {
    // 4s elapsed of a 5s budget leaves 4s... (start=1000, now=2000 -> 1s elapsed).
    try std.testing.expectEqual(@as(?u32, 4000), remainingBudgetMs(1000, 2000, 5000));
    // 1ms left.
    try std.testing.expectEqual(@as(?u32, 1), remainingBudgetMs(1000, 5999, 5000));
    // Exactly at the deadline is expired (null), never a 0 timeval (which would
    // mean "block forever" for SO_RCVTIMEO).
    try std.testing.expectEqual(@as(?u32, null), remainingBudgetMs(1000, 6000, 5000));
    // Past the deadline is expired.
    try std.testing.expectEqual(@as(?u32, null), remainingBudgetMs(1000, 9000, 5000));
}
