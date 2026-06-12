// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Shared I/O helpers for TCP-based DNS transports
//!
//! Provides timeout-aware connect, write, and read operations on non-blocking
//! POSIX sockets using poll(). Used by stub resolver, TCP transport, and
//! connection pool to avoid duplicating the same logic.

const std = @import("std");
const net = @import("net_compat");
const clock = @import("clock");

inline fn timeMilli() i64 {
    return clock.milliTimestamp();
}

/// Connect a non-blocking socket with a timeout.
///
/// On non-blocking sockets:
///   - EINPROGRESS (mapped to WouldBlock by Zig) = connection initiated, poll for completion
///   - EALREADY (mapped to ConnectionPending) = previous connect still in progress
/// Both are expected for non-blocking connect and should fall through to poll().
pub fn connectWithTimeout(sock: std.posix.socket_t, address: net.Address, timeout_ms: u32) !void {
    net.connect(sock, &address.any, address.getOsSockLen()) catch |err| switch (err) {
        error.WouldBlock, error.ConnectionPending => {},
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
    try net.getsockoptError(sock);
}

/// Write all data to a non-blocking socket with a deadline-based timeout.
///
/// Polls for writability and retries partial writes until all data is sent
/// or the deadline is exceeded.
pub fn writeAllWithTimeout(sock: std.posix.socket_t, data: []const u8, timeout_ms: u32) !void {
    var sent: usize = 0;
    const deadline = timeMilli() + timeout_ms;
    while (sent < data.len) {
        const now = timeMilli();
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

        const n = net.write(sock, data[sent..]) catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return err,
        };
        sent += n;
    }
}

/// Maximum payload kept on the stack by writeFramedWithTimeout's fast
/// path. Covers every DNS query this library builds (max_query_size is
/// 282 bytes) plus standard 512-byte UDP-sized messages.
pub const framed_stack_payload_max: usize = 514;

/// Write a TCP-framed DNS message -- 2-byte big-endian length prefix
/// followed by the payload -- as a SINGLE write (GAP-0888).
///
/// Sending the prefix and payload as two writeAllWithTimeout calls under
/// TCP_NODELAY produces two TCP segments and two syscalls per query;
/// coalescing them into one buffer halves both. Payloads up to
/// framed_stack_payload_max use a stack buffer; larger payloads fall back
/// to a transient heap allocation.
pub fn writeFramedWithTimeout(
    allocator: std.mem.Allocator,
    sock: std.posix.socket_t,
    payload: []const u8,
    timeout_ms: u32,
) !void {
    // SECURITY (SEC-SCAN-04): Bounds check before @intCast to u16 (CWE-681)
    if (payload.len > std.math.maxInt(u16)) return error.MessageTooLong;

    if (payload.len <= framed_stack_payload_max) {
        var buf: [2 + framed_stack_payload_max]u8 = undefined;
        std.mem.writeInt(u16, buf[0..2], @intCast(payload.len), .big);
        @memcpy(buf[2..][0..payload.len], payload);
        return writeAllWithTimeout(sock, buf[0 .. 2 + payload.len], timeout_ms);
    }

    const buf = try allocator.alloc(u8, 2 + payload.len);
    defer allocator.free(buf);
    std.mem.writeInt(u16, buf[0..2], @intCast(payload.len), .big);
    @memcpy(buf[2..], payload);
    return writeAllWithTimeout(sock, buf, timeout_ms);
}

/// Read from a non-blocking socket with a deadline-based timeout.
///
/// Polls for readability and returns the number of bytes read (may be less
/// than the buffer size). Returns 0 only if the peer closed the connection.
pub fn readWithTimeout(sock: std.posix.socket_t, buffer: []u8, timeout_ms: u32) !usize {
    const deadline = timeMilli() + timeout_ms;
    while (true) {
        const now = timeMilli();
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

/// Read exactly `buffer.len` bytes from a non-blocking socket with a timeout.
///
/// Calls readWithTimeout repeatedly until the buffer is completely filled.
/// Returns error.ConnectionClosed if the peer closes before all bytes arrive.
pub fn readExactWithTimeout(sock: std.posix.socket_t, buffer: []u8, timeout_ms: u32) !void {
    var read_total: usize = 0;
    while (read_total < buffer.len) {
        const n = try readWithTimeout(sock, buffer[read_total..], timeout_ms);
        if (n == 0) return error.ConnectionClosed;
        read_total += n;
    }
}

// ============================================================================
// Tests
// ============================================================================

const builtin = @import("builtin");

/// Create a UNIX socketpair for testing. Returns [2]fd_t.
/// std.posix does not expose socketpair, so we use the Linux syscall directly.
/// Public so other transport test modules can reuse it instead of duplicating.
pub fn testSocketPair() ![2]std.posix.fd_t {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const sock_type: i32 = std.posix.SOCK.STREAM | std.posix.SOCK.NONBLOCK;
    var fds: [2]i32 = undefined;
    const rc = std.os.linux.socketpair(std.posix.AF.UNIX, sock_type, 0, &fds);
    const errno = std.posix.errno(rc);
    if (errno != .SUCCESS) return error.SocketPairFailed;
    return fds;
}

test "writeAllWithTimeout writes full buffer through socketpair" {
    const pair = try testSocketPair();
    defer _ = std.os.linux.close(pair[0]);
    defer _ = std.os.linux.close(pair[1]);

    const data = "Hello, DNS transport!";
    try writeAllWithTimeout(pair[0], data, 5000);

    var buf: [64]u8 = undefined;
    const n = try readWithTimeout(pair[1], &buf, 5000);
    try std.testing.expectEqualStrings(data, buf[0..n]);
}

test "readExactWithTimeout reads exact number of bytes" {
    const pair = try testSocketPair();
    defer _ = std.os.linux.close(pair[0]);
    defer _ = std.os.linux.close(pair[1]);

    const data = "exact-read-test";
    try writeAllWithTimeout(pair[0], data, 5000);

    var buf: [15]u8 = undefined;
    try readExactWithTimeout(pair[1], &buf, 5000);
    try std.testing.expectEqualStrings(data, &buf);
}

test "readExactWithTimeout returns ConnectionClosed on early EOF" {
    const pair = try testSocketPair();
    defer _ = std.os.linux.close(pair[1]);

    // Write partial data then close the write end
    try writeAllWithTimeout(pair[0], "short", 5000);
    _ = std.os.linux.close(pair[0]);

    // Try to read more than was written
    var buf: [20]u8 = undefined;
    const result = readExactWithTimeout(pair[1], &buf, 5000);
    try std.testing.expectError(error.ConnectionClosed, result);
}

test "GAP-0888: writeFramedWithTimeout sends prefix and payload as one frame" {
    const pair = try testSocketPair();
    defer _ = std.os.linux.close(pair[0]);
    defer _ = std.os.linux.close(pair[1]);

    const payload = "framed-dns-query";
    try writeFramedWithTimeout(std.testing.allocator, pair[0], payload, 5000);

    var buf: [64]u8 = undefined;
    var total: usize = 0;
    while (total < 2 + payload.len) {
        const n = try readWithTimeout(pair[1], buf[total..], 5000);
        if (n == 0) break;
        total += n;
    }
    try std.testing.expectEqual(@as(usize, 2 + payload.len), total);
    try std.testing.expectEqual(
        @as(u16, payload.len),
        std.mem.readInt(u16, buf[0..2], .big),
    );
    try std.testing.expectEqualStrings(payload, buf[2..total]);
}

test "GAP-0888: writeFramedWithTimeout heap fallback for large payloads" {
    const pair = try testSocketPair();
    defer _ = std.os.linux.close(pair[0]);
    defer _ = std.os.linux.close(pair[1]);

    // Larger than the stack fast-path threshold.
    var payload: [2048]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);

    try writeFramedWithTimeout(std.testing.allocator, pair[0], &payload, 5000);

    var buf: [4096]u8 = undefined;
    var total: usize = 0;
    while (total < 2 + payload.len) {
        const n = try readWithTimeout(pair[1], buf[total..], 5000);
        if (n == 0) break;
        total += n;
    }
    try std.testing.expectEqual(@as(usize, 2 + payload.len), total);
    try std.testing.expectEqual(
        @as(u16, payload.len),
        std.mem.readInt(u16, buf[0..2], .big),
    );
    try std.testing.expectEqualSlices(u8, &payload, buf[2..total]);
}

test "GAP-0888: writeFramedWithTimeout rejects oversized payloads" {
    const pair = try testSocketPair();
    defer _ = std.os.linux.close(pair[0]);
    defer _ = std.os.linux.close(pair[1]);

    const oversized = try std.testing.allocator.alloc(u8, 65536);
    defer std.testing.allocator.free(oversized);
    @memset(oversized, 0);

    try std.testing.expectError(
        error.MessageTooLong,
        writeFramedWithTimeout(std.testing.allocator, pair[0], oversized, 5000),
    );
}

test "writeAllWithTimeout handles partial writes" {
    const pair = try testSocketPair();
    defer _ = std.os.linux.close(pair[0]);
    defer _ = std.os.linux.close(pair[1]);

    // Write a larger buffer to exercise partial-write path
    var data: [8192]u8 = undefined;
    for (&data) |*b| b.* = 0xAB;

    try writeAllWithTimeout(pair[0], &data, 5000);

    // Read it all back
    var total_read: usize = 0;
    var recv: [8192]u8 = undefined;
    while (total_read < data.len) {
        const n = try readWithTimeout(pair[1], recv[total_read..], 5000);
        if (n == 0) break;
        total_read += n;
    }
    try std.testing.expectEqual(data.len, total_read);
    try std.testing.expectEqualSlices(u8, &data, recv[0..total_read]);
}
