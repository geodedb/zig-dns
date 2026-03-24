// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Shared I/O helpers for TCP-based DNS transports
//!
//! Provides timeout-aware connect, write, and read operations on non-blocking
//! POSIX sockets using poll(). Used by stub resolver, TCP transport, and
//! connection pool to avoid duplicating the same logic.

const std = @import("std");

/// Connect a non-blocking socket with a timeout.
///
/// On non-blocking sockets:
///   - EINPROGRESS (mapped to WouldBlock by Zig) = connection initiated, poll for completion
///   - EALREADY (mapped to ConnectionPending) = previous connect still in progress
/// Both are expected for non-blocking connect and should fall through to poll().
pub fn connectWithTimeout(sock: std.posix.socket_t, address: std.net.Address, timeout_ms: u32) !void {
    std.posix.connect(sock, &address.any, address.getOsSockLen()) catch |err| switch (err) {
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
    try std.posix.getsockoptError(sock);
}

/// Write all data to a non-blocking socket with a deadline-based timeout.
///
/// Polls for writability and retries partial writes until all data is sent
/// or the deadline is exceeded.
pub fn writeAllWithTimeout(sock: std.posix.socket_t, data: []const u8, timeout_ms: u32) !void {
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

/// Read from a non-blocking socket with a deadline-based timeout.
///
/// Polls for readability and returns the number of bytes read (may be less
/// than the buffer size). Returns 0 only if the peer closed the connection.
pub fn readWithTimeout(sock: std.posix.socket_t, buffer: []u8, timeout_ms: u32) !usize {
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
    defer std.posix.close(pair[0]);
    defer std.posix.close(pair[1]);

    const data = "Hello, DNS transport!";
    try writeAllWithTimeout(pair[0], data, 5000);

    var buf: [64]u8 = undefined;
    const n = try readWithTimeout(pair[1], &buf, 5000);
    try std.testing.expectEqualStrings(data, buf[0..n]);
}

test "readExactWithTimeout reads exact number of bytes" {
    const pair = try testSocketPair();
    defer std.posix.close(pair[0]);
    defer std.posix.close(pair[1]);

    const data = "exact-read-test";
    try writeAllWithTimeout(pair[0], data, 5000);

    var buf: [15]u8 = undefined;
    try readExactWithTimeout(pair[1], &buf, 5000);
    try std.testing.expectEqualStrings(data, &buf);
}

test "readExactWithTimeout returns ConnectionClosed on early EOF" {
    const pair = try testSocketPair();
    defer std.posix.close(pair[1]);

    // Write partial data then close the write end
    try writeAllWithTimeout(pair[0], "short", 5000);
    std.posix.close(pair[0]);

    // Try to read more than was written
    var buf: [20]u8 = undefined;
    const result = readExactWithTimeout(pair[1], &buf, 5000);
    try std.testing.expectError(error.ConnectionClosed, result);
}

test "writeAllWithTimeout handles partial writes" {
    const pair = try testSocketPair();
    defer std.posix.close(pair[0]);
    defer std.posix.close(pair[1]);

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
