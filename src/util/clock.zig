// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Clock Abstraction
//!
//! Provides a mockable clock interface for deterministic testing.

const std = @import("std");

/// Replacement for `std.time.timestamp` (seconds since epoch), which is
/// not present in Zig 0.16.0's `std.time`; wall-clock reads go through
/// `std.Io.Clock` instead. All modules should use this shim rather than
/// re-implementing it (GAP-0877).
pub fn timestamp() i64 {
    const io = std.Io.Threaded.global_single_threaded.io();
    return std.Io.Clock.Timestamp.now(io, .real).raw.toSeconds();
}

/// Replacement for `std.time.milliTimestamp` (ms since epoch), which is
/// not present in Zig 0.16.0's `std.time`; wall-clock reads go through
/// `std.Io.Clock` instead. All modules should use this shim rather than
/// re-implementing it (GAP-0877).
pub fn milliTimestamp() i64 {
    const io = std.Io.Threaded.global_single_threaded.io();
    return std.Io.Clock.Timestamp.now(io, .real).raw.toMilliseconds();
}

/// Clock interface for time operations
pub const Clock = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    const VTable = struct {
        now_fn: *const fn (ptr: *anyopaque) i64,
        now_ms_fn: *const fn (ptr: *anyopaque) i64,
    };

    /// Get current time as Unix timestamp (seconds since epoch)
    pub fn now(self: Clock) i64 {
        return self.vtable.now_fn(self.ptr);
    }

    /// Get current time in milliseconds since epoch
    pub fn nowMs(self: Clock) i64 {
        return self.vtable.now_ms_fn(self.ptr);
    }
};

/// System clock implementation using real time
pub const SystemClock = struct {
    const Self = @This();

    pub fn clock(self: *Self) Clock {
        return Clock{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    fn nowImpl(_: *anyopaque) i64 {
        return timestamp();
    }

    fn nowMsImpl(_: *anyopaque) i64 {
        return milliTimestamp();
    }

    const vtable = Clock.VTable{
        .now_fn = nowImpl,
        .now_ms_fn = nowMsImpl,
    };
};

/// Mock clock for deterministic testing
pub const MockClock = struct {
    current_time_s: i64,
    current_time_ms: i64,

    const Self = @This();

    /// Create a mock clock with fixed time
    /// Default: 2025-01-02T03:04:05Z (Unix timestamp: 1735790645)
    pub fn init() Self {
        return Self{
            .current_time_s = 1735790645,
            .current_time_ms = 1735790645000,
        };
    }

    /// Create with specific timestamp
    pub fn initWithTime(timestamp_s: i64) Self {
        return Self{
            .current_time_s = timestamp_s,
            .current_time_ms = timestamp_s * 1000,
        };
    }

    pub fn clock(self: *Self) Clock {
        return Clock{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    /// Advance time by seconds
    pub fn advance(self: *Self, seconds: i64) void {
        self.current_time_s += seconds;
        self.current_time_ms += seconds * 1000;
    }

    /// Advance time by milliseconds
    pub fn advanceMs(self: *Self, ms: i64) void {
        self.current_time_ms += ms;
        self.current_time_s = @divFloor(self.current_time_ms, 1000);
    }

    /// Set absolute time
    pub fn setTime(self: *Self, timestamp_s: i64) void {
        self.current_time_s = timestamp_s;
        self.current_time_ms = timestamp_s * 1000;
    }

    fn nowImpl(ptr: *anyopaque) i64 {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.current_time_s;
    }

    fn nowMsImpl(ptr: *anyopaque) i64 {
        const self: *Self = @ptrCast(@alignCast(ptr));
        return self.current_time_ms;
    }

    const vtable = Clock.VTable{
        .now_fn = nowImpl,
        .now_ms_fn = nowMsImpl,
    };
};

/// Get the default system clock
pub fn systemClock() SystemClock {
    return SystemClock{};
}

test "timestamp and milliTimestamp advance monotonically (within tolerance)" {
    const ms_first = milliTimestamp();
    const ms_second = milliTimestamp();
    // Wall clocks may be adjusted between reads; allow 1s of slack but
    // catch unit mix-ups (e.g. seconds returned where ms are expected).
    try std.testing.expect(ms_second >= ms_first - 1000);
    // Sanity: epoch ms must be far past 2001-09-09 (1e12 ms).
    try std.testing.expect(ms_first > 1_000_000_000_000);

    const s_first = timestamp();
    try std.testing.expect(s_first > 1_000_000_000); // past 2001 in seconds
    // Seconds and milliseconds shims must agree on the same epoch.
    try std.testing.expect(@abs(ms_first - s_first * 1000) < 10_000);
}

test "MockClock init" {
    var mock = MockClock.init();
    const clk = mock.clock();
    try std.testing.expectEqual(@as(i64, 1735790645), clk.now());
    try std.testing.expectEqual(@as(i64, 1735790645000), clk.nowMs());
}

test "MockClock advance" {
    var mock = MockClock.init();
    const clk = mock.clock();
    mock.advance(60);
    try std.testing.expectEqual(@as(i64, 1735790705), clk.now());
}
