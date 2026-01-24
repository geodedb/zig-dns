// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Clock Abstraction
//!
//! Provides a mockable clock interface for deterministic testing.

const std = @import("std");

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
        return std.time.timestamp();
    }

    fn nowMsImpl(_: *anyopaque) i64 {
        return std.time.milliTimestamp();
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
