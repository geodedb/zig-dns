// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Synchronization Shims (Zig 0.16.0)
//!
//! Single shared compatibility wrapper for code written against the
//! pre-0.16 `std.Thread.Mutex` API. Zig 0.16.0 moved the mutex to
//! `std.Io.Mutex`, whose lock/unlock operations require an `std.Io`
//! instance; this wrapper supplies the global single-threaded I/O
//! instance so call sites keep the simple `lock()`/`unlock()` shape.

const std = @import("std");

/// Zig 0.16.0-compatible mutex shim with 0.15.x-style `lock`/`unlock`
/// (and `tryLock`) API on top of `std.Io.Mutex`.
pub const Mutex = struct {
    inner: std.Io.Mutex = .init,

    pub fn lock(self: *Mutex) void {
        self.inner.lockUncancelable(std.Io.Threaded.global_single_threaded.io());
    }

    pub fn unlock(self: *Mutex) void {
        self.inner.unlock(std.Io.Threaded.global_single_threaded.io());
    }

    pub fn tryLock(self: *Mutex) bool {
        return self.inner.tryLock();
    }
};

test "Mutex lock/unlock does not deadlock" {
    var m: Mutex = .{};
    m.lock();
    m.unlock();
    // A second cycle proves unlock fully released the mutex.
    m.lock();
    m.unlock();
}

test "Mutex tryLock acquires and releases" {
    var m: Mutex = .{};
    try std.testing.expect(m.tryLock());
    m.unlock();
    m.lock();
    m.unlock();
}
