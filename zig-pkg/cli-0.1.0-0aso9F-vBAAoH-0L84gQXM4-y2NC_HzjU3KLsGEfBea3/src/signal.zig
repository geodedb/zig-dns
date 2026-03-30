// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Signal Handling Module
//!
//! Cross-platform signal handling for graceful shutdown and interrupt handling.
//!
//! ## Usage
//!
//! ```zig
//! const signal = @import("cli").signal;
//!
//! pub fn main() !void {
//!     // Install default handlers
//!     signal.install(.{}) catch {};
//!
//!     while (!signal.wasInterrupted()) {
//!         // Do work...
//!     }
//!
//!     // Or register a custom cleanup handler
//!     signal.onCleanup(myCleanupFn);
//! }
//! ```

const std = @import("std");
const builtin = @import("builtin");

/// Signal types we handle
pub const Signal = enum {
    /// SIGINT (Ctrl+C)
    interrupt,
    /// SIGTERM
    terminate,
    /// SIGHUP
    hangup,
    /// SIGQUIT
    quit,
};

/// Signal handler configuration
pub const Config = struct {
    /// Handle SIGINT (Ctrl+C)
    handle_interrupt: bool = true,
    /// Handle SIGTERM
    handle_terminate: bool = true,
    /// Handle SIGHUP
    handle_hangup: bool = false,
    /// Handle SIGQUIT
    handle_quit: bool = false,
};

/// Cleanup callback function type
pub const CleanupFn = *const fn () void;

/// Global state for signal handling
var interrupted: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var terminated: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);
var cleanup_callbacks: [16]?CleanupFn = .{null} ** 16;
var callback_count: usize = 0;
var mutex: std.Thread.Mutex = .{};

/// Check if an interrupt signal was received (SIGINT)
pub fn wasInterrupted() bool {
    return interrupted.load(.acquire);
}

/// Check if a termination signal was received (SIGTERM)
pub fn wasTerminated() bool {
    return terminated.load(.acquire);
}

/// Check if any shutdown signal was received
pub fn shouldShutdown() bool {
    return wasInterrupted() or wasTerminated();
}

/// Register a cleanup callback to be called on signal
/// Returns error if max callbacks reached
pub fn onCleanup(callback: CleanupFn) !void {
    mutex.lock();
    defer mutex.unlock();

    if (callback_count >= cleanup_callbacks.len) {
        return error.TooManyCallbacks;
    }

    cleanup_callbacks[callback_count] = callback;
    callback_count += 1;
}

/// Clear the interrupted flag (useful for testing or restart scenarios)
pub fn clearInterrupted() void {
    interrupted.store(false, .release);
}

/// Clear the terminated flag
pub fn clearTerminated() void {
    terminated.store(false, .release);
}

/// Install signal handlers
pub fn install(config: Config) !void {
    if (builtin.os.tag == .windows) {
        try installWindows(config);
    } else {
        try installPosix(config);
    }
}

/// Uninstall signal handlers and restore defaults
pub fn uninstall() void {
    if (builtin.os.tag == .windows) {
        uninstallWindows();
    } else {
        uninstallPosix();
    }
}

// ============================================================================
// POSIX Implementation
// ============================================================================

fn installPosix(config: Config) !void {
    const handler = std.posix.Sigaction{
        .handler = .{ .handler = posixSignalHandler },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };

    if (config.handle_interrupt) {
        std.posix.sigaction(std.posix.SIG.INT, &handler, null);
    }
    if (config.handle_terminate) {
        std.posix.sigaction(std.posix.SIG.TERM, &handler, null);
    }
    if (config.handle_hangup) {
        std.posix.sigaction(std.posix.SIG.HUP, &handler, null);
    }
    if (config.handle_quit) {
        std.posix.sigaction(std.posix.SIG.QUIT, &handler, null);
    }
}

fn uninstallPosix() void {
    const default_handler = std.posix.Sigaction{
        .handler = .{ .handler = std.posix.SIG.DFL },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };

    std.posix.sigaction(std.posix.SIG.INT, &default_handler, null);
    std.posix.sigaction(std.posix.SIG.TERM, &default_handler, null);
    std.posix.sigaction(std.posix.SIG.HUP, &default_handler, null);
    std.posix.sigaction(std.posix.SIG.QUIT, &default_handler, null);
}

fn posixSignalHandler(sig: c_int) callconv(.c) void {
    switch (sig) {
        std.posix.SIG.INT => {
            interrupted.store(true, .release);
        },
        std.posix.SIG.TERM => {
            terminated.store(true, .release);
        },
        std.posix.SIG.HUP, std.posix.SIG.QUIT => {
            terminated.store(true, .release);
        },
        else => {},
    }

    // Run cleanup callbacks
    runCleanupCallbacks();
}

// ============================================================================
// Windows Implementation
// ============================================================================

fn installWindows(config: Config) !void {
    if (builtin.os.tag != .windows) {
        return;
    }

    _ = config;

    const windows = std.os.windows;
    const kernel32 = windows.kernel32;

    // SetConsoleCtrlHandler
    const SetConsoleCtrlHandler = @as(*const fn (
        ?*const fn (windows.DWORD) callconv(windows.WINAPI) windows.BOOL,
        windows.BOOL,
    ) callconv(windows.WINAPI) windows.BOOL, @ptrCast(@alignCast(
        kernel32.GetProcAddress(
            kernel32.GetModuleHandleW(std.unicode.utf8ToUtf16LeStringLiteral("kernel32.dll")),
            "SetConsoleCtrlHandler",
        ) orelse return error.FunctionNotFound,
    )));

    if (SetConsoleCtrlHandler(windowsCtrlHandler, 1) == 0) {
        return error.SetHandlerFailed;
    }
}

fn uninstallWindows() void {
    if (builtin.os.tag != .windows) {
        return;
    }

    const windows = std.os.windows;
    const kernel32 = windows.kernel32;

    const SetConsoleCtrlHandler = @as(*const fn (
        ?*const fn (windows.DWORD) callconv(windows.WINAPI) windows.BOOL,
        windows.BOOL,
    ) callconv(windows.WINAPI) windows.BOOL, @ptrCast(@alignCast(
        kernel32.GetProcAddress(
            kernel32.GetModuleHandleW(std.unicode.utf8ToUtf16LeStringLiteral("kernel32.dll")),
            "SetConsoleCtrlHandler",
        ) orelse return,
    )));

    _ = SetConsoleCtrlHandler(windowsCtrlHandler, 0);
}

fn windowsCtrlHandler(ctrl_type: std.os.windows.DWORD) callconv(std.os.windows.WINAPI) std.os.windows.BOOL {
    const CTRL_C_EVENT: std.os.windows.DWORD = 0;
    const CTRL_BREAK_EVENT: std.os.windows.DWORD = 1;
    const CTRL_CLOSE_EVENT: std.os.windows.DWORD = 2;

    switch (ctrl_type) {
        CTRL_C_EVENT, CTRL_BREAK_EVENT => {
            interrupted.store(true, .release);
            runCleanupCallbacks();
            return 1; // TRUE - handled
        },
        CTRL_CLOSE_EVENT => {
            terminated.store(true, .release);
            runCleanupCallbacks();
            return 1; // TRUE - handled
        },
        else => return 0, // FALSE - not handled
    }
}

// ============================================================================
// Shared Helpers
// ============================================================================

fn runCleanupCallbacks() void {
    // Note: Called from signal handler context, must be async-signal-safe
    // We only read the array, no locking needed
    for (cleanup_callbacks[0..callback_count]) |maybe_cb| {
        if (maybe_cb) |cb| {
            cb();
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

test "initial state is not interrupted" {
    clearInterrupted();
    clearTerminated();
    try std.testing.expect(!wasInterrupted());
    try std.testing.expect(!wasTerminated());
    try std.testing.expect(!shouldShutdown());
}

test "install and uninstall handlers" {
    if (builtin.os.tag == .windows) {
        // Skip on Windows in test environment
        return;
    }

    try install(.{});
    uninstall();
}

test "register cleanup callback" {
    // Reset state for test
    callback_count = 0;
    cleanup_callbacks = .{null} ** 16;

    const cb = struct {
        fn callback() void {
            // Placeholder - actual test would verify this was called
        }
    }.callback;

    try onCleanup(cb);
    try std.testing.expectEqual(@as(usize, 1), callback_count);
}
