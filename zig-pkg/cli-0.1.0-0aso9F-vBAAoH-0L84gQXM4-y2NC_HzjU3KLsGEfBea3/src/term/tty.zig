// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # TTY Module
//!
//! Terminal detection and capabilities.

const std = @import("std");
const builtin = @import("builtin");

/// Terminal information
pub const TermInfo = struct {
    /// Whether stdout is a TTY
    is_tty: bool,
    /// Terminal width (columns)
    width: u16,
    /// Terminal height (rows)
    height: u16,
    /// Terminal type (from TERM env)
    term_type: ?[]const u8,
    /// Whether color is supported
    color_supported: bool,
    /// Whether unicode is supported
    unicode_supported: bool,
};

/// Get terminal information for stdout
pub fn getInfo() TermInfo {
    const stdout = std.fs.File.stdout();
    const is_tty = stdout.isTty();

    var width: u16 = 80;
    var height: u16 = 24;

    if (is_tty) {
        if (getTermSize()) |size| {
            width = size.cols;
            height = size.rows;
        }
    }

    const term_type = std.posix.getenv("TERM");
    const color_supported = is_tty and !isDumb(term_type) and !hasNoColor();

    return .{
        .is_tty = is_tty,
        .width = width,
        .height = height,
        .term_type = term_type,
        .color_supported = color_supported,
        .unicode_supported = is_tty and !isDumb(term_type),
    };
}

/// Terminal size
pub const TermSize = struct {
    cols: u16,
    rows: u16,
};

/// Get terminal size
pub fn getTermSize() ?TermSize {
    if (builtin.os.tag == .windows) {
        return getTermSizeWindows();
    } else {
        return getTermSizePosix();
    }
}

fn getTermSizePosix() ?TermSize {
    var ws: std.posix.winsize = undefined;
    if (std.posix.system.ioctl(std.fs.File.stdout().handle, std.posix.T.IOCGWINSZ, @intFromPtr(&ws)) == 0) {
        return .{
            .cols = ws.col,
            .rows = ws.row,
        };
    }
    return null;
}

fn getTermSizeWindows() ?TermSize {
    if (builtin.os.tag != .windows) {
        return null;
    }

    const windows = std.os.windows;
    const kernel32 = windows.kernel32;

    // CONSOLE_SCREEN_BUFFER_INFO structure
    const CONSOLE_SCREEN_BUFFER_INFO = extern struct {
        dwSize: windows.COORD,
        dwCursorPosition: windows.COORD,
        wAttributes: windows.WORD,
        srWindow: windows.SMALL_RECT,
        dwMaximumWindowSize: windows.COORD,
    };

    var csbi: CONSOLE_SCREEN_BUFFER_INFO = undefined;
    const stdout_handle = kernel32.GetStdHandle(windows.STD_OUTPUT_HANDLE);

    if (stdout_handle == windows.INVALID_HANDLE_VALUE) {
        return null;
    }

    // GetConsoleScreenBufferInfo
    const GetConsoleScreenBufferInfo = @as(*const fn (
        windows.HANDLE,
        *CONSOLE_SCREEN_BUFFER_INFO,
    ) callconv(windows.WINAPI) windows.BOOL, @ptrCast(@alignCast(
        kernel32.GetProcAddress(
            kernel32.GetModuleHandleW(std.unicode.utf8ToUtf16LeStringLiteral("kernel32.dll")),
            "GetConsoleScreenBufferInfo",
        ) orelse return null,
    )));

    if (GetConsoleScreenBufferInfo(stdout_handle, &csbi) == 0) {
        return null;
    }

    // Calculate visible window size
    const width = @as(u16, @intCast(csbi.srWindow.Right - csbi.srWindow.Left + 1));
    const height = @as(u16, @intCast(csbi.srWindow.Bottom - csbi.srWindow.Top + 1));

    if (width == 0 or height == 0) {
        return null;
    }

    return .{
        .cols = width,
        .rows = height,
    };
}

/// Check if TERM is dumb
fn isDumb(term: ?[]const u8) bool {
    if (term) |t| {
        return std.mem.eql(u8, t, "dumb");
    }
    return false;
}

/// Check if NO_COLOR is set
fn hasNoColor() bool {
    return std.posix.getenv("NO_COLOR") != null;
}

/// Check if stdout is a TTY
pub fn isStdoutTty() bool {
    return std.fs.File.stdout().isTty();
}

/// Check if stderr is a TTY
pub fn isStderrTty() bool {
    return std.fs.File.stderr().isTty();
}

/// Check if stdin is a TTY
pub fn isStdinTty() bool {
    return std.fs.File.stdin().isTty();
}

// ============================================================================
// Tests
// ============================================================================

test "getInfo returns valid struct" {
    const info = getInfo();
    try std.testing.expect(info.width > 0);
    try std.testing.expect(info.height > 0);
}

test "isDumb detection" {
    try std.testing.expect(isDumb("dumb"));
    try std.testing.expect(!isDumb("xterm-256color"));
    try std.testing.expect(!isDumb(null));
}
