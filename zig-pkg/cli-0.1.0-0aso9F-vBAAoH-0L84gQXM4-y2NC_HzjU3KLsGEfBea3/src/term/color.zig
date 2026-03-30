// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Color Module
//!
//! ANSI color codes and formatting for terminal output.

const std = @import("std");
const tty = @import("tty.zig");

/// ANSI color codes
pub const Color = enum(u8) {
    black = 30,
    red = 31,
    green = 32,
    yellow = 33,
    blue = 34,
    magenta = 35,
    cyan = 36,
    white = 37,
    default = 39,

    // Bright variants
    bright_black = 90,
    bright_red = 91,
    bright_green = 92,
    bright_yellow = 93,
    bright_blue = 94,
    bright_magenta = 95,
    bright_cyan = 96,
    bright_white = 97,
};

/// Text styles
pub const Style = enum(u8) {
    reset = 0,
    bold = 1,
    dim = 2,
    italic = 3,
    underline = 4,
    blink = 5,
    reverse = 7,
    hidden = 8,
    strikethrough = 9,
};

/// Color context for conditional coloring
pub const ColorContext = struct {
    enabled: bool,

    const Self = @This();

    /// Create a new color context
    pub fn init(force_color: ?bool, no_color: bool) Self {
        const enabled = if (force_color) |f| f else blk: {
            if (no_color) break :blk false;
            if (std.posix.getenv("NO_COLOR") != null) break :blk false;
            if (std.posix.getenv("TERM")) |term| {
                if (std.mem.eql(u8, term, "dumb")) break :blk false;
            }
            break :blk tty.isStdoutTty();
        };

        return .{ .enabled = enabled };
    }

    /// Format text with color
    pub fn colored(self: Self, text: []const u8, color: Color) []const u8 {
        if (!self.enabled) return text;
        // In practice, we'd allocate and format
        _ = color;
        return text;
    }

    /// Format text with style
    pub fn styled(self: Self, text: []const u8, style: Style) []const u8 {
        if (!self.enabled) return text;
        _ = style;
        return text;
    }

    /// Write colored text to writer
    pub fn writeColored(self: Self, writer: anytype, text: []const u8, color: Color) !void {
        if (self.enabled) {
            try writer.print("\x1b[{d}m{s}\x1b[0m", .{ @intFromEnum(color), text });
        } else {
            try writer.print("{s}", .{text});
        }
    }

    /// Write styled text to writer
    pub fn writeStyled(self: Self, writer: anytype, text: []const u8, style: Style) !void {
        if (self.enabled) {
            try writer.print("\x1b[{d}m{s}\x1b[0m", .{ @intFromEnum(style), text });
        } else {
            try writer.print("{s}", .{text});
        }
    }
};

/// Get escape sequence for color
pub fn colorCode(color: Color) []const u8 {
    return switch (color) {
        .red => "\x1b[31m",
        .green => "\x1b[32m",
        .yellow => "\x1b[33m",
        .blue => "\x1b[34m",
        .magenta => "\x1b[35m",
        .cyan => "\x1b[36m",
        .white => "\x1b[37m",
        .black => "\x1b[30m",
        .default => "\x1b[39m",
        .bright_red => "\x1b[91m",
        .bright_green => "\x1b[92m",
        .bright_yellow => "\x1b[93m",
        .bright_blue => "\x1b[94m",
        .bright_magenta => "\x1b[95m",
        .bright_cyan => "\x1b[96m",
        .bright_white => "\x1b[97m",
        .bright_black => "\x1b[90m",
    };
}

/// Reset sequence
pub const reset: []const u8 = "\x1b[0m";

/// Bold sequence
pub const bold: []const u8 = "\x1b[1m";

/// Dim sequence
pub const dim: []const u8 = "\x1b[2m";

/// Underline sequence
pub const underline: []const u8 = "\x1b[4m";

/// Strip ANSI codes from text
pub fn stripAnsi(text: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    var result: std.ArrayList(u8) = .empty;

    var i: usize = 0;
    while (i < text.len) {
        if (text[i] == '\x1b' and i + 1 < text.len and text[i + 1] == '[') {
            // Skip ANSI sequence
            i += 2;
            while (i < text.len and text[i] != 'm') : (i += 1) {}
            if (i < text.len) i += 1; // Skip 'm'
        } else {
            try result.append(allocator, text[i]);
            i += 1;
        }
    }

    return result.toOwnedSlice(allocator);
}

// ============================================================================
// Tests
// ============================================================================

test "colorCode returns valid sequence" {
    try std.testing.expectEqualStrings("\x1b[31m", colorCode(.red));
    try std.testing.expectEqualStrings("\x1b[32m", colorCode(.green));
}

test "stripAnsi removes sequences" {
    const colored = "\x1b[31mhello\x1b[0m world";
    const stripped = try stripAnsi(colored, std.testing.allocator);
    defer std.testing.allocator.free(stripped);

    try std.testing.expectEqualStrings("hello world", stripped);
}
