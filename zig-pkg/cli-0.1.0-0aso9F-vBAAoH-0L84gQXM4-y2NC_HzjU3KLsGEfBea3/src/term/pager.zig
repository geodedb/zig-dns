// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Pager Module
//!
//! Pipes long output through a pager (like `less`) when appropriate.

const std = @import("std");
const builtin = @import("builtin");
const tty = @import("tty.zig");

/// Pager configuration
pub const PagerConfig = struct {
    /// Minimum lines to trigger pager
    min_lines: u16 = 0,
    /// Environment variable for pager command
    pager_env: []const u8 = "PAGER",
    /// Default pager command
    default_pager: []const u8 = "less -FIRX",
    /// Force pager even if not TTY
    force: bool = false,
};

/// Write content through a pager if appropriate
pub fn writeIfTty(content: []const u8, config: PagerConfig) !void {
    const stdout = std.fs.File.stdout();

    // Check if we should use pager
    if (!config.force and !stdout.isTty()) {
        // Not a TTY, write directly
        try stdout.writeAll(content);
        return;
    }

    // Count lines
    var line_count: u16 = 0;
    for (content) |c| {
        if (c == '\n') line_count += 1;
    }

    // Get terminal height
    const term_info = tty.getInfo();

    // If content fits in terminal, write directly
    if (line_count < term_info.height and line_count >= config.min_lines) {
        try stdout.writeAll(content);
        return;
    }

    // Try to use pager
    const pager_cmd = std.posix.getenv(config.pager_env) orelse config.default_pager;

    if (builtin.os.tag == .windows) {
        // Windows: fall back to direct output
        try stdout.writeAll(content);
        return;
    }

    // Spawn pager process
    var child = std.process.Child.init(&.{ "/bin/sh", "-c", pager_cmd }, std.heap.page_allocator);
    child.stdin_behavior = .Pipe;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;

    try child.spawn();

    // Write content to pager stdin
    if (child.stdin) |stdin| {
        stdin.writeAll(content) catch {};
        stdin.close();
    }

    // Wait for pager to finish
    _ = child.wait() catch {};
}

/// Create a pager writer that buffers output
pub const PagerWriter = struct {
    buffer: std.ArrayList(u8),
    allocator: std.mem.Allocator,
    config: PagerConfig,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator, config: PagerConfig) Self {
        return .{
            .buffer = .empty,
            .allocator = allocator,
            .config = config,
        };
    }

    pub fn deinit(self: *Self) void {
        self.buffer.deinit(self.allocator);
    }

    pub fn writer(self: *Self) std.ArrayList(u8).Writer {
        return self.buffer.writer(self.allocator);
    }

    pub fn flush(self: *Self) !void {
        try writeIfTty(self.buffer.items, self.config);
        self.buffer.clearRetainingCapacity();
    }
};

// ============================================================================
// Tests
// ============================================================================

test "PagerWriter initialization" {
    var pw = PagerWriter.init(std.testing.allocator, .{});
    defer pw.deinit();

    const w = pw.writer();
    try w.print("Hello, World!\n", .{});

    try std.testing.expect(pw.buffer.items.len > 0);
}

test "pager: PagerConfig default values" {
    const config = PagerConfig{};

    try std.testing.expectEqual(@as(u16, 0), config.min_lines);
    try std.testing.expectEqualStrings("PAGER", config.pager_env);
    try std.testing.expectEqualStrings("less -FIRX", config.default_pager);
    try std.testing.expectEqual(false, config.force);
}

test "pager: PagerConfig custom values" {
    const config = PagerConfig{
        .min_lines = 50,
        .pager_env = "MY_PAGER",
        .default_pager = "more",
        .force = true,
    };

    try std.testing.expectEqual(@as(u16, 50), config.min_lines);
    try std.testing.expectEqualStrings("MY_PAGER", config.pager_env);
    try std.testing.expectEqualStrings("more", config.default_pager);
    try std.testing.expectEqual(true, config.force);
}

test "pager: PagerWriter write multiple lines" {
    var pw = PagerWriter.init(std.testing.allocator, .{});
    defer pw.deinit();

    const w = pw.writer();
    try w.print("Line 1\n", .{});
    try w.print("Line 2\n", .{});
    try w.print("Line 3\n", .{});

    const output = pw.buffer.items;
    try std.testing.expect(std.mem.indexOf(u8, output, "Line 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Line 2") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Line 3") != null);
}

test "pager: PagerWriter buffer grows" {
    var pw = PagerWriter.init(std.testing.allocator, .{});
    defer pw.deinit();

    const w = pw.writer();

    // Write a large amount of data
    for (0..100) |i| {
        try w.print("Line {d}: This is some content to fill the buffer\n", .{i});
    }

    try std.testing.expect(pw.buffer.items.len > 1000);
}

test "pager: PagerWriter deinit cleans up" {
    var pw = PagerWriter.init(std.testing.allocator, .{});

    const w = pw.writer();
    try w.print("Some content\n", .{});

    pw.deinit();
    // If we reach here without memory leaks, the test passes
}

test "pager: PagerWriter writer returns valid writer" {
    var pw = PagerWriter.init(std.testing.allocator, .{});
    defer pw.deinit();

    const w = pw.writer();

    // Test writing formatted output
    try w.print("{s}: {d}\n", .{ "count", 42 });

    const output = pw.buffer.items;
    try std.testing.expectEqualStrings("count: 42\n", output);
}

test "pager: PagerWriter handles empty writes" {
    var pw = PagerWriter.init(std.testing.allocator, .{});
    defer pw.deinit();

    const w = pw.writer();
    try w.print("", .{});

    try std.testing.expectEqual(@as(usize, 0), pw.buffer.items.len);
}

test "pager: PagerWriter preserves content order" {
    var pw = PagerWriter.init(std.testing.allocator, .{});
    defer pw.deinit();

    const w = pw.writer();
    try w.print("first", .{});
    try w.print("second", .{});
    try w.print("third", .{});

    try std.testing.expectEqualStrings("firstsecondthird", pw.buffer.items);
}
