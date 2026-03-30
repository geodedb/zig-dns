// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Progress Module
//!
//! Progress indicators (spinners, bars) for long-running operations.
//! Only shows progress when stdout is a TTY.

const std = @import("std");
const tty = @import("tty.zig");

/// Spinner characters
pub const SpinnerStyle = enum {
    dots,
    line,
    arrow,
    pulse,

    pub fn frames(self: SpinnerStyle) []const []const u8 {
        return switch (self) {
            .dots => &.{ ".", "..", "...", ".." },
            .line => &.{ "-", "\\", "|", "/" },
            .arrow => &.{ ">", ">>", ">>>", ">>" },
            .pulse => &.{ ".", "o", "O", "o" },
        };
    }
};

/// Progress indicator
pub const Progress = struct {
    enabled: bool,
    message: []const u8,
    spinner_style: SpinnerStyle,
    frame_index: usize,
    writer: std.fs.File.DeprecatedWriter,

    const Self = @This();

    /// Start a new progress indicator
    pub fn start(message: []const u8) Self {
        const is_tty = tty.isStderrTty();

        var self = Self{
            .enabled = is_tty,
            .message = message,
            .spinner_style = .dots,
            .frame_index = 0,
            .writer = std.fs.File.stderr().deprecatedWriter(),
        };

        if (self.enabled) {
            // Hide cursor
            self.writer.print("\x1b[?25l", .{}) catch {};
            self.render() catch {};
        }

        return self;
    }

    /// Start with TTY check from context
    pub fn startIfTty(is_tty: bool, message: []const u8) Self {
        var self = Self{
            .enabled = is_tty,
            .message = message,
            .spinner_style = .dots,
            .frame_index = 0,
            .writer = std.fs.File.stderr().deprecatedWriter(),
        };

        if (self.enabled) {
            self.writer.print("\x1b[?25l", .{}) catch {};
            self.render() catch {};
        }

        return self;
    }

    /// Update progress message
    pub fn update(self: *Self, message: []const u8) void {
        self.message = message;
        if (self.enabled) {
            self.render() catch {};
        }
    }

    /// Tick the spinner
    pub fn tick(self: *Self) void {
        if (!self.enabled) return;

        const frames = self.spinner_style.frames();
        self.frame_index = (self.frame_index + 1) % frames.len;
        self.render() catch {};
    }

    /// Stop the progress indicator
    pub fn stop(self: *Self) void {
        if (!self.enabled) return;

        // Clear line and show cursor
        self.writer.print("\r\x1b[K\x1b[?25h", .{}) catch {};
    }

    /// Stop with a completion message
    pub fn stopWithMessage(self: *Self, message: []const u8) void {
        if (self.enabled) {
            // Clear line, show message, show cursor
            self.writer.print("\r\x1b[K{s}\n\x1b[?25h", .{message}) catch {};
        } else {
            self.writer.print("{s}\n", .{message}) catch {};
        }
    }

    fn render(self: *Self) !void {
        const frames = self.spinner_style.frames();
        const frame = frames[self.frame_index];

        // Clear line and write progress
        try self.writer.print("\r\x1b[K{s} {s}", .{ frame, self.message });
    }
};

/// Progress bar
pub const ProgressBar = struct {
    total: usize,
    current: usize,
    width: u16,
    enabled: bool,
    message: []const u8,
    writer: std.fs.File.DeprecatedWriter,

    const Self = @This();

    /// Create a new progress bar
    pub fn init(total: usize, message: []const u8) Self {
        const term_info = tty.getInfo();

        return .{
            .total = total,
            .current = 0,
            .width = @min(term_info.width - 20, 50),
            .enabled = term_info.is_tty,
            .message = message,
            .writer = std.fs.File.stderr().deprecatedWriter(),
        };
    }

    /// Update progress
    pub fn update(self: *Self, current: usize) void {
        self.current = @min(current, self.total);
        if (self.enabled) {
            self.render() catch {};
        }
    }

    /// Increment by one
    pub fn increment(self: *Self) void {
        self.update(self.current + 1);
    }

    /// Complete the progress bar
    pub fn finish(self: *Self) void {
        self.update(self.total);
        if (self.enabled) {
            self.writer.print("\n", .{}) catch {};
        }
    }

    fn render(self: *Self) !void {
        const percent = if (self.total > 0)
            (self.current * 100) / self.total
        else
            0;

        const filled = if (self.total > 0)
            (self.current * self.width) / self.total
        else
            0;

        const empty = self.width - filled;

        try self.writer.print("\r{s} [", .{self.message});

        for (0..filled) |_| {
            try self.writer.print("=", .{});
        }

        for (0..empty) |_| {
            try self.writer.print(" ", .{});
        }

        try self.writer.print("] {d}%", .{percent});
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Progress indicator creation" {
    var progress = Progress.startIfTty(false, "Loading...");
    progress.tick();
    progress.stop();
}

test "ProgressBar initialization" {
    const bar = ProgressBar.init(100, "Progress");
    try std.testing.expectEqual(@as(usize, 0), bar.current);
    try std.testing.expectEqual(@as(usize, 100), bar.total);
}

test "progress: SpinnerStyle dots frames" {
    const frames = SpinnerStyle.dots.frames();
    try std.testing.expectEqual(@as(usize, 4), frames.len);
    try std.testing.expectEqualStrings(".", frames[0]);
    try std.testing.expectEqualStrings("..", frames[1]);
    try std.testing.expectEqualStrings("...", frames[2]);
    try std.testing.expectEqualStrings("..", frames[3]);
}

test "progress: SpinnerStyle line frames" {
    const frames = SpinnerStyle.line.frames();
    try std.testing.expectEqual(@as(usize, 4), frames.len);
    try std.testing.expectEqualStrings("-", frames[0]);
    try std.testing.expectEqualStrings("\\", frames[1]);
    try std.testing.expectEqualStrings("|", frames[2]);
    try std.testing.expectEqualStrings("/", frames[3]);
}

test "progress: SpinnerStyle arrow frames" {
    const frames = SpinnerStyle.arrow.frames();
    try std.testing.expectEqual(@as(usize, 4), frames.len);
    try std.testing.expectEqualStrings(">", frames[0]);
    try std.testing.expectEqualStrings(">>", frames[1]);
    try std.testing.expectEqualStrings(">>>", frames[2]);
    try std.testing.expectEqualStrings(">>", frames[3]);
}

test "progress: SpinnerStyle pulse frames" {
    const frames = SpinnerStyle.pulse.frames();
    try std.testing.expectEqual(@as(usize, 4), frames.len);
    try std.testing.expectEqualStrings(".", frames[0]);
    try std.testing.expectEqualStrings("o", frames[1]);
    try std.testing.expectEqualStrings("O", frames[2]);
    try std.testing.expectEqualStrings("o", frames[3]);
}

test "progress: Progress disabled when not TTY" {
    var progress = Progress.startIfTty(false, "Loading...");
    try std.testing.expectEqual(false, progress.enabled);
    progress.stop();
}

test "progress: Progress message update" {
    var progress = Progress.startIfTty(false, "Initial");
    try std.testing.expectEqualStrings("Initial", progress.message);

    progress.update("Updated");
    try std.testing.expectEqualStrings("Updated", progress.message);
    progress.stop();
}

test "progress: Progress tick when disabled does not crash" {
    var progress = Progress.startIfTty(false, "Loading...");
    // When disabled, tick returns early without modifying frame_index
    progress.tick();
    progress.tick();
    progress.stop();
    // Just verify it doesn't crash
}

test "progress: Progress frame_index starts at zero" {
    var progress = Progress.startIfTty(false, "Loading...");
    try std.testing.expectEqual(@as(usize, 0), progress.frame_index);
    progress.stop();
}

test "progress: Progress default spinner style" {
    var progress = Progress.startIfTty(false, "Loading...");
    try std.testing.expectEqual(SpinnerStyle.dots, progress.spinner_style);
    progress.stop();
}

test "progress: ProgressBar update within bounds" {
    var bar = ProgressBar.init(100, "Progress");
    bar.enabled = false; // Disable TTY output for test

    bar.update(50);
    try std.testing.expectEqual(@as(usize, 50), bar.current);

    bar.update(100);
    try std.testing.expectEqual(@as(usize, 100), bar.current);
}

test "progress: ProgressBar update clamps to total" {
    var bar = ProgressBar.init(100, "Progress");
    bar.enabled = false;

    bar.update(150); // Over the total
    try std.testing.expectEqual(@as(usize, 100), bar.current);
}

test "progress: ProgressBar increment" {
    var bar = ProgressBar.init(100, "Progress");
    bar.enabled = false;

    try std.testing.expectEqual(@as(usize, 0), bar.current);

    bar.increment();
    try std.testing.expectEqual(@as(usize, 1), bar.current);

    bar.increment();
    try std.testing.expectEqual(@as(usize, 2), bar.current);
}

test "progress: ProgressBar finish sets to total" {
    var bar = ProgressBar.init(100, "Progress");
    bar.enabled = false;

    bar.update(50);
    bar.finish();

    try std.testing.expectEqual(@as(usize, 100), bar.current);
}

test "progress: ProgressBar zero total" {
    var bar = ProgressBar.init(0, "Empty");
    bar.enabled = false;

    // Should not crash with zero total
    bar.update(0);
    bar.increment();
    bar.finish();

    try std.testing.expectEqual(@as(usize, 0), bar.current);
}

test "progress: ProgressBar message" {
    const bar = ProgressBar.init(100, "Downloading");
    try std.testing.expectEqualStrings("Downloading", bar.message);
}

test "progress: Progress stopWithMessage when disabled" {
    var progress = Progress.startIfTty(false, "Loading...");
    // Should not crash when disabled
    progress.stopWithMessage("Done!");
}
