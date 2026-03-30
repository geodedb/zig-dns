// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Errors Module
//!
//! Error formatting and handling utilities.

const std = @import("std");

/// Error severity levels
pub const Severity = enum {
    info,
    warning,
    @"error",

    pub fn symbol(self: Severity) []const u8 {
        return switch (self) {
            .info => "info",
            .warning => "warning",
            .@"error" => "error",
        };
    }

    pub fn colorCode(self: Severity) []const u8 {
        return switch (self) {
            .info => "\x1b[36m",
            .warning => "\x1b[33m",
            .@"error" => "\x1b[31m",
        };
    }
};

/// Formatted error for display
pub const FormattedError = struct {
    severity: Severity,
    message: []const u8,
    hint: ?[]const u8 = null,
    context: ?[]const u8 = null,

    /// Print error to writer
    pub fn print(self: *const FormattedError, writer: anytype, use_color: bool) !void {
        // Severity
        if (use_color) {
            try writer.print("{s}{s}\x1b[0m: ", .{ self.severity.colorCode(), self.severity.symbol() });
        } else {
            try writer.print("{s}: ", .{self.severity.symbol()});
        }

        // Message
        try writer.print("{s}\n", .{self.message});

        // Context
        if (self.context) |ctx| {
            try writer.print("  --> {s}\n", .{ctx});
        }

        // Hint
        if (self.hint) |hint| {
            if (use_color) {
                try writer.print("\x1b[36mhint\x1b[0m: {s}\n", .{hint});
            } else {
                try writer.print("hint: {s}\n", .{hint});
            }
        }
    }
};

/// Print an error message
pub fn printError(writer: anytype, message: []const u8, use_color: bool) !void {
    const err = FormattedError{
        .severity = .@"error",
        .message = message,
    };
    try err.print(writer, use_color);
}

/// Print a warning message
pub fn printWarning(writer: anytype, message: []const u8, use_color: bool) !void {
    const warn = FormattedError{
        .severity = .warning,
        .message = message,
    };
    try warn.print(writer, use_color);
}

/// Print an error with suggestion
pub fn printErrorWithSuggestion(
    writer: anytype,
    message: []const u8,
    suggestion: ?[]const u8,
    use_color: bool,
) !void {
    const err = FormattedError{
        .severity = .@"error",
        .message = message,
        .hint = suggestion,
    };
    try err.print(writer, use_color);
}

/// Format unknown command error with suggestion
pub fn formatUnknownCommand(
    input: []const u8,
    suggestion: ?[]const u8,
    allocator: std.mem.Allocator,
) !FormattedError {
    const message = try std.fmt.allocPrint(allocator, "'{s}' is not a command", .{input});

    const hint = if (suggestion) |s|
        try std.fmt.allocPrint(allocator, "Did you mean '{s}'?", .{s})
    else
        null;

    return .{
        .severity = .warning,
        .message = message,
        .hint = hint,
    };
}

/// Standard exit codes
pub const ExitCode = enum(u8) {
    success = 0,
    general_error = 1,
    usage_error = 2,
    permission_denied = 77,
    config_error = 78,
    io_error = 74,

    pub fn toInt(self: ExitCode) u8 {
        return @intFromEnum(self);
    }
};

// ============================================================================
// Tests
// ============================================================================

test "errors: Severity symbol returns correct string" {
    try std.testing.expectEqualStrings("info", Severity.info.symbol());
    try std.testing.expectEqualStrings("warning", Severity.warning.symbol());
    try std.testing.expectEqualStrings("error", Severity.@"error".symbol());
}

test "errors: Severity colorCode returns ANSI codes" {
    try std.testing.expectEqualStrings("\x1b[36m", Severity.info.colorCode());
    try std.testing.expectEqualStrings("\x1b[33m", Severity.warning.colorCode());
    try std.testing.expectEqualStrings("\x1b[31m", Severity.@"error".colorCode());
}

test "errors: FormattedError print without color" {
    var buffer: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    const err = FormattedError{
        .severity = .@"error",
        .message = "something went wrong",
        .hint = "try this instead",
    };

    try err.print(writer, false);
    const output = stream.getWritten();

    try std.testing.expect(std.mem.indexOf(u8, output, "error:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "something went wrong") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "hint:") != null);
}

test "errors: FormattedError print with color" {
    var buffer: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    const err = FormattedError{
        .severity = .@"error",
        .message = "something went wrong",
    };

    try err.print(writer, true);
    const output = stream.getWritten();

    // Should contain ANSI color codes
    try std.testing.expect(std.mem.indexOf(u8, output, "\x1b[31m") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\x1b[0m") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "something went wrong") != null);
}

test "errors: FormattedError with context" {
    var buffer: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    const err = FormattedError{
        .severity = .warning,
        .message = "deprecated function",
        .context = "src/main.zig:42",
    };

    try err.print(writer, false);
    const output = stream.getWritten();

    try std.testing.expect(std.mem.indexOf(u8, output, "warning:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "deprecated function") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "--> src/main.zig:42") != null);
}

test "errors: FormattedError with all fields" {
    var buffer: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    const err = FormattedError{
        .severity = .@"error",
        .message = "file not found",
        .context = "config.toml",
        .hint = "create the file or use --config flag",
    };

    try err.print(writer, false);
    const output = stream.getWritten();

    try std.testing.expect(std.mem.indexOf(u8, output, "error:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "file not found") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "--> config.toml") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "hint:") != null);
}

test "errors: FormattedError info severity" {
    var buffer: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    const err = FormattedError{
        .severity = .info,
        .message = "operation completed",
    };

    try err.print(writer, false);
    const output = stream.getWritten();

    try std.testing.expect(std.mem.indexOf(u8, output, "info:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "operation completed") != null);
}

test "errors: printError helper" {
    var buffer: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    try printError(writer, "test error message", false);
    const output = stream.getWritten();

    try std.testing.expect(std.mem.indexOf(u8, output, "error:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "test error message") != null);
}

test "errors: printWarning helper" {
    var buffer: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    try printWarning(writer, "test warning message", false);
    const output = stream.getWritten();

    try std.testing.expect(std.mem.indexOf(u8, output, "warning:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "test warning message") != null);
}

test "errors: printErrorWithSuggestion helper" {
    var buffer: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    try printErrorWithSuggestion(writer, "invalid option", "use --help", false);
    const output = stream.getWritten();

    try std.testing.expect(std.mem.indexOf(u8, output, "error:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "invalid option") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "hint:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "use --help") != null);
}

test "errors: printErrorWithSuggestion without suggestion" {
    var buffer: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    try printErrorWithSuggestion(writer, "error message", null, false);
    const output = stream.getWritten();

    try std.testing.expect(std.mem.indexOf(u8, output, "error:") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "hint:") == null);
}

test "errors: formatUnknownCommand with suggestion" {
    const err = try formatUnknownCommand("statsu", "status", std.testing.allocator);
    defer std.testing.allocator.free(err.message);
    defer if (err.hint) |h| std.testing.allocator.free(h);

    try std.testing.expect(std.mem.indexOf(u8, err.message, "statsu") != null);
    try std.testing.expect(std.mem.indexOf(u8, err.message, "not a command") != null);
    try std.testing.expect(err.hint != null);
    try std.testing.expect(std.mem.indexOf(u8, err.hint.?, "status") != null);
}

test "errors: formatUnknownCommand without suggestion" {
    const err = try formatUnknownCommand("foobar", null, std.testing.allocator);
    defer std.testing.allocator.free(err.message);

    try std.testing.expect(std.mem.indexOf(u8, err.message, "foobar") != null);
    try std.testing.expect(err.hint == null);
}

test "errors: ExitCode values" {
    try std.testing.expectEqual(@as(u8, 0), ExitCode.success.toInt());
    try std.testing.expectEqual(@as(u8, 1), ExitCode.general_error.toInt());
    try std.testing.expectEqual(@as(u8, 2), ExitCode.usage_error.toInt());
    try std.testing.expectEqual(@as(u8, 77), ExitCode.permission_denied.toInt());
    try std.testing.expectEqual(@as(u8, 78), ExitCode.config_error.toInt());
    try std.testing.expectEqual(@as(u8, 74), ExitCode.io_error.toInt());
}
