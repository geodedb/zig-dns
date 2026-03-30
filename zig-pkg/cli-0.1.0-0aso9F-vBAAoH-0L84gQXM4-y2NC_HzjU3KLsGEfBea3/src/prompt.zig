// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Interactive Prompts Module
//!
//! Utilities for interactive CLI input with support for:
//! - Text input with validation
//! - Password input (hidden characters)
//! - Yes/No confirmation
//! - Single-select from list
//! - Multi-select from list
//!
//! ## Usage
//!
//! ```zig
//! const prompt = @import("cli").prompt;
//!
//! // Simple input
//! const name = try prompt.input("Enter your name: ", .{});
//!
//! // Password (hidden)
//! const password = try prompt.password("Password: ");
//!
//! // Confirmation with default
//! if (try prompt.confirm("Continue?", true)) {
//!     // proceed
//! }
//!
//! // Select from options
//! const choice = try prompt.select("Choose:", &.{"Option A", "Option B", "Option C"});
//! ```

const std = @import("std");
const builtin = @import("builtin");
const tty = @import("term/tty.zig");

/// Error types for prompt operations
pub const PromptError = error{
    /// Input was cancelled (Ctrl+C or EOF)
    Cancelled,
    /// Non-interactive terminal (stdin not a TTY)
    NotInteractive,
    /// Read error from stdin
    ReadError,
    /// Invalid input
    InvalidInput,
    /// Out of memory
    OutOfMemory,
};

/// Configuration for text input
pub const InputConfig = struct {
    /// Default value if user presses Enter without input
    default: ?[]const u8 = null,
    /// Validator function - return true if valid
    validator: ?*const fn ([]const u8) bool = null,
    /// Error message for invalid input
    validation_error: []const u8 = "Invalid input",
    /// Maximum input length
    max_length: usize = 1024,
    /// Allow empty input
    allow_empty: bool = true,
};

/// Read a line of text input from the user
pub fn input(message: []const u8, config: InputConfig, allocator: std.mem.Allocator) PromptError![]const u8 {
    const stdin = std.io.getStdIn();
    const stdout = std.io.getStdOut();

    // Check if interactive
    if (!stdin.isTty()) {
        return PromptError.NotInteractive;
    }

    while (true) {
        // Print prompt
        stdout.writer().print("{s}", .{message}) catch return PromptError.ReadError;
        if (config.default) |def| {
            stdout.writer().print(" [{s}]", .{def}) catch return PromptError.ReadError;
        }
        stdout.writer().print(": ", .{}) catch return PromptError.ReadError;

        // Read line
        var buffer: [1024]u8 = undefined;
        const line = stdin.reader().readUntilDelimiterOrEof(&buffer, '\n') catch {
            return PromptError.ReadError;
        };

        if (line == null) {
            // EOF
            return PromptError.Cancelled;
        }

        const trimmed = std.mem.trim(u8, line.?, " \t\r");

        // Handle empty input
        if (trimmed.len == 0) {
            if (config.default) |def| {
                return allocator.dupe(u8, def) catch return PromptError.OutOfMemory;
            }
            if (!config.allow_empty) {
                stdout.writer().print("Input cannot be empty. Please try again.\n", .{}) catch {};
                continue;
            }
            return allocator.dupe(u8, "") catch return PromptError.OutOfMemory;
        }

        // Check length
        if (trimmed.len > config.max_length) {
            stdout.writer().print("Input too long (max {d} characters). Please try again.\n", .{config.max_length}) catch {};
            continue;
        }

        // Validate
        if (config.validator) |validate| {
            if (!validate(trimmed)) {
                stdout.writer().print("{s}. Please try again.\n", .{config.validation_error}) catch {};
                continue;
            }
        }

        return allocator.dupe(u8, trimmed) catch return PromptError.OutOfMemory;
    }
}

/// Read a password without echoing characters
pub fn password(message: []const u8, allocator: std.mem.Allocator) PromptError![]const u8 {
    const stdin = std.io.getStdIn();
    const stdout = std.io.getStdOut();

    // Check if interactive
    if (!stdin.isTty()) {
        return PromptError.NotInteractive;
    }

    // Print prompt
    stdout.writer().print("{s}", .{message}) catch return PromptError.ReadError;

    // Disable echo
    if (builtin.os.tag != .windows) {
        var termios = std.posix.tcgetattr(stdin.handle) catch return PromptError.ReadError;
        const original = termios;

        // Disable ECHO
        termios.lflag.ECHO = false;
        std.posix.tcsetattr(stdin.handle, .FLUSH, termios) catch return PromptError.ReadError;

        defer {
            // Restore original settings
            std.posix.tcsetattr(stdin.handle, .FLUSH, original) catch {};
            stdout.writer().print("\n", .{}) catch {};
        }

        // Read line
        var buffer: [1024]u8 = undefined;
        const line = stdin.reader().readUntilDelimiterOrEof(&buffer, '\n') catch {
            return PromptError.ReadError;
        };

        if (line == null) {
            return PromptError.Cancelled;
        }

        return allocator.dupe(u8, std.mem.trim(u8, line.?, " \t\r")) catch return PromptError.OutOfMemory;
    } else {
        // Windows: Use _getch or similar
        // For now, fall back to regular input
        return inputSimple(stdin, allocator);
    }
}

fn inputSimple(stdin: std.fs.File, allocator: std.mem.Allocator) PromptError![]const u8 {
    var buffer: [1024]u8 = undefined;
    const line = stdin.reader().readUntilDelimiterOrEof(&buffer, '\n') catch {
        return PromptError.ReadError;
    };

    if (line == null) {
        return PromptError.Cancelled;
    }

    const stdout = std.io.getStdOut();
    stdout.writer().print("\n", .{}) catch {};

    return allocator.dupe(u8, std.mem.trim(u8, line.?, " \t\r")) catch return PromptError.OutOfMemory;
}

/// Ask for yes/no confirmation
pub fn confirm(message: []const u8, default: bool) PromptError!bool {
    const stdin = std.io.getStdIn();
    const stdout = std.io.getStdOut();

    // Check if interactive
    if (!stdin.isTty()) {
        return PromptError.NotInteractive;
    }

    while (true) {
        // Print prompt with default indicator
        if (default) {
            stdout.writer().print("{s} [Y/n]: ", .{message}) catch return PromptError.ReadError;
        } else {
            stdout.writer().print("{s} [y/N]: ", .{message}) catch return PromptError.ReadError;
        }

        // Read response
        var buffer: [64]u8 = undefined;
        const line = stdin.reader().readUntilDelimiterOrEof(&buffer, '\n') catch {
            return PromptError.ReadError;
        };

        if (line == null) {
            return PromptError.Cancelled;
        }

        const trimmed = std.mem.trim(u8, line.?, " \t\r");

        // Handle empty input (use default)
        if (trimmed.len == 0) {
            return default;
        }

        // Parse response
        if (trimmed.len == 1) {
            const c = std.ascii.toLower(trimmed[0]);
            if (c == 'y') return true;
            if (c == 'n') return false;
        }

        // Check for full words
        const lower = std.ascii.lowerString(&buffer, trimmed);
        if (std.mem.eql(u8, lower, "yes")) return true;
        if (std.mem.eql(u8, lower, "no")) return false;

        stdout.writer().print("Please enter 'y' or 'n'.\n", .{}) catch {};
    }
}

/// Select one option from a list
pub fn select(message: []const u8, options: []const []const u8) PromptError!usize {
    const stdin = std.io.getStdIn();
    const stdout = std.io.getStdOut();

    // Check if interactive
    if (!stdin.isTty()) {
        return PromptError.NotInteractive;
    }

    if (options.len == 0) {
        return PromptError.InvalidInput;
    }

    while (true) {
        // Print prompt and options
        stdout.writer().print("{s}\n", .{message}) catch return PromptError.ReadError;
        for (options, 0..) |opt, i| {
            stdout.writer().print("  {d}. {s}\n", .{ i + 1, opt }) catch return PromptError.ReadError;
        }
        stdout.writer().print("Enter choice [1-{d}]: ", .{options.len}) catch return PromptError.ReadError;

        // Read response
        var buffer: [64]u8 = undefined;
        const line = stdin.reader().readUntilDelimiterOrEof(&buffer, '\n') catch {
            return PromptError.ReadError;
        };

        if (line == null) {
            return PromptError.Cancelled;
        }

        const trimmed = std.mem.trim(u8, line.?, " \t\r");

        // Parse number
        const choice = std.fmt.parseInt(usize, trimmed, 10) catch {
            stdout.writer().print("Please enter a number between 1 and {d}.\n", .{options.len}) catch {};
            continue;
        };

        if (choice >= 1 and choice <= options.len) {
            return choice - 1;
        }

        stdout.writer().print("Please enter a number between 1 and {d}.\n", .{options.len}) catch {};
    }
}

/// Select multiple options from a list
pub fn multiSelect(message: []const u8, options: []const []const u8, allocator: std.mem.Allocator) PromptError![]usize {
    const stdin = std.io.getStdIn();
    const stdout = std.io.getStdOut();

    // Check if interactive
    if (!stdin.isTty()) {
        return PromptError.NotInteractive;
    }

    if (options.len == 0) {
        return PromptError.InvalidInput;
    }

    while (true) {
        // Print prompt and options
        stdout.writer().print("{s}\n", .{message}) catch return PromptError.ReadError;
        for (options, 0..) |opt, i| {
            stdout.writer().print("  {d}. {s}\n", .{ i + 1, opt }) catch return PromptError.ReadError;
        }
        stdout.writer().print("Enter choices (comma-separated, e.g., 1,3,4): ", .{}) catch return PromptError.ReadError;

        // Read response
        var buffer: [256]u8 = undefined;
        const line = stdin.reader().readUntilDelimiterOrEof(&buffer, '\n') catch {
            return PromptError.ReadError;
        };

        if (line == null) {
            return PromptError.Cancelled;
        }

        const trimmed = std.mem.trim(u8, line.?, " \t\r");

        // Parse selections
        var selections = std.ArrayList(usize).init(allocator);
        errdefer selections.deinit();

        var valid = true;
        var iter = std.mem.splitSequence(u8, trimmed, ",");
        while (iter.next()) |part| {
            const num_str = std.mem.trim(u8, part, " \t");
            if (num_str.len == 0) continue;

            const choice = std.fmt.parseInt(usize, num_str, 10) catch {
                valid = false;
                break;
            };

            if (choice < 1 or choice > options.len) {
                valid = false;
                break;
            }

            selections.append(choice - 1) catch return PromptError.OutOfMemory;
        }

        if (!valid or selections.items.len == 0) {
            selections.deinit();
            stdout.writer().print("Please enter valid numbers between 1 and {d}.\n", .{options.len}) catch {};
            continue;
        }

        return selections.toOwnedSlice() catch return PromptError.OutOfMemory;
    }
}

// ============================================================================
// Tests
// ============================================================================

test "InputConfig defaults" {
    const config = InputConfig{};
    try std.testing.expect(config.default == null);
    try std.testing.expect(config.validator == null);
    try std.testing.expectEqual(@as(usize, 1024), config.max_length);
    try std.testing.expect(config.allow_empty);
}

test "PromptError is error type" {
    // Just verify the error type compiles correctly
    const err: PromptError = PromptError.NotInteractive;
    try std.testing.expectEqual(PromptError.NotInteractive, err);
}
