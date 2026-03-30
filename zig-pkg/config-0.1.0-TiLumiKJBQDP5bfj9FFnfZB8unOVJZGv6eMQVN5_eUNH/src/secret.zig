// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Secret Module
//!
//! Secure handling of secrets - enforces reading from files or stdin only.

const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const Allocator = mem.Allocator;

/// Secret loading errors
pub const SecretError = error{
    /// Secret was provided via flag or environment (not allowed)
    SecretInFlagOrEnv,
    /// Secret file not found
    FileNotFound,
    /// Secret file read error
    ReadError,
    /// Invalid secret format
    InvalidFormat,
    /// Stdin not available
    StdinNotAvailable,
};

/// Read a secret from a file
pub fn readFromFile(path: []const u8, allocator: Allocator) SecretError![]const u8 {
    const file = fs.cwd().openFile(path, .{}) catch {
        return SecretError.FileNotFound;
    };
    defer file.close();

    const content = file.readToEndAlloc(allocator, 64 * 1024) catch {
        return SecretError.ReadError;
    };

    // Trim trailing newlines
    return mem.trim(u8, content, "\n\r");
}

/// Read a secret from stdin
pub fn readFromStdin(allocator: Allocator) SecretError![]const u8 {
    const stdin = std.io.getStdIn();

    // Check if stdin is a pipe or has data
    if (stdin.isTty()) {
        // Interactive mode - prompt for input
        const stderr = std.io.getStdErr().writer();
        stderr.print("Enter secret: ", .{}) catch {};

        const content = stdin.reader().readUntilDelimiterAlloc(allocator, '\n', 64 * 1024) catch {
            return SecretError.StdinNotAvailable;
        };

        return content;
    } else {
        // Pipe mode - read all
        const content = stdin.readToEndAlloc(allocator, 64 * 1024) catch {
            return SecretError.StdinNotAvailable;
        };

        return mem.trim(u8, content, "\n\r");
    }
}

/// Validate that a secret was not provided via flag or environment
pub fn validateNotInFlagOrEnv(flag_value: ?[]const u8, env_name: []const u8) SecretError!void {
    if (flag_value != null) {
        return SecretError.SecretInFlagOrEnv;
    }

    if (std.posix.getenv(env_name) != null) {
        return SecretError.SecretInFlagOrEnv;
    }
}

/// Redact a secret value for display (e.g., in logs)
pub fn redact(value: []const u8) []const u8 {
    _ = value;
    return "***REDACTED***";
}

/// Securely zero memory containing a secret
pub fn secureZero(buffer: []u8) void {
    // Use volatile write to prevent optimization
    for (buffer) |*byte| {
        @as(*volatile u8, byte).* = 0;
    }
}

// ============================================================================
// Tests
// ============================================================================

test "redact hides secret" {
    const redacted = redact("super-secret-password");
    try std.testing.expectEqualStrings("***REDACTED***", redacted);
}

test "secureZero clears buffer" {
    var buffer = [_]u8{ 's', 'e', 'c', 'r', 'e', 't' };
    secureZero(&buffer);

    for (buffer) |byte| {
        try std.testing.expectEqual(@as(u8, 0), byte);
    }
}
