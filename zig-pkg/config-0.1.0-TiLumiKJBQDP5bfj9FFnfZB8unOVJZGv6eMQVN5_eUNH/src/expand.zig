// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Environment Variable Expansion Module
//!
//! Provides utilities for expanding environment variable references in strings.
//! Supports multiple syntaxes:
//! - `${VAR}` - Standard shell-style
//! - `$VAR` - Simple shell-style
//! - `${VAR:-default}` - With default value
//! - `${VAR:+alternate}` - Alternate value if set
//!
//! Example:
//! ```zig
//! const expanded = try expand("${HOME}/config", allocator);
//! // Result: "/home/user/config"
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Expansion options
pub const ExpandOptions = struct {
    /// Whether to fail on undefined variables
    strict: bool = false,
    /// Default value for undefined variables (when not strict)
    undefined_value: []const u8 = "",
    /// Whether to expand nested variables
    recursive: bool = true,
    /// Maximum recursion depth (to prevent infinite loops)
    max_depth: u8 = 10,
};

/// Error types for expansion
pub const ExpandError = error{
    UndefinedVariable,
    MalformedExpression,
    RecursionLimitExceeded,
    OutOfMemory,
};

/// Expand environment variables in a string
pub fn expand(input: []const u8, allocator: Allocator) ExpandError![]u8 {
    return expandWithOptions(input, allocator, .{});
}

/// Expand environment variables with custom options
pub fn expandWithOptions(input: []const u8, allocator: Allocator, options: ExpandOptions) ExpandError![]u8 {
    return expandRecursive(input, allocator, options, 0);
}

/// Recursive expansion with depth tracking
fn expandRecursive(input: []const u8, allocator: Allocator, options: ExpandOptions, depth: u8) ExpandError![]u8 {
    if (depth > options.max_depth) {
        return ExpandError.RecursionLimitExceeded;
    }

    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '$') {
            if (i + 1 < input.len and input[i + 1] == '{') {
                // ${VAR} syntax
                const start = i + 2;
                const end = findClosingBrace(input, start) orelse {
                    return ExpandError.MalformedExpression;
                };

                const var_expr = input[start..end];
                const expanded_value = try expandVariable(var_expr, allocator, options);
                defer allocator.free(expanded_value);

                // Recursive expansion if enabled
                if (options.recursive and mem.indexOf(u8, expanded_value, "$") != null) {
                    const recursed = try expandRecursive(expanded_value, allocator, options, depth + 1);
                    defer allocator.free(recursed);
                    try result.appendSlice(recursed);
                } else {
                    try result.appendSlice(expanded_value);
                }

                i = end + 1;
            } else if (i + 1 < input.len and isVarStartChar(input[i + 1])) {
                // $VAR syntax
                const start = i + 1;
                var end = start;
                while (end < input.len and isVarChar(input[end])) {
                    end += 1;
                }

                const var_name = input[start..end];
                const value = getEnvValue(var_name, options);
                try result.appendSlice(value);
                i = end;
            } else if (i + 1 < input.len and input[i + 1] == '$') {
                // $$ escape sequence - literal $
                try result.append('$');
                i += 2;
            } else {
                // Just a $ character
                try result.append('$');
                i += 1;
            }
        } else {
            try result.append(input[i]);
            i += 1;
        }
    }

    return result.toOwnedSlice();
}

/// Find the closing brace for a variable expression
fn findClosingBrace(input: []const u8, start: usize) ?usize {
    var depth: usize = 1;
    var i = start;

    while (i < input.len) {
        if (input[i] == '{') {
            depth += 1;
        } else if (input[i] == '}') {
            depth -= 1;
            if (depth == 0) {
                return i;
            }
        }
        i += 1;
    }

    return null;
}

/// Check if character can start a variable name
fn isVarStartChar(c: u8) bool {
    return std.ascii.isAlphabetic(c) or c == '_';
}

/// Check if character can be in a variable name
fn isVarChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

/// Expand a variable expression (handles modifiers)
fn expandVariable(expr: []const u8, allocator: Allocator, options: ExpandOptions) ExpandError![]u8 {
    // Check for modifiers
    if (mem.indexOf(u8, expr, ":-")) |idx| {
        // ${VAR:-default} - use default if unset or empty
        const var_name = expr[0..idx];
        const default_value = expr[idx + 2 ..];

        if (std.posix.getenv(var_name)) |value| {
            if (value.len > 0) {
                return allocator.dupe(u8, value) catch return ExpandError.OutOfMemory;
            }
        }
        return allocator.dupe(u8, default_value) catch return ExpandError.OutOfMemory;
    } else if (mem.indexOf(u8, expr, ":+")) |idx| {
        // ${VAR:+alternate} - use alternate if set and non-empty
        const var_name = expr[0..idx];
        const alternate_value = expr[idx + 2 ..];

        if (std.posix.getenv(var_name)) |value| {
            if (value.len > 0) {
                return allocator.dupe(u8, alternate_value) catch return ExpandError.OutOfMemory;
            }
        }
        return allocator.dupe(u8, "") catch return ExpandError.OutOfMemory;
    } else if (mem.indexOf(u8, expr, "-")) |idx| {
        // ${VAR-default} - use default if unset (empty is ok)
        const var_name = expr[0..idx];
        const default_value = expr[idx + 1 ..];

        if (std.posix.getenv(var_name)) |value| {
            return allocator.dupe(u8, value) catch return ExpandError.OutOfMemory;
        }
        return allocator.dupe(u8, default_value) catch return ExpandError.OutOfMemory;
    } else if (mem.indexOf(u8, expr, "+")) |idx| {
        // ${VAR+alternate} - use alternate if set (even if empty)
        const var_name = expr[0..idx];
        const alternate_value = expr[idx + 1 ..];

        if (std.posix.getenv(var_name)) |_| {
            return allocator.dupe(u8, alternate_value) catch return ExpandError.OutOfMemory;
        }
        return allocator.dupe(u8, "") catch return ExpandError.OutOfMemory;
    } else {
        // Simple ${VAR}
        const value = getEnvValue(expr, options);
        if (options.strict and std.posix.getenv(expr) == null) {
            return ExpandError.UndefinedVariable;
        }
        return allocator.dupe(u8, value) catch return ExpandError.OutOfMemory;
    }
}

/// Get environment variable value with fallback
fn getEnvValue(name: []const u8, options: ExpandOptions) []const u8 {
    return std.posix.getenv(name) orelse options.undefined_value;
}

/// Expand environment variables in all string fields of a struct
pub fn expandStruct(comptime T: type, value: *T, allocator: Allocator, options: ExpandOptions) ExpandError!void {
    const info = @typeInfo(T);

    inline for (info.@"struct".fields) |field| {
        if (field.type == []const u8) {
            const current = @field(value, field.name);
            if (mem.indexOf(u8, current, "$") != null) {
                const expanded = try expandWithOptions(current, allocator, options);
                @field(value, field.name) = expanded;
            }
        } else if (field.type == ?[]const u8) {
            if (@field(value, field.name)) |current| {
                if (mem.indexOf(u8, current, "$") != null) {
                    const expanded = try expandWithOptions(current, allocator, options);
                    @field(value, field.name) = expanded;
                }
            }
        }
    }
}

/// Check if a string contains any variable references
pub fn containsVariables(input: []const u8) bool {
    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '$') {
            if (i + 1 < input.len) {
                if (input[i + 1] == '{' or isVarStartChar(input[i + 1])) {
                    return true;
                }
                if (input[i + 1] == '$') {
                    // Escaped $, skip
                    i += 2;
                    continue;
                }
            }
        }
        i += 1;
    }
    return false;
}

// ============================================================================
// Tests
// ============================================================================

test "expand simple variable" {
    // PATH should exist on most systems
    if (std.posix.getenv("PATH")) |_| {
        const result = try expand("$PATH", std.testing.allocator);
        defer std.testing.allocator.free(result);
        try std.testing.expect(result.len > 0);
    }
}

test "expand ${VAR} syntax" {
    if (std.posix.getenv("HOME")) |home| {
        const result = try expand("${HOME}/config", std.testing.allocator);
        defer std.testing.allocator.free(result);

        try std.testing.expect(mem.startsWith(u8, result, home));
        try std.testing.expect(mem.endsWith(u8, result, "/config"));
    }
}

test "expand undefined variable returns empty" {
    const result = try expand("${UNDEFINED_VAR_12345}", std.testing.allocator);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "expand with default value" {
    const result = try expand("${UNDEFINED_VAR:-default_value}", std.testing.allocator);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("default_value", result);
}

test "expand with existing default" {
    // PATH exists so default should not be used
    if (std.posix.getenv("PATH")) |path| {
        const result = try expand("${PATH:-unused}", std.testing.allocator);
        defer std.testing.allocator.free(result);
        try std.testing.expectEqualStrings(path, result);
    }
}

test "expand escape sequence" {
    const result = try expand("price is $$5", std.testing.allocator);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("price is $5", result);
}

test "expand no variables" {
    const result = try expand("no variables here", std.testing.allocator);
    defer std.testing.allocator.free(result);
    try std.testing.expectEqualStrings("no variables here", result);
}

test "expand strict mode" {
    const result = expandWithOptions("${UNDEFINED_12345}", std.testing.allocator, .{ .strict = true });
    try std.testing.expectError(ExpandError.UndefinedVariable, result);
}

test "containsVariables" {
    try std.testing.expect(containsVariables("${HOME}/path"));
    try std.testing.expect(containsVariables("$HOME/path"));
    try std.testing.expect(!containsVariables("no variables"));
    try std.testing.expect(!containsVariables("$$escaped"));
}

test "expand malformed expression" {
    const result = expand("${UNCLOSED", std.testing.allocator);
    try std.testing.expectError(ExpandError.MalformedExpression, result);
}

test "expand multiple variables" {
    if (std.posix.getenv("HOME")) |_| {
        const result = try expand("${HOME}:${HOME}", std.testing.allocator);
        defer std.testing.allocator.free(result);
        try std.testing.expect(mem.indexOf(u8, result, ":") != null);
    }
}

test "expand alternate value if set" {
    // PATH is set, so alternate should be used
    if (std.posix.getenv("PATH")) |_| {
        const result = try expand("${PATH:+alternate}", std.testing.allocator);
        defer std.testing.allocator.free(result);
        try std.testing.expectEqualStrings("alternate", result);
    }

    // UNDEFINED is not set, so empty string
    const result2 = try expand("${UNDEFINED_12345:+alternate}", std.testing.allocator);
    defer std.testing.allocator.free(result2);
    try std.testing.expectEqualStrings("", result2);
}
