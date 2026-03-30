// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Text Module
//!
//! Text formatting and manipulation utilities.

const std = @import("std");
const mem = std.mem;

/// Wrap text to a given width
pub fn wordWrap(text: []const u8, width: usize, allocator: std.mem.Allocator) ![]const u8 {
    if (text.len <= width) return text;

    var result: std.ArrayList(u8) = .empty;
    var line_start: usize = 0;
    var last_space: ?usize = null;

    for (text, 0..) |c, i| {
        if (c == ' ') {
            last_space = i;
        }

        if (i - line_start >= width) {
            if (last_space) |space| {
                if (space > line_start) {
                    try result.appendSlice(allocator, text[line_start..space]);
                    try result.append(allocator, '\n');
                    line_start = space + 1;
                    last_space = null;
                    continue;
                }
            }
            // No space found, break at width
            try result.appendSlice(allocator, text[line_start..i]);
            try result.append(allocator, '\n');
            line_start = i;
        }
    }

    // Append remaining text
    if (line_start < text.len) {
        try result.appendSlice(allocator, text[line_start..]);
    }

    return result.toOwnedSlice(allocator);
}

/// Indent text by a given number of spaces
pub fn indent(text: []const u8, spaces: usize, allocator: std.mem.Allocator) ![]const u8 {
    var result: std.ArrayList(u8) = .empty;
    var lines = mem.splitScalar(u8, text, '\n');

    var first = true;
    while (lines.next()) |line| {
        if (!first) try result.append(allocator, '\n');
        first = false;

        for (0..spaces) |_| {
            try result.append(allocator, ' ');
        }
        try result.appendSlice(allocator, line);
    }

    return result.toOwnedSlice(allocator);
}

/// Pad string to a minimum width
pub fn padRight(text: []const u8, width: usize, allocator: std.mem.Allocator) ![]const u8 {
    if (text.len >= width) return text;

    var result: std.ArrayList(u8) = .empty;
    try result.appendSlice(allocator, text);

    for (text.len..width) |_| {
        try result.append(allocator, ' ');
    }

    return result.toOwnedSlice(allocator);
}

/// Pad string on the left
pub fn padLeft(text: []const u8, width: usize, allocator: std.mem.Allocator) ![]const u8 {
    if (text.len >= width) return text;

    var result: std.ArrayList(u8) = .empty;

    for (text.len..width) |_| {
        try result.append(allocator, ' ');
    }
    try result.appendSlice(allocator, text);

    return result.toOwnedSlice(allocator);
}

/// Center text in a given width
pub fn center(text: []const u8, width: usize, allocator: std.mem.Allocator) ![]const u8 {
    if (text.len >= width) return text;

    var result: std.ArrayList(u8) = .empty;
    const padding = (width - text.len) / 2;

    for (0..padding) |_| {
        try result.append(allocator, ' ');
    }
    try result.appendSlice(allocator, text);
    for (text.len + padding..width) |_| {
        try result.append(allocator, ' ');
    }

    return result.toOwnedSlice(allocator);
}

/// Truncate text with ellipsis
pub fn truncate(text: []const u8, max_len: usize, allocator: std.mem.Allocator) ![]const u8 {
    if (text.len <= max_len) return text;
    if (max_len <= 3) return text[0..max_len];

    var result: std.ArrayList(u8) = .empty;
    try result.appendSlice(allocator, text[0 .. max_len - 3]);
    try result.appendSlice(allocator, "...");

    return result.toOwnedSlice(allocator);
}

/// Convert to uppercase
pub fn toUpper(text: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    var result = try allocator.alloc(u8, text.len);
    for (text, 0..) |c, i| {
        result[i] = std.ascii.toUpper(c);
    }
    return result;
}

/// Convert to lowercase
pub fn toLower(text: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    var result = try allocator.alloc(u8, text.len);
    for (text, 0..) |c, i| {
        result[i] = std.ascii.toLower(c);
    }
    return result;
}

/// Split on any whitespace
pub fn splitWhitespace(text: []const u8, allocator: std.mem.Allocator) ![]const []const u8 {
    var words = std.ArrayList([]const u8).init(allocator);
    var start: ?usize = null;

    for (text, 0..) |c, i| {
        if (std.ascii.isWhitespace(c)) {
            if (start) |s| {
                try words.append(text[s..i]);
                start = null;
            }
        } else {
            if (start == null) {
                start = i;
            }
        }
    }

    // Handle last word
    if (start) |s| {
        try words.append(text[s..]);
    }

    return words.toOwnedSlice();
}

// ============================================================================
// Tests
// ============================================================================

test "padRight" {
    const padded = try padRight("hello", 10, std.testing.allocator);
    defer std.testing.allocator.free(padded);

    try std.testing.expectEqual(@as(usize, 10), padded.len);
    try std.testing.expect(mem.startsWith(u8, padded, "hello"));
}

test "truncate" {
    const truncated = try truncate("hello world", 8, std.testing.allocator);
    defer std.testing.allocator.free(truncated);

    try std.testing.expectEqualStrings("hello...", truncated);
}

test "toUpper" {
    const upper = try toUpper("hello", std.testing.allocator);
    defer std.testing.allocator.free(upper);

    try std.testing.expectEqualStrings("HELLO", upper);
}
