// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Suggest Module
//!
//! Suggestion utilities using Levenshtein distance for typo correction.

const std = @import("std");

/// Calculate Levenshtein distance between two strings
pub fn levenshteinDistance(a: []const u8, b: []const u8) usize {
    if (a.len == 0) return b.len;
    if (b.len == 0) return a.len;

    // Use a single row for space optimization
    var row: [256]usize = undefined;

    // Initialize first row
    for (0..b.len + 1) |i| {
        row[i] = i;
    }

    for (a, 0..) |ca, i| {
        var prev = i;
        row[0] = i + 1;

        for (b, 0..) |cb, j| {
            const cost: usize = if (ca == cb) 0 else 1;
            const current = row[j + 1];

            row[j + 1] = @min(
                @min(row[j + 1] + 1, row[j] + 1),
                prev + cost,
            );

            prev = current;
        }
    }

    return row[b.len];
}

/// Find the closest match to input from a list of choices
pub fn suggestClosest(
    input: []const u8,
    choices: []const []const u8,
    max_distance: usize,
) ?[]const u8 {
    var best_match: ?[]const u8 = null;
    var best_distance: usize = max_distance + 1;

    for (choices) |choice| {
        const distance = levenshteinDistance(input, choice);
        if (distance < best_distance) {
            best_distance = distance;
            best_match = choice;
        }
    }

    if (best_distance <= max_distance) {
        return best_match;
    }

    return null;
}

/// Find all matches within a given distance
pub fn suggestAll(
    input: []const u8,
    choices: []const []const u8,
    max_distance: usize,
    allocator: std.mem.Allocator,
) ![]const []const u8 {
    var matches = std.ArrayList([]const u8).init(allocator);

    for (choices) |choice| {
        const distance = levenshteinDistance(input, choice);
        if (distance <= max_distance) {
            try matches.append(choice);
        }
    }

    return matches.toOwnedSlice();
}

/// Check if input is a prefix of any choice
pub fn hasPrefix(input: []const u8, choices: []const []const u8) bool {
    for (choices) |choice| {
        if (std.mem.startsWith(u8, choice, input)) {
            return true;
        }
    }
    return false;
}

/// Find all choices that start with input
pub fn findByPrefix(
    input: []const u8,
    choices: []const []const u8,
    allocator: std.mem.Allocator,
) ![]const []const u8 {
    var matches = std.ArrayList([]const u8).init(allocator);

    for (choices) |choice| {
        if (std.mem.startsWith(u8, choice, input)) {
            try matches.append(choice);
        }
    }

    return matches.toOwnedSlice();
}

// ============================================================================
// Tests
// ============================================================================

test "levenshteinDistance" {
    // Same strings
    try std.testing.expectEqual(@as(usize, 0), levenshteinDistance("hello", "hello"));

    // One char different
    try std.testing.expectEqual(@as(usize, 1), levenshteinDistance("hello", "hallo"));

    // One char missing
    try std.testing.expectEqual(@as(usize, 1), levenshteinDistance("hello", "helo"));

    // Completely different
    try std.testing.expect(levenshteinDistance("hello", "world") > 2);
}

test "suggestClosest" {
    const choices = &.{ "status", "start", "stop", "serve" };

    // Typo: 'staus' -> 'status'
    const suggestion = suggestClosest("staus", choices, 2);
    try std.testing.expect(suggestion != null);
    try std.testing.expectEqualStrings("status", suggestion.?);

    // Typo: 'pss' should not match anything with max_distance=2
    const no_match = suggestClosest("xyz", choices, 2);
    try std.testing.expect(no_match == null);
}

test "hasPrefix" {
    const choices = &.{ "status", "start", "stop", "serve" };

    try std.testing.expect(hasPrefix("st", choices));
    try std.testing.expect(hasPrefix("sta", choices));
    try std.testing.expect(!hasPrefix("xyz", choices));
}
