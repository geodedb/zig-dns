// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Configuration Diff and Comparison Module
//!
//! Provides utilities for comparing configuration values and detecting changes.
//! Useful for:
//! - Hot-reload change detection
//! - Configuration auditing
//! - Migration validation
//!
//! Example usage:
//! ```zig
//! const diff = @import("diff");
//!
//! var old_config = std.StringHashMap([]const u8).init(allocator);
//! var new_config = std.StringHashMap([]const u8).init(allocator);
//!
//! // ... populate configs ...
//!
//! const changes = try diff.compare(allocator, old_config, new_config);
//! defer allocator.free(changes);
//!
//! for (changes) |change| {
//!     std.debug.print("{s}: {s} -> {s}\n", .{change.key, change.old_value, change.new_value});
//! }
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Type of change detected
pub const ChangeType = enum {
    added,
    removed,
    modified,
    unchanged,
};

/// A single configuration change
pub const Change = struct {
    key: []const u8,
    change_type: ChangeType,
    old_value: ?[]const u8,
    new_value: ?[]const u8,

    pub fn format(
        self: Change,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;

        switch (self.change_type) {
            .added => try writer.print("+ {s}: {s}", .{ self.key, self.new_value orelse "(null)" }),
            .removed => try writer.print("- {s}: {s}", .{ self.key, self.old_value orelse "(null)" }),
            .modified => try writer.print("~ {s}: {s} -> {s}", .{
                self.key,
                self.old_value orelse "(null)",
                self.new_value orelse "(null)",
            }),
            .unchanged => try writer.print("  {s}: {s}", .{ self.key, self.old_value orelse "(null)" }),
        }
    }
};

/// Result of a diff operation
pub const DiffResult = struct {
    changes: []Change,
    added_count: usize,
    removed_count: usize,
    modified_count: usize,
    unchanged_count: usize,

    pub fn hasChanges(self: DiffResult) bool {
        return self.added_count > 0 or self.removed_count > 0 or self.modified_count > 0;
    }

    pub fn totalChanges(self: DiffResult) usize {
        return self.added_count + self.removed_count + self.modified_count;
    }
};

/// Compare two configuration maps and return all changes
pub fn compare(
    allocator: Allocator,
    old_config: std.StringHashMap([]const u8),
    new_config: std.StringHashMap([]const u8),
) !DiffResult {
    return compareWithOptions(allocator, old_config, new_config, .{});
}

/// Comparison options
pub const CompareOptions = struct {
    /// Include unchanged keys in result
    include_unchanged: bool = false,
    /// Case-insensitive key comparison
    case_insensitive: bool = false,
    /// Ignore whitespace differences in values
    ignore_whitespace: bool = false,
};

/// Compare two configuration maps with options
pub fn compareWithOptions(
    allocator: Allocator,
    old_config: std.StringHashMap([]const u8),
    new_config: std.StringHashMap([]const u8),
    options: CompareOptions,
) !DiffResult {
    var changes: std.ArrayListUnmanaged(Change) = .{};
    errdefer changes.deinit(allocator);

    var added_count: usize = 0;
    var removed_count: usize = 0;
    var modified_count: usize = 0;
    var unchanged_count: usize = 0;

    // Track which keys from new_config we've seen
    var seen_keys = std.StringHashMap(void).init(allocator);
    defer seen_keys.deinit();

    // Check old keys
    var old_iter = old_config.iterator();
    while (old_iter.next()) |old_entry| {
        const key = old_entry.key_ptr.*;
        const old_value = old_entry.value_ptr.*;

        if (getValueForKey(new_config, key, options.case_insensitive)) |new_value| {
            try seen_keys.put(key, {});

            const values_equal = if (options.ignore_whitespace)
                trimmedEqual(old_value, new_value)
            else
                mem.eql(u8, old_value, new_value);

            if (values_equal) {
                unchanged_count += 1;
                if (options.include_unchanged) {
                    try changes.append(allocator, .{
                        .key = key,
                        .change_type = .unchanged,
                        .old_value = old_value,
                        .new_value = new_value,
                    });
                }
            } else {
                modified_count += 1;
                try changes.append(allocator, .{
                    .key = key,
                    .change_type = .modified,
                    .old_value = old_value,
                    .new_value = new_value,
                });
            }
        } else {
            removed_count += 1;
            try changes.append(allocator, .{
                .key = key,
                .change_type = .removed,
                .old_value = old_value,
                .new_value = null,
            });
        }
    }

    // Check for added keys
    var new_iter = new_config.iterator();
    while (new_iter.next()) |new_entry| {
        const key = new_entry.key_ptr.*;

        const was_seen = if (options.case_insensitive)
            containsKeyInsensitive(seen_keys, key)
        else
            seen_keys.contains(key);

        if (!was_seen) {
            if (getValueForKey(old_config, key, options.case_insensitive) == null) {
                added_count += 1;
                try changes.append(allocator, .{
                    .key = key,
                    .change_type = .added,
                    .old_value = null,
                    .new_value = new_entry.value_ptr.*,
                });
            }
        }
    }

    return .{
        .changes = try changes.toOwnedSlice(allocator),
        .added_count = added_count,
        .removed_count = removed_count,
        .modified_count = modified_count,
        .unchanged_count = unchanged_count,
    };
}

fn getValueForKey(map: std.StringHashMap([]const u8), key: []const u8, case_insensitive: bool) ?[]const u8 {
    if (!case_insensitive) {
        return map.get(key);
    }

    var iter = map.iterator();
    while (iter.next()) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, key)) {
            return entry.value_ptr.*;
        }
    }
    return null;
}

fn containsKeyInsensitive(map: std.StringHashMap(void), key: []const u8) bool {
    var iter = map.keyIterator();
    while (iter.next()) |k| {
        if (std.ascii.eqlIgnoreCase(k.*, key)) {
            return true;
        }
    }
    return false;
}

fn trimmedEqual(a: []const u8, b: []const u8) bool {
    const trimmed_a = mem.trim(u8, a, " \t\r\n");
    const trimmed_b = mem.trim(u8, b, " \t\r\n");
    return mem.eql(u8, trimmed_a, trimmed_b);
}

/// Generate a human-readable diff report
pub fn formatDiff(allocator: Allocator, result: DiffResult) ![]u8 {
    var output: std.ArrayListUnmanaged(u8) = .{};
    errdefer output.deinit(allocator);

    const writer = output.writer(allocator);

    try writer.print("Configuration Diff Report\n", .{});
    try writer.print("========================\n\n", .{});

    if (!result.hasChanges()) {
        try writer.print("No changes detected.\n", .{});
    } else {
        try writer.print("Summary: {d} added, {d} removed, {d} modified\n\n", .{
            result.added_count,
            result.removed_count,
            result.modified_count,
        });

        // Group by change type
        if (result.added_count > 0) {
            try writer.print("Added:\n", .{});
            for (result.changes) |change| {
                if (change.change_type == .added) {
                    try writer.print("  + {s} = {s}\n", .{ change.key, change.new_value orelse "" });
                }
            }
            try writer.print("\n", .{});
        }

        if (result.removed_count > 0) {
            try writer.print("Removed:\n", .{});
            for (result.changes) |change| {
                if (change.change_type == .removed) {
                    try writer.print("  - {s} = {s}\n", .{ change.key, change.old_value orelse "" });
                }
            }
            try writer.print("\n", .{});
        }

        if (result.modified_count > 0) {
            try writer.print("Modified:\n", .{});
            for (result.changes) |change| {
                if (change.change_type == .modified) {
                    try writer.print("  ~ {s}: {s} -> {s}\n", .{
                        change.key,
                        change.old_value orelse "",
                        change.new_value orelse "",
                    });
                }
            }
        }
    }

    return output.toOwnedSlice(allocator);
}

/// Free a DiffResult
pub fn freeDiffResult(allocator: Allocator, result: *DiffResult) void {
    allocator.free(result.changes);
    result.changes = &.{};
}

/// Check if two configs are equivalent
pub fn isEquivalent(
    old_config: std.StringHashMap([]const u8),
    new_config: std.StringHashMap([]const u8),
) bool {
    if (old_config.count() != new_config.count()) return false;

    var iter = old_config.iterator();
    while (iter.next()) |entry| {
        if (new_config.get(entry.key_ptr.*)) |new_value| {
            if (!mem.eql(u8, entry.value_ptr.*, new_value)) {
                return false;
            }
        } else {
            return false;
        }
    }

    return true;
}

/// Get keys that exist in both configs
pub fn intersection(
    allocator: Allocator,
    config1: std.StringHashMap([]const u8),
    config2: std.StringHashMap([]const u8),
) ![]const []const u8 {
    var result: std.ArrayListUnmanaged([]const u8) = .{};
    errdefer result.deinit(allocator);

    var iter = config1.keyIterator();
    while (iter.next()) |key| {
        if (config2.contains(key.*)) {
            try result.append(allocator, key.*);
        }
    }

    return result.toOwnedSlice(allocator);
}

/// Get keys that exist only in config1
pub fn difference(
    allocator: Allocator,
    config1: std.StringHashMap([]const u8),
    config2: std.StringHashMap([]const u8),
) ![]const []const u8 {
    var result: std.ArrayListUnmanaged([]const u8) = .{};
    errdefer result.deinit(allocator);

    var iter = config1.keyIterator();
    while (iter.next()) |key| {
        if (!config2.contains(key.*)) {
            try result.append(allocator, key.*);
        }
    }

    return result.toOwnedSlice(allocator);
}

/// Merge two configs with conflict resolution
pub const MergeStrategy = enum {
    /// Keep old value on conflict
    keep_old,
    /// Use new value on conflict
    use_new,
    /// Fail on conflict
    fail,
};

pub const MergeError = error{
    Conflict,
    OutOfMemory,
};

/// Merge two configs
pub fn merge(
    allocator: Allocator,
    base: std.StringHashMap([]const u8),
    overlay: std.StringHashMap([]const u8),
    strategy: MergeStrategy,
) MergeError!std.StringHashMap([]const u8) {
    var result = std.StringHashMap([]const u8).init(allocator);
    errdefer result.deinit();

    // Copy base
    var base_iter = base.iterator();
    while (base_iter.next()) |entry| {
        result.put(entry.key_ptr.*, entry.value_ptr.*) catch return MergeError.OutOfMemory;
    }

    // Apply overlay
    var overlay_iter = overlay.iterator();
    while (overlay_iter.next()) |entry| {
        const key = entry.key_ptr.*;
        const new_value = entry.value_ptr.*;

        if (result.get(key)) |_| {
            // Conflict
            switch (strategy) {
                .keep_old => {}, // Do nothing
                .use_new => {
                    result.put(key, new_value) catch return MergeError.OutOfMemory;
                },
                .fail => return MergeError.Conflict,
            }
        } else {
            result.put(key, new_value) catch return MergeError.OutOfMemory;
        }
    }

    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "compare detects added keys" {
    var old = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer old.deinit();

    var new = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer new.deinit();

    try new.put("host", "localhost");

    const result = try compare(std.testing.allocator, old, new);
    defer std.testing.allocator.free(result.changes);

    try std.testing.expectEqual(@as(usize, 1), result.added_count);
    try std.testing.expectEqual(@as(usize, 0), result.removed_count);
    try std.testing.expectEqual(@as(usize, 0), result.modified_count);
}

test "compare detects removed keys" {
    var old = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer old.deinit();

    var new = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer new.deinit();

    try old.put("host", "localhost");

    const result = try compare(std.testing.allocator, old, new);
    defer std.testing.allocator.free(result.changes);

    try std.testing.expectEqual(@as(usize, 0), result.added_count);
    try std.testing.expectEqual(@as(usize, 1), result.removed_count);
    try std.testing.expectEqual(@as(usize, 0), result.modified_count);
}

test "compare detects modified keys" {
    var old = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer old.deinit();

    var new = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer new.deinit();

    try old.put("host", "localhost");
    try new.put("host", "example.com");

    const result = try compare(std.testing.allocator, old, new);
    defer std.testing.allocator.free(result.changes);

    try std.testing.expectEqual(@as(usize, 0), result.added_count);
    try std.testing.expectEqual(@as(usize, 0), result.removed_count);
    try std.testing.expectEqual(@as(usize, 1), result.modified_count);
}

test "compare with unchanged" {
    var old = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer old.deinit();

    var new = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer new.deinit();

    try old.put("host", "localhost");
    try new.put("host", "localhost");

    const result = try compareWithOptions(std.testing.allocator, old, new, .{ .include_unchanged = true });
    defer std.testing.allocator.free(result.changes);

    try std.testing.expectEqual(@as(usize, 1), result.unchanged_count);
    try std.testing.expectEqual(@as(usize, 1), result.changes.len);
}

test "isEquivalent" {
    var config1 = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer config1.deinit();

    var config2 = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer config2.deinit();

    try config1.put("host", "localhost");
    try config1.put("port", "8080");

    try config2.put("host", "localhost");
    try config2.put("port", "8080");

    try std.testing.expect(isEquivalent(config1, config2));

    try config2.put("debug", "true");
    try std.testing.expect(!isEquivalent(config1, config2));
}

test "intersection" {
    var config1 = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer config1.deinit();

    var config2 = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer config2.deinit();

    try config1.put("host", "localhost");
    try config1.put("port", "8080");
    try config1.put("debug", "true");

    try config2.put("host", "example.com");
    try config2.put("timeout", "30");

    const common = try intersection(std.testing.allocator, config1, config2);
    defer std.testing.allocator.free(common);

    try std.testing.expectEqual(@as(usize, 1), common.len);
    try std.testing.expectEqualStrings("host", common[0]);
}

test "difference" {
    var config1 = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer config1.deinit();

    var config2 = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer config2.deinit();

    try config1.put("host", "localhost");
    try config1.put("port", "8080");

    try config2.put("host", "example.com");

    const diff_keys = try difference(std.testing.allocator, config1, config2);
    defer std.testing.allocator.free(diff_keys);

    try std.testing.expectEqual(@as(usize, 1), diff_keys.len);
    try std.testing.expectEqualStrings("port", diff_keys[0]);
}

test "merge with use_new strategy" {
    var base = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer base.deinit();

    var overlay = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer overlay.deinit();

    try base.put("host", "localhost");
    try base.put("port", "8080");

    try overlay.put("host", "example.com");
    try overlay.put("debug", "true");

    var result = try merge(std.testing.allocator, base, overlay, .use_new);
    defer result.deinit();

    try std.testing.expectEqualStrings("example.com", result.get("host").?);
    try std.testing.expectEqualStrings("8080", result.get("port").?);
    try std.testing.expectEqualStrings("true", result.get("debug").?);
}

test "merge with fail strategy" {
    var base = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer base.deinit();

    var overlay = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer overlay.deinit();

    try base.put("host", "localhost");
    try overlay.put("host", "example.com");

    const result = merge(std.testing.allocator, base, overlay, .fail);
    try std.testing.expectError(MergeError.Conflict, result);
}

test "DiffResult hasChanges" {
    const no_changes = DiffResult{
        .changes = &.{},
        .added_count = 0,
        .removed_count = 0,
        .modified_count = 0,
        .unchanged_count = 5,
    };

    try std.testing.expect(!no_changes.hasChanges());

    const has_changes = DiffResult{
        .changes = &.{},
        .added_count = 1,
        .removed_count = 0,
        .modified_count = 0,
        .unchanged_count = 5,
    };

    try std.testing.expect(has_changes.hasChanges());
}

test "formatDiff" {
    var old = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer old.deinit();

    var new = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer new.deinit();

    try old.put("removed_key", "old_value");
    try new.put("added_key", "new_value");

    const result = try compare(std.testing.allocator, old, new);
    defer std.testing.allocator.free(result.changes);

    const report = try formatDiff(std.testing.allocator, result);
    defer std.testing.allocator.free(report);

    try std.testing.expect(mem.indexOf(u8, report, "Configuration Diff Report") != null);
    try std.testing.expect(mem.indexOf(u8, report, "1 added") != null);
    try std.testing.expect(mem.indexOf(u8, report, "1 removed") != null);
}
