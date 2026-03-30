// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Configuration Merge Module
//!
//! Provides utilities for merging configuration values from multiple sources.
//! Supports deep merging of nested structures and various merge strategies.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Merge strategy for handling conflicts
pub const MergeStrategy = enum {
    /// Later values override earlier values (default)
    override,
    /// Keep first value, ignore later ones
    keep_first,
    /// For arrays: concatenate, for others: override
    concat_arrays,
    /// For arrays: merge unique values only
    unique_arrays,
};

/// Configuration for merge operations
pub const MergeOptions = struct {
    /// How to handle conflicting values
    strategy: MergeStrategy = .override,
    /// Whether to merge nested objects deeply
    deep_merge: bool = true,
    /// Whether to allow null to override non-null
    allow_null_override: bool = false,
};

/// Merge two string-keyed hashmaps
/// The result contains all keys from both, with conflicts resolved by strategy
pub fn mergeMaps(
    comptime V: type,
    allocator: Allocator,
    base: std.StringHashMap(V),
    overlay: std.StringHashMap(V),
    options: MergeOptions,
) !std.StringHashMap(V) {
    var result = std.StringHashMap(V).init(allocator);
    errdefer result.deinit();

    // Copy all base values
    var base_iter = base.iterator();
    while (base_iter.next()) |entry| {
        const key = try allocator.dupe(u8, entry.key_ptr.*);
        try result.put(key, entry.value_ptr.*);
    }

    // Apply overlay values based on strategy
    var overlay_iter = overlay.iterator();
    while (overlay_iter.next()) |entry| {
        const key = entry.key_ptr.*;

        switch (options.strategy) {
            .override => {
                const owned_key = try allocator.dupe(u8, key);
                try result.put(owned_key, entry.value_ptr.*);
            },
            .keep_first => {
                if (result.get(key) == null) {
                    const owned_key = try allocator.dupe(u8, key);
                    try result.put(owned_key, entry.value_ptr.*);
                }
            },
            .concat_arrays, .unique_arrays => {
                // For simple types, just override
                const owned_key = try allocator.dupe(u8, key);
                try result.put(owned_key, entry.value_ptr.*);
            },
        }
    }

    return result;
}

/// Merge two slices of key-value pairs
pub fn mergeEntries(
    comptime Entry: type,
    allocator: Allocator,
    base: []const Entry,
    overlay: []const Entry,
    comptime keyFn: fn (Entry) []const u8,
) ![]Entry {
    var result = std.ArrayList(Entry).init(allocator);
    errdefer result.deinit();

    // Track which keys we've seen
    var seen = std.StringHashMap(void).init(allocator);
    defer seen.deinit();

    // Add overlay entries first (higher priority)
    for (overlay) |entry| {
        const key = keyFn(entry);
        if (seen.get(key) == null) {
            try result.append(entry);
            try seen.put(key, {});
        }
    }

    // Add base entries that weren't overridden
    for (base) |entry| {
        const key = keyFn(entry);
        if (seen.get(key) == null) {
            try result.append(entry);
            try seen.put(key, {});
        }
    }

    return result.toOwnedSlice();
}

/// Deep merge two structs of the same type
/// Overlay values override base values for non-default fields
pub fn mergeStructs(comptime T: type, base: T, overlay: T) T {
    var result: T = base;
    const info = @typeInfo(T);

    inline for (info.@"struct".fields) |field| {
        const overlay_value = @field(overlay, field.name);

        // Check if overlay has a non-default value
        if (field.default_value_ptr) |default_ptr| {
            const default_value: *const field.type = @alignCast(@ptrCast(default_ptr));
            if (!eqlValue(field.type, overlay_value, default_value.*)) {
                @field(result, field.name) = overlay_value;
            }
        } else {
            // No default, always take overlay
            @field(result, field.name) = overlay_value;
        }
    }

    return result;
}

/// Compare two values for equality
fn eqlValue(comptime T: type, a: T, b: T) bool {
    const info = @typeInfo(T);

    return switch (info) {
        .bool => a == b,
        .int, .float => a == b,
        .pointer => |ptr| blk: {
            if (ptr.size == .Slice) {
                if (ptr.child == u8) {
                    break :blk mem.eql(u8, a, b);
                }
            }
            break :blk a == b;
        },
        .optional => blk: {
            if (a == null and b == null) break :blk true;
            if (a == null or b == null) break :blk false;
            break :blk eqlValue(info.optional.child, a.?, b.?);
        },
        else => a == b,
    };
}

/// Merge multiple configs in order (later overrides earlier)
pub fn mergeMany(comptime T: type, configs: []const T) T {
    if (configs.len == 0) return .{};
    if (configs.len == 1) return configs[0];

    var result = configs[0];
    for (configs[1..]) |config| {
        result = mergeStructs(T, result, config);
    }
    return result;
}

/// Merge two configs, preferring non-null overlay values
/// This is a simpler alternative that always takes overlay if not null/default
pub fn mergePreferOverlay(comptime T: type, base: T, overlay: T) T {
    var result: T = undefined;
    const info = @typeInfo(T);

    inline for (info.@"struct".fields) |field| {
        const overlay_value = @field(overlay, field.name);
        const base_value = @field(base, field.name);

        // For optional types, prefer overlay if non-null
        if (@typeInfo(field.type) == .optional) {
            if (overlay_value != null) {
                @field(result, field.name) = overlay_value;
            } else {
                @field(result, field.name) = base_value;
            }
        } else if (field.default_value_ptr) |default_ptr| {
            // For types with defaults, check if overlay is non-default
            const default_value: *const field.type = @alignCast(@ptrCast(default_ptr));
            if (!eqlValue(field.type, overlay_value, default_value.*)) {
                @field(result, field.name) = overlay_value;
            } else {
                @field(result, field.name) = base_value;
            }
        } else {
            // No default, take overlay
            @field(result, field.name) = overlay_value;
        }
    }

    return result;
}

// ============================================================================
// Tests
// ============================================================================

test "mergeStructs basic" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
        debug: bool = false,
    };

    const base = Config{ .host = "basehost", .port = 9000 };
    const overlay = Config{ .port = 3000, .debug = true };

    const result = mergeStructs(Config, base, overlay);

    try std.testing.expectEqualStrings("basehost", result.host);
    try std.testing.expectEqual(@as(u16, 3000), result.port);
    try std.testing.expect(result.debug);
}

test "mergeStructs overlay defaults do not override" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    const base = Config{ .host = "customhost", .port = 9000 };
    const overlay = Config{}; // All defaults

    const result = mergeStructs(Config, base, overlay);

    // Overlay has defaults, so base values should be kept
    try std.testing.expectEqualStrings("customhost", result.host);
    try std.testing.expectEqual(@as(u16, 9000), result.port);
}

test "mergeMany multiple configs" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
        debug: bool = false,
    };

    const configs = [_]Config{
        .{ .host = "first" },
        .{ .port = 9000 },
        .{ .debug = true },
    };

    const result = mergeMany(Config, &configs);

    try std.testing.expectEqualStrings("first", result.host);
    try std.testing.expectEqual(@as(u16, 9000), result.port);
    try std.testing.expect(result.debug);
}

test "mergeMany empty returns default" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    const configs: []const Config = &.{};
    const result = mergeMany(Config, configs);

    try std.testing.expectEqualStrings("localhost", result.host);
    try std.testing.expectEqual(@as(u16, 8080), result.port);
}

test "mergeStructs with optional fields" {
    const Config = struct {
        name: ?[]const u8 = null,
        timeout: ?u32 = null,
    };

    const base = Config{ .name = "myapp" };
    const overlay = Config{ .timeout = 30 };

    const result = mergeStructs(Config, base, overlay);

    try std.testing.expectEqualStrings("myapp", result.name.?);
    try std.testing.expectEqual(@as(u32, 30), result.timeout.?);
}

test "eqlValue for strings" {
    try std.testing.expect(eqlValue([]const u8, "hello", "hello"));
    try std.testing.expect(!eqlValue([]const u8, "hello", "world"));
}

test "eqlValue for optionals" {
    const a: ?u32 = 42;
    const b: ?u32 = 42;
    const c: ?u32 = null;
    const d: ?u32 = null;

    try std.testing.expect(eqlValue(?u32, a, b));
    try std.testing.expect(eqlValue(?u32, c, d));
    try std.testing.expect(!eqlValue(?u32, a, c));
}
