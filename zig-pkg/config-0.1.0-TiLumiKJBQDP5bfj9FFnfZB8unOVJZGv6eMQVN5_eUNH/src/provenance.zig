// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Provenance Module
//!
//! Tracks the source of configuration values for debugging
//! and transparency.

const std = @import("std");

/// Configuration value source
pub const Source = enum {
    /// Value from explicit Set() call (highest precedence)
    override,
    /// Value from command-line flag
    flag,
    /// Value from environment variable
    env,
    /// Value from project-level config (CWD)
    project,
    /// Value from user-level config (~/.config)
    user,
    /// Value from system-level config (/etc)
    system,
    /// Runtime default set via SetDefault()
    runtime_default,
    /// Default value from code (lowest precedence)
    default,

    pub fn format(self: Source) []const u8 {
        return switch (self) {
            .override => "override",
            .flag => "flag",
            .env => "env",
            .project => "project",
            .user => "user",
            .system => "system",
            .runtime_default => "runtime_default",
            .default => "default",
        };
    }

    /// Get precedence (lower = higher priority)
    pub fn precedence(self: Source) u8 {
        return switch (self) {
            .override => 0,
            .flag => 1,
            .env => 2,
            .project => 3,
            .user => 4,
            .system => 5,
            .runtime_default => 6,
            .default => 7,
        };
    }
};

/// Tracked configuration value
pub const TrackedValue = struct {
    /// The key name
    key: []const u8,
    /// The value as string
    value: []const u8,
    /// Where this value came from
    source: Source,
    /// Optional source path (file path or env var name)
    source_path: ?[]const u8 = null,
};

/// Configuration provenance tracker
pub const ProvenanceTracker = struct {
    allocator: std.mem.Allocator,
    values: std.StringHashMap(TrackedValue),

    const Self = @This();

    /// Initialize a new tracker
    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .values = std.StringHashMap(TrackedValue).init(allocator),
        };
    }

    /// Deinitialize the tracker
    pub fn deinit(self: *Self) void {
        self.values.deinit();
    }

    /// Set a value with source tracking (respects precedence)
    pub fn set(
        self: *Self,
        key: []const u8,
        value: []const u8,
        source: Source,
        source_path: ?[]const u8,
    ) !void {
        // Check if we already have a value with higher precedence
        if (self.values.get(key)) |existing| {
            if (existing.source.precedence() <= source.precedence()) {
                // Existing value has higher or equal precedence, don't override
                return;
            }
        }

        try self.values.put(key, .{
            .key = key,
            .value = value,
            .source = source,
            .source_path = source_path,
        });
    }

    /// Get a tracked value
    pub fn get(self: *const Self, key: []const u8) ?TrackedValue {
        return self.values.get(key);
    }

    /// Get all tracked values
    pub fn getAll(self: *const Self) []TrackedValue {
        var list: std.ArrayList(TrackedValue) = .empty;
        var iter = self.values.valueIterator();
        while (iter.next()) |val| {
            list.append(self.allocator, val.*) catch {};
        }
        return list.toOwnedSlice(self.allocator) catch &.{};
    }

    /// Print JSON provenance report
    pub fn printJson(self: *const Self, writer: anytype) !void {
        try writer.print("[", .{});
        var first = true;
        var iter = self.values.valueIterator();
        while (iter.next()) |val| {
            if (!first) try writer.print(",", .{});
            first = false;
            try writer.print("{{\"key\":\"{s}\",\"value\":\"{s}\",\"source\":\"{s}\"}}", .{
                val.key,
                val.value,
                val.source.format(),
            });
        }
        try writer.print("]\n", .{});
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Source precedence" {
    try std.testing.expect(Source.flag.precedence() < Source.env.precedence());
    try std.testing.expect(Source.env.precedence() < Source.project.precedence());
    try std.testing.expect(Source.project.precedence() < Source.user.precedence());
    try std.testing.expect(Source.user.precedence() < Source.system.precedence());
    try std.testing.expect(Source.system.precedence() < Source.default.precedence());
}

test "ProvenanceTracker respects precedence" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    // Set from system
    try tracker.set("port", "8080", .system, "/etc/app/config.toml");

    // Try to override from user (higher precedence)
    try tracker.set("port", "9000", .user, "~/.config/app/config.toml");

    // Value should be from user
    const val = tracker.get("port").?;
    try std.testing.expectEqualStrings("9000", val.value);
    try std.testing.expectEqual(Source.user, val.source);

    // Try to override from system again (lower precedence) - should not change
    try tracker.set("port", "7000", .system, "/etc/app2/config.toml");
    const val2 = tracker.get("port").?;
    try std.testing.expectEqualStrings("9000", val2.value);
}

test "provenance: Source format returns correct string" {
    try std.testing.expectEqualStrings("flag", Source.flag.format());
    try std.testing.expectEqualStrings("env", Source.env.format());
    try std.testing.expectEqualStrings("project", Source.project.format());
    try std.testing.expectEqualStrings("user", Source.user.format());
    try std.testing.expectEqualStrings("system", Source.system.format());
    try std.testing.expectEqualStrings("default", Source.default.format());
}

test "provenance: ProvenanceTracker init and deinit" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    // Initial state should be empty
    try std.testing.expect(tracker.get("nonexistent") == null);
}

test "provenance: ProvenanceTracker set and get" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.set("host", "localhost", .project, "./config.toml");

    const val = tracker.get("host").?;
    try std.testing.expectEqualStrings("host", val.key);
    try std.testing.expectEqualStrings("localhost", val.value);
    try std.testing.expectEqual(Source.project, val.source);
    try std.testing.expectEqualStrings("./config.toml", val.source_path.?);
}

test "provenance: ProvenanceTracker set without source path" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.set("debug", "true", .default, null);

    const val = tracker.get("debug").?;
    try std.testing.expectEqualStrings("debug", val.key);
    try std.testing.expectEqualStrings("true", val.value);
    try std.testing.expectEqual(Source.default, val.source);
    try std.testing.expect(val.source_path == null);
}

test "provenance: flag precedence overrides all" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    // Set from various sources
    try tracker.set("port", "default", .default, null);
    try tracker.set("port", "system", .system, null);
    try tracker.set("port", "user", .user, null);
    try tracker.set("port", "project", .project, null);
    try tracker.set("port", "env", .env, null);
    try tracker.set("port", "flag", .flag, null);

    const val = tracker.get("port").?;
    try std.testing.expectEqualStrings("flag", val.value);
    try std.testing.expectEqual(Source.flag, val.source);
}

test "provenance: flag cannot be overridden" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    // Set from flag first
    try tracker.set("port", "flag_value", .flag, null);

    // Try to override with other sources - should not change
    try tracker.set("port", "env_value", .env, null);
    try tracker.set("port", "default_value", .default, null);

    const val = tracker.get("port").?;
    try std.testing.expectEqualStrings("flag_value", val.value);
    try std.testing.expectEqual(Source.flag, val.source);
}

test "provenance: multiple keys tracked independently" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.set("host", "localhost", .project, null);
    try tracker.set("port", "8080", .env, null);
    try tracker.set("debug", "true", .flag, null);

    try std.testing.expectEqualStrings("localhost", tracker.get("host").?.value);
    try std.testing.expectEqualStrings("8080", tracker.get("port").?.value);
    try std.testing.expectEqualStrings("true", tracker.get("debug").?.value);

    try std.testing.expectEqual(Source.project, tracker.get("host").?.source);
    try std.testing.expectEqual(Source.env, tracker.get("port").?.source);
    try std.testing.expectEqual(Source.flag, tracker.get("debug").?.source);
}

test "provenance: getAll returns all tracked values" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.set("host", "localhost", .project, null);
    try tracker.set("port", "8080", .env, null);
    try tracker.set("debug", "true", .flag, null);

    const all = tracker.getAll();
    defer std.testing.allocator.free(all);

    try std.testing.expectEqual(@as(usize, 3), all.len);
}

test "provenance: printJson outputs valid format" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.set("host", "localhost", .project, null);

    var buffer: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    try tracker.printJson(writer);
    const output = stream.getWritten();

    // Verify JSON structure
    try std.testing.expect(std.mem.startsWith(u8, output, "["));
    try std.testing.expect(std.mem.indexOf(u8, output, "\"key\":\"host\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"value\":\"localhost\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"source\":\"project\"") != null);
}

test "provenance: printJson empty tracker" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    var buffer: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buffer);
    const writer = stream.writer();

    try tracker.printJson(writer);
    const output = stream.getWritten();

    try std.testing.expectEqualStrings("[]\n", output);
}

test "provenance: equal precedence does not override" {
    var tracker = ProvenanceTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.set("port", "first", .user, "/path/1");
    try tracker.set("port", "second", .user, "/path/2");

    const val = tracker.get("port").?;
    try std.testing.expectEqualStrings("first", val.value);
}
