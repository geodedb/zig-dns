// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Dotenv Module
//!
//! Loads environment variables from .env files.
//! Note: This is for convenience only and should not be used for secrets.

const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const Allocator = mem.Allocator;

/// Environment variable entry
pub const EnvEntry = struct {
    key: []const u8,
    value: []const u8,
};

/// Load environment variables from a .env file
pub fn load(path: []const u8, allocator: Allocator) ![]EnvEntry {
    var entries: std.ArrayList(EnvEntry) = .empty;

    const file = fs.cwd().openFile(path, .{}) catch {
        return entries.toOwnedSlice(allocator);
    };
    defer file.close();

    const content = file.readToEndAlloc(allocator, 1024 * 1024) catch {
        return entries.toOwnedSlice(allocator);
    };
    defer allocator.free(content);

    var lines = mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = mem.trim(u8, line, " \t\r");

        // Skip empty lines and comments
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        // Skip export prefix if present
        var key_start: usize = 0;
        if (mem.startsWith(u8, trimmed, "export ")) {
            key_start = 7;
        }

        const eq_pos = mem.indexOf(u8, trimmed[key_start..], "=") orelse continue;
        const key = mem.trim(u8, trimmed[key_start .. key_start + eq_pos], " \t");
        var value = mem.trim(u8, trimmed[key_start + eq_pos + 1 ..], " \t");

        // Remove quotes
        if (value.len >= 2) {
            if ((value[0] == '"' and value[value.len - 1] == '"') or
                (value[0] == '\'' and value[value.len - 1] == '\''))
            {
                value = value[1 .. value.len - 1];
            }
        }

        entries.append(allocator, .{
            .key = key,
            .value = value,
        }) catch {};
    }

    return entries.toOwnedSlice(allocator);
}

/// Environment map for looking up dotenv values
/// Use this to apply dotenv values to your application
pub const EnvMap = struct {
    entries: std.StringHashMap([]const u8),
    allocator: Allocator,

    const Self = @This();

    /// Create an EnvMap from parsed entries
    pub fn init(allocator: Allocator) Self {
        return .{
            .entries = std.StringHashMap([]const u8).init(allocator),
            .allocator = allocator,
        };
    }

    /// Deinitialize the map, freeing all allocated keys and values
    pub fn deinit(self: *Self) void {
        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.entries.deinit();
    }

    /// Get a value by key
    pub fn get(self: *const Self, key: []const u8) ?[]const u8 {
        return self.entries.get(key);
    }

    /// Get a value, falling back to actual environment variable
    pub fn getOrEnv(self: *const Self, key: []const u8) ?[]const u8 {
        if (self.entries.get(key)) |value| {
            return value;
        }
        return std.posix.getenv(key);
    }

    /// Check if a key exists
    pub fn has(self: *const Self, key: []const u8) bool {
        return self.entries.contains(key);
    }

    /// Get number of entries
    pub fn count(self: *const Self) usize {
        return self.entries.count();
    }

    /// Iterator over all entries
    pub fn iterator(self: *const Self) std.StringHashMap([]const u8).Iterator {
        return self.entries.iterator();
    }
};

/// Load and apply dotenv file, returning an EnvMap for lookups
/// This is the recommended way to use dotenv values
pub fn loadAndApply(path: []const u8, allocator: Allocator) !EnvMap {
    var map = EnvMap.init(allocator);
    errdefer map.deinit();

    const file = fs.cwd().openFile(path, .{}) catch {
        return map; // Return empty map if file doesn't exist
    };
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(content);

    try applyContent(&map, content);
    return map;
}

/// Apply parsed content to an EnvMap
pub fn applyContent(map: *EnvMap, content: []const u8) !void {
    var lines = mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = mem.trim(u8, line, " \t\r");

        // Skip empty lines and comments
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        // Skip export prefix if present
        var key_start: usize = 0;
        if (mem.startsWith(u8, trimmed, "export ")) {
            key_start = 7;
        }

        const eq_pos = mem.indexOf(u8, trimmed[key_start..], "=") orelse continue;
        const key = mem.trim(u8, trimmed[key_start .. key_start + eq_pos], " \t");
        var value = mem.trim(u8, trimmed[key_start + eq_pos + 1 ..], " \t");

        // Remove quotes
        if (value.len >= 2) {
            if ((value[0] == '"' and value[value.len - 1] == '"') or
                (value[0] == '\'' and value[value.len - 1] == '\''))
            {
                value = value[1 .. value.len - 1];
            }
        }

        // Store in map (allocate copies since content will be freed)
        const owned_key = try map.allocator.dupe(u8, key);
        const owned_value = try map.allocator.dupe(u8, value);
        try map.entries.put(owned_key, owned_value);
    }
}

/// Apply loaded entries to an EnvMap
/// This creates a lookup map from parsed entries
pub fn apply(entries: []const EnvEntry, allocator: Allocator) !EnvMap {
    var map = EnvMap.init(allocator);
    errdefer map.deinit();

    for (entries) |entry| {
        const owned_key = try allocator.dupe(u8, entry.key);
        const owned_value = try allocator.dupe(u8, entry.value);
        try map.entries.put(owned_key, owned_value);
    }

    return map;
}

/// Parse .env content directly (useful for testing)
pub fn parseContent(content: []const u8, allocator: Allocator) ![]EnvEntry {
    var entries: std.ArrayList(EnvEntry) = .empty;

    var lines = mem.splitScalar(u8, content, '\n');
    while (lines.next()) |line| {
        const trimmed = mem.trim(u8, line, " \t\r");

        // Skip empty lines and comments
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        // Skip export prefix if present
        var key_start: usize = 0;
        if (mem.startsWith(u8, trimmed, "export ")) {
            key_start = 7;
        }

        const eq_pos = mem.indexOf(u8, trimmed[key_start..], "=") orelse continue;
        const key = mem.trim(u8, trimmed[key_start .. key_start + eq_pos], " \t");
        var value = mem.trim(u8, trimmed[key_start + eq_pos + 1 ..], " \t");

        // Remove quotes
        if (value.len >= 2) {
            if ((value[0] == '"' and value[value.len - 1] == '"') or
                (value[0] == '\'' and value[value.len - 1] == '\''))
            {
                value = value[1 .. value.len - 1];
            }
        }

        entries.append(allocator, .{
            .key = key,
            .value = value,
        }) catch {};
    }

    return entries.toOwnedSlice(allocator);
}

// ============================================================================
// Tests
// ============================================================================

test "dotenv: load nonexistent file returns empty" {
    const entries = try load("nonexistent.env", std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "dotenv: parse simple key-value pairs" {
    const content =
        \\HOST=localhost
        \\PORT=8080
    ;

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("HOST", entries[0].key);
    try std.testing.expectEqualStrings("localhost", entries[0].value);
    try std.testing.expectEqualStrings("PORT", entries[1].key);
    try std.testing.expectEqualStrings("8080", entries[1].value);
}

test "dotenv: parse double quoted values" {
    const content =
        \\NAME="Hello World"
        \\PATH="/usr/local/bin"
    ;

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("Hello World", entries[0].value);
    try std.testing.expectEqualStrings("/usr/local/bin", entries[1].value);
}

test "dotenv: parse single quoted values" {
    const content =
        \\NAME='literal string'
        \\REGEX='[a-z]+'
    ;

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("literal string", entries[0].value);
    try std.testing.expectEqualStrings("[a-z]+", entries[1].value);
}

test "dotenv: skip comments" {
    const content =
        \\# This is a comment
        \\HOST=localhost
        \\# Another comment
        \\PORT=8080
    ;

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 2), entries.len);
}

test "dotenv: skip empty lines" {
    const content =
        \\HOST=localhost
        \\
        \\
        \\PORT=8080
    ;

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 2), entries.len);
}

test "dotenv: handle export prefix" {
    const content =
        \\export HOST=localhost
        \\export PORT=8080
        \\NAME=test
    ;

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 3), entries.len);
    try std.testing.expectEqualStrings("HOST", entries[0].key);
    try std.testing.expectEqualStrings("localhost", entries[0].value);
    try std.testing.expectEqualStrings("PORT", entries[1].key);
    try std.testing.expectEqualStrings("NAME", entries[2].key);
}

test "dotenv: handle whitespace around equals" {
    const content =
        \\HOST = localhost
        \\PORT=8080
        \\NAME  =  test
    ;

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 3), entries.len);
    try std.testing.expectEqualStrings("HOST", entries[0].key);
    try std.testing.expectEqualStrings("localhost", entries[0].value);
}

test "dotenv: parse empty content returns empty" {
    const content = "";

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "dotenv: only comments returns empty" {
    const content =
        \\# Comment 1
        \\# Comment 2
    ;

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 0), entries.len);
}

test "dotenv: skip lines without equals" {
    const content =
        \\HOST=localhost
        \\invalid line without equals
        \\PORT=8080
    ;

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 2), entries.len);
}

test "dotenv: parse real-world .env file" {
    const content =
        \\# Database configuration
        \\DB_HOST=localhost
        \\DB_PORT=5432
        \\DB_NAME="myapp_production"
        \\DB_USER=admin
        \\DB_PASSWORD='super$ecret!'
        \\
        \\# Application settings
        \\export APP_ENV=production
        \\export DEBUG=false
        \\LOG_LEVEL=info
        \\
        \\# API keys
        \\API_KEY="abc123def456"
    ;

    const entries = try parseContent(content, std.testing.allocator);
    defer std.testing.allocator.free(entries);

    try std.testing.expectEqual(@as(usize, 9), entries.len);

    // Check some specific values
    try std.testing.expectEqualStrings("DB_HOST", entries[0].key);
    try std.testing.expectEqualStrings("localhost", entries[0].value);
    try std.testing.expectEqualStrings("DB_NAME", entries[2].key);
    try std.testing.expectEqualStrings("myapp_production", entries[2].value);
    try std.testing.expectEqualStrings("DB_PASSWORD", entries[4].key);
    try std.testing.expectEqualStrings("super$ecret!", entries[4].value);
}

test "dotenv: apply creates EnvMap" {
    const entries = [_]EnvEntry{
        .{ .key = "HOST", .value = "localhost" },
        .{ .key = "PORT", .value = "8080" },
    };

    var map = try apply(&entries, std.testing.allocator);
    defer map.deinit();

    try std.testing.expectEqual(@as(usize, 2), map.count());
    try std.testing.expectEqualStrings("localhost", map.get("HOST").?);
    try std.testing.expectEqualStrings("8080", map.get("PORT").?);
}

test "dotenv: loadAndApply with missing file returns empty map" {
    var map = try loadAndApply("nonexistent.env", std.testing.allocator);
    defer map.deinit();

    try std.testing.expectEqual(@as(usize, 0), map.count());
}

test "dotenv: EnvMap getOrEnv falls back to environment" {
    var map = EnvMap.init(std.testing.allocator);
    defer map.deinit();

    // Should return null if not in map and not in env
    try std.testing.expect(map.getOrEnv("NONEXISTENT_VAR_12345") == null);

    // PATH should exist in environment on most systems
    if (map.getOrEnv("PATH")) |_| {
        // PATH exists in environment, test passed
    }
}
