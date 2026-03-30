// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Configuration Serialization Module
//!
//! Provides utilities for serializing configuration structs to various formats.
//! Supports YAML, JSON, and TOML output formats.

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Output format for serialization
pub const OutputFormat = enum {
    json,
    json_pretty,
    yaml,
    toml,
    env,
};

/// Serialization options
pub const SerializeOptions = struct {
    /// Output format
    format: OutputFormat = .json_pretty,
    /// Include null/default values
    include_defaults: bool = true,
    /// Prefix for env format (e.g., "MYAPP_")
    env_prefix: []const u8 = "",
    /// Indent string for pretty printing
    indent: []const u8 = "  ",
};

/// Serialize a struct to a string
pub fn serialize(comptime T: type, value: T, allocator: Allocator, options: SerializeOptions) ![]u8 {
    return switch (options.format) {
        .json => serializeJson(T, value, allocator, false),
        .json_pretty => serializeJson(T, value, allocator, true),
        .yaml => serializeYaml(T, value, allocator, options),
        .toml => serializeToml(T, value, allocator, options),
        .env => serializeEnv(T, value, allocator, options),
    };
}

/// Serialize to JSON format
fn serializeJson(comptime T: type, value: T, allocator: Allocator, pretty: bool) ![]u8 {
    var list = std.ArrayList(u8).init(allocator);
    errdefer list.deinit();

    const writer = list.writer();
    try writeJsonValue(T, value, writer, 0, pretty);

    if (pretty) {
        try writer.writeByte('\n');
    }

    return list.toOwnedSlice();
}

/// Write a JSON value
fn writeJsonValue(comptime T: type, value: T, writer: anytype, depth: usize, pretty: bool) !void {
    const info = @typeInfo(T);

    switch (info) {
        .@"struct" => {
            try writer.writeByte('{');
            if (pretty) try writer.writeByte('\n');

            var first = true;
            inline for (info.@"struct".fields) |field| {
                if (!first) {
                    try writer.writeByte(',');
                    if (pretty) try writer.writeByte('\n');
                }
                first = false;

                if (pretty) {
                    try writeIndent(writer, depth + 1);
                }

                try writer.print("\"{s}\":", .{field.name});
                if (pretty) try writer.writeByte(' ');

                const field_value = @field(value, field.name);
                try writeJsonValue(field.type, field_value, writer, depth + 1, pretty);
            }

            if (pretty) {
                try writer.writeByte('\n');
                try writeIndent(writer, depth);
            }
            try writer.writeByte('}');
        },
        .optional => {
            if (value) |v| {
                try writeJsonValue(info.optional.child, v, writer, depth, pretty);
            } else {
                try writer.writeAll("null");
            }
        },
        .bool => {
            try writer.writeAll(if (value) "true" else "false");
        },
        .int => {
            try writer.print("{d}", .{value});
        },
        .float => {
            try writer.print("{d}", .{value});
        },
        .pointer => |ptr| {
            if (ptr.size == .Slice and ptr.child == u8) {
                // String
                try writer.writeByte('"');
                for (value) |c| {
                    switch (c) {
                        '"' => try writer.writeAll("\\\""),
                        '\\' => try writer.writeAll("\\\\"),
                        '\n' => try writer.writeAll("\\n"),
                        '\r' => try writer.writeAll("\\r"),
                        '\t' => try writer.writeAll("\\t"),
                        else => try writer.writeByte(c),
                    }
                }
                try writer.writeByte('"');
            } else if (ptr.size == .Slice) {
                // Array
                try writer.writeByte('[');
                if (pretty) try writer.writeByte('\n');
                for (value, 0..) |item, i| {
                    if (i > 0) {
                        try writer.writeByte(',');
                        if (pretty) try writer.writeByte('\n');
                    }
                    if (pretty) try writeIndent(writer, depth + 1);
                    try writeJsonValue(ptr.child, item, writer, depth + 1, pretty);
                }
                if (pretty) {
                    try writer.writeByte('\n');
                    try writeIndent(writer, depth);
                }
                try writer.writeByte(']');
            }
        },
        .@"enum" => {
            try writer.print("\"{s}\"", .{@tagName(value)});
        },
        else => {
            try writer.writeAll("null");
        },
    }
}

/// Write indentation
fn writeIndent(writer: anytype, depth: usize) !void {
    for (0..depth) |_| {
        try writer.writeAll("  ");
    }
}

/// Serialize to YAML format
fn serializeYaml(comptime T: type, value: T, allocator: Allocator, options: SerializeOptions) ![]u8 {
    var list = std.ArrayList(u8).init(allocator);
    errdefer list.deinit();

    const writer = list.writer();
    try writeYamlValue(T, value, writer, 0, options);

    return list.toOwnedSlice();
}

/// Write a YAML value
fn writeYamlValue(comptime T: type, value: T, writer: anytype, depth: usize, options: SerializeOptions) !void {
    const info = @typeInfo(T);

    switch (info) {
        .@"struct" => {
            inline for (info.@"struct".fields, 0..) |field, i| {
                if (i > 0 or depth > 0) {
                    try writer.writeByte('\n');
                }
                for (0..depth) |_| {
                    try writer.writeAll(options.indent);
                }
                try writer.print("{s}:", .{field.name});

                const field_value = @field(value, field.name);
                const field_info = @typeInfo(field.type);

                if (field_info == .@"struct") {
                    try writeYamlValue(field.type, field_value, writer, depth + 1, options);
                } else {
                    try writer.writeByte(' ');
                    try writeYamlScalar(field.type, field_value, writer);
                }
            }
            try writer.writeByte('\n');
        },
        else => {
            try writeYamlScalar(T, value, writer);
        },
    }
}

/// Write a YAML scalar value
fn writeYamlScalar(comptime T: type, value: T, writer: anytype) !void {
    const info = @typeInfo(T);

    switch (info) {
        .optional => {
            if (value) |v| {
                try writeYamlScalar(info.optional.child, v, writer);
            } else {
                try writer.writeAll("null");
            }
        },
        .bool => {
            try writer.writeAll(if (value) "true" else "false");
        },
        .int => {
            try writer.print("{d}", .{value});
        },
        .float => {
            try writer.print("{d}", .{value});
        },
        .pointer => |ptr| {
            if (ptr.size == .Slice and ptr.child == u8) {
                // Check if we need quotes
                const needs_quotes = value.len == 0 or
                    mem.indexOf(u8, value, ":") != null or
                    mem.indexOf(u8, value, "#") != null or
                    mem.indexOf(u8, value, "\n") != null or
                    value[0] == ' ' or
                    value[value.len - 1] == ' ';

                if (needs_quotes) {
                    try writer.writeByte('"');
                    for (value) |c| {
                        switch (c) {
                            '"' => try writer.writeAll("\\\""),
                            '\\' => try writer.writeAll("\\\\"),
                            '\n' => try writer.writeAll("\\n"),
                            else => try writer.writeByte(c),
                        }
                    }
                    try writer.writeByte('"');
                } else {
                    try writer.writeAll(value);
                }
            }
        },
        .@"enum" => {
            try writer.writeAll(@tagName(value));
        },
        else => {
            try writer.writeAll("null");
        },
    }
}

/// Serialize to TOML format
fn serializeToml(comptime T: type, value: T, allocator: Allocator, _: SerializeOptions) ![]u8 {
    var list = std.ArrayList(u8).init(allocator);
    errdefer list.deinit();

    const writer = list.writer();
    try writeTomlValue(T, value, writer, "");

    return list.toOwnedSlice();
}

/// Write a TOML value
fn writeTomlValue(comptime T: type, value: T, writer: anytype, section: []const u8) !void {
    const info = @typeInfo(T);

    if (info != .@"struct") return;

    // First pass: write simple values
    inline for (info.@"struct".fields) |field| {
        const field_info = @typeInfo(field.type);
        if (field_info != .@"struct") {
            try writer.print("{s} = ", .{field.name});
            try writeTomlScalar(field.type, @field(value, field.name), writer);
            try writer.writeByte('\n');
        }
    }

    // Second pass: write nested sections
    inline for (info.@"struct".fields) |field| {
        const field_info = @typeInfo(field.type);
        if (field_info == .@"struct") {
            try writer.writeByte('\n');
            if (section.len > 0) {
                try writer.print("[{s}.{s}]\n", .{ section, field.name });
            } else {
                try writer.print("[{s}]\n", .{field.name});
            }
            const new_section = if (section.len > 0)
                section ++ "." ++ field.name
            else
                field.name;
            try writeTomlValue(field.type, @field(value, field.name), writer, new_section);
        }
    }
}

/// Write a TOML scalar value
fn writeTomlScalar(comptime T: type, value: T, writer: anytype) !void {
    const info = @typeInfo(T);

    switch (info) {
        .optional => {
            if (value) |v| {
                try writeTomlScalar(info.optional.child, v, writer);
            } else {
                // TOML doesn't have null, so we skip or use empty string
                try writer.writeAll("\"\"");
            }
        },
        .bool => {
            try writer.writeAll(if (value) "true" else "false");
        },
        .int => {
            try writer.print("{d}", .{value});
        },
        .float => {
            try writer.print("{d}", .{value});
        },
        .pointer => |ptr| {
            if (ptr.size == .Slice and ptr.child == u8) {
                try writer.writeByte('"');
                for (value) |c| {
                    switch (c) {
                        '"' => try writer.writeAll("\\\""),
                        '\\' => try writer.writeAll("\\\\"),
                        '\n' => try writer.writeAll("\\n"),
                        '\t' => try writer.writeAll("\\t"),
                        else => try writer.writeByte(c),
                    }
                }
                try writer.writeByte('"');
            }
        },
        .@"enum" => {
            try writer.print("\"{s}\"", .{@tagName(value)});
        },
        else => {
            try writer.writeAll("\"\"");
        },
    }
}

/// Serialize to environment variable format
fn serializeEnv(comptime T: type, value: T, allocator: Allocator, options: SerializeOptions) ![]u8 {
    var list = std.ArrayList(u8).init(allocator);
    errdefer list.deinit();

    const writer = list.writer();
    try writeEnvValue(T, value, writer, options.env_prefix);

    return list.toOwnedSlice();
}

/// Write environment variables
fn writeEnvValue(comptime T: type, value: T, writer: anytype, prefix: []const u8) !void {
    const info = @typeInfo(T);

    if (info != .@"struct") return;

    inline for (info.@"struct".fields) |field| {
        const field_info = @typeInfo(field.type);
        const field_value = @field(value, field.name);

        if (field_info == .@"struct") {
            // Nested struct: add field name to prefix
            var new_prefix_buf: [256]u8 = undefined;
            const new_prefix = std.fmt.bufPrint(&new_prefix_buf, "{s}{s}_", .{ prefix, toUpperCase(field.name) }) catch continue;
            try writeEnvValue(field.type, field_value, writer, new_prefix);
        } else {
            // Simple value
            try writer.writeAll(prefix);
            try writer.writeAll(toUpperCase(field.name));
            try writer.writeByte('=');
            try writeEnvScalar(field.type, field_value, writer);
            try writer.writeByte('\n');
        }
    }
}

/// Convert to uppercase
fn toUpperCase(comptime s: []const u8) []const u8 {
    comptime {
        var result: [s.len]u8 = undefined;
        for (s, 0..) |c, i| {
            result[i] = std.ascii.toUpper(c);
        }
        return &result;
    }
}

/// Write an env scalar value
fn writeEnvScalar(comptime T: type, value: T, writer: anytype) !void {
    const info = @typeInfo(T);

    switch (info) {
        .optional => {
            if (value) |v| {
                try writeEnvScalar(info.optional.child, v, writer);
            }
            // Skip null values
        },
        .bool => {
            try writer.writeAll(if (value) "true" else "false");
        },
        .int => {
            try writer.print("{d}", .{value});
        },
        .float => {
            try writer.print("{d}", .{value});
        },
        .pointer => |ptr| {
            if (ptr.size == .Slice and ptr.child == u8) {
                // Quote if contains spaces or special chars
                const needs_quotes = mem.indexOf(u8, value, " ") != null or
                    mem.indexOf(u8, value, "\"") != null or
                    mem.indexOf(u8, value, "'") != null;

                if (needs_quotes) {
                    try writer.writeByte('"');
                    for (value) |c| {
                        switch (c) {
                            '"' => try writer.writeAll("\\\""),
                            '\\' => try writer.writeAll("\\\\"),
                            else => try writer.writeByte(c),
                        }
                    }
                    try writer.writeByte('"');
                } else {
                    try writer.writeAll(value);
                }
            }
        },
        .@"enum" => {
            try writer.writeAll(@tagName(value));
        },
        else => {},
    }
}

/// Write a config struct to a file
pub fn writeToFile(comptime T: type, value: T, path: []const u8, allocator: Allocator, options: SerializeOptions) !void {
    const content = try serialize(T, value, allocator, options);
    defer allocator.free(content);

    const file = try std.fs.cwd().createFile(path, .{});
    defer file.close();

    try file.writeAll(content);
}

/// Atomically write a config struct to a file (safe write)
/// This writes to a temporary file first, then atomically renames to the target path.
/// This prevents corruption if the write is interrupted (power failure, crash, etc.)
pub fn safeWriteToFile(comptime T: type, value: T, path: []const u8, allocator: Allocator, options: SerializeOptions) !void {
    const content = try serialize(T, value, allocator, options);
    defer allocator.free(content);

    // Create temp file path
    const temp_path = try std.fmt.allocPrint(allocator, "{s}.tmp.{d}", .{ path, std.time.milliTimestamp() });
    defer allocator.free(temp_path);

    // Write to temp file
    const temp_file = try std.fs.cwd().createFile(temp_path, .{});
    errdefer std.fs.cwd().deleteFile(temp_path) catch {};

    try temp_file.writeAll(content);
    try temp_file.sync(); // Ensure data is flushed to disk
    temp_file.close();

    // Atomically rename temp file to target path
    std.fs.cwd().rename(temp_path, path) catch |err| {
        // If rename fails, try to clean up temp file
        std.fs.cwd().deleteFile(temp_path) catch {};
        return err;
    };
}

/// Write config only if the file doesn't exist (safe write, no overwrite)
pub fn writeToFileIfNotExists(comptime T: type, value: T, path: []const u8, allocator: Allocator, options: SerializeOptions) !bool {
    // Check if file exists
    std.fs.cwd().access(path, .{}) catch {
        // File doesn't exist, write it
        try safeWriteToFile(T, value, path, allocator, options);
        return true;
    };
    // File exists, don't overwrite
    return false;
}

/// Write config with backup of existing file
pub fn writeToFileWithBackup(comptime T: type, value: T, path: []const u8, allocator: Allocator, options: SerializeOptions) !void {
    // Check if file exists and create backup
    std.fs.cwd().access(path, .{}) catch {
        // File doesn't exist, just write it
        try safeWriteToFile(T, value, path, allocator, options);
        return;
    };

    // Create backup path
    const backup_path = try std.fmt.allocPrint(allocator, "{s}.bak", .{path});
    defer allocator.free(backup_path);

    // Copy existing file to backup (delete old backup first if exists)
    std.fs.cwd().deleteFile(backup_path) catch {};
    std.fs.cwd().copyFile(path, std.fs.cwd(), backup_path, .{}) catch |err| {
        // If copy fails due to source not existing, ignore and proceed
        if (err != error.FileNotFound) return err;
    };

    // Now safe write the new config
    try safeWriteToFile(T, value, path, allocator, options);
}

// ============================================================================
// Tests
// ============================================================================

test "serialize JSON" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
        debug: bool = false,
    };

    const config = Config{ .host = "example.com", .port = 443, .debug = true };
    const json = try serialize(Config, config, std.testing.allocator, .{ .format = .json });
    defer std.testing.allocator.free(json);

    try std.testing.expect(mem.indexOf(u8, json, "\"host\":\"example.com\"") != null);
    try std.testing.expect(mem.indexOf(u8, json, "\"port\":443") != null);
    try std.testing.expect(mem.indexOf(u8, json, "\"debug\":true") != null);
}

test "serialize JSON pretty" {
    const Config = struct {
        name: []const u8 = "test",
    };

    const config = Config{};
    const json = try serialize(Config, config, std.testing.allocator, .{ .format = .json_pretty });
    defer std.testing.allocator.free(json);

    // Pretty should have newlines
    try std.testing.expect(mem.indexOf(u8, json, "\n") != null);
}

test "serialize YAML" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    const config = Config{ .host = "myhost" };
    const yaml = try serialize(Config, config, std.testing.allocator, .{ .format = .yaml });
    defer std.testing.allocator.free(yaml);

    try std.testing.expect(mem.indexOf(u8, yaml, "host: myhost") != null);
    try std.testing.expect(mem.indexOf(u8, yaml, "port: 8080") != null);
}

test "serialize TOML" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    const config = Config{};
    const toml_str = try serialize(Config, config, std.testing.allocator, .{ .format = .toml });
    defer std.testing.allocator.free(toml_str);

    try std.testing.expect(mem.indexOf(u8, toml_str, "host = \"localhost\"") != null);
    try std.testing.expect(mem.indexOf(u8, toml_str, "port = 8080") != null);
}

test "serialize env" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    const config = Config{};
    const env = try serialize(Config, config, std.testing.allocator, .{
        .format = .env,
        .env_prefix = "APP_",
    });
    defer std.testing.allocator.free(env);

    try std.testing.expect(mem.indexOf(u8, env, "APP_HOST=localhost") != null);
    try std.testing.expect(mem.indexOf(u8, env, "APP_PORT=8080") != null);
}

test "serialize optional fields" {
    const Config = struct {
        name: ?[]const u8 = null,
        count: ?u32 = null,
    };

    const config = Config{ .name = "test" };
    const json = try serialize(Config, config, std.testing.allocator, .{ .format = .json });
    defer std.testing.allocator.free(json);

    try std.testing.expect(mem.indexOf(u8, json, "\"name\":\"test\"") != null);
    try std.testing.expect(mem.indexOf(u8, json, "\"count\":null") != null);
}

test "safeWriteToFile atomic write" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    const config = Config{};
    const test_path = "/tmp/zigconfig_test_safe_write.json";

    // Write config atomically
    try safeWriteToFile(Config, config, test_path, std.testing.allocator, .{ .format = .json });

    // Verify file was created
    const file = try std.fs.cwd().openFile(test_path, .{});
    defer file.close();

    const content = try file.readToEndAlloc(std.testing.allocator, 4096);
    defer std.testing.allocator.free(content);

    try std.testing.expect(mem.indexOf(u8, content, "localhost") != null);

    // Clean up
    std.fs.cwd().deleteFile(test_path) catch {};
}

test "writeToFileIfNotExists" {
    const Config = struct {
        value: []const u8 = "original",
    };

    const test_path = "/tmp/zigconfig_test_if_not_exists.json";

    // Ensure file doesn't exist
    std.fs.cwd().deleteFile(test_path) catch {};

    // First write should succeed
    const written = try writeToFileIfNotExists(Config, .{}, test_path, std.testing.allocator, .{ .format = .json });
    try std.testing.expect(written);

    // Second write should return false (file exists)
    const written2 = try writeToFileIfNotExists(Config, .{ .value = "modified" }, test_path, std.testing.allocator, .{ .format = .json });
    try std.testing.expect(!written2);

    // Clean up
    std.fs.cwd().deleteFile(test_path) catch {};
}
