// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Java Properties Format Parser
//!
//! Parses Java .properties configuration files with support for:
//! - Key-value pairs: key=value or key:value or key value
//! - Comments: # comment or ! comment
//! - Multiline values with backslash continuation
//! - Unicode escapes: \uXXXX
//! - Special character escapes: \t, \n, \r, \\
//!
//! Example .properties file:
//! ```properties
//! # Database configuration
//! database.host=localhost
//! database.port=5432
//! database.name=myapp
//!
//! # Server settings
//! server.host=0.0.0.0
//! server.port=8080
//! server.message=Hello \
//!     World
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Properties parsing errors
pub const PropertiesError = error{
    InvalidSyntax,
    InvalidEscape,
    InvalidUnicodeEscape,
    OutOfMemory,
};

/// Parsed properties document
pub const Properties = struct {
    allocator: Allocator,
    /// Key-value pairs
    values: std.StringHashMap([]const u8),
    /// Arena for string storage
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: Allocator) Properties {
        return .{
            .allocator = allocator,
            .values = std.StringHashMap([]const u8).init(allocator),
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *Properties) void {
        self.values.deinit();
        self.arena.deinit();
    }

    /// Get a value by key
    pub fn get(self: *const Properties, key: []const u8) ?[]const u8 {
        return self.values.get(key);
    }

    /// Check if a key exists
    pub fn has(self: *const Properties, key: []const u8) bool {
        return self.values.contains(key);
    }

    /// Get all keys
    pub fn keys(self: *const Properties) ![]const []const u8 {
        var result: std.ArrayListUnmanaged([]const u8) = .{};
        errdefer result.deinit(self.allocator);

        var iter = self.values.keyIterator();
        while (iter.next()) |key| {
            try result.append(self.allocator, key.*);
        }

        return result.toOwnedSlice(self.allocator);
    }

    /// Get number of properties
    pub fn count(self: *const Properties) usize {
        return self.values.count();
    }

    /// Iterator over key-value pairs
    pub fn iterator(self: *const Properties) std.StringHashMap([]const u8).Iterator {
        return self.values.iterator();
    }
};

/// Parse properties content from a string
pub fn parse(allocator: Allocator, content: []const u8) PropertiesError!Properties {
    var props = Properties.init(allocator);
    errdefer props.deinit();

    var lines = mem.splitScalar(u8, content, '\n');
    var pending_key: ?[]const u8 = null;
    var pending_value: std.ArrayListUnmanaged(u8) = .{};
    defer pending_value.deinit(allocator);

    while (lines.next()) |raw_line| {
        var line = mem.trimRight(u8, raw_line, "\r");

        // Handle line continuation
        if (pending_key != null) {
            // Continue previous line - trim leading whitespace
            line = mem.trimLeft(u8, line, " \t");
            const continues = line.len > 0 and line[line.len - 1] == '\\';
            const line_content = if (continues) line[0 .. line.len - 1] else line;

            try appendUnescaped(allocator, &pending_value, line_content);

            if (!continues) {
                // End of multiline value
                const owned_value = props.arena.allocator().dupe(u8, pending_value.items) catch return PropertiesError.OutOfMemory;
                props.values.put(pending_key.?, owned_value) catch return PropertiesError.OutOfMemory;
                pending_key = null;
                pending_value.clearRetainingCapacity();
            }
            continue;
        }

        // Skip leading whitespace
        const trimmed = mem.trimLeft(u8, line, " \t");

        // Skip empty lines and comments
        if (trimmed.len == 0) continue;
        if (trimmed[0] == '#' or trimmed[0] == '!') continue;

        // Find separator (=, :, or first whitespace)
        var sep_pos: ?usize = null;
        var sep_len: usize = 1;

        for (trimmed, 0..) |c, i| {
            // Skip escaped characters
            if (i > 0 and trimmed[i - 1] == '\\') continue;

            if (c == '=' or c == ':') {
                sep_pos = i;
                break;
            }
            if (c == ' ' or c == '\t') {
                sep_pos = i;
                // Check if followed by = or :
                const after_ws = mem.trimLeft(u8, trimmed[i..], " \t");
                if (after_ws.len > 0 and (after_ws[0] == '=' or after_ws[0] == ':')) {
                    sep_pos = trimmed.len - after_ws.len;
                    sep_len = trimmed.len - after_ws.len - i + 1;
                }
                break;
            }
        }

        if (sep_pos) |pos| {
            const raw_key = mem.trim(u8, trimmed[0..pos], " \t");
            const raw_value_start = pos + sep_len;
            const raw_value = if (raw_value_start < trimmed.len)
                mem.trimLeft(u8, trimmed[raw_value_start..], " \t")
            else
                "";

            // Unescape key
            var key_buf: std.ArrayListUnmanaged(u8) = .{};
            defer key_buf.deinit(allocator);
            try appendUnescaped(allocator, &key_buf, raw_key);
            const owned_key = props.arena.allocator().dupe(u8, key_buf.items) catch return PropertiesError.OutOfMemory;

            // Check for line continuation
            const continues = raw_value.len > 0 and raw_value[raw_value.len - 1] == '\\';
            const value_content = if (continues) raw_value[0 .. raw_value.len - 1] else raw_value;

            if (continues) {
                pending_key = owned_key;
                try appendUnescaped(allocator, &pending_value, value_content);
            } else {
                var value_buf: std.ArrayListUnmanaged(u8) = .{};
                defer value_buf.deinit(allocator);
                try appendUnescaped(allocator, &value_buf, value_content);
                const owned_value = props.arena.allocator().dupe(u8, value_buf.items) catch return PropertiesError.OutOfMemory;
                props.values.put(owned_key, owned_value) catch return PropertiesError.OutOfMemory;
            }
        }
    }

    return props;
}

/// Append string with escape sequence processing
fn appendUnescaped(allocator: Allocator, buf: *std.ArrayListUnmanaged(u8), input: []const u8) PropertiesError!void {
    var i: usize = 0;
    while (i < input.len) {
        if (input[i] == '\\' and i + 1 < input.len) {
            const next = input[i + 1];
            switch (next) {
                't' => {
                    buf.append(allocator, '\t') catch return PropertiesError.OutOfMemory;
                    i += 2;
                },
                'n' => {
                    buf.append(allocator, '\n') catch return PropertiesError.OutOfMemory;
                    i += 2;
                },
                'r' => {
                    buf.append(allocator, '\r') catch return PropertiesError.OutOfMemory;
                    i += 2;
                },
                '\\' => {
                    buf.append(allocator, '\\') catch return PropertiesError.OutOfMemory;
                    i += 2;
                },
                '=' => {
                    buf.append(allocator, '=') catch return PropertiesError.OutOfMemory;
                    i += 2;
                },
                ':' => {
                    buf.append(allocator, ':') catch return PropertiesError.OutOfMemory;
                    i += 2;
                },
                ' ' => {
                    buf.append(allocator, ' ') catch return PropertiesError.OutOfMemory;
                    i += 2;
                },
                'u' => {
                    // Unicode escape \uXXXX
                    if (i + 5 < input.len) {
                        const hex = input[i + 2 .. i + 6];
                        const codepoint = std.fmt.parseInt(u21, hex, 16) catch return PropertiesError.InvalidUnicodeEscape;
                        var utf8_buf: [4]u8 = undefined;
                        const len = std.unicode.utf8Encode(codepoint, &utf8_buf) catch return PropertiesError.InvalidUnicodeEscape;
                        buf.appendSlice(allocator, utf8_buf[0..len]) catch return PropertiesError.OutOfMemory;
                        i += 6;
                    } else {
                        return PropertiesError.InvalidUnicodeEscape;
                    }
                },
                else => {
                    // Unknown escape, keep as-is
                    buf.append(allocator, input[i]) catch return PropertiesError.OutOfMemory;
                    i += 1;
                },
            }
        } else {
            buf.append(allocator, input[i]) catch return PropertiesError.OutOfMemory;
            i += 1;
        }
    }
}

/// Parse properties from a file
pub fn parseFile(allocator: Allocator, path: []const u8) !Properties {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
    defer allocator.free(content);

    return parse(allocator, content);
}

/// Serialize properties to string format
pub fn serialize(props: *const Properties, allocator: Allocator) ![]u8 {
    var result: std.ArrayListUnmanaged(u8) = .{};
    errdefer result.deinit(allocator);

    var iter = props.values.iterator();
    while (iter.next()) |entry| {
        try result.appendSlice(allocator, entry.key_ptr.*);
        try result.append(allocator, '=');
        try result.appendSlice(allocator, entry.value_ptr.*);
        try result.append(allocator, '\n');
    }

    return result.toOwnedSlice(allocator);
}

// ============================================================================
// Tests
// ============================================================================

test "parse simple properties" {
    const content =
        \\database.host=localhost
        \\database.port=5432
        \\server.host=0.0.0.0
    ;

    var props = try parse(std.testing.allocator, content);
    defer props.deinit();

    try std.testing.expectEqualStrings("localhost", props.get("database.host").?);
    try std.testing.expectEqualStrings("5432", props.get("database.port").?);
    try std.testing.expectEqualStrings("0.0.0.0", props.get("server.host").?);
}

test "parse properties with colon separator" {
    const content =
        \\key1:value1
        \\key2 : value2
    ;

    var props = try parse(std.testing.allocator, content);
    defer props.deinit();

    try std.testing.expectEqualStrings("value1", props.get("key1").?);
    try std.testing.expectEqualStrings("value2", props.get("key2").?);
}

test "parse properties with comments" {
    const content =
        \\# This is a comment
        \\! This is also a comment
        \\key=value
    ;

    var props = try parse(std.testing.allocator, content);
    defer props.deinit();

    try std.testing.expectEqual(@as(usize, 1), props.count());
    try std.testing.expectEqualStrings("value", props.get("key").?);
}

test "parse properties with escape sequences" {
    const content =
        \\path=C:\\Users\\test
        \\message=Hello\tWorld
        \\newline=Line1\nLine2
    ;

    var props = try parse(std.testing.allocator, content);
    defer props.deinit();

    try std.testing.expectEqualStrings("C:\\Users\\test", props.get("path").?);
    try std.testing.expectEqualStrings("Hello\tWorld", props.get("message").?);
    try std.testing.expectEqualStrings("Line1\nLine2", props.get("newline").?);
}

test "parse properties with unicode escape" {
    const content =
        \\greeting=Hello \u0057orld
    ;

    var props = try parse(std.testing.allocator, content);
    defer props.deinit();

    try std.testing.expectEqualStrings("Hello World", props.get("greeting").?);
}

test "parse multiline properties" {
    const content =
        \\message=Hello \
        \\    World
        \\other=value
    ;

    var props = try parse(std.testing.allocator, content);
    defer props.deinit();

    try std.testing.expectEqualStrings("Hello World", props.get("message").?);
    try std.testing.expectEqualStrings("value", props.get("other").?);
}

test "properties keys" {
    const content =
        \\key1=value1
        \\key2=value2
    ;

    var props = try parse(std.testing.allocator, content);
    defer props.deinit();

    const all_keys = try props.keys();
    defer std.testing.allocator.free(all_keys);

    try std.testing.expectEqual(@as(usize, 2), all_keys.len);
}

test "properties has" {
    const content =
        \\existing=value
    ;

    var props = try parse(std.testing.allocator, content);
    defer props.deinit();

    try std.testing.expect(props.has("existing"));
    try std.testing.expect(!props.has("nonexistent"));
}

test "parse empty value" {
    const content =
        \\empty=
        \\novalue
    ;

    var props = try parse(std.testing.allocator, content);
    defer props.deinit();

    try std.testing.expectEqualStrings("", props.get("empty").?);
}
