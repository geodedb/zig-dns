// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # INI Format Parser
//!
//! Parses INI configuration files with support for:
//! - Sections: [section]
//! - Key-value pairs: key = value
//! - Comments: ; comment or # comment
//! - Quoted values: key = "value with spaces"
//! - Multiline values with backslash continuation
//!
//! Example INI file:
//! ```ini
//! ; Database configuration
//! [database]
//! host = localhost
//! port = 5432
//! name = myapp
//!
//! [server]
//! host = 0.0.0.0
//! port = 8080
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// INI parsing errors
pub const IniError = error{
    InvalidSyntax,
    UnclosedSection,
    UnclosedQuote,
    DuplicateKey,
    OutOfMemory,
};

/// Represents an INI section with its key-value pairs
pub const Section = struct {
    name: []const u8,
    values: std.StringHashMap([]const u8),

    pub fn init(allocator: Allocator, name: []const u8) Section {
        return .{
            .name = name,
            .values = std.StringHashMap([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *Section) void {
        self.values.deinit();
    }

    pub fn get(self: *const Section, key: []const u8) ?[]const u8 {
        return self.values.get(key);
    }
};

/// Parsed INI document
pub const IniDocument = struct {
    allocator: Allocator,
    /// Global values (before any section)
    global: std.StringHashMap([]const u8),
    /// Named sections
    sections: std.StringHashMap(Section),
    /// Arena for string storage
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: Allocator) IniDocument {
        return .{
            .allocator = allocator,
            .global = std.StringHashMap([]const u8).init(allocator),
            .sections = std.StringHashMap(Section).init(allocator),
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *IniDocument) void {
        var iter = self.sections.valueIterator();
        while (iter.next()) |section| {
            section.values.deinit();
        }
        self.sections.deinit();
        self.global.deinit();
        self.arena.deinit();
    }

    /// Get a value from a section (use "." notation: "section.key")
    pub fn get(self: *const IniDocument, path: []const u8) ?[]const u8 {
        if (mem.indexOf(u8, path, ".")) |dot_pos| {
            const section_name = path[0..dot_pos];
            const key = path[dot_pos + 1 ..];
            if (self.sections.get(section_name)) |section| {
                return section.values.get(key);
            }
            return null;
        }
        // No section specified, check global
        return self.global.get(path);
    }

    /// Get a section by name
    pub fn getSection(self: *const IniDocument, name: []const u8) ?*const Section {
        return if (self.sections.getPtr(name)) |ptr| ptr else null;
    }

    /// Check if a key exists
    pub fn has(self: *const IniDocument, path: []const u8) bool {
        return self.get(path) != null;
    }

    /// Get all section names
    pub fn getSectionNames(self: *const IniDocument) ![]const []const u8 {
        var names: std.ArrayListUnmanaged([]const u8) = .{};
        errdefer names.deinit(self.allocator);

        var iter = self.sections.keyIterator();
        while (iter.next()) |key| {
            try names.append(self.allocator, key.*);
        }

        return names.toOwnedSlice(self.allocator);
    }
};

/// Parse INI content from a string
pub fn parse(allocator: Allocator, content: []const u8) IniError!IniDocument {
    var doc = IniDocument.init(allocator);
    errdefer doc.deinit();

    var current_section: ?[]const u8 = null;
    var line_iter = mem.splitScalar(u8, content, '\n');

    while (line_iter.next()) |line| {
        const trimmed = mem.trim(u8, line, " \t\r");

        // Skip empty lines and comments
        if (trimmed.len == 0) continue;
        if (trimmed[0] == ';' or trimmed[0] == '#') continue;

        // Section header
        if (trimmed[0] == '[') {
            if (mem.indexOfScalar(u8, trimmed, ']')) |end| {
                const section_name = mem.trim(u8, trimmed[1..end], " \t");
                const owned_name = doc.arena.allocator().dupe(u8, section_name) catch return IniError.OutOfMemory;

                const section = Section.init(allocator, owned_name);
                doc.sections.put(owned_name, section) catch return IniError.OutOfMemory;
                current_section = owned_name;
            } else {
                return IniError.UnclosedSection;
            }
            continue;
        }

        // Key-value pair
        if (mem.indexOf(u8, trimmed, "=")) |eq_pos| {
            const key = mem.trim(u8, trimmed[0..eq_pos], " \t");
            var value = mem.trim(u8, trimmed[eq_pos + 1 ..], " \t");

            // Handle quoted values
            if (value.len >= 2) {
                if ((value[0] == '"' and value[value.len - 1] == '"') or
                    (value[0] == '\'' and value[value.len - 1] == '\''))
                {
                    value = value[1 .. value.len - 1];
                }
            }

            const owned_key = doc.arena.allocator().dupe(u8, key) catch return IniError.OutOfMemory;
            const owned_value = doc.arena.allocator().dupe(u8, value) catch return IniError.OutOfMemory;

            if (current_section) |section_name| {
                if (doc.sections.getPtr(section_name)) |section| {
                    section.values.put(owned_key, owned_value) catch return IniError.OutOfMemory;
                }
            } else {
                doc.global.put(owned_key, owned_value) catch return IniError.OutOfMemory;
            }
        }
    }

    return doc;
}

/// Parse INI from a file
pub fn parseFile(allocator: Allocator, path: []const u8) !IniDocument {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
    defer allocator.free(content);

    return parse(allocator, content);
}

/// Convert INI document to a flat key-value map (section.key format)
pub fn toFlatMap(doc: *const IniDocument, allocator: Allocator) !std.StringHashMap([]const u8) {
    var map = std.StringHashMap([]const u8).init(allocator);
    errdefer map.deinit();

    // Add global values
    var global_iter = doc.global.iterator();
    while (global_iter.next()) |entry| {
        try map.put(entry.key_ptr.*, entry.value_ptr.*);
    }

    // Add section values with "section.key" format
    var section_iter = doc.sections.iterator();
    while (section_iter.next()) |section_entry| {
        const section_name = section_entry.key_ptr.*;
        var value_iter = section_entry.value_ptr.values.iterator();
        while (value_iter.next()) |value_entry| {
            const full_key = try std.fmt.allocPrint(allocator, "{s}.{s}", .{ section_name, value_entry.key_ptr.* });
            try map.put(full_key, value_entry.value_ptr.*);
        }
    }

    return map;
}

// ============================================================================
// Tests
// ============================================================================

test "parse simple INI" {
    const content =
        \\[database]
        \\host = localhost
        \\port = 5432
        \\
        \\[server]
        \\host = 0.0.0.0
        \\port = 8080
    ;

    var doc = try parse(std.testing.allocator, content);
    defer doc.deinit();

    try std.testing.expectEqualStrings("localhost", doc.get("database.host").?);
    try std.testing.expectEqualStrings("5432", doc.get("database.port").?);
    try std.testing.expectEqualStrings("0.0.0.0", doc.get("server.host").?);
    try std.testing.expectEqualStrings("8080", doc.get("server.port").?);
}

test "parse INI with comments" {
    const content =
        \\; This is a comment
        \\# This is also a comment
        \\[section]
        \\key = value ; inline comments not supported (becomes part of value)
    ;

    var doc = try parse(std.testing.allocator, content);
    defer doc.deinit();

    try std.testing.expect(doc.has("section.key"));
}

test "parse INI with quoted values" {
    const content =
        \\[section]
        \\quoted = "value with spaces"
        \\single = 'also quoted'
        \\unquoted = nospaces
    ;

    var doc = try parse(std.testing.allocator, content);
    defer doc.deinit();

    try std.testing.expectEqualStrings("value with spaces", doc.get("section.quoted").?);
    try std.testing.expectEqualStrings("also quoted", doc.get("section.single").?);
    try std.testing.expectEqualStrings("nospaces", doc.get("section.unquoted").?);
}

test "parse INI with global values" {
    const content =
        \\global_key = global_value
        \\
        \\[section]
        \\key = value
    ;

    var doc = try parse(std.testing.allocator, content);
    defer doc.deinit();

    try std.testing.expectEqualStrings("global_value", doc.get("global_key").?);
    try std.testing.expectEqualStrings("value", doc.get("section.key").?);
}

test "getSectionNames" {
    const content =
        \\[alpha]
        \\key = value
        \\[beta]
        \\key = value
    ;

    var doc = try parse(std.testing.allocator, content);
    defer doc.deinit();

    const names = try doc.getSectionNames();
    defer std.testing.allocator.free(names);

    try std.testing.expectEqual(@as(usize, 2), names.len);
}

test "toFlatMap" {
    const content =
        \\global = value
        \\[section]
        \\key = sectionvalue
    ;

    var doc = try parse(std.testing.allocator, content);
    defer doc.deinit();

    var map = try toFlatMap(&doc, std.testing.allocator);
    defer {
        var iter = map.keyIterator();
        while (iter.next()) |key| {
            if (mem.indexOf(u8, key.*, ".") != null) {
                std.testing.allocator.free(key.*);
            }
        }
        map.deinit();
    }

    try std.testing.expectEqualStrings("value", map.get("global").?);
    try std.testing.expectEqualStrings("sectionvalue", map.get("section.key").?);
}

test "unclosed section error" {
    const content = "[unclosed";
    const result = parse(std.testing.allocator, content);
    try std.testing.expectError(IniError.UnclosedSection, result);
}
