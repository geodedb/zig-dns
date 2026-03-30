// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Command-Line Flag Parsing Module
//!
//! Provides Viper-like command-line flag integration for configuration.
//! Supports:
//! - Long flags: `--config=value` or `--config value`
//! - Short flags: `-c value`
//! - Boolean flags: `--debug` (true) or `--no-debug` (false)
//! - Flag binding to configuration keys

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Flag definition
pub const Flag = struct {
    /// Long flag name (without --)
    name: []const u8,
    /// Short flag (single character, without -)
    short: ?u8 = null,
    /// Description for help text
    description: []const u8 = "",
    /// Default value (as string)
    default: ?[]const u8 = null,
    /// Whether this is a boolean flag
    is_bool: bool = false,
    /// The config key this flag maps to (defaults to name)
    config_key: ?[]const u8 = null,

    /// Get the config key for this flag
    pub fn getConfigKey(self: Flag) []const u8 {
        return self.config_key orelse self.name;
    }
};

/// Parsed flag value
pub const FlagValue = struct {
    key: []const u8,
    value: []const u8,
    from_flag: []const u8,
};

/// Flag parsing errors
pub const FlagError = error{
    UnknownFlag,
    MissingValue,
    InvalidFormat,
    OutOfMemory,
};

/// Flag parser for command-line arguments
pub const FlagParser = struct {
    allocator: Allocator,
    flags: std.StringHashMap(Flag),
    short_flags: std.AutoHashMap(u8, []const u8),
    values: std.ArrayListUnmanaged(FlagValue),
    positional: std.ArrayListUnmanaged([]const u8),
    arena: std.heap.ArenaAllocator,

    const Self = @This();

    /// Initialize a new flag parser
    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .flags = std.StringHashMap(Flag).init(allocator),
            .short_flags = std.AutoHashMap(u8, []const u8).init(allocator),
            .values = .{},
            .positional = .{},
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    /// Deinitialize the parser
    pub fn deinit(self: *Self) void {
        self.flags.deinit();
        self.short_flags.deinit();
        self.values.deinit(self.allocator);
        self.positional.deinit(self.allocator);
        self.arena.deinit();
    }

    /// Add a flag definition
    pub fn addFlag(self: *Self, flag: Flag) !void {
        const owned_name = try self.arena.allocator().dupe(u8, flag.name);
        try self.flags.put(owned_name, flag);

        if (flag.short) |short| {
            try self.short_flags.put(short, owned_name);
        }
    }

    /// Add a string flag
    pub fn string(self: *Self, name: []const u8, short: ?u8, description: []const u8, default: ?[]const u8) !void {
        try self.addFlag(.{
            .name = name,
            .short = short,
            .description = description,
            .default = default,
            .is_bool = false,
        });
    }

    /// Add a boolean flag
    pub fn boolean(self: *Self, name: []const u8, short: ?u8, description: []const u8) !void {
        try self.addFlag(.{
            .name = name,
            .short = short,
            .description = description,
            .default = "false",
            .is_bool = true,
        });
    }

    /// Add a flag bound to a specific config key
    pub fn bind(self: *Self, name: []const u8, config_key: []const u8, short: ?u8, description: []const u8) !void {
        try self.addFlag(.{
            .name = name,
            .short = short,
            .description = description,
            .config_key = config_key,
            .is_bool = false,
        });
    }

    /// Parse command-line arguments
    pub fn parse(self: *Self, args: []const []const u8) FlagError!void {
        var i: usize = 0;
        while (i < args.len) : (i += 1) {
            const arg = args[i];

            if (mem.startsWith(u8, arg, "--")) {
                // Long flag
                try self.parseLongFlag(arg[2..], args, &i);
            } else if (arg.len == 2 and arg[0] == '-' and arg[1] != '-') {
                // Short flag
                try self.parseShortFlag(arg[1], args, &i);
            } else if (arg[0] == '-' and arg.len > 2) {
                // Combined short flags or short with value
                try self.parseShortFlags(arg[1..], args, &i);
            } else {
                // Positional argument
                try self.positional.append(self.allocator, arg);
            }
        }
    }

    /// Parse from std.process.args()
    pub fn parseArgs(self: *Self) !void {
        var args = try std.process.argsAlloc(self.allocator);
        defer std.process.argsFree(self.allocator, args);

        // Skip the program name
        if (args.len > 0) {
            try self.parse(args[1..]);
        }
    }

    fn parseLongFlag(self: *Self, arg: []const u8, args: []const []const u8, i: *usize) FlagError!void {
        // Check for --no-flag format (boolean negation)
        if (mem.startsWith(u8, arg, "no-")) {
            const flag_name = arg[3..];
            if (self.flags.get(flag_name)) |flag| {
                if (flag.is_bool) {
                    try self.addValue(flag.getConfigKey(), "false", flag_name);
                    return;
                }
            }
        }

        // Check for --flag=value format
        if (mem.indexOf(u8, arg, "=")) |eq_pos| {
            const flag_name = arg[0..eq_pos];
            const value = arg[eq_pos + 1 ..];

            if (self.flags.get(flag_name)) |flag| {
                try self.addValue(flag.getConfigKey(), value, flag_name);
            } else {
                return FlagError.UnknownFlag;
            }
            return;
        }

        // Check for --flag value or --flag (boolean)
        if (self.flags.get(arg)) |flag| {
            if (flag.is_bool) {
                try self.addValue(flag.getConfigKey(), "true", arg);
            } else {
                // Need to get next arg as value
                if (i.* + 1 < args.len) {
                    i.* += 1;
                    try self.addValue(flag.getConfigKey(), args[i.*], arg);
                } else {
                    return FlagError.MissingValue;
                }
            }
        } else {
            return FlagError.UnknownFlag;
        }
    }

    fn parseShortFlag(self: *Self, short: u8, args: []const []const u8, i: *usize) FlagError!void {
        if (self.short_flags.get(short)) |flag_name| {
            if (self.flags.get(flag_name)) |flag| {
                if (flag.is_bool) {
                    try self.addValue(flag.getConfigKey(), "true", flag_name);
                } else {
                    if (i.* + 1 < args.len) {
                        i.* += 1;
                        try self.addValue(flag.getConfigKey(), args[i.*], flag_name);
                    } else {
                        return FlagError.MissingValue;
                    }
                }
                return;
            }
        }
        return FlagError.UnknownFlag;
    }

    fn parseShortFlags(self: *Self, shorts: []const u8, args: []const []const u8, i: *usize) FlagError!void {
        for (shorts, 0..) |short, idx| {
            if (self.short_flags.get(short)) |flag_name| {
                if (self.flags.get(flag_name)) |flag| {
                    if (flag.is_bool) {
                        try self.addValue(flag.getConfigKey(), "true", flag_name);
                    } else {
                        // Rest of the string is the value
                        if (idx + 1 < shorts.len) {
                            try self.addValue(flag.getConfigKey(), shorts[idx + 1 ..], flag_name);
                            return;
                        } else if (i.* + 1 < args.len) {
                            i.* += 1;
                            try self.addValue(flag.getConfigKey(), args[i.*], flag_name);
                            return;
                        } else {
                            return FlagError.MissingValue;
                        }
                    }
                }
            } else {
                return FlagError.UnknownFlag;
            }
        }
    }

    fn addValue(self: *Self, key: []const u8, value: []const u8, from_flag: []const u8) !void {
        const owned_key = try self.arena.allocator().dupe(u8, key);
        const owned_value = try self.arena.allocator().dupe(u8, value);
        const owned_flag = try self.arena.allocator().dupe(u8, from_flag);

        try self.values.append(self.allocator, .{
            .key = owned_key,
            .value = owned_value,
            .from_flag = owned_flag,
        });
    }

    /// Get all parsed flag values
    pub fn getValues(self: *const Self) []const FlagValue {
        return self.values.items;
    }

    /// Get a specific flag value
    pub fn get(self: *const Self, key: []const u8) ?[]const u8 {
        for (self.values.items) |fv| {
            if (mem.eql(u8, fv.key, key)) {
                return fv.value;
            }
        }
        // Check default
        if (self.flags.get(key)) |flag| {
            return flag.default;
        }
        return null;
    }

    /// Get positional arguments
    pub fn getPositional(self: *const Self) []const []const u8 {
        return self.positional.items;
    }

    /// Generate help text
    pub fn help(self: *const Self, writer: anytype, program_name: []const u8) !void {
        try writer.print("Usage: {s} [OPTIONS]\n\n", .{program_name});
        try writer.print("Options:\n", .{});

        var iter = self.flags.iterator();
        while (iter.next()) |entry| {
            const flag = entry.value_ptr.*;
            if (flag.short) |s| {
                try writer.print("  -{c}, --{s}", .{ s, flag.name });
            } else {
                try writer.print("      --{s}", .{flag.name});
            }

            if (!flag.is_bool) {
                try writer.print(" <value>", .{});
            }

            if (flag.description.len > 0) {
                try writer.print("\n        {s}", .{flag.description});
            }

            if (flag.default) |def| {
                try writer.print(" (default: {s})", .{def});
            }

            try writer.print("\n", .{});
        }
    }
};

// ============================================================================
// Tests
// ============================================================================

test "FlagParser: basic long flag" {
    var parser = FlagParser.init(std.testing.allocator);
    defer parser.deinit();

    try parser.string("config", 'c', "Config file path", null);

    try parser.parse(&.{ "--config", "app.toml" });

    try std.testing.expectEqualStrings("app.toml", parser.get("config").?);
}

test "FlagParser: long flag with equals" {
    var parser = FlagParser.init(std.testing.allocator);
    defer parser.deinit();

    try parser.string("config", null, "Config file path", null);

    try parser.parse(&.{"--config=app.toml"});

    try std.testing.expectEqualStrings("app.toml", parser.get("config").?);
}

test "FlagParser: short flag" {
    var parser = FlagParser.init(std.testing.allocator);
    defer parser.deinit();

    try parser.string("verbose", 'v', "Verbose output", null);

    try parser.parse(&.{ "-v", "true" });

    try std.testing.expectEqualStrings("true", parser.get("verbose").?);
}

test "FlagParser: boolean flag" {
    var parser = FlagParser.init(std.testing.allocator);
    defer parser.deinit();

    try parser.boolean("debug", 'd', "Enable debug mode");

    try parser.parse(&.{"--debug"});

    try std.testing.expectEqualStrings("true", parser.get("debug").?);
}

test "FlagParser: boolean flag negation" {
    var parser = FlagParser.init(std.testing.allocator);
    defer parser.deinit();

    try parser.boolean("debug", 'd', "Enable debug mode");

    try parser.parse(&.{"--no-debug"});

    try std.testing.expectEqualStrings("false", parser.get("debug").?);
}

test "FlagParser: default value" {
    var parser = FlagParser.init(std.testing.allocator);
    defer parser.deinit();

    try parser.string("port", 'p', "Port number", "8080");

    try parser.parse(&.{});

    try std.testing.expectEqualStrings("8080", parser.get("port").?);
}

test "FlagParser: flag binding" {
    var parser = FlagParser.init(std.testing.allocator);
    defer parser.deinit();

    try parser.bind("cfg", "config_file", 'c', "Config file");

    try parser.parse(&.{ "--cfg", "app.toml" });

    try std.testing.expectEqualStrings("app.toml", parser.get("config_file").?);
}

test "FlagParser: positional arguments" {
    var parser = FlagParser.init(std.testing.allocator);
    defer parser.deinit();

    try parser.boolean("verbose", 'v', "Verbose");

    try parser.parse(&.{ "--verbose", "file1.txt", "file2.txt" });

    const positional = parser.getPositional();
    try std.testing.expectEqual(@as(usize, 2), positional.len);
    try std.testing.expectEqualStrings("file1.txt", positional[0]);
    try std.testing.expectEqualStrings("file2.txt", positional[1]);
}

test "FlagParser: unknown flag returns error" {
    var parser = FlagParser.init(std.testing.allocator);
    defer parser.deinit();

    const result = parser.parse(&.{"--unknown"});
    try std.testing.expectError(FlagError.UnknownFlag, result);
}

test "FlagParser: missing value returns error" {
    var parser = FlagParser.init(std.testing.allocator);
    defer parser.deinit();

    try parser.string("config", 'c', "Config file", null);

    const result = parser.parse(&.{"--config"});
    try std.testing.expectError(FlagError.MissingValue, result);
}
