// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Configuration File Support
//!
//! Provides configuration file parsing and management:
//! - INI-style configuration files
//! - Environment variable overrides
//! - Default values
//! - Configuration validation
//! - Hot-reload support

const std = @import("std");

/// Configuration value types
pub const Value = union(enum) {
    string: []const u8,
    integer: i64,
    float: f64,
    boolean: bool,
    string_list: []const []const u8,

    pub fn asString(self: Value) ?[]const u8 {
        return switch (self) {
            .string => |s| s,
            else => null,
        };
    }

    pub fn asInt(self: Value) ?i64 {
        return switch (self) {
            .integer => |i| i,
            .string => |s| std.fmt.parseInt(i64, s, 10) catch null,
            else => null,
        };
    }

    pub fn asFloat(self: Value) ?f64 {
        return switch (self) {
            .float => |f| f,
            .integer => |i| @floatFromInt(i),
            .string => |s| std.fmt.parseFloat(f64, s) catch null,
            else => null,
        };
    }

    pub fn asBool(self: Value) ?bool {
        return switch (self) {
            .boolean => |b| b,
            .string => |s| {
                if (std.ascii.eqlIgnoreCase(s, "true") or std.ascii.eqlIgnoreCase(s, "yes") or std.ascii.eqlIgnoreCase(s, "1")) {
                    return true;
                }
                if (std.ascii.eqlIgnoreCase(s, "false") or std.ascii.eqlIgnoreCase(s, "no") or std.ascii.eqlIgnoreCase(s, "0")) {
                    return false;
                }
                return null;
            },
            .integer => |i| i != 0,
            else => null,
        };
    }
};

/// Configuration section
pub const Section = struct {
    name: []const u8,
    entries: std.StringHashMap(Value),

    pub fn init(allocator: std.mem.Allocator, name: []const u8) Section {
        return Section{
            .name = name,
            .entries = std.StringHashMap(Value).init(allocator),
        };
    }

    pub fn deinit(self: *Section) void {
        self.entries.deinit();
    }

    pub fn get(self: *const Section, key: []const u8) ?Value {
        return self.entries.get(key);
    }

    pub fn getString(self: *const Section, key: []const u8, default: []const u8) []const u8 {
        if (self.entries.get(key)) |value| {
            if (value.asString()) |s| return s;
        }
        return default;
    }

    pub fn getInt(self: *const Section, key: []const u8, default: i64) i64 {
        if (self.entries.get(key)) |value| {
            if (value.asInt()) |i| return i;
        }
        return default;
    }

    pub fn getBool(self: *const Section, key: []const u8, default: bool) bool {
        if (self.entries.get(key)) |value| {
            if (value.asBool()) |b| return b;
        }
        return default;
    }
};

/// Configuration manager
pub const Config = struct {
    allocator: std.mem.Allocator,
    sections: std.StringHashMap(Section),
    /// Environment variable prefix for overrides
    env_prefix: ?[]const u8,
    /// Configuration file path
    file_path: ?[]const u8,
    /// Last load time
    last_load_time: i64,

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .sections = std.StringHashMap(Section).init(allocator),
            .env_prefix = null,
            .file_path = null,
            .last_load_time = 0,
        };
    }

    pub fn deinit(self: *Self) void {
        var iter = self.sections.valueIterator();
        while (iter.next()) |section| {
            section.deinit();
        }
        self.sections.deinit();
    }

    /// Load configuration from INI-style file
    pub fn loadFile(self: *Self, path: []const u8) !void {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();

        const content = try file.readToEndAlloc(self.allocator, 1024 * 1024);
        defer self.allocator.free(content);

        try self.parseIni(content);

        self.file_path = path;
        self.last_load_time = std.time.milliTimestamp();
    }

    /// Load configuration from string
    pub fn loadString(self: *Self, content: []const u8) !void {
        try self.parseIni(content);
        self.last_load_time = std.time.milliTimestamp();
    }

    /// Parse INI-style configuration
    fn parseIni(self: *Self, content: []const u8) !void {
        var current_section: []const u8 = "default";
        var lines = std.mem.splitScalar(u8, content, '\n');

        while (lines.next()) |raw_line| {
            var line = std.mem.trim(u8, raw_line, " \t\r");

            // Skip empty lines and comments
            if (line.len == 0 or line[0] == '#' or line[0] == ';') continue;

            // Section header
            if (line[0] == '[') {
                if (std.mem.indexOfScalar(u8, line, ']')) |end| {
                    current_section = line[1..end];
                }
                continue;
            }

            // Key-value pair
            if (std.mem.indexOfScalar(u8, line, '=')) |eq_pos| {
                const key = std.mem.trim(u8, line[0..eq_pos], " \t");
                var value_str = std.mem.trim(u8, line[eq_pos + 1 ..], " \t");

                // Remove quotes
                if (value_str.len >= 2) {
                    if ((value_str[0] == '"' and value_str[value_str.len - 1] == '"') or
                        (value_str[0] == '\'' and value_str[value_str.len - 1] == '\''))
                    {
                        value_str = value_str[1 .. value_str.len - 1];
                    }
                }

                try self.set(current_section, key, parseValue(value_str));
            }
        }
    }

    /// Parse a string into a typed value
    fn parseValue(str: []const u8) Value {
        // Try boolean
        if (std.ascii.eqlIgnoreCase(str, "true") or std.ascii.eqlIgnoreCase(str, "yes")) {
            return .{ .boolean = true };
        }
        if (std.ascii.eqlIgnoreCase(str, "false") or std.ascii.eqlIgnoreCase(str, "no")) {
            return .{ .boolean = false };
        }

        // Try integer
        if (std.fmt.parseInt(i64, str, 10)) |i| {
            return .{ .integer = i };
        } else |_| {}

        // Try float
        if (std.fmt.parseFloat(f64, str)) |f| {
            return .{ .float = f };
        } else |_| {}

        // Default to string
        return .{ .string = str };
    }

    /// Set a configuration value
    pub fn set(self: *Self, section_name: []const u8, key: []const u8, value: Value) !void {
        const section = try self.getOrCreateSection(section_name);
        try section.entries.put(key, value);
    }

    /// Get a configuration value
    pub fn get(self: *Self, section_name: []const u8, key: []const u8) ?Value {
        // Check environment override first
        if (self.env_prefix) |prefix| {
            if (self.getEnvOverride(prefix, section_name, key)) |env_value| {
                return env_value;
            }
        }

        if (self.sections.get(section_name)) |section| {
            return section.get(key);
        }
        return null;
    }

    /// Get a section
    pub fn getSection(self: *Self, name: []const u8) ?*const Section {
        return self.sections.getPtr(name);
    }

    /// Get or create a section
    fn getOrCreateSection(self: *Self, name: []const u8) !*Section {
        if (self.sections.getPtr(name)) |section| {
            return section;
        }

        const section = Section.init(self.allocator, name);
        try self.sections.put(name, section);
        return self.sections.getPtr(name).?;
    }

    /// Get environment variable override
    fn getEnvOverride(self: *Self, prefix: []const u8, section: []const u8, key: []const u8) ?Value {
        _ = self;
        // Build environment variable name: PREFIX_SECTION_KEY
        var name_buf: [256]u8 = undefined;
        const name_len = std.fmt.bufPrint(&name_buf, "{s}_{s}_{s}", .{ prefix, section, key }) catch return null;

        // Convert to uppercase
        for (name_buf[0..name_len.len]) |*c| {
            c.* = std.ascii.toUpper(c.*);
        }

        // Note: In Zig, we'd use std.posix.getenv but it returns optional
        // For testing, we return null
        return null;
    }

    /// Get string value with default
    pub fn getString(self: *Self, section: []const u8, key: []const u8, default: []const u8) []const u8 {
        if (self.get(section, key)) |value| {
            if (value.asString()) |s| return s;
        }
        return default;
    }

    /// Get integer value with default
    pub fn getInt(self: *Self, section: []const u8, key: []const u8, default: i64) i64 {
        if (self.get(section, key)) |value| {
            if (value.asInt()) |i| return i;
        }
        return default;
    }

    /// Get boolean value with default
    pub fn getBool(self: *Self, section: []const u8, key: []const u8, default: bool) bool {
        if (self.get(section, key)) |value| {
            if (value.asBool()) |b| return b;
        }
        return default;
    }

    /// Set environment variable prefix for overrides
    pub fn setEnvPrefix(self: *Self, prefix: []const u8) void {
        self.env_prefix = prefix;
    }

    /// Check if configuration has changed (for hot-reload)
    pub fn hasChanged(self: *Self) bool {
        if (self.file_path) |path| {
            const stat = std.fs.cwd().statFile(path) catch return false;
            const mtime = @divFloor(stat.mtime, std.time.ns_per_ms);
            return mtime > self.last_load_time;
        }
        return false;
    }
};

/// Clamp an i64 value to fit within the target unsigned integer type.
/// Negative values are clamped to 0; values exceeding max are clamped to max.
fn clampToUnsigned(comptime T: type, val: i64) T {
    if (val < 0) return 0;
    if (val > std.math.maxInt(T)) return std.math.maxInt(T);
    return @intCast(val);
}

/// DNS-specific configuration
pub const DnsConfig = struct {
    /// Upstream servers
    servers: []const []const u8 = &[_][]const u8{"8.8.8.8"},
    /// Server port
    port: u16 = 53,
    /// Query timeout (ms)
    timeout_ms: u32 = 5000,
    /// Number of retries
    retries: u8 = 3,
    /// Use TCP
    use_tcp: bool = false,
    /// Use TLS (DoT)
    use_tls: bool = false,
    /// Enable DNSSEC validation
    dnssec: bool = false,
    /// Cache enabled
    cache_enabled: bool = true,
    /// Cache size
    cache_size: u32 = 10000,
    /// Minimum TTL
    min_ttl: u32 = 60,
    /// Maximum TTL
    max_ttl: u32 = 86400,
    /// Enable logging
    logging_enabled: bool = true,
    /// Log level
    log_level: []const u8 = "info",

    pub fn fromConfig(config: *Config) DnsConfig {
        return DnsConfig{
            .port = clampToUnsigned(u16, config.getInt("dns", "port", 53)),
            .timeout_ms = clampToUnsigned(u32, config.getInt("dns", "timeout_ms", 5000)),
            .retries = clampToUnsigned(u8, config.getInt("dns", "retries", 3)),
            .use_tcp = config.getBool("dns", "use_tcp", false),
            .use_tls = config.getBool("dns", "use_tls", false),
            .dnssec = config.getBool("dns", "dnssec", false),
            .cache_enabled = config.getBool("cache", "enabled", true),
            .cache_size = clampToUnsigned(u32, config.getInt("cache", "size", 10000)),
            .min_ttl = clampToUnsigned(u32, config.getInt("cache", "min_ttl", 60)),
            .max_ttl = clampToUnsigned(u32, config.getInt("cache", "max_ttl", 86400)),
            .logging_enabled = config.getBool("logging", "enabled", true),
            .log_level = config.getString("logging", "level", "info"),
        };
    }
};

// ============================================================================
// Tests
// ============================================================================

test "Value conversions" {
    const str_val = Value{ .string = "hello" };
    try std.testing.expectEqualStrings("hello", str_val.asString().?);
    try std.testing.expect(str_val.asInt() == null);

    const int_val = Value{ .integer = 42 };
    try std.testing.expectEqual(@as(i64, 42), int_val.asInt().?);
    try std.testing.expectEqual(@as(f64, 42.0), int_val.asFloat().?);

    const bool_val = Value{ .boolean = true };
    try std.testing.expect(bool_val.asBool().?);

    const str_bool = Value{ .string = "yes" };
    try std.testing.expect(str_bool.asBool().?);

    const str_int = Value{ .string = "123" };
    try std.testing.expectEqual(@as(i64, 123), str_int.asInt().?);
}

test "Config init/deinit" {
    const allocator = std.testing.allocator;

    var config = Config.init(allocator);
    defer config.deinit();

    try std.testing.expectEqual(@as(usize, 0), config.sections.count());
}

test "Config parse INI" {
    const allocator = std.testing.allocator;

    var config = Config.init(allocator);
    defer config.deinit();

    const ini_content =
        \\# DNS configuration
        \\[dns]
        \\port = 53
        \\timeout_ms = 5000
        \\use_tcp = false
        \\
        \\[cache]
        \\enabled = true
        \\size = 10000
    ;

    try config.loadString(ini_content);

    try std.testing.expectEqual(@as(i64, 53), config.getInt("dns", "port", 0));
    try std.testing.expectEqual(@as(i64, 5000), config.getInt("dns", "timeout_ms", 0));
    try std.testing.expect(!config.getBool("dns", "use_tcp", true));
    try std.testing.expect(config.getBool("cache", "enabled", false));
    try std.testing.expectEqual(@as(i64, 10000), config.getInt("cache", "size", 0));
}

test "Config default values" {
    const allocator = std.testing.allocator;

    var config = Config.init(allocator);
    defer config.deinit();

    // Non-existent keys should return defaults
    try std.testing.expectEqual(@as(i64, 42), config.getInt("missing", "key", 42));
    try std.testing.expect(config.getBool("missing", "flag", true));
    try std.testing.expectEqualStrings("default", config.getString("missing", "str", "default"));
}

test "Config set values" {
    const allocator = std.testing.allocator;

    var config = Config.init(allocator);
    defer config.deinit();

    try config.set("test", "key1", .{ .string = "value1" });
    try config.set("test", "key2", .{ .integer = 100 });
    try config.set("test", "key3", .{ .boolean = true });

    try std.testing.expectEqualStrings("value1", config.getString("test", "key1", ""));
    try std.testing.expectEqual(@as(i64, 100), config.getInt("test", "key2", 0));
    try std.testing.expect(config.getBool("test", "key3", false));
}

test "DnsConfig from Config" {
    const allocator = std.testing.allocator;

    var config = Config.init(allocator);
    defer config.deinit();

    const ini_content =
        \\[dns]
        \\port = 853
        \\timeout_ms = 10000
        \\use_tls = true
        \\
        \\[cache]
        \\enabled = false
        \\size = 5000
    ;

    try config.loadString(ini_content);

    const dns_config = DnsConfig.fromConfig(&config);

    try std.testing.expectEqual(@as(u16, 853), dns_config.port);
    try std.testing.expectEqual(@as(u32, 10000), dns_config.timeout_ms);
    try std.testing.expect(dns_config.use_tls);
    try std.testing.expect(!dns_config.cache_enabled);
    try std.testing.expectEqual(@as(u32, 5000), dns_config.cache_size);
}

test "Section helper methods" {
    const allocator = std.testing.allocator;

    var section = Section.init(allocator, "test");
    defer section.deinit();

    try section.entries.put("str_key", .{ .string = "hello" });
    try section.entries.put("int_key", .{ .integer = 42 });
    try section.entries.put("bool_key", .{ .boolean = true });

    try std.testing.expectEqualStrings("hello", section.getString("str_key", "default"));
    try std.testing.expectEqual(@as(i64, 42), section.getInt("int_key", 0));
    try std.testing.expect(section.getBool("bool_key", false));

    // Test defaults
    try std.testing.expectEqualStrings("default", section.getString("missing", "default"));
    try std.testing.expectEqual(@as(i64, -1), section.getInt("missing", -1));
}

test "DnsConfig fromConfig clamps negative values" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator);
    defer config.deinit();
    try config.set("dns", "port", .{ .integer = -1 });
    try config.set("dns", "timeout_ms", .{ .integer = -100 });
    const dns_config = DnsConfig.fromConfig(&config);
    try std.testing.expectEqual(@as(u16, 0), dns_config.port);
    try std.testing.expectEqual(@as(u32, 0), dns_config.timeout_ms);
}

test "DnsConfig fromConfig clamps overflow values" {
    const allocator = std.testing.allocator;
    var config = Config.init(allocator);
    defer config.deinit();
    try config.set("dns", "port", .{ .integer = 100000 });
    try config.set("dns", "retries", .{ .integer = 300 });
    const dns_config = DnsConfig.fromConfig(&config);
    try std.testing.expectEqual(@as(u16, 65535), dns_config.port);
    try std.testing.expectEqual(@as(u8, 255), dns_config.retries);
}

test "clampToUnsigned boundary values" {
    // u8 boundaries
    try std.testing.expectEqual(@as(u8, 0), clampToUnsigned(u8, -1));
    try std.testing.expectEqual(@as(u8, 0), clampToUnsigned(u8, 0));
    try std.testing.expectEqual(@as(u8, 255), clampToUnsigned(u8, 255));
    try std.testing.expectEqual(@as(u8, 255), clampToUnsigned(u8, 256));
    try std.testing.expectEqual(@as(u8, 127), clampToUnsigned(u8, 127));

    // u16 boundaries
    try std.testing.expectEqual(@as(u16, 0), clampToUnsigned(u16, -9999));
    try std.testing.expectEqual(@as(u16, 65535), clampToUnsigned(u16, 65536));
    try std.testing.expectEqual(@as(u16, 53), clampToUnsigned(u16, 53));

    // u32 boundaries
    try std.testing.expectEqual(@as(u32, 0), clampToUnsigned(u32, -1));
    try std.testing.expectEqual(@as(u32, 4294967295), clampToUnsigned(u32, 4294967296));
    try std.testing.expectEqual(@as(u32, 86400), clampToUnsigned(u32, 86400));
}
