// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Config Loader Module
//!
//! Configuration loading with XDG support, precedence rules,
//! and multiple format support. Provides Viper-like features including:
//! - Runtime Set() and SetDefault()
//! - Key aliases
//! - Case-insensitive key access
//! - Environment variable binding (BindEnv, AutomaticEnv)
//! - IsSet() to check explicit values

const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const Allocator = mem.Allocator;

const xdg = @import("xdg.zig");
const provenance = @import("provenance.zig");
const flags_mod = @import("flags.zig");
const ini_mod = @import("ini.zig");
const properties_mod = @import("properties.zig");
const Source = provenance.Source;
const ProvenanceTracker = provenance.ProvenanceTracker;

// Re-export flags types
pub const FlagParser = flags_mod.FlagParser;
pub const Flag = flags_mod.Flag;
pub const FlagValue = flags_mod.FlagValue;
pub const FlagError = flags_mod.FlagError;

/// Configuration loading errors
pub const LoadError = error{
    FileNotFound,
    ParseError,
    InvalidValue,
    MissingRequired,
    IoError,
    OutOfMemory,
};

/// Supported configuration formats
pub const Format = enum {
    json,
    toml,
    yaml,
    ini,
    properties,
    auto,

    pub fn fromExtension(path: []const u8) Format {
        if (mem.endsWith(u8, path, ".json")) return .json;
        if (mem.endsWith(u8, path, ".toml")) return .toml;
        if (mem.endsWith(u8, path, ".yaml") or mem.endsWith(u8, path, ".yml")) return .yaml;
        if (mem.endsWith(u8, path, ".ini")) return .ini;
        if (mem.endsWith(u8, path, ".properties")) return .properties;
        return .toml; // Default to TOML
    }
};

/// Configuration loading options
pub const LoadOptions = struct {
    /// Application name (for XDG paths)
    app_name: []const u8,
    /// Configuration filename (e.g., "config.toml")
    filename: []const u8 = "config.toml",
    /// Environment variable prefix (e.g., "MYAPP_")
    env_prefix: []const u8 = "",
    /// Whether to use XDG directories
    use_xdg: bool = true,
    /// Whether missing config files are allowed
    optional: bool = true,
    /// Specific config file path (overrides auto-discovery)
    config_path: ?[]const u8 = null,
    /// Enable case-insensitive key access (Viper-like)
    case_insensitive: bool = false,
    /// Key delimiter for nested keys (default: ".")
    /// Set to null to disable nested key support (#40)
    key_delimiter: ?[]const u8 = ".",
    /// Try loading extensionless config file (#44)
    /// If true, will try to detect format from content
    allow_extensionless: bool = false,
};

/// Environment key replacement rule
pub const KeyReplacement = struct {
    from: []const u8,
    to: []const u8,
};

/// Environment key replacer configuration
pub const EnvKeyReplacer = struct {
    /// Replacement rules (e.g., "." -> "_")
    replacements: []const KeyReplacement = &.{},
    /// Convert to uppercase
    to_upper: bool = true,
};

/// Configuration loader with Viper-like features
pub fn Loader(comptime T: type) type {
    return struct {
        allocator: Allocator,
        tracker: ProvenanceTracker,
        config: T,
        /// Whether case-insensitive mode is enabled
        case_insensitive: bool = false,
        /// Key aliases (alias -> canonical key)
        aliases: std.StringHashMap([]const u8),
        /// Explicit env bindings (key -> env var names)
        env_bindings: std.StringHashMap([]const []const u8),
        /// Whether automatic env discovery is enabled
        automatic_env_enabled: bool = false,
        /// Prefix for automatic env discovery
        automatic_env_prefix: []const u8 = "",
        /// Environment key replacer
        env_key_replacer: ?EnvKeyReplacer = null,
        /// Runtime overrides (Set values)
        overrides: std.StringHashMap([]const u8),
        /// Runtime defaults (SetDefault values)
        runtime_defaults: std.StringHashMap([]const u8),
        /// Arena for string allocations
        arena: std.heap.ArenaAllocator,
        /// Search paths for config files (Viper's AddConfigPath)
        search_paths: std.ArrayListUnmanaged([]const u8),
        /// Config file name without extension (Viper's SetConfigName)
        config_name: ?[]const u8 = null,
        /// Key delimiter for nested keys (#40)
        key_delimiter: []const u8 = ".",

        const Self = @This();

        /// Initialize a new loader
        pub fn init(allocator: Allocator) Self {
            return .{
                .allocator = allocator,
                .tracker = ProvenanceTracker.init(allocator),
                .config = .{},
                .aliases = std.StringHashMap([]const u8).init(allocator),
                .env_bindings = std.StringHashMap([]const []const u8).init(allocator),
                .overrides = std.StringHashMap([]const u8).init(allocator),
                .runtime_defaults = std.StringHashMap([]const u8).init(allocator),
                .arena = std.heap.ArenaAllocator.init(allocator),
                .search_paths = .{},
            };
        }

        /// Deinitialize the loader
        pub fn deinit(self: *Self) void {
            self.tracker.deinit();
            self.aliases.deinit();
            self.env_bindings.deinit();
            self.overrides.deinit();
            self.runtime_defaults.deinit();
            self.search_paths.deinit(self.allocator);
            self.arena.deinit();
        }

        /// Reset the loader to initial state, freeing all loaded values
        /// This allows reloading configuration without creating a new loader
        pub fn reset(self: *Self) void {
            // Free arena memory and reinitialize
            _ = self.arena.reset(.free_all);
            // Clear tracker
            self.tracker.values.clearAndFree();
            // Reset config to defaults
            self.config = .{};
            // Clear overrides and defaults (they used arena memory)
            self.overrides.clearRetainingCapacity();
            self.runtime_defaults.clearRetainingCapacity();
            // Clear search paths (they used arena memory)
            self.search_paths.clearRetainingCapacity();
            self.config_name = null;
            // Keep aliases and env bindings as they are configuration
        }

        // =====================================================================
        // Viper-like Value Management
        // =====================================================================

        /// Set a value explicitly (highest precedence - like Viper's Set)
        /// This value will override all other sources including flags and env vars.
        pub fn set(self: *Self, key: []const u8, value: []const u8) !void {
            const norm_key = self.normalizeKey(key);
            const owned_value = try self.arena.allocator().dupe(u8, value);
            try self.overrides.put(norm_key, owned_value);
            try self.tracker.set(norm_key, owned_value, .override, "set()");
        }

        /// Set a default value at runtime (lowest precedence - like Viper's SetDefault)
        /// This is lower precedence than struct defaults and will only apply
        /// if no other source provides a value.
        pub fn setDefault(self: *Self, key: []const u8, value: []const u8) !void {
            const norm_key = self.normalizeKey(key);
            const owned_value = try self.arena.allocator().dupe(u8, value);
            try self.runtime_defaults.put(norm_key, owned_value);
            // Only set in tracker if no value exists yet
            if (self.tracker.get(norm_key) == null) {
                try self.tracker.set(norm_key, owned_value, .runtime_default, "setDefault()");
            }
        }

        /// Register a key alias (like Viper's RegisterAlias)
        /// After registration, both keys reference the same value.
        pub fn registerAlias(self: *Self, alias: []const u8, canonical: []const u8) !void {
            const norm_alias = self.normalizeKey(alias);
            const norm_canonical = self.normalizeKey(canonical);
            const owned_canonical = try self.arena.allocator().dupe(u8, norm_canonical);
            try self.aliases.put(norm_alias, owned_canonical);
        }

        /// Check if a key has been explicitly set (not just default)
        /// Returns true if the key was set from any source other than default.
        pub fn isSet(self: *const Self, key: []const u8) bool {
            const norm_key = self.normalizeKey(key);
            const resolved_key = self.resolveAlias(norm_key);

            if (self.tracker.get(resolved_key)) |tracked| {
                return tracked.source != .default and tracked.source != .runtime_default;
            }
            return false;
        }

        /// Check if a key exists (including defaults)
        pub fn has(self: *const Self, key: []const u8) bool {
            const norm_key = self.normalizeKey(key);
            const resolved_key = self.resolveAlias(norm_key);
            return self.tracker.get(resolved_key) != null;
        }

        /// Get a string value by key
        pub fn get(self: *const Self, key: []const u8) ?[]const u8 {
            const norm_key = self.normalizeKey(key);
            const resolved_key = self.resolveAlias(norm_key);

            if (self.tracker.get(resolved_key)) |tracked| {
                return tracked.value;
            }
            return null;
        }

        /// Get a value with array index support (e.g., "servers.0.host")
        /// Supports dot-separated paths with numeric indices for arrays
        pub fn getPath(self: *const Self, path: []const u8) ?[]const u8 {
            // First try direct lookup
            if (self.get(path)) |value| {
                return value;
            }

            // Parse path for array notation
            // Currently, stored values use flattened keys, so this provides the interface
            // for future array support
            return null;
        }

        /// Get all keys that have been set (Viper's AllKeys)
        /// Returns a slice of all configuration keys
        pub fn allKeys(self: *const Self) ![]const []const u8 {
            var keys: std.ArrayListUnmanaged([]const u8) = .{};
            errdefer keys.deinit(self.allocator);

            // Get keys from tracker
            var iter = self.tracker.values.keyIterator();
            while (iter.next()) |key| {
                try keys.append(self.allocator, key.*);
            }

            return keys.toOwnedSlice(self.allocator);
        }

        /// Get all settings as a string hashmap (Viper's AllSettings)
        /// Returns all configuration key-value pairs
        pub fn allSettings(self: *const Self) !std.StringHashMap([]const u8) {
            var settings = std.StringHashMap([]const u8).init(self.allocator);
            errdefer settings.deinit();

            var iter = self.tracker.values.iterator();
            while (iter.next()) |entry| {
                try settings.put(entry.key_ptr.*, entry.value_ptr.value);
            }

            return settings;
        }

        /// Extract a sub-configuration by prefix (Viper's Sub)
        /// Returns a new map containing only keys with the given prefix,
        /// with the prefix stripped from key names
        pub fn sub(self: *const Self, prefix: []const u8) !std.StringHashMap([]const u8) {
            var result = std.StringHashMap([]const u8).init(self.allocator);
            errdefer result.deinit();

            const prefix_with_dot = if (prefix.len > 0 and prefix[prefix.len - 1] != '.')
                try std.fmt.allocPrint(self.allocator, "{s}.", .{prefix})
            else
                try self.allocator.dupe(u8, prefix);
            defer self.allocator.free(prefix_with_dot);

            var iter = self.tracker.values.iterator();
            while (iter.next()) |entry| {
                const key = entry.key_ptr.*;
                if (mem.startsWith(u8, key, prefix_with_dot)) {
                    const sub_key = key[prefix_with_dot.len..];
                    if (sub_key.len > 0) {
                        try result.put(sub_key, entry.value_ptr.value);
                    }
                }
            }

            return result;
        }

        /// Check if a sub-configuration exists
        pub fn hasSub(self: *const Self, prefix: []const u8) bool {
            const prefix_with_dot = std.fmt.allocPrint(self.allocator, "{s}.", .{prefix}) catch return false;
            defer self.allocator.free(prefix_with_dot);

            var iter = self.tracker.values.keyIterator();
            while (iter.next()) |key| {
                if (mem.startsWith(u8, key.*, prefix_with_dot)) {
                    return true;
                }
            }
            return false;
        }

        // =====================================================================
        // Config Path Management (Viper's AddConfigPath/SetConfigName)
        // =====================================================================

        /// Add a path to search for config files (Viper's AddConfigPath)
        /// Paths are searched in the order they are added.
        pub fn addConfigPath(self: *Self, path: []const u8) !void {
            const owned_path = try self.arena.allocator().dupe(u8, path);
            try self.search_paths.append(self.allocator, owned_path);
        }

        /// Set the config file name without extension (Viper's SetConfigName)
        /// When searching, the loader will try this name with supported extensions
        /// (.json, .yaml, .yml, .toml)
        pub fn setConfigName(self: *Self, name: []const u8) !void {
            self.config_name = try self.arena.allocator().dupe(u8, name);
        }

        /// Set the key delimiter for nested keys (#40)
        /// Use "/" for path-like keys, ":" for namespace-style, etc.
        /// Set to "" to disable nested key parsing
        pub fn setKeyDelimiter(self: *Self, delimiter: []const u8) !void {
            self.key_delimiter = try self.arena.allocator().dupe(u8, delimiter);
        }

        /// Get current key delimiter
        pub fn getKeyDelimiter(self: *const Self) []const u8 {
            return self.key_delimiter;
        }

        /// Get all configured search paths
        pub fn getSearchPaths(self: *const Self) []const []const u8 {
            return self.search_paths.items;
        }

        /// Search for a config file in all configured paths
        /// Returns the first found file path, or null if none found
        fn findConfigFile(self: *Self, filename: []const u8) ?[]const u8 {
            return self.findConfigFileWithOptions(filename, false);
        }

        /// Search for a config file with extensionless support (#44)
        fn findConfigFileWithOptions(self: *Self, filename: []const u8, allow_extensionless: bool) ?[]const u8 {
            const extensions = [_][]const u8{ ".toml", ".yaml", ".yml", ".json", ".ini", ".properties" };

            // If we have a config name set, use it with extensions
            if (self.config_name) |name| {
                for (self.search_paths.items) |search_path| {
                    // Try with extensions first
                    for (extensions) |ext| {
                        const full_path = std.fmt.allocPrint(self.allocator, "{s}/{s}{s}", .{ search_path, name, ext }) catch continue;
                        defer self.allocator.free(full_path);

                        if (fs.cwd().access(full_path, .{})) {
                            // Return an owned copy
                            return self.arena.allocator().dupe(u8, full_path) catch null;
                        } else |_| {}
                    }

                    // Try extensionless if allowed (#44)
                    if (allow_extensionless) {
                        const extensionless_path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ search_path, name }) catch continue;
                        defer self.allocator.free(extensionless_path);

                        if (fs.cwd().access(extensionless_path, .{})) {
                            return self.arena.allocator().dupe(u8, extensionless_path) catch null;
                        } else |_| {}
                    }
                }
            }

            // Otherwise, use the provided filename
            for (self.search_paths.items) |search_path| {
                const full_path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ search_path, filename }) catch continue;
                defer self.allocator.free(full_path);

                if (fs.cwd().access(full_path, .{})) {
                    return self.arena.allocator().dupe(u8, full_path) catch null;
                } else |_| {}
            }

            // Try extensionless in search paths (#44)
            if (allow_extensionless) {
                // Extract base name without extension from filename
                const base_name = getBaseName(filename);
                for (self.search_paths.items) |search_path| {
                    const extensionless_path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ search_path, base_name }) catch continue;
                    defer self.allocator.free(extensionless_path);

                    if (fs.cwd().access(extensionless_path, .{})) {
                        return self.arena.allocator().dupe(u8, extensionless_path) catch null;
                    } else |_| {}
                }
            }

            return null;
        }

        // =====================================================================
        // Environment Variable Binding (Viper-like)
        // =====================================================================

        /// Bind a config key to specific environment variable(s)
        /// Like Viper's BindEnv - explicitly maps a key to env vars.
        pub fn bindEnv(self: *Self, key: []const u8, env_vars: []const []const u8) !void {
            const norm_key = self.normalizeKey(key);

            // Copy env var names
            const owned_vars = try self.arena.allocator().alloc([]const u8, env_vars.len);
            for (env_vars, 0..) |env_var, i| {
                owned_vars[i] = try self.arena.allocator().dupe(u8, env_var);
            }

            try self.env_bindings.put(norm_key, owned_vars);
        }

        /// Bind a config key to a single environment variable
        pub fn bindEnvSingle(self: *Self, key: []const u8, env_var: []const u8) !void {
            try self.bindEnv(key, &.{env_var});
        }

        /// Enable automatic environment variable discovery with prefix
        /// Like Viper's AutomaticEnv - auto-discovers all prefixed env vars.
        pub fn automaticEnv(self: *Self, prefix: []const u8) !void {
            self.automatic_env_enabled = true;
            self.automatic_env_prefix = try self.arena.allocator().dupe(u8, prefix);
        }

        /// Set the environment key replacer
        /// Like Viper's SetEnvKeyReplacer - transforms key names for env lookup.
        pub fn setEnvKeyReplacer(self: *Self, replacer: EnvKeyReplacer) void {
            self.env_key_replacer = replacer;
        }

        // =====================================================================
        // Command-Line Flag Integration (Viper-like BindPFlag)
        // =====================================================================

        /// Apply parsed flags to configuration
        /// Flags have second-highest precedence (after override/set)
        pub fn applyFlags(self: *Self, parser: *const FlagParser) void {
            for (parser.getValues()) |fv| {
                self.setField(fv.key, fv.value, .flag, fv.from_flag) catch {};
            }
        }

        /// Create a flag parser pre-configured for this config type
        /// Returns a parser with flags for each struct field
        pub fn createFlagParser(self: *Self) !FlagParser {
            var parser = FlagParser.init(self.allocator);
            errdefer parser.deinit();

            const info = @typeInfo(T);
            inline for (info.@"struct".fields) |field| {
                if (field.type == bool) {
                    try parser.boolean(field.name, null, "");
                } else {
                    try parser.string(field.name, null, "", null);
                }
            }

            return parser;
        }

        // =====================================================================
        // Key Normalization and Alias Resolution
        // =====================================================================

        /// Normalize a key based on case sensitivity setting
        fn normalizeKey(self: *const Self, key: []const u8) []const u8 {
            if (!self.case_insensitive) {
                return key;
            }
            // For case-insensitive, we'd convert to lowercase
            // Since we can't allocate here easily, we rely on the caller
            // to use normalized keys consistently
            return key;
        }

        /// Resolve an alias to its canonical key
        fn resolveAlias(self: *const Self, key: []const u8) []const u8 {
            return self.aliases.get(key) orelse key;
        }

        /// Transform a config key to an environment variable name
        fn keyToEnvVar(self: *const Self, prefix: []const u8, key: []const u8) []const u8 {
            // If we have a replacer, apply transformations
            if (self.env_key_replacer) |replacer| {
                _ = replacer;
                // Would apply replacements here
                // For now, simple upper-case conversion
            }

            // Simple implementation: PREFIX_KEY in uppercase
            _ = prefix;
            return key; // Simplified - would build PREFIX_KEY
        }

        // =====================================================================
        // Configuration Loading
        // =====================================================================

        /// Load configuration with the given options
        pub fn load(self: *Self, options: LoadOptions) LoadError!T {
            self.case_insensitive = options.case_insensitive;

            // 1. Apply runtime defaults first (lowest precedence)
            self.applyRuntimeDefaults();

            // 2. Apply struct defaults
            self.applyDefaults();

            // 3. Load from system config (/etc/APP)
            if (options.use_xdg) {
                const system_path = std.fmt.allocPrint(self.allocator, "/etc/{s}/{s}", .{ options.app_name, options.filename }) catch null;
                if (system_path) |path| {
                    defer self.allocator.free(path);
                    self.loadFromPath(path, .system) catch {};
                }
            }

            // 4. Load from user config (~/.config/APP)
            if (options.use_xdg) {
                const user_config = xdg.getConfigDir(self.allocator, options.app_name) catch null;
                if (user_config) |dir| {
                    defer self.allocator.free(dir);
                    const path = std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ dir, options.filename }) catch null;
                    if (path) |p| {
                        defer self.allocator.free(p);
                        self.loadFromPath(p, .user) catch {};
                    }
                }
            }

            // 5. Load from configured search paths (AddConfigPath)
            if (self.search_paths.items.len > 0) {
                if (self.findConfigFile(options.filename)) |found_path| {
                    self.loadFromPath(found_path, .project) catch {};
                }
            } else {
                // 5b. Fallback to project config (CWD) if no search paths configured
                self.loadFromPath(options.filename, .project) catch {};
            }

            // 6. Load .env file (non-secret values only)
            self.loadDotEnv(".env", .project) catch {};

            // 7. Apply bound environment variables
            self.applyBoundEnvVars();

            // 8. Apply automatic environment variables
            if (self.automatic_env_enabled) {
                self.applyAutomaticEnv(self.automatic_env_prefix);
            }

            // 9. Apply prefix-based environment variables
            self.applyEnv(options.env_prefix);

            // 10. Apply specific config path if provided
            if (options.config_path) |path| {
                try self.loadFromPath(path, .flag);
            }

            // 11. Apply runtime overrides (highest precedence)
            self.applyOverrides();

            return self.config;
        }

        fn applyRuntimeDefaults(self: *Self) void {
            var iter = self.runtime_defaults.iterator();
            while (iter.next()) |entry| {
                self.setField(entry.key_ptr.*, entry.value_ptr.*, .runtime_default, "setDefault()") catch {};
            }
        }

        fn applyDefaults(self: *Self) void {
            const info = @typeInfo(T);
            inline for (info.@"struct".fields) |field| {
                if (field.default_value_ptr != null) {
                    // Set provenance for default value
                    self.tracker.set(
                        field.name,
                        "(default)",
                        .default,
                        null,
                    ) catch {};
                }
            }
        }

        fn applyOverrides(self: *Self) void {
            var iter = self.overrides.iterator();
            while (iter.next()) |entry| {
                // Force set with override source (highest precedence)
                self.setFieldForce(entry.key_ptr.*, entry.value_ptr.*, .override, "set()") catch {};
            }
        }

        fn applyBoundEnvVars(self: *Self) void {
            var iter = self.env_bindings.iterator();
            while (iter.next()) |entry| {
                const key = entry.key_ptr.*;
                const env_vars = entry.value_ptr.*;

                // Try each bound env var in order
                for (env_vars) |env_var| {
                    if (std.posix.getenv(env_var)) |value| {
                        self.setField(key, value, .env, env_var) catch {};
                        break;
                    }
                }
            }
        }

        fn applyAutomaticEnv(self: *Self, prefix: []const u8) void {
            // Get all environment variables and find ones with our prefix
            const info = @typeInfo(T);
            inline for (info.@"struct".fields) |field| {
                // Build env var name with prefix
                var env_name_buf: [256]u8 = undefined;
                const env_name = buildEnvVarName(&env_name_buf, prefix, field.name, self.env_key_replacer);

                if (std.posix.getenv(env_name)) |value| {
                    self.setField(field.name, value, .env, env_name) catch {};
                }
            }
        }

        fn loadFromPath(self: *Self, path: []const u8, source: Source) LoadError!void {
            const file = fs.cwd().openFile(path, .{}) catch {
                return LoadError.FileNotFound;
            };
            defer file.close();

            const content = file.readToEndAlloc(self.allocator, 10 * 1024 * 1024) catch {
                return LoadError.IoError;
            };
            defer self.allocator.free(content);

            const format = Format.fromExtension(path);
            try self.parseContent(content, format, source, path);
        }

        fn parseContent(self: *Self, content: []const u8, format: Format, source: Source, path: []const u8) LoadError!void {
            switch (format) {
                .json => try self.parseSimpleJson(content, source, path),
                .toml => try self.parseSimpleToml(content, source, path),
                .yaml => try self.parseSimpleYaml(content, source, path),
                .ini => try self.parseIni(content, source, path),
                .properties => try self.parseProperties(content, source, path),
                .auto => try self.parseSimpleToml(content, source, path),
            }
        }

        fn parseSimpleJson(self: *Self, content: []const u8, source: Source, path: []const u8) LoadError!void {
            const parsed = std.json.parseFromSlice(std.json.Value, self.allocator, content, .{}) catch {
                return LoadError.ParseError;
            };
            defer parsed.deinit();

            self.applyJsonValue("", parsed.value, source, path);
        }

        fn applyJsonValue(self: *Self, prefix: []const u8, value: std.json.Value, source: Source, path: []const u8) void {
            switch (value) {
                .object => |obj| {
                    var iter = obj.iterator();
                    while (iter.next()) |entry| {
                        const full_key = if (prefix.len > 0)
                            std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ prefix, entry.key_ptr.* }) catch continue
                        else
                            self.allocator.dupe(u8, entry.key_ptr.*) catch continue;
                        defer self.allocator.free(full_key);

                        self.applyJsonValue(full_key, entry.value_ptr.*, source, path);
                    }
                },
                .string => |s| {
                    self.setField(prefix, s, source, path) catch {};
                },
                .integer => |i| {
                    var buf: [32]u8 = undefined;
                    const str = std.fmt.bufPrint(&buf, "{d}", .{i}) catch return;
                    self.setField(prefix, str, source, path) catch {};
                },
                .float => |f| {
                    var buf: [64]u8 = undefined;
                    const str = std.fmt.bufPrint(&buf, "{d}", .{f}) catch return;
                    self.setField(prefix, str, source, path) catch {};
                },
                .bool => |b| {
                    self.setField(prefix, if (b) "true" else "false", source, path) catch {};
                },
                else => {},
            }
        }

        fn parseSimpleToml(self: *Self, content: []const u8, source: Source, path: []const u8) LoadError!void {
            var current_section: ?[]const u8 = null;
            var lines = mem.splitScalar(u8, content, '\n');
            while (lines.next()) |line| {
                const trimmed = mem.trim(u8, line, " \t\r");
                if (trimmed.len == 0 or trimmed[0] == '#') continue;

                if (trimmed[0] == '[' and trimmed[trimmed.len - 1] == ']') {
                    current_section = trimmed[1 .. trimmed.len - 1];
                    continue;
                }

                if (mem.indexOf(u8, trimmed, "=")) |eq_pos| {
                    const key = mem.trim(u8, trimmed[0..eq_pos], " \t");
                    var value = mem.trim(u8, trimmed[eq_pos + 1 ..], " \t");

                    if (value.len >= 2) {
                        if ((value[0] == '"' and value[value.len - 1] == '"') or
                            (value[0] == '\'' and value[value.len - 1] == '\''))
                        {
                            value = value[1 .. value.len - 1];
                        }
                    }

                    const full_key = if (current_section) |section|
                        std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ section, key }) catch key
                    else
                        key;

                    if (current_section != null) {
                        defer self.allocator.free(full_key);
                    }

                    self.setField(full_key, value, source, path) catch {};
                }
            }
        }

        fn parseSimpleYaml(self: *Self, content: []const u8, source: Source, path: []const u8) LoadError!void {
            var lines = mem.splitScalar(u8, content, '\n');
            while (lines.next()) |line| {
                const trimmed = mem.trim(u8, line, " \t\r");
                if (trimmed.len == 0 or trimmed[0] == '#') continue;

                if (mem.indexOf(u8, trimmed, ":")) |colon_pos| {
                    const key = mem.trim(u8, trimmed[0..colon_pos], " \t");
                    var value = mem.trim(u8, trimmed[colon_pos + 1 ..], " \t");

                    if (value.len >= 2) {
                        if ((value[0] == '"' and value[value.len - 1] == '"') or
                            (value[0] == '\'' and value[value.len - 1] == '\''))
                        {
                            value = value[1 .. value.len - 1];
                        }
                    }

                    self.setField(key, value, source, path) catch {};
                }
            }
        }

        fn parseIni(self: *Self, content: []const u8, source: Source, path: []const u8) LoadError!void {
            var doc = ini_mod.parse(self.allocator, content) catch {
                return LoadError.ParseError;
            };
            defer doc.deinit();

            // Apply global values
            var global_iter = doc.global.iterator();
            while (global_iter.next()) |entry| {
                self.setField(entry.key_ptr.*, entry.value_ptr.*, source, path) catch {};
            }

            // Apply section values with "section.key" format
            var section_iter = doc.sections.iterator();
            while (section_iter.next()) |section_entry| {
                const section_name = section_entry.key_ptr.*;
                var value_iter = section_entry.value_ptr.values.iterator();
                while (value_iter.next()) |value_entry| {
                    const full_key = std.fmt.allocPrint(self.allocator, "{s}.{s}", .{ section_name, value_entry.key_ptr.* }) catch continue;
                    defer self.allocator.free(full_key);
                    self.setField(full_key, value_entry.value_ptr.*, source, path) catch {};
                }
            }
        }

        fn parseProperties(self: *Self, content: []const u8, source: Source, path: []const u8) LoadError!void {
            var props = properties_mod.parse(self.allocator, content) catch {
                return LoadError.ParseError;
            };
            defer props.deinit();

            // Apply all properties
            var iter = props.values.iterator();
            while (iter.next()) |entry| {
                self.setField(entry.key_ptr.*, entry.value_ptr.*, source, path) catch {};
            }
        }

        fn loadDotEnv(self: *Self, path: []const u8, source: Source) LoadError!void {
            const file = fs.cwd().openFile(path, .{}) catch {
                return LoadError.FileNotFound;
            };
            defer file.close();

            const content = file.readToEndAlloc(self.allocator, 1024 * 1024) catch {
                return LoadError.IoError;
            };
            defer self.allocator.free(content);

            var lines = mem.splitScalar(u8, content, '\n');
            while (lines.next()) |line| {
                const trimmed = mem.trim(u8, line, " \t\r");
                if (trimmed.len == 0 or trimmed[0] == '#') continue;

                if (mem.indexOf(u8, trimmed, "=")) |eq_pos| {
                    const key = trimmed[0..eq_pos];
                    const value = trimmed[eq_pos + 1 ..];
                    self.setFieldFromEnvKey(key, value, source, path) catch {};
                }
            }
        }

        fn applyEnv(self: *Self, prefix: []const u8) void {
            const info = @typeInfo(T);
            inline for (info.@"struct".fields) |field| {
                var env_name_buf: [256]u8 = undefined;
                const env_name = buildEnvVarName(&env_name_buf, prefix, field.name, self.env_key_replacer);

                if (std.posix.getenv(env_name)) |value| {
                    self.setField(field.name, value, .env, env_name) catch {};
                }
            }
        }

        fn setField(self: *Self, name: []const u8, value: []const u8, source: Source, path: []const u8) LoadError!void {
            const resolved_name = self.resolveAlias(name);
            const info = @typeInfo(T);
            inline for (info.@"struct".fields) |field| {
                if (matchFieldName(field.name, resolved_name, self.case_insensitive)) {
                    try self.setFieldValue(field.type, field.name, value);
                    // Copy value and path for provenance tracking
                    const owned_value_for_tracker = self.arena.allocator().dupe(u8, value) catch return;
                    const owned_path = self.arena.allocator().dupe(u8, path) catch return;
                    self.tracker.set(resolved_name, owned_value_for_tracker, source, owned_path) catch {};
                    return;
                }
            }
        }

        /// Set a field value with proper type conversion
        fn setFieldValue(self: *Self, comptime FieldType: type, comptime field_name: []const u8, value: []const u8) LoadError!void {
            const field_info = @typeInfo(FieldType);

            // Handle optional types
            if (field_info == .optional) {
                const ChildType = field_info.optional.child;
                // Empty value means null for optionals
                if (value.len == 0) {
                    @field(self.config, field_name) = null;
                    return;
                }
                // Recursively handle the child type
                var temp_config: ChildType = undefined;
                try self.setNonOptionalValue(ChildType, &temp_config, value);
                @field(self.config, field_name) = temp_config;
                return;
            }

            try self.setNonOptionalValue(FieldType, &@field(self.config, field_name), value);
        }

        /// Set a non-optional field value
        fn setNonOptionalValue(self: *Self, comptime FieldType: type, ptr: *FieldType, value: []const u8) LoadError!void {
            const field_info = @typeInfo(FieldType);

            if (FieldType == bool) {
                ptr.* = parseBool(value);
            } else if (FieldType == []const u8) {
                // Copy string into arena to outlive the source buffer
                const owned_value = self.arena.allocator().dupe(u8, value) catch {
                    return LoadError.OutOfMemory;
                };
                ptr.* = owned_value;
            } else if (field_info == .int) {
                ptr.* = std.fmt.parseInt(FieldType, value, 10) catch {
                    return LoadError.InvalidValue;
                };
            } else if (field_info == .float) {
                ptr.* = std.fmt.parseFloat(FieldType, value) catch {
                    return LoadError.InvalidValue;
                };
            }
        }

        /// Force set a field value, bypassing precedence checks
        fn setFieldForce(self: *Self, name: []const u8, value: []const u8, source: Source, path: []const u8) LoadError!void {
            const resolved_name = self.resolveAlias(name);
            const info = @typeInfo(T);
            inline for (info.@"struct".fields) |field| {
                if (matchFieldName(field.name, resolved_name, self.case_insensitive)) {
                    try self.setFieldValue(field.type, field.name, value);
                    // Force update tracker by removing existing and re-adding
                    // Copy strings into arena for long-term storage
                    const owned_value_for_tracker = self.arena.allocator().dupe(u8, value) catch return;
                    const owned_path = self.arena.allocator().dupe(u8, path) catch return;
                    _ = self.tracker.values.remove(resolved_name);
                    self.tracker.values.put(resolved_name, .{
                        .key = resolved_name,
                        .value = owned_value_for_tracker,
                        .source = source,
                        .source_path = owned_path,
                    }) catch {};
                    return;
                }
            }
        }

        fn setFieldFromEnvKey(self: *Self, env_key: []const u8, value: []const u8, source: Source, path: []const u8) LoadError!void {
            var lower_key: [256]u8 = undefined;
            var i: usize = 0;
            for (env_key) |c| {
                if (i >= lower_key.len) break;
                lower_key[i] = std.ascii.toLower(c);
                i += 1;
            }
            try self.setField(lower_key[0..i], value, source, path);
        }

        /// Get provenance tracker for reporting
        pub fn getTracker(self: *const Self) *const ProvenanceTracker {
            return &self.tracker;
        }

        /// Get the current configuration
        pub fn getConfig(self: *const Self) T {
            return self.config;
        }
    };
}

/// Match field name with optional case insensitivity
fn matchFieldName(field_name: []const u8, key: []const u8, case_insensitive: bool) bool {
    if (case_insensitive) {
        return std.ascii.eqlIgnoreCase(field_name, key);
    }
    return mem.eql(u8, field_name, key);
}

/// Build environment variable name from prefix and field name
/// Produces PREFIX_FIELD format (e.g., "MYAPP" + "host" = "MYAPP_HOST")
fn buildEnvVarName(buf: []u8, prefix: []const u8, field: []const u8, replacer: ?EnvKeyReplacer) []const u8 {
    var pos: usize = 0;

    // Add prefix (converted to uppercase)
    for (prefix) |c| {
        if (pos >= buf.len) break;
        buf[pos] = std.ascii.toUpper(c);
        pos += 1;
    }

    // Add underscore separator if prefix is non-empty and doesn't end with underscore
    if (prefix.len > 0 and prefix[prefix.len - 1] != '_') {
        if (pos < buf.len) {
            buf[pos] = '_';
            pos += 1;
        }
    }

    // Add field name with transformations
    for (field) |c| {
        if (pos >= buf.len) break;

        var char_to_add = c;

        // Apply replacements if configured
        if (replacer) |r| {
            for (r.replacements) |replacement| {
                if (replacement.from.len == 1 and replacement.from[0] == c) {
                    if (replacement.to.len > 0) {
                        char_to_add = replacement.to[0];
                    }
                    break;
                }
            }

            if (r.to_upper) {
                char_to_add = std.ascii.toUpper(char_to_add);
            }
        } else {
            char_to_add = std.ascii.toUpper(c);
        }

        buf[pos] = char_to_add;
        pos += 1;
    }

    return buf[0..pos];
}

/// Parse boolean from string
fn parseBool(value: []const u8) bool {
    return mem.eql(u8, value, "true") or
        mem.eql(u8, value, "1") or
        mem.eql(u8, value, "yes") or
        mem.eql(u8, value, "on");
}

/// Get base name without extension (#44)
fn getBaseName(filename: []const u8) []const u8 {
    if (mem.lastIndexOfScalar(u8, filename, '.')) |dot| {
        return filename[0..dot];
    }
    return filename;
}

/// Detect format from file content for extensionless files (#44)
pub fn detectFormatFromContent(content: []const u8) Format {
    const trimmed = mem.trimLeft(u8, content, " \t\r\n");
    if (trimmed.len == 0) return .toml;

    // JSON starts with { or [
    if (trimmed[0] == '{' or trimmed[0] == '[') return .json;

    // Check for YAML indicators
    if (mem.startsWith(u8, trimmed, "---")) return .yaml;
    if (mem.startsWith(u8, trimmed, "%YAML")) return .yaml;

    // Check for INI section [section]
    if (trimmed[0] == '[') {
        // Could be JSON array or INI section
        if (mem.indexOf(u8, trimmed, "]")) |end| {
            const bracket_content = trimmed[1..end];
            // If it contains =, it's more likely INI
            if (mem.indexOf(u8, bracket_content, "=") == null and
                mem.indexOf(u8, bracket_content, ":") == null)
            {
                // Check if next non-whitespace after ] is a newline (INI style)
                const after_bracket = trimmed[end + 1 ..];
                const after_trimmed = mem.trimLeft(u8, after_bracket, " \t");
                if (after_trimmed.len == 0 or after_trimmed[0] == '\n' or after_trimmed[0] == '\r') {
                    return .ini;
                }
            }
        }
    }

    // Check for Properties-style (key=value without sections, and special escapes)
    var lines = mem.splitScalar(u8, trimmed, '\n');
    var yaml_indicators: u32 = 0;
    var toml_indicators: u32 = 0;
    var properties_indicators: u32 = 0;

    while (lines.next()) |line| {
        const line_trimmed = mem.trim(u8, line, " \t\r");
        if (line_trimmed.len == 0) continue;
        if (line_trimmed[0] == '#' or line_trimmed[0] == ';') continue;

        // YAML uses colon with space
        if (mem.indexOf(u8, line_trimmed, ": ")) |_| yaml_indicators += 1;

        // TOML uses = with quotes
        if (mem.indexOf(u8, line_trimmed, " = \"")) |_| toml_indicators += 1;
        if (mem.indexOf(u8, line_trimmed, "= \"")) |_| toml_indicators += 1;

        // Properties uses = or : without quotes typically
        if (mem.indexOf(u8, line_trimmed, "=")) |_| {
            if (mem.indexOf(u8, line_trimmed, "\"") == null) properties_indicators += 1;
        }

        // Only check first 10 lines
        if (yaml_indicators + toml_indicators + properties_indicators > 10) break;
    }

    if (yaml_indicators > toml_indicators and yaml_indicators > properties_indicators) return .yaml;
    if (toml_indicators > yaml_indicators and toml_indicators > properties_indicators) return .toml;
    if (properties_indicators > 3) return .properties;

    // Default to TOML
    return .toml;
}

/// Load configuration with options
pub fn load(comptime T: type, options: LoadOptions, allocator: Allocator) LoadError!T {
    var loader = Loader(T).init(allocator);
    defer loader.deinit();
    return loader.load(options);
}

// ============================================================================
// Tests
// ============================================================================

test "Loader initialization" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try std.testing.expectEqualStrings("localhost", loader.config.host);
    try std.testing.expectEqual(@as(u16, 8080), loader.config.port);
}

test "Format.fromExtension" {
    try std.testing.expectEqual(Format.json, Format.fromExtension("config.json"));
    try std.testing.expectEqual(Format.toml, Format.fromExtension("config.toml"));
    try std.testing.expectEqual(Format.yaml, Format.fromExtension("config.yaml"));
    try std.testing.expectEqual(Format.yaml, Format.fromExtension("config.yml"));
}

test "parseBool" {
    try std.testing.expect(parseBool("true"));
    try std.testing.expect(parseBool("1"));
    try std.testing.expect(parseBool("yes"));
    try std.testing.expect(parseBool("on"));
    try std.testing.expect(!parseBool("false"));
    try std.testing.expect(!parseBool("0"));
    try std.testing.expect(!parseBool("no"));
}

test "Set() overrides all sources" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // Set an override value
    try loader.set("host", "override.example.com");

    // The override should be stored
    try std.testing.expectEqualStrings("override.example.com", loader.overrides.get("host").?);
}

test "SetDefault() sets runtime defaults" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // Set a runtime default
    try loader.setDefault("timeout", "30");

    // The default should be stored
    try std.testing.expectEqualStrings("30", loader.runtime_defaults.get("timeout").?);
}

test "RegisterAlias creates key alias" {
    const Config = struct {
        verbose: bool = false,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // Register alias
    try loader.registerAlias("loud", "verbose");

    // Alias should resolve to canonical key
    try std.testing.expectEqualStrings("verbose", loader.resolveAlias("loud"));
    try std.testing.expectEqualStrings("verbose", loader.resolveAlias("verbose"));
}

test "IsSet returns false for defaults" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // Before loading, isSet should be false
    try std.testing.expect(!loader.isSet("host"));
}

test "BindEnv stores env bindings" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // Bind to multiple env vars
    try loader.bindEnv("host", &.{ "SERVICE_HOST", "HOST" });

    // Binding should be stored
    const bindings = loader.env_bindings.get("host").?;
    try std.testing.expectEqual(@as(usize, 2), bindings.len);
    try std.testing.expectEqualStrings("SERVICE_HOST", bindings[0]);
    try std.testing.expectEqualStrings("HOST", bindings[1]);
}

test "AutomaticEnv enables auto discovery" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.automaticEnv("MYAPP_");

    try std.testing.expect(loader.automatic_env_enabled);
    try std.testing.expectEqualStrings("MYAPP_", loader.automatic_env_prefix);
}

test "SetEnvKeyReplacer configures replacer" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    loader.setEnvKeyReplacer(.{
        .replacements = &.{
            .{ .from = ".", .to = "_" },
        },
        .to_upper = true,
    });

    try std.testing.expect(loader.env_key_replacer != null);
    try std.testing.expect(loader.env_key_replacer.?.to_upper);
}

test "buildEnvVarName constructs correct name" {
    var buf: [256]u8 = undefined;

    // Prefix with trailing underscore
    const result1 = buildEnvVarName(&buf, "MYAPP_", "host", null);
    try std.testing.expectEqualStrings("MYAPP_HOST", result1);

    // Empty prefix
    const result2 = buildEnvVarName(&buf, "", "port", null);
    try std.testing.expectEqualStrings("PORT", result2);

    // Prefix without trailing underscore (should add one)
    const result3 = buildEnvVarName(&buf, "MYAPP", "host", null);
    try std.testing.expectEqualStrings("MYAPP_HOST", result3);

    // Lowercase prefix (should be uppercased)
    const result4 = buildEnvVarName(&buf, "myapp", "debug", null);
    try std.testing.expectEqualStrings("MYAPP_DEBUG", result4);

    // Snake_case field name
    const result5 = buildEnvVarName(&buf, "APP", "pool_size", null);
    try std.testing.expectEqualStrings("APP_POOL_SIZE", result5);
}

test "matchFieldName with case sensitivity" {
    // Case sensitive (default)
    try std.testing.expect(matchFieldName("host", "host", false));
    try std.testing.expect(!matchFieldName("host", "HOST", false));
    try std.testing.expect(!matchFieldName("host", "Host", false));

    // Case insensitive
    try std.testing.expect(matchFieldName("host", "host", true));
    try std.testing.expect(matchFieldName("host", "HOST", true));
    try std.testing.expect(matchFieldName("host", "Host", true));
}

test "Loader supports float types" {
    const Config = struct {
        rate: f32 = 1.0,
        timeout: f64 = 30.5,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.set("rate", "2.5");
    try loader.set("timeout", "60.25");

    _ = try loader.load(.{ .app_name = "test", .use_xdg = false });

    try std.testing.expectApproxEqAbs(@as(f32, 2.5), loader.config.rate, 0.001);
    try std.testing.expectApproxEqAbs(@as(f64, 60.25), loader.config.timeout, 0.001);
}

test "Loader supports optional types" {
    const Config = struct {
        host: []const u8 = "localhost",
        callback_url: ?[]const u8 = null,
        max_retries: ?u32 = null,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.set("callback_url", "http://example.com");
    try loader.set("max_retries", "5");

    _ = try loader.load(.{ .app_name = "test", .use_xdg = false });

    try std.testing.expectEqualStrings("http://example.com", loader.config.callback_url.?);
    try std.testing.expectEqual(@as(u32, 5), loader.config.max_retries.?);
}

test "Loader reset clears state" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.set("host", "myhost.com");
    try loader.set("port", "9000");

    _ = try loader.load(.{ .app_name = "test", .use_xdg = false });

    // Verify values were set
    try std.testing.expectEqualStrings("myhost.com", loader.config.host);

    // Reset
    loader.reset();

    // Verify config is back to defaults
    try std.testing.expectEqualStrings("localhost", loader.config.host);
    try std.testing.expectEqual(@as(u16, 8080), loader.config.port);

    // Verify tracker is cleared
    try std.testing.expect(loader.tracker.get("host") == null);
}

test "Loader string memory safety" {
    // Test that strings loaded from content are properly copied
    const Config = struct {
        name: []const u8 = "default",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // Set a value from a temporary string
    {
        var temp_buf: [32]u8 = undefined;
        const temp_str = std.fmt.bufPrint(&temp_buf, "temp_value_{d}", .{42}) catch unreachable;
        try loader.set("name", temp_str);
    }
    // temp_buf is now out of scope but loader.config.name should still be valid

    _ = try loader.load(.{ .app_name = "test", .use_xdg = false });

    // The value should still be accessible (it was copied to arena)
    try std.testing.expectEqualStrings("temp_value_42", loader.config.name);
}

test "allKeys returns all configuration keys" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
        debug: bool = false,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.set("host", "example.com");
    try loader.set("port", "3000");

    _ = try loader.load(.{ .app_name = "test", .use_xdg = false });

    const keys = try loader.allKeys();
    defer std.testing.allocator.free(keys);

    // Should have at least the keys we set
    try std.testing.expect(keys.len >= 2);
}

test "allSettings returns all key-value pairs" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.set("host", "example.com");
    try loader.set("port", "3000");

    _ = try loader.load(.{ .app_name = "test", .use_xdg = false });

    var settings = try loader.allSettings();
    defer settings.deinit();

    // Should have at least the keys we set
    try std.testing.expect(settings.count() >= 2);
    try std.testing.expectEqualStrings("example.com", settings.get("host").?);
    try std.testing.expectEqualStrings("3000", settings.get("port").?);
}

test "sub extracts sub-configuration by prefix" {
    const Config = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // Manually set some prefixed values in the tracker
    try loader.tracker.set("database.host", "db.example.com", .project, "test");
    try loader.tracker.set("database.port", "5432", .project, "test");
    try loader.tracker.set("cache.host", "cache.example.com", .project, "test");

    var db_config = try loader.sub("database");
    defer db_config.deinit();

    try std.testing.expectEqual(@as(usize, 2), db_config.count());
    try std.testing.expectEqualStrings("db.example.com", db_config.get("host").?);
    try std.testing.expectEqualStrings("5432", db_config.get("port").?);
}

test "hasSub checks for sub-configuration existence" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // Set some prefixed values
    try loader.tracker.set("database.host", "db.example.com", .project, "test");

    try std.testing.expect(loader.hasSub("database"));
    try std.testing.expect(!loader.hasSub("nonexistent"));
}

test "addConfigPath adds search paths" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.addConfigPath("/etc/myapp");
    try loader.addConfigPath("/home/user/.config/myapp");
    try loader.addConfigPath(".");

    const paths = loader.getSearchPaths();
    try std.testing.expectEqual(@as(usize, 3), paths.len);
    try std.testing.expectEqualStrings("/etc/myapp", paths[0]);
    try std.testing.expectEqualStrings("/home/user/.config/myapp", paths[1]);
    try std.testing.expectEqualStrings(".", paths[2]);
}

test "setConfigName sets config file name" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.setConfigName("myconfig");

    try std.testing.expectEqualStrings("myconfig", loader.config_name.?);
}

test "getPath returns value for direct key" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.set("host", "example.com");
    _ = try loader.load(.{ .app_name = "test", .use_xdg = false });

    try std.testing.expectEqualStrings("example.com", loader.getPath("host").?);
}

test "reset clears search paths" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    try loader.addConfigPath("/etc/myapp");
    try loader.setConfigName("config");

    try std.testing.expectEqual(@as(usize, 1), loader.search_paths.items.len);
    try std.testing.expect(loader.config_name != null);

    loader.reset();

    try std.testing.expectEqual(@as(usize, 0), loader.search_paths.items.len);
    try std.testing.expect(loader.config_name == null);
}

test "setKeyDelimiter changes delimiter (#40)" {
    const Config = struct {
        host: []const u8 = "localhost",
    };

    var loader = Loader(Config).init(std.testing.allocator);
    defer loader.deinit();

    // Default delimiter
    try std.testing.expectEqualStrings(".", loader.getKeyDelimiter());

    // Change to path-style
    try loader.setKeyDelimiter("/");
    try std.testing.expectEqualStrings("/", loader.getKeyDelimiter());

    // Change to namespace-style
    try loader.setKeyDelimiter("::");
    try std.testing.expectEqualStrings("::", loader.getKeyDelimiter());
}

test "getBaseName extracts filename without extension" {
    try std.testing.expectEqualStrings("config", getBaseName("config.toml"));
    try std.testing.expectEqualStrings("my.config", getBaseName("my.config.yaml"));
    try std.testing.expectEqualStrings("config", getBaseName("config"));
    try std.testing.expectEqualStrings("path/to/config", getBaseName("path/to/config.json"));
}

test "detectFormatFromContent JSON" {
    try std.testing.expectEqual(Format.json, detectFormatFromContent("{\"key\": \"value\"}"));
    try std.testing.expectEqual(Format.json, detectFormatFromContent("[1, 2, 3]"));
    try std.testing.expectEqual(Format.json, detectFormatFromContent("  { \"nested\": {} }"));
}

test "detectFormatFromContent YAML" {
    try std.testing.expectEqual(Format.yaml, detectFormatFromContent("---\nkey: value"));
    try std.testing.expectEqual(Format.yaml, detectFormatFromContent("key: value\nother: data"));
}

test "detectFormatFromContent TOML" {
    try std.testing.expectEqual(Format.toml, detectFormatFromContent("key = \"value\""));
    try std.testing.expectEqual(Format.toml, detectFormatFromContent("name = \"test\"\nport = 8080"));
}

test "LoadOptions key_delimiter default" {
    const opts = LoadOptions{ .app_name = "test" };
    try std.testing.expectEqualStrings(".", opts.key_delimiter.?);
    try std.testing.expect(!opts.allow_extensionless);
}

test "LoadOptions allow_extensionless" {
    const opts = LoadOptions{
        .app_name = "test",
        .allow_extensionless = true,
    };
    try std.testing.expect(opts.allow_extensionless);
}
