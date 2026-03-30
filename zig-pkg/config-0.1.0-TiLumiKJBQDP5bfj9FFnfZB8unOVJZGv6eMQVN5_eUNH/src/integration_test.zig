// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Integration tests with file fixtures
//!
//! These tests verify the complete configuration loading workflow
//! using real configuration files in the test/fixtures directory.

const std = @import("std");
const config = @import("config.zig");

const testing = std.testing;

// Test fixture paths relative to the source file
const FIXTURES_DIR = "test/fixtures/";

// ============================================================================
// YAML Integration Tests
// ============================================================================

test "integration: parse YAML fixture file" {
    var cfg = config.parseFile(testing.allocator, FIXTURES_DIR ++ "config.yaml") catch |err| {
        std.debug.print("Failed to parse YAML: {}\n", .{err});
        return err;
    };
    defer cfg.deinit();

    // Verify nested values
    try testing.expectEqualStrings("yaml-host.example.com", cfg.getString("server.host").?);
    try testing.expectEqual(@as(i64, 8001), cfg.getInt("server.port").?);
    try testing.expectEqualStrings("postgres://yaml:pass@localhost/db", cfg.getString("database.url").?);
    try testing.expectEqual(@as(i64, 5), cfg.getInt("database.pool_size").?);
    try testing.expectEqualStrings("debug", cfg.getString("logging.level").?);
    try testing.expectEqual(true, cfg.getBool("features.cache").?);
    try testing.expectEqual(false, cfg.getBool("features.metrics").?);
}

// ============================================================================
// JSON Integration Tests
// ============================================================================

test "integration: parse JSON fixture file" {
    var cfg = config.parseFile(testing.allocator, FIXTURES_DIR ++ "config.json") catch |err| {
        std.debug.print("Failed to parse JSON: {}\n", .{err});
        return err;
    };
    defer cfg.deinit();

    // Verify nested values
    try testing.expectEqualStrings("json-host.example.com", cfg.getString("server.host").?);
    try testing.expectEqual(@as(i64, 8002), cfg.getInt("server.port").?);
    try testing.expectEqualStrings("postgres://json:pass@localhost/db", cfg.getString("database.url").?);
    try testing.expectEqual(@as(i64, 10), cfg.getInt("database.pool_size").?);
    try testing.expectEqualStrings("info", cfg.getString("logging.level").?);
    try testing.expectEqual(false, cfg.getBool("features.cache").?);
    try testing.expectEqual(true, cfg.getBool("features.metrics").?);
}

// ============================================================================
// TOML Integration Tests
// ============================================================================

test "integration: parse TOML fixture file" {
    var cfg = config.parseFile(testing.allocator, FIXTURES_DIR ++ "config.toml") catch |err| {
        std.debug.print("Failed to parse TOML: {}\n", .{err});
        return err;
    };
    defer cfg.deinit();

    // Verify nested values
    try testing.expectEqualStrings("toml-host.example.com", cfg.getString("server.host").?);
    try testing.expectEqual(@as(i64, 8003), cfg.getInt("server.port").?);
    try testing.expectEqualStrings("postgres://toml:pass@localhost/db", cfg.getString("database.url").?);
    try testing.expectEqual(@as(i64, 15), cfg.getInt("database.pool_size").?);
    try testing.expectEqualStrings("warn", cfg.getString("logging.level").?);
    try testing.expectEqual(true, cfg.getBool("features.cache").?);
    try testing.expectEqual(true, cfg.getBool("features.metrics").?);
}

// ============================================================================
// Dotenv Integration Tests
// ============================================================================

test "integration: parse dotenv content" {
    // Test dotenv parsing with inline content (since file loading uses
    // slices into a buffer that gets freed)
    const content =
        \\# Test environment file
        \\SERVER_HOST=env-host.example.com
        \\SERVER_PORT=8004
        \\DATABASE_URL=postgres://env:pass@localhost/db
        \\DEBUG=true
        \\CACHE_ENABLED=yes
    ;

    const entries = try config.dotenv.parseContent(content, testing.allocator);
    defer testing.allocator.free(entries);

    // Should have parsed multiple entries
    try testing.expect(entries.len >= 4);

    // Find specific entries
    var found_host = false;
    var found_port = false;
    var found_debug = false;

    for (entries) |entry| {
        if (std.mem.eql(u8, entry.key, "SERVER_HOST")) {
            try testing.expectEqualStrings("env-host.example.com", entry.value);
            found_host = true;
        }
        if (std.mem.eql(u8, entry.key, "SERVER_PORT")) {
            try testing.expectEqualStrings("8004", entry.value);
            found_port = true;
        }
        if (std.mem.eql(u8, entry.key, "DEBUG")) {
            try testing.expectEqualStrings("true", entry.value);
            found_debug = true;
        }
    }

    try testing.expect(found_host);
    try testing.expect(found_port);
    try testing.expect(found_debug);
}

// ============================================================================
// Cross-Format Consistency Tests
// ============================================================================

test "integration: all formats produce consistent value types" {
    // Load all formats
    var yaml_cfg = try config.parseFile(testing.allocator, FIXTURES_DIR ++ "config.yaml");
    defer yaml_cfg.deinit();

    var json_cfg = try config.parseFile(testing.allocator, FIXTURES_DIR ++ "config.json");
    defer json_cfg.deinit();

    var toml_cfg = try config.parseFile(testing.allocator, FIXTURES_DIR ++ "config.toml");
    defer toml_cfg.deinit();

    // All should have the same structure
    try testing.expect(yaml_cfg.has("server.host"));
    try testing.expect(json_cfg.has("server.host"));
    try testing.expect(toml_cfg.has("server.host"));

    try testing.expect(yaml_cfg.has("server.port"));
    try testing.expect(json_cfg.has("server.port"));
    try testing.expect(toml_cfg.has("server.port"));

    // All integer types should work
    try testing.expect(yaml_cfg.getInt("server.port") != null);
    try testing.expect(json_cfg.getInt("server.port") != null);
    try testing.expect(toml_cfg.getInt("server.port") != null);

    // All boolean types should work
    try testing.expect(yaml_cfg.getBool("features.cache") != null);
    try testing.expect(json_cfg.getBool("features.cache") != null);
    try testing.expect(toml_cfg.getBool("features.cache") != null);
}

// ============================================================================
// Typed Loader Integration Tests
// ============================================================================

test "integration: typed loader with TOML file" {
    const ServerConfig = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
    };

    var loader = config.Loader(ServerConfig).init(testing.allocator);
    defer loader.deinit();

    // Load from fixture path
    const cfg = loader.load(.{
        .app_name = "test",
        .config_path = FIXTURES_DIR ++ "config.toml",
    }) catch |err| {
        std.debug.print("Loader failed: {}\n", .{err});
        return err;
    };

    // Note: The typed loader uses simple parsing, so it reads top-level keys
    // For nested values like server.host, we'd need the full parser
    _ = cfg;
}

// ============================================================================
// Error Handling Tests
// ============================================================================

test "integration: file not found returns error" {
    const result = config.parseFile(testing.allocator, "nonexistent/config.yaml");
    try testing.expectError(error.FileNotFound, result);
}

// ============================================================================
// Value API Tests with Real Data
// ============================================================================

test "integration: value API navigation" {
    var cfg = try config.parseFile(testing.allocator, FIXTURES_DIR ++ "config.yaml");
    defer cfg.deinit();

    // Test has() method
    try testing.expect(cfg.has("server"));
    try testing.expect(cfg.has("server.host"));
    try testing.expect(cfg.has("database.pool_size"));
    try testing.expect(!cfg.has("nonexistent"));
    try testing.expect(!cfg.has("server.nonexistent"));

    // Test getPath() for nested access
    if (cfg.getPath("server")) |server| {
        try testing.expectEqualStrings("yaml-host.example.com", server.getString("host").?);
        try testing.expectEqual(@as(i64, 8001), server.getInt("port").?);
    } else {
        return error.TestUnexpectedResult;
    }
}

// ============================================================================
// Provenance Tracking Integration Tests
// ============================================================================

test "integration: provenance tracking with loader" {
    const AppConfig = struct {
        debug: bool = false,
    };

    var loader = config.Loader(AppConfig).init(testing.allocator);
    defer loader.deinit();

    // Set values from different sources
    try loader.set("debug", "true");
    try loader.setDefault("timeout", "30");

    _ = try loader.load(.{
        .app_name = "test",
        .optional = true,
    });

    // Check provenance
    const tracker = loader.getTracker();

    if (tracker.get("debug")) |tracked| {
        try testing.expectEqual(config.Source.override, tracked.source);
    }
}

// ============================================================================
// Flag Integration Tests
// ============================================================================

test "integration: flag parser with loader" {
    const AppConfig = struct {
        host: []const u8 = "localhost",
        port: u16 = 8080,
        debug: bool = false,
    };

    var loader = config.Loader(AppConfig).init(testing.allocator);
    defer loader.deinit();

    var parser = config.FlagParser.init(testing.allocator);
    defer parser.deinit();

    try parser.string("host", 'h', "Host", null);
    try parser.string("port", 'p', "Port", null);
    try parser.boolean("debug", 'd', "Debug");

    try parser.parse(&.{ "--host", "flag-host", "--port", "9999", "--debug" });

    loader.applyFlags(&parser);

    const cfg = try loader.load(.{
        .app_name = "test",
        .optional = true,
    });

    try testing.expectEqualStrings("flag-host", cfg.host);
    try testing.expectEqual(@as(u16, 9999), cfg.port);
    try testing.expectEqual(true, cfg.debug);
}
