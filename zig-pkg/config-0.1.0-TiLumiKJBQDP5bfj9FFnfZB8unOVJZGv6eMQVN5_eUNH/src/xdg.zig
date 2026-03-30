// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # XDG Base Directory Module
//!
//! Implements XDG Base Directory Specification for configuration,
//! data, and cache directories. Also provides platform-specific
//! equivalents for Windows and macOS.
//!
//! Platform defaults:
//! - Linux: XDG spec (~/.config, ~/.local/share, ~/.cache)
//! - macOS: ~/Library paths (Preferences, Application Support, Caches)
//! - Windows: %APPDATA%, %LOCALAPPDATA%

const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const builtin = @import("builtin");

/// Platform type for path resolution
pub const Platform = enum {
    linux,
    macos,
    windows,
    other,

    pub fn current() Platform {
        return switch (builtin.os.tag) {
            .linux, .freebsd, .openbsd, .netbsd => .linux,
            .macos => .macos,
            .windows => .windows,
            else => .other,
        };
    }
};

/// XDG directory paths
pub const XdgPaths = struct {
    /// User configuration directory (~/.config on Linux, ~/Library/Preferences on macOS, %APPDATA% on Windows)
    config_home: []const u8,
    /// User data directory (~/.local/share on Linux, ~/Library/Application Support on macOS, %LOCALAPPDATA% on Windows)
    data_home: []const u8,
    /// User cache directory (~/.cache on Linux, ~/Library/Caches on macOS, %LOCALAPPDATA%\cache on Windows)
    cache_home: []const u8,
    /// User state directory (~/.local/state on Linux)
    state_home: []const u8,
    /// User runtime directory (/run/user/$UID on Linux)
    runtime_dir: ?[]const u8,
    /// System configuration directories (/etc/xdg on Linux, /Library/Preferences on macOS, %PROGRAMDATA% on Windows)
    config_dirs: []const []const u8,
    /// System data directories (/usr/local/share, /usr/share on Linux)
    data_dirs: []const []const u8,
    /// The allocator used for paths
    allocator: std.mem.Allocator,

    /// Free all allocated paths
    pub fn deinit(self: *XdgPaths) void {
        self.allocator.free(self.config_home);
        self.allocator.free(self.data_home);
        self.allocator.free(self.cache_home);
        self.allocator.free(self.state_home);
    }
};

/// Get XDG directories for the current user (platform-aware)
pub fn getPaths(allocator: std.mem.Allocator) !XdgPaths {
    return getPathsForPlatform(allocator, Platform.current());
}

/// Get XDG directories for a specific platform (useful for testing)
pub fn getPathsForPlatform(allocator: std.mem.Allocator, platform: Platform) !XdgPaths {
    return switch (platform) {
        .linux, .other => getLinuxPaths(allocator),
        .macos => getMacosPaths(allocator),
        .windows => getWindowsPaths(allocator),
    };
}

/// Get Linux/BSD XDG paths
fn getLinuxPaths(allocator: std.mem.Allocator) !XdgPaths {
    const home = std.posix.getenv("HOME") orelse "/";

    // Config home
    const config_home = if (std.posix.getenv("XDG_CONFIG_HOME")) |ch|
        try allocator.dupe(u8, ch)
    else
        try std.fmt.allocPrint(allocator, "{s}/.config", .{home});

    // Data home
    const data_home = if (std.posix.getenv("XDG_DATA_HOME")) |dh|
        try allocator.dupe(u8, dh)
    else
        try std.fmt.allocPrint(allocator, "{s}/.local/share", .{home});

    // Cache home
    const cache_home = if (std.posix.getenv("XDG_CACHE_HOME")) |ch|
        try allocator.dupe(u8, ch)
    else
        try std.fmt.allocPrint(allocator, "{s}/.cache", .{home});

    // State home
    const state_home = if (std.posix.getenv("XDG_STATE_HOME")) |sh|
        try allocator.dupe(u8, sh)
    else
        try std.fmt.allocPrint(allocator, "{s}/.local/state", .{home});

    // Runtime dir (may not be set)
    const runtime_dir = std.posix.getenv("XDG_RUNTIME_DIR");

    return XdgPaths{
        .config_home = config_home,
        .data_home = data_home,
        .cache_home = cache_home,
        .state_home = state_home,
        .runtime_dir = runtime_dir,
        .config_dirs = &.{"/etc/xdg"},
        .data_dirs = &.{ "/usr/local/share", "/usr/share" },
        .allocator = allocator,
    };
}

/// Get macOS paths following Apple conventions
fn getMacosPaths(allocator: std.mem.Allocator) !XdgPaths {
    const home = std.posix.getenv("HOME") orelse "/";

    // macOS uses ~/Library paths by default
    // But still respect XDG vars if set for compatibility
    const config_home = if (std.posix.getenv("XDG_CONFIG_HOME")) |ch|
        try allocator.dupe(u8, ch)
    else
        try std.fmt.allocPrint(allocator, "{s}/Library/Preferences", .{home});

    const data_home = if (std.posix.getenv("XDG_DATA_HOME")) |dh|
        try allocator.dupe(u8, dh)
    else
        try std.fmt.allocPrint(allocator, "{s}/Library/Application Support", .{home});

    const cache_home = if (std.posix.getenv("XDG_CACHE_HOME")) |ch|
        try allocator.dupe(u8, ch)
    else
        try std.fmt.allocPrint(allocator, "{s}/Library/Caches", .{home});

    // State goes to Application Support on macOS
    const state_home = if (std.posix.getenv("XDG_STATE_HOME")) |sh|
        try allocator.dupe(u8, sh)
    else
        try std.fmt.allocPrint(allocator, "{s}/Library/Application Support", .{home});

    const runtime_dir = std.posix.getenv("XDG_RUNTIME_DIR");

    return XdgPaths{
        .config_home = config_home,
        .data_home = data_home,
        .cache_home = cache_home,
        .state_home = state_home,
        .runtime_dir = runtime_dir,
        .config_dirs = &.{"/Library/Preferences"},
        .data_dirs = &.{"/Library/Application Support"},
        .allocator = allocator,
    };
}

/// Get Windows paths following Windows conventions
fn getWindowsPaths(allocator: std.mem.Allocator) !XdgPaths {
    // Windows uses environment variables for paths
    // APPDATA = C:\Users\<user>\AppData\Roaming
    // LOCALAPPDATA = C:\Users\<user>\AppData\Local
    // PROGRAMDATA = C:\ProgramData

    const appdata = std.posix.getenv("APPDATA") orelse
        std.posix.getenv("USERPROFILE") orelse "C:\\Users\\Default";
    const localappdata = std.posix.getenv("LOCALAPPDATA") orelse appdata;

    // Still respect XDG vars if set for cross-platform compatibility
    const config_home = if (std.posix.getenv("XDG_CONFIG_HOME")) |ch|
        try allocator.dupe(u8, ch)
    else
        try allocator.dupe(u8, appdata);

    const data_home = if (std.posix.getenv("XDG_DATA_HOME")) |dh|
        try allocator.dupe(u8, dh)
    else
        try allocator.dupe(u8, localappdata);

    const cache_home = if (std.posix.getenv("XDG_CACHE_HOME")) |ch|
        try allocator.dupe(u8, ch)
    else
        try std.fmt.allocPrint(allocator, "{s}\\cache", .{localappdata});

    const state_home = if (std.posix.getenv("XDG_STATE_HOME")) |sh|
        try allocator.dupe(u8, sh)
    else
        try allocator.dupe(u8, localappdata);

    const runtime_dir = std.posix.getenv("XDG_RUNTIME_DIR");

    // System config/data directories on Windows
    const programdata = std.posix.getenv("PROGRAMDATA") orelse "C:\\ProgramData";
    _ = programdata;

    return XdgPaths{
        .config_home = config_home,
        .data_home = data_home,
        .cache_home = cache_home,
        .state_home = state_home,
        .runtime_dir = runtime_dir,
        .config_dirs = &.{}, // Windows doesn't have standard system config dirs
        .data_dirs = &.{}, // Windows doesn't have standard system data dirs
        .allocator = allocator,
    };
}

/// Get the configuration directory for an application (platform-aware)
pub fn getConfigDir(allocator: std.mem.Allocator, app_name: []const u8) ![]const u8 {
    return getConfigDirForPlatform(allocator, app_name, Platform.current());
}

/// Get the configuration directory for a specific platform
pub fn getConfigDirForPlatform(allocator: std.mem.Allocator, app_name: []const u8, platform: Platform) ![]const u8 {
    // Always respect XDG_CONFIG_HOME if set
    if (std.posix.getenv("XDG_CONFIG_HOME")) |ch| {
        return try std.fmt.allocPrint(allocator, "{s}/{s}", .{ ch, app_name });
    }

    return switch (platform) {
        .linux, .other => {
            const home = std.posix.getenv("HOME") orelse "/";
            return try std.fmt.allocPrint(allocator, "{s}/.config/{s}", .{ home, app_name });
        },
        .macos => {
            const home = std.posix.getenv("HOME") orelse "/";
            return try std.fmt.allocPrint(allocator, "{s}/Library/Preferences/{s}", .{ home, app_name });
        },
        .windows => {
            const appdata = std.posix.getenv("APPDATA") orelse
                std.posix.getenv("USERPROFILE") orelse "C:\\Users\\Default";
            return try std.fmt.allocPrint(allocator, "{s}\\{s}", .{ appdata, app_name });
        },
    };
}

/// Get the data directory for an application (platform-aware)
pub fn getDataDir(allocator: std.mem.Allocator, app_name: []const u8) ![]const u8 {
    return getDataDirForPlatform(allocator, app_name, Platform.current());
}

/// Get the data directory for a specific platform
pub fn getDataDirForPlatform(allocator: std.mem.Allocator, app_name: []const u8, platform: Platform) ![]const u8 {
    // Always respect XDG_DATA_HOME if set
    if (std.posix.getenv("XDG_DATA_HOME")) |dh| {
        return try std.fmt.allocPrint(allocator, "{s}/{s}", .{ dh, app_name });
    }

    return switch (platform) {
        .linux, .other => {
            const home = std.posix.getenv("HOME") orelse "/";
            return try std.fmt.allocPrint(allocator, "{s}/.local/share/{s}", .{ home, app_name });
        },
        .macos => {
            const home = std.posix.getenv("HOME") orelse "/";
            return try std.fmt.allocPrint(allocator, "{s}/Library/Application Support/{s}", .{ home, app_name });
        },
        .windows => {
            const localappdata = std.posix.getenv("LOCALAPPDATA") orelse
                std.posix.getenv("APPDATA") orelse
                std.posix.getenv("USERPROFILE") orelse "C:\\Users\\Default";
            return try std.fmt.allocPrint(allocator, "{s}\\{s}", .{ localappdata, app_name });
        },
    };
}

/// Get the cache directory for an application (platform-aware)
pub fn getCacheDir(allocator: std.mem.Allocator, app_name: []const u8) ![]const u8 {
    return getCacheDirForPlatform(allocator, app_name, Platform.current());
}

/// Get the cache directory for a specific platform
pub fn getCacheDirForPlatform(allocator: std.mem.Allocator, app_name: []const u8, platform: Platform) ![]const u8 {
    // Always respect XDG_CACHE_HOME if set
    if (std.posix.getenv("XDG_CACHE_HOME")) |ch| {
        return try std.fmt.allocPrint(allocator, "{s}/{s}", .{ ch, app_name });
    }

    return switch (platform) {
        .linux, .other => {
            const home = std.posix.getenv("HOME") orelse "/";
            return try std.fmt.allocPrint(allocator, "{s}/.cache/{s}", .{ home, app_name });
        },
        .macos => {
            const home = std.posix.getenv("HOME") orelse "/";
            return try std.fmt.allocPrint(allocator, "{s}/Library/Caches/{s}", .{ home, app_name });
        },
        .windows => {
            const localappdata = std.posix.getenv("LOCALAPPDATA") orelse
                std.posix.getenv("APPDATA") orelse
                std.posix.getenv("USERPROFILE") orelse "C:\\Users\\Default";
            return try std.fmt.allocPrint(allocator, "{s}\\cache\\{s}", .{ localappdata, app_name });
        },
    };
}

/// Get the system configuration directory for an application (platform-aware)
pub fn getSystemConfigDir(app_name: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    return getSystemConfigDirForPlatform(app_name, allocator, Platform.current());
}

/// Get the system configuration directory for a specific platform
pub fn getSystemConfigDirForPlatform(app_name: []const u8, allocator: std.mem.Allocator, platform: Platform) ![]const u8 {
    return switch (platform) {
        .linux, .other => try std.fmt.allocPrint(allocator, "/etc/{s}", .{app_name}),
        .macos => try std.fmt.allocPrint(allocator, "/Library/Preferences/{s}", .{app_name}),
        .windows => {
            const programdata = std.posix.getenv("PROGRAMDATA") orelse "C:\\ProgramData";
            return try std.fmt.allocPrint(allocator, "{s}\\{s}", .{ programdata, app_name });
        },
    };
}

/// Get all configuration file paths in precedence order (user first)
pub fn getConfigFilePaths(
    allocator: std.mem.Allocator,
    app_name: []const u8,
    filename: []const u8,
) ![]const []const u8 {
    var paths = std.ArrayList([]const u8).init(allocator);

    // Project-level (current directory)
    const cwd_config = try std.fmt.allocPrint(allocator, "./{s}", .{filename});
    try paths.append(cwd_config);

    // User-level
    const user_config = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{
        std.posix.getenv("XDG_CONFIG_HOME") orelse "~/.config",
        app_name,
        filename,
    });
    try paths.append(user_config);

    // System-level
    const system_config = try std.fmt.allocPrint(allocator, "/etc/{s}/{s}", .{ app_name, filename });
    try paths.append(system_config);

    return paths.toOwnedSlice();
}

// ============================================================================
// Tests
// ============================================================================

test "getConfigDir" {
    const dir = try getConfigDir(std.testing.allocator, "testapp");
    defer std.testing.allocator.free(dir);

    // Should end with the app name
    try std.testing.expect(mem.endsWith(u8, dir, "testapp"));
}

test "getSystemConfigDir Linux" {
    const dir = try getSystemConfigDirForPlatform("testapp", std.testing.allocator, .linux);
    defer std.testing.allocator.free(dir);

    try std.testing.expectEqualStrings("/etc/testapp", dir);
}

test "getSystemConfigDir macOS" {
    const dir = try getSystemConfigDirForPlatform("testapp", std.testing.allocator, .macos);
    defer std.testing.allocator.free(dir);

    try std.testing.expectEqualStrings("/Library/Preferences/testapp", dir);
}

test "Platform.current returns valid platform" {
    const platform = Platform.current();
    try std.testing.expect(platform == .linux or platform == .macos or platform == .windows or platform == .other);
}

test "getConfigDirForPlatform Linux" {
    // Linux without XDG_CONFIG_HOME set uses ~/.config
    const dir = try getConfigDirForPlatform(std.testing.allocator, "myapp", .linux);
    defer std.testing.allocator.free(dir);

    try std.testing.expect(mem.endsWith(u8, dir, "myapp"));
    try std.testing.expect(mem.indexOf(u8, dir, ".config") != null or mem.indexOf(u8, dir, "XDG") != null);
}

test "getDataDirForPlatform Linux" {
    const dir = try getDataDirForPlatform(std.testing.allocator, "myapp", .linux);
    defer std.testing.allocator.free(dir);

    try std.testing.expect(mem.endsWith(u8, dir, "myapp"));
}

test "getCacheDirForPlatform Linux" {
    const dir = try getCacheDirForPlatform(std.testing.allocator, "myapp", .linux);
    defer std.testing.allocator.free(dir);

    try std.testing.expect(mem.endsWith(u8, dir, "myapp"));
}

test "getPathsForPlatform returns valid paths" {
    var paths = try getPathsForPlatform(std.testing.allocator, .linux);
    defer paths.deinit();

    try std.testing.expect(paths.config_home.len > 0);
    try std.testing.expect(paths.data_home.len > 0);
    try std.testing.expect(paths.cache_home.len > 0);
}

test "XdgPaths deinit frees memory" {
    var paths = try getPathsForPlatform(std.testing.allocator, .linux);
    paths.deinit();
    // If we get here without crash, deinit worked
}
