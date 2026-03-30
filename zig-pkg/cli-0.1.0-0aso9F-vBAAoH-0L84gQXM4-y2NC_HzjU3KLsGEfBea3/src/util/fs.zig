// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Filesystem Module
//!
//! Filesystem utilities with security-conscious design.

const std = @import("std");
const fs = std.fs;
const mem = std.mem;

/// File operation errors
pub const FsError = error{
    NotFound,
    PermissionDenied,
    IoError,
    PathTooLong,
    InvalidPath,
};

/// Check if a path exists
pub fn exists(path: []const u8) bool {
    fs.cwd().access(path, .{}) catch return false;
    return true;
}

/// Check if path is a directory
pub fn isDirectory(path: []const u8) bool {
    const stat = fs.cwd().statFile(path) catch return false;
    return stat.kind == .directory;
}

/// Check if path is a regular file
pub fn isFile(path: []const u8) bool {
    const stat = fs.cwd().statFile(path) catch return false;
    return stat.kind == .file;
}

/// Read file contents with size limit
pub fn readFile(path: []const u8, allocator: std.mem.Allocator, max_size: usize) FsError![]const u8 {
    const file = fs.cwd().openFile(path, .{}) catch |err| {
        return switch (err) {
            error.FileNotFound => FsError.NotFound,
            error.AccessDenied => FsError.PermissionDenied,
            else => FsError.IoError,
        };
    };
    defer file.close();

    return file.readToEndAlloc(allocator, max_size) catch FsError.IoError;
}

/// Write file atomically (write to temp, then rename)
pub fn writeFileAtomic(path: []const u8, content: []const u8) FsError!void {
    const dir = fs.cwd();

    // Create temp file
    const temp_path = blk: {
        var buf: [std.fs.max_path_bytes]u8 = undefined;
        break :blk std.fmt.bufPrint(&buf, "{s}.tmp", .{path}) catch return FsError.PathTooLong;
    };

    // Write to temp file
    const temp_file = dir.createFile(temp_path, .{}) catch |err| {
        return switch (err) {
            error.AccessDenied => FsError.PermissionDenied,
            else => FsError.IoError,
        };
    };
    defer temp_file.close();

    temp_file.writeAll(content) catch return FsError.IoError;

    // Rename temp to target
    dir.rename(temp_path, path) catch return FsError.IoError;
}

/// Ensure a directory exists, creating it if necessary
pub fn ensureDir(path: []const u8) FsError!void {
    fs.cwd().makePath(path) catch |err| {
        return switch (err) {
            error.AccessDenied => FsError.PermissionDenied,
            else => FsError.IoError,
        };
    };
}

/// Get absolute path
pub fn absolutePath(relative: []const u8, allocator: std.mem.Allocator) FsError![]const u8 {
    return fs.cwd().realpathAlloc(allocator, relative) catch FsError.NotFound;
}

/// Redact path for error messages (hide sensitive parts)
pub fn redactPath(path: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    // Check for sensitive paths
    const sensitive_patterns = &.{
        "/etc/shadow",
        "/etc/passwd",
        ".ssh/",
        ".gnupg/",
        ".aws/",
        "credentials",
        "secrets",
        ".env",
    };

    for (sensitive_patterns) |pattern| {
        if (mem.indexOf(u8, path, pattern) != null) {
            return try std.fmt.allocPrint(allocator, "[REDACTED]/{s}", .{pattern});
        }
    }

    return path;
}

/// Check if a path is safe to read (not in sensitive locations)
pub fn isSafePath(path: []const u8) bool {
    const unsafe_prefixes: []const []const u8 = &.{
        "/etc/shadow",
        "/etc/sudoers",
    };

    for (unsafe_prefixes) |prefix| {
        if (mem.startsWith(u8, path, prefix)) {
            return false;
        }
    }

    return true;
}

/// Handle "-" as stdin/stdout
pub fn resolveStdio(path: []const u8) enum { stdin, stdout, path } {
    if (mem.eql(u8, path, "-")) {
        // Context determines stdin vs stdout
        return .stdin; // Caller should determine based on operation
    }
    return .path;
}

// ============================================================================
// Tests
// ============================================================================

test "exists" {
    // Current directory should exist
    try std.testing.expect(exists("."));
}

test "isDirectory" {
    try std.testing.expect(isDirectory("."));
}

test "isSafePath" {
    try std.testing.expect(isSafePath("/home/user/file.txt"));
    try std.testing.expect(!isSafePath("/etc/shadow"));
}

test "resolveStdio" {
    try std.testing.expectEqual(@as(@TypeOf(resolveStdio("-")), .stdin), resolveStdio("-"));
    try std.testing.expectEqual(@as(@TypeOf(resolveStdio("file.txt")), .path), resolveStdio("file.txt"));
}
