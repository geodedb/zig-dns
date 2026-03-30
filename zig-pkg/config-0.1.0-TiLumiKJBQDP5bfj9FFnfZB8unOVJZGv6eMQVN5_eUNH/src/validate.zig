// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Validation Module
//!
//! Configuration validation utilities.

const std = @import("std");
const mem = std.mem;

/// Validation errors
pub const ValidationError = error{
    /// Value is required but missing
    Required,
    /// Value is too short
    TooShort,
    /// Value is too long
    TooLong,
    /// Value is not in allowed range
    OutOfRange,
    /// Value does not match pattern
    PatternMismatch,
    /// Value is not in allowed set
    NotInSet,
    /// Custom validation failed
    CustomFailed,
};

/// Validation result
pub const ValidationResult = struct {
    valid: bool,
    errors: []const []const u8,

    pub fn ok() ValidationResult {
        return .{ .valid = true, .errors = &.{} };
    }

    pub fn fail(errors: []const []const u8) ValidationResult {
        return .{ .valid = false, .errors = errors };
    }
};

/// Validate that a string is not empty
pub fn required(value: ?[]const u8) ValidationError!void {
    if (value == null or value.?.len == 0) {
        return ValidationError.Required;
    }
}

/// Validate string minimum length
pub fn minLength(value: []const u8, min: usize) ValidationError!void {
    if (value.len < min) {
        return ValidationError.TooShort;
    }
}

/// Validate string maximum length
pub fn maxLength(value: []const u8, max: usize) ValidationError!void {
    if (value.len > max) {
        return ValidationError.TooLong;
    }
}

/// Validate integer range
pub fn intRange(value: i64, min: i64, max: i64) ValidationError!void {
    if (value < min or value > max) {
        return ValidationError.OutOfRange;
    }
}

/// Validate value is in allowed set
pub fn oneOf(value: []const u8, allowed: []const []const u8) ValidationError!void {
    for (allowed) |a| {
        if (mem.eql(u8, value, a)) {
            return;
        }
    }
    return ValidationError.NotInSet;
}

/// Validate port number
pub fn port(value: u16) ValidationError!void {
    if (value == 0) {
        return ValidationError.OutOfRange;
    }
}

/// Validate hostname
pub fn hostname(value: []const u8) ValidationError!void {
    if (value.len == 0 or value.len > 253) {
        return ValidationError.TooLong;
    }

    // Basic hostname validation
    for (value) |c| {
        if (!std.ascii.isAlphanumeric(c) and c != '.' and c != '-') {
            return ValidationError.PatternMismatch;
        }
    }
}

/// Validate URL
pub fn url(value: []const u8) ValidationError!void {
    if (!mem.startsWith(u8, value, "http://") and !mem.startsWith(u8, value, "https://")) {
        return ValidationError.PatternMismatch;
    }
}

/// Validate email address (basic)
pub fn email(value: []const u8) ValidationError!void {
    if (mem.indexOf(u8, value, "@") == null) {
        return ValidationError.PatternMismatch;
    }
}

/// Validate file path exists
pub fn pathExists(path: []const u8) ValidationError!void {
    std.fs.cwd().access(path, .{}) catch {
        return ValidationError.CustomFailed;
    };
}

// ============================================================================
// Tests
// ============================================================================

test "required validation" {
    try required("value");
    try std.testing.expectError(ValidationError.Required, required(null));
    try std.testing.expectError(ValidationError.Required, required(""));
}

test "minLength validation" {
    try minLength("hello", 3);
    try std.testing.expectError(ValidationError.TooShort, minLength("hi", 3));
}

test "maxLength validation" {
    try maxLength("hi", 5);
    try std.testing.expectError(ValidationError.TooLong, maxLength("hello world", 5));
}

test "intRange validation" {
    try intRange(50, 0, 100);
    try std.testing.expectError(ValidationError.OutOfRange, intRange(-1, 0, 100));
    try std.testing.expectError(ValidationError.OutOfRange, intRange(101, 0, 100));
}

test "oneOf validation" {
    try oneOf("debug", &.{ "debug", "info", "warn", "error" });
    try std.testing.expectError(ValidationError.NotInSet, oneOf("trace", &.{ "debug", "info", "warn", "error" }));
}

test "url validation" {
    try url("https://example.com");
    try url("http://localhost:8080");
    try std.testing.expectError(ValidationError.PatternMismatch, url("ftp://example.com"));
}
