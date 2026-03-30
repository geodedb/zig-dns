// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! # Configuration Validation Module
//!
//! Provides validation utilities for configuration values including:
//! - Regex pattern validation (#10)
//! - Custom validation functions (#11)
//! - Common validators (email, URL, IP, etc.)
//!
//! Example usage:
//! ```zig
//! const validation = @import("validation");
//!
//! var validator = validation.Validator.init(allocator);
//! defer validator.deinit();
//!
//! // Add regex pattern validation
//! try validator.pattern("email", "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
//!
//! // Add custom validation function
//! try validator.custom("port", struct {
//!     fn validate(value: []const u8) bool {
//!         const port = std.fmt.parseInt(u16, value, 10) catch return false;
//!         return port >= 1 and port <= 65535;
//!     }
//! }.validate);
//!
//! // Validate a value
//! const result = validator.validate("email", "test@example.com");
//! ```

const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

/// Validation errors
pub const ValidationError = error{
    InvalidPattern,
    ValidationFailed,
    UnknownField,
    OutOfMemory,
};

/// Result of a validation check
pub const ValidationResult = struct {
    valid: bool,
    field: []const u8,
    message: ?[]const u8,

    pub fn ok(field: []const u8) ValidationResult {
        return .{ .valid = true, .field = field, .message = null };
    }

    pub fn fail(field: []const u8, message: []const u8) ValidationResult {
        return .{ .valid = false, .field = field, .message = message };
    }
};

/// Custom validation function type
pub const ValidatorFn = *const fn (value: []const u8) bool;

/// Custom validation function with context
pub const ValidatorWithContextFn = *const fn (value: []const u8, context: ?*anyopaque) bool;

/// Rule type enum
const RuleType = enum {
    pattern,
    custom,
    custom_with_context,
    range,
    length,
    one_of,
    required,
};

/// Validation rule
const ValidationRule = struct {
    field: []const u8,
    rule_type: RuleType,
    /// Pattern string for regex validation (simplified pattern matching)
    pattern: ?[]const u8 = null,
    /// Custom validation function
    custom_fn: ?ValidatorFn = null,
    /// Custom validation function with context
    custom_with_context_fn: ?ValidatorWithContextFn = null,
    /// Context for custom_with_context_fn
    context: ?*anyopaque = null,
    /// Min value for range validation
    min: ?i64 = null,
    /// Max value for range validation
    max: ?i64 = null,
    /// Min length for length validation
    min_len: ?usize = null,
    /// Max length for length validation
    max_len: ?usize = null,
    /// Allowed values for one_of validation
    allowed_values: ?[]const []const u8 = null,
    /// Error message
    message: []const u8 = "Validation failed",
};

/// Configuration validator with support for patterns and custom functions
pub const Validator = struct {
    allocator: Allocator,
    rules: std.ArrayListUnmanaged(ValidationRule),
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: Allocator) Validator {
        return .{
            .allocator = allocator,
            .rules = .{},
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *Validator) void {
        self.rules.deinit(self.allocator);
        self.arena.deinit();
    }

    /// Add a regex pattern validation rule
    /// Note: This uses simplified pattern matching, not full regex
    pub fn pattern(self: *Validator, field: []const u8, pat: []const u8) !void {
        try self.patternWithMessage(field, pat, "Value does not match required pattern");
    }

    /// Add a regex pattern validation rule with custom message
    pub fn patternWithMessage(self: *Validator, field: []const u8, pat: []const u8, message: []const u8) !void {
        const owned_field = try self.arena.allocator().dupe(u8, field);
        const owned_pattern = try self.arena.allocator().dupe(u8, pat);
        const owned_message = try self.arena.allocator().dupe(u8, message);

        try self.rules.append(self.allocator, .{
            .field = owned_field,
            .rule_type = .pattern,
            .pattern = owned_pattern,
            .message = owned_message,
        });
    }

    /// Add a custom validation function
    pub fn custom(self: *Validator, field: []const u8, validator_fn: ValidatorFn) !void {
        try self.customWithMessage(field, validator_fn, "Custom validation failed");
    }

    /// Add a custom validation function with message
    pub fn customWithMessage(self: *Validator, field: []const u8, validator_fn: ValidatorFn, message: []const u8) !void {
        const owned_field = try self.arena.allocator().dupe(u8, field);
        const owned_message = try self.arena.allocator().dupe(u8, message);

        try self.rules.append(self.allocator, .{
            .field = owned_field,
            .rule_type = .custom,
            .custom_fn = validator_fn,
            .message = owned_message,
        });
    }

    /// Add a custom validation function with context
    pub fn customWithContext(self: *Validator, field: []const u8, validator_fn: ValidatorWithContextFn, context: ?*anyopaque) !void {
        try self.customWithContextAndMessage(field, validator_fn, context, "Custom validation failed");
    }

    /// Add a custom validation function with context and message
    pub fn customWithContextAndMessage(self: *Validator, field: []const u8, validator_fn: ValidatorWithContextFn, context: ?*anyopaque, message: []const u8) !void {
        const owned_field = try self.arena.allocator().dupe(u8, field);
        const owned_message = try self.arena.allocator().dupe(u8, message);

        try self.rules.append(self.allocator, .{
            .field = owned_field,
            .rule_type = .custom_with_context,
            .custom_with_context_fn = validator_fn,
            .context = context,
            .message = owned_message,
        });
    }

    /// Add a numeric range validation rule
    pub fn range(self: *Validator, field: []const u8, min: ?i64, max: ?i64) !void {
        const owned_field = try self.arena.allocator().dupe(u8, field);

        try self.rules.append(self.allocator, .{
            .field = owned_field,
            .rule_type = .range,
            .min = min,
            .max = max,
            .message = "Value out of range",
        });
    }

    /// Add a string length validation rule
    pub fn length(self: *Validator, field: []const u8, min_len: ?usize, max_len: ?usize) !void {
        const owned_field = try self.arena.allocator().dupe(u8, field);

        try self.rules.append(self.allocator, .{
            .field = owned_field,
            .rule_type = .length,
            .min_len = min_len,
            .max_len = max_len,
            .message = "Invalid length",
        });
    }

    /// Add an enumeration validation rule (value must be one of the allowed values)
    pub fn oneOf(self: *Validator, field: []const u8, allowed: []const []const u8) !void {
        const owned_field = try self.arena.allocator().dupe(u8, field);
        const owned_allowed = try self.arena.allocator().alloc([]const u8, allowed.len);
        for (allowed, 0..) |val, i| {
            owned_allowed[i] = try self.arena.allocator().dupe(u8, val);
        }

        try self.rules.append(self.allocator, .{
            .field = owned_field,
            .rule_type = .one_of,
            .allowed_values = owned_allowed,
            .message = "Value not in allowed set",
        });
    }

    /// Add a required field validation rule
    pub fn required(self: *Validator, field: []const u8) !void {
        const owned_field = try self.arena.allocator().dupe(u8, field);

        try self.rules.append(self.allocator, .{
            .field = owned_field,
            .rule_type = .required,
            .message = "Field is required",
        });
    }

    /// Validate a single field value
    pub fn validate(self: *const Validator, field: []const u8, value: []const u8) ValidationResult {
        for (self.rules.items) |rule| {
            if (mem.eql(u8, rule.field, field)) {
                if (!self.checkRule(&rule, value)) {
                    return ValidationResult.fail(field, rule.message);
                }
            }
        }
        return ValidationResult.ok(field);
    }

    /// Validate all fields in a map
    pub fn validateAll(self: *const Validator, values: std.StringHashMap([]const u8)) ![]ValidationResult {
        var results: std.ArrayListUnmanaged(ValidationResult) = .{};
        errdefer results.deinit(self.allocator);

        // Check each rule
        for (self.rules.items) |rule| {
            if (rule.rule_type == .required) {
                if (values.get(rule.field) == null) {
                    try results.append(self.allocator, ValidationResult.fail(rule.field, rule.message));
                    continue;
                }
            }

            if (values.get(rule.field)) |value| {
                if (!self.checkRule(&rule, value)) {
                    try results.append(self.allocator, ValidationResult.fail(rule.field, rule.message));
                }
            }
        }

        return results.toOwnedSlice(self.allocator);
    }

    /// Check if all validations pass
    pub fn isValid(self: *const Validator, values: std.StringHashMap([]const u8)) bool {
        for (self.rules.items) |rule| {
            if (rule.rule_type == .required) {
                if (values.get(rule.field) == null) {
                    return false;
                }
            }

            if (values.get(rule.field)) |value| {
                if (!self.checkRule(&rule, value)) {
                    return false;
                }
            }
        }
        return true;
    }

    fn checkRule(self: *const Validator, rule: *const ValidationRule, value: []const u8) bool {
        _ = self;
        switch (rule.rule_type) {
            .pattern => {
                if (rule.pattern) |pat| {
                    return matchPattern(pat, value);
                }
                return true;
            },
            .custom => {
                if (rule.custom_fn) |func| {
                    return func(value);
                }
                return true;
            },
            .custom_with_context => {
                if (rule.custom_with_context_fn) |func| {
                    return func(value, rule.context);
                }
                return true;
            },
            .range => {
                const num = std.fmt.parseInt(i64, value, 10) catch return false;
                if (rule.min) |min| {
                    if (num < min) return false;
                }
                if (rule.max) |max| {
                    if (num > max) return false;
                }
                return true;
            },
            .length => {
                if (rule.min_len) |min| {
                    if (value.len < min) return false;
                }
                if (rule.max_len) |max| {
                    if (value.len > max) return false;
                }
                return true;
            },
            .one_of => {
                if (rule.allowed_values) |allowed| {
                    for (allowed) |allowed_value| {
                        if (mem.eql(u8, value, allowed_value)) return true;
                    }
                    return false;
                }
                return true;
            },
            .required => {
                return value.len > 0;
            },
        }
    }
};

/// Simplified pattern matching (not full regex, but covers common cases)
/// Supports:
/// - ^ (start anchor)
/// - $ (end anchor)
/// - . (any single char)
/// - * (zero or more of previous)
/// - + (one or more of previous)
/// - ? (zero or one of previous)
/// - [...] (character class)
/// - [^...] (negated character class)
/// - \d (digit)
/// - \w (word char)
/// - \s (whitespace)
pub fn matchPattern(pattern: []const u8, input: []const u8) bool {
    return matchPatternImpl(pattern, input, 0, 0);
}

fn matchPatternImpl(pattern: []const u8, input: []const u8, pat_idx: usize, input_idx: usize) bool {
    var pi = pat_idx;
    var ii = input_idx;

    while (pi < pattern.len) {
        // Check for end anchor
        if (pattern[pi] == '$') {
            if (pi + 1 == pattern.len) {
                return ii == input.len;
            }
            pi += 1;
            continue;
        }

        // Check for start anchor (only valid at beginning)
        if (pattern[pi] == '^') {
            if (pi == 0 and ii != 0) return false;
            pi += 1;
            continue;
        }

        // Handle character class with quantifier
        if (pattern[pi] == '[') {
            const class_end = findClassEnd(pattern[pi..]);
            if (class_end == null) return false;

            const class_end_idx = pi + class_end.?;
            const has_star = (class_end_idx + 1 < pattern.len and pattern[class_end_idx + 1] == '*');
            const has_plus = (class_end_idx + 1 < pattern.len and pattern[class_end_idx + 1] == '+');
            const has_question = (class_end_idx + 1 < pattern.len and pattern[class_end_idx + 1] == '?');

            const negated = pattern[pi + 1] == '^';
            const class_start = if (negated) pi + 2 else pi + 1;
            const class_content = pattern[class_start..class_end_idx];

            if (has_plus) {
                // One or more of char class
                if (ii >= input.len) return false;
                const first_matches = matchCharClass(class_content, input[ii]);
                if (negated) {
                    if (first_matches) return false;
                } else {
                    if (!first_matches) return false;
                }
                ii += 1;

                // Match more
                while (ii < input.len) {
                    const next_matches = matchCharClass(class_content, input[ii]);
                    const should_match = if (negated) !next_matches else next_matches;
                    if (!should_match) break;
                    ii += 1;
                }
                pi = class_end_idx + 2;
                continue;
            }

            if (has_star) {
                // Zero or more of char class
                const next_pi = class_end_idx + 2;
                // Try zero matches
                if (matchPatternImpl(pattern, input, next_pi, ii)) return true;
                // Try more
                while (ii < input.len) {
                    const next_matches = matchCharClass(class_content, input[ii]);
                    const should_match = if (negated) !next_matches else next_matches;
                    if (!should_match) break;
                    ii += 1;
                    if (matchPatternImpl(pattern, input, next_pi, ii)) return true;
                }
                return false;
            }

            if (has_question) {
                const next_pi = class_end_idx + 2;
                if (matchPatternImpl(pattern, input, next_pi, ii)) return true;
                if (ii < input.len) {
                    const next_matches = matchCharClass(class_content, input[ii]);
                    const should_match = if (negated) !next_matches else next_matches;
                    if (should_match) return matchPatternImpl(pattern, input, next_pi, ii + 1);
                }
                return false;
            }

            // No quantifier - single match
            if (ii >= input.len) return false;
            const matches = matchCharClass(class_content, input[ii]);
            if (negated) {
                if (matches) return false;
            } else {
                if (!matches) return false;
            }
            pi = class_end_idx + 1;
            ii += 1;
            continue;
        }

        // Check for quantifiers on next position
        const has_star = (pi + 1 < pattern.len and pattern[pi + 1] == '*');
        const has_plus = (pi + 1 < pattern.len and pattern[pi + 1] == '+');
        const has_question = (pi + 1 < pattern.len and pattern[pi + 1] == '?');

        if (has_star) {
            // Zero or more - try matching zero first, then more
            const char_or_class = pattern[pi];
            pi += 2; // Skip char and *

            // Try matching zero occurrences first
            if (matchPatternImpl(pattern, input, pi, ii)) {
                return true;
            }

            // Try matching one or more
            while (ii < input.len and matchSingleChar(char_or_class, pattern, pat_idx, input[ii])) {
                ii += 1;
                if (matchPatternImpl(pattern, input, pi, ii)) {
                    return true;
                }
            }
            return false;
        }

        if (has_plus) {
            // One or more
            const char_or_class = pattern[pi];
            pi += 2; // Skip char and +

            // Must match at least once
            if (ii >= input.len or !matchSingleChar(char_or_class, pattern, pat_idx, input[ii])) {
                return false;
            }
            ii += 1;

            // Try matching more
            while (ii < input.len and matchSingleChar(char_or_class, pattern, pat_idx, input[ii])) {
                ii += 1;
                if (matchPatternImpl(pattern, input, pi, ii)) {
                    return true;
                }
            }
            return matchPatternImpl(pattern, input, pi, ii);
        }

        if (has_question) {
            // Zero or one
            const char_or_class = pattern[pi];
            pi += 2; // Skip char and ?

            // Try matching zero
            if (matchPatternImpl(pattern, input, pi, ii)) {
                return true;
            }

            // Try matching one
            if (ii < input.len and matchSingleChar(char_or_class, pattern, pat_idx, input[ii])) {
                return matchPatternImpl(pattern, input, pi, ii + 1);
            }
            return false;
        }

        // Escape sequences
        if (pattern[pi] == '\\' and pi + 1 < pattern.len) {
            if (ii >= input.len) return false;

            const escape_char = pattern[pi + 1];
            const matches = switch (escape_char) {
                'd' => std.ascii.isDigit(input[ii]),
                'w' => std.ascii.isAlphanumeric(input[ii]) or input[ii] == '_',
                's' => std.ascii.isWhitespace(input[ii]),
                'D' => !std.ascii.isDigit(input[ii]),
                'W' => !(std.ascii.isAlphanumeric(input[ii]) or input[ii] == '_'),
                'S' => !std.ascii.isWhitespace(input[ii]),
                else => input[ii] == escape_char,
            };

            if (!matches) return false;
            pi += 2;
            ii += 1;
            continue;
        }

        // Dot matches any character
        if (pattern[pi] == '.') {
            if (ii >= input.len) return false;
            pi += 1;
            ii += 1;
            continue;
        }

        // Literal character match
        if (ii >= input.len) return false;
        if (pattern[pi] != input[ii]) return false;
        pi += 1;
        ii += 1;
    }

    // Pattern exhausted - check if input is also exhausted
    return ii == input.len;
}

fn matchSingleChar(pattern_char: u8, pattern: []const u8, pattern_start: usize, input_char: u8) bool {
    _ = pattern;
    _ = pattern_start;

    if (pattern_char == '.') return true;

    // Handle escape sequences
    if (pattern_char == '\\') {
        // This is simplified - full implementation would look ahead in pattern
        return false;
    }

    return pattern_char == input_char;
}

fn findClassEnd(pattern: []const u8) ?usize {
    if (pattern.len == 0 or pattern[0] != '[') return null;

    var i: usize = 1;
    while (i < pattern.len) {
        if (pattern[i] == ']' and i > 1) {
            return i;
        }
        i += 1;
    }
    return null;
}

fn matchCharClass(class: []const u8, char: u8) bool {
    var i: usize = 0;
    while (i < class.len) {
        // Range a-z
        if (i + 2 < class.len and class[i + 1] == '-') {
            if (char >= class[i] and char <= class[i + 2]) {
                return true;
            }
            i += 3;
            continue;
        }

        // Single character
        if (class[i] == char) {
            return true;
        }
        i += 1;
    }
    return false;
}

// ============================================================================
// Common Pre-built Validators
// ============================================================================

/// Validates that a string looks like an email address
pub fn isEmail(value: []const u8) bool {
    // Simple email validation: something@something.something
    const at_pos = mem.indexOf(u8, value, "@") orelse return false;
    if (at_pos == 0 or at_pos >= value.len - 1) return false;

    const domain = value[at_pos + 1 ..];
    const dot_pos = mem.indexOf(u8, domain, ".") orelse return false;
    if (dot_pos == 0 or dot_pos >= domain.len - 1) return false;

    return true;
}

/// Validates that a string is a valid URL
pub fn isUrl(value: []const u8) bool {
    return mem.startsWith(u8, value, "http://") or
        mem.startsWith(u8, value, "https://") or
        mem.startsWith(u8, value, "ftp://");
}

/// Validates that a string is a valid IPv4 address
pub fn isIPv4(value: []const u8) bool {
    var parts: usize = 0;
    var current: u32 = 0;
    var digits: u8 = 0;

    for (value) |c| {
        if (c == '.') {
            if (digits == 0 or current > 255) return false;
            parts += 1;
            current = 0;
            digits = 0;
        } else if (std.ascii.isDigit(c)) {
            current = current * 10 + (c - '0');
            digits += 1;
            if (digits > 3) return false;
        } else {
            return false;
        }
    }

    // Check last part
    if (digits == 0 or current > 255) return false;
    parts += 1;

    return parts == 4;
}

/// Validates that a string is a valid port number (1-65535)
pub fn isPort(value: []const u8) bool {
    const port = std.fmt.parseInt(u16, value, 10) catch return false;
    return port >= 1;
}

/// Validates that a string contains only alphanumeric characters
pub fn isAlphanumeric(value: []const u8) bool {
    for (value) |c| {
        if (!std.ascii.isAlphanumeric(c)) return false;
    }
    return value.len > 0;
}

/// Validates that a string is a valid hostname
pub fn isHostname(value: []const u8) bool {
    if (value.len == 0 or value.len > 253) return false;

    // Hostname cannot start with a dash
    if (value[0] == '-') return false;

    var label_len: usize = 0;
    var prev_char: u8 = 0;
    for (value) |c| {
        if (c == '.') {
            // Label cannot be empty or end with dash
            if (label_len == 0 or label_len > 63 or prev_char == '-') return false;
            label_len = 0;
        } else if (std.ascii.isAlphanumeric(c) or c == '-') {
            // Label cannot start with dash
            if (label_len == 0 and c == '-') return false;
            label_len += 1;
        } else {
            return false;
        }
        prev_char = c;
    }

    // Last label cannot be empty or end with dash
    if (label_len == 0 or label_len > 63 or prev_char == '-') return false;

    return true;
}

/// Validates that a string is not empty
pub fn notEmpty(value: []const u8) bool {
    return value.len > 0;
}

/// Validates that a string is a valid boolean representation
pub fn isBool(value: []const u8) bool {
    return mem.eql(u8, value, "true") or
        mem.eql(u8, value, "false") or
        mem.eql(u8, value, "1") or
        mem.eql(u8, value, "0") or
        mem.eql(u8, value, "yes") or
        mem.eql(u8, value, "no");
}

// ============================================================================
// Tests
// ============================================================================

test "Validator custom function" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    // Add a custom port validator
    try validator.custom("port", isPort);

    const valid_result = validator.validate("port", "8080");
    try std.testing.expect(valid_result.valid);

    const invalid_result = validator.validate("port", "invalid");
    try std.testing.expect(!invalid_result.valid);
}

test "Validator range validation" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    try validator.range("age", 0, 150);

    try std.testing.expect(validator.validate("age", "25").valid);
    try std.testing.expect(validator.validate("age", "0").valid);
    try std.testing.expect(validator.validate("age", "150").valid);
    try std.testing.expect(!validator.validate("age", "-1").valid);
    try std.testing.expect(!validator.validate("age", "151").valid);
}

test "Validator length validation" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    try validator.length("username", 3, 20);

    try std.testing.expect(validator.validate("username", "john").valid);
    try std.testing.expect(!validator.validate("username", "ab").valid);
    try std.testing.expect(!validator.validate("username", "thisusernameiswaytoolong").valid);
}

test "Validator oneOf validation" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    try validator.oneOf("env", &.{ "development", "staging", "production" });

    try std.testing.expect(validator.validate("env", "development").valid);
    try std.testing.expect(validator.validate("env", "production").valid);
    try std.testing.expect(!validator.validate("env", "invalid").valid);
}

test "Validator required validation" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    try validator.required("name");

    var values = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer values.deinit();

    // Missing required field
    try std.testing.expect(!validator.isValid(values));

    // Empty required field
    try values.put("name", "");
    try std.testing.expect(!validator.isValid(values));

    // Valid required field
    try values.put("name", "John");
    try std.testing.expect(validator.isValid(values));
}

test "matchPattern basic" {
    // Literal matching
    try std.testing.expect(matchPattern("hello", "hello"));
    try std.testing.expect(!matchPattern("hello", "world"));

    // Any character
    try std.testing.expect(matchPattern("h.llo", "hello"));
    try std.testing.expect(matchPattern("h.llo", "hallo"));

    // Anchors
    try std.testing.expect(matchPattern("^hello", "hello"));
    try std.testing.expect(!matchPattern("^hello", "say hello"));
    try std.testing.expect(matchPattern("hello$", "hello"));
    try std.testing.expect(!matchPattern("hello$", "hello world"));
}

test "matchPattern character classes" {
    try std.testing.expect(matchPattern("[abc]", "a"));
    try std.testing.expect(matchPattern("[abc]", "b"));
    try std.testing.expect(!matchPattern("[abc]", "d"));

    // Ranges
    try std.testing.expect(matchPattern("[a-z]", "m"));
    try std.testing.expect(!matchPattern("[a-z]", "5"));
    try std.testing.expect(matchPattern("[0-9]", "5"));
}

test "matchPattern escape sequences" {
    try std.testing.expect(matchPattern("\\d", "5"));
    try std.testing.expect(!matchPattern("\\d", "a"));
    try std.testing.expect(matchPattern("\\w", "a"));
    try std.testing.expect(matchPattern("\\w", "5"));
    try std.testing.expect(matchPattern("\\w", "_"));
}

test "matchPattern quantifiers" {
    // Star (zero or more)
    try std.testing.expect(matchPattern("ab*c", "ac"));
    try std.testing.expect(matchPattern("ab*c", "abc"));
    try std.testing.expect(matchPattern("ab*c", "abbc"));

    // Plus (one or more)
    try std.testing.expect(!matchPattern("ab+c", "ac"));
    try std.testing.expect(matchPattern("ab+c", "abc"));
    try std.testing.expect(matchPattern("ab+c", "abbc"));

    // Question (zero or one)
    try std.testing.expect(matchPattern("ab?c", "ac"));
    try std.testing.expect(matchPattern("ab?c", "abc"));
    try std.testing.expect(!matchPattern("ab?c", "abbc"));
}

test "isEmail" {
    try std.testing.expect(isEmail("test@example.com"));
    try std.testing.expect(isEmail("user.name@domain.org"));
    try std.testing.expect(!isEmail("invalid"));
    try std.testing.expect(!isEmail("@example.com"));
    try std.testing.expect(!isEmail("test@"));
}

test "isUrl" {
    try std.testing.expect(isUrl("http://example.com"));
    try std.testing.expect(isUrl("https://example.com/path"));
    try std.testing.expect(isUrl("ftp://files.example.com"));
    try std.testing.expect(!isUrl("example.com"));
    try std.testing.expect(!isUrl("invalid-url"));
}

test "isIPv4" {
    try std.testing.expect(isIPv4("192.168.1.1"));
    try std.testing.expect(isIPv4("0.0.0.0"));
    try std.testing.expect(isIPv4("255.255.255.255"));
    try std.testing.expect(!isIPv4("256.1.1.1"));
    try std.testing.expect(!isIPv4("1.2.3"));
    try std.testing.expect(!isIPv4("invalid"));
}

test "isPort" {
    try std.testing.expect(isPort("80"));
    try std.testing.expect(isPort("443"));
    try std.testing.expect(isPort("8080"));
    try std.testing.expect(isPort("65535"));
    try std.testing.expect(!isPort("0"));
    try std.testing.expect(!isPort("65536"));
    try std.testing.expect(!isPort("invalid"));
}

test "isHostname" {
    try std.testing.expect(isHostname("example.com"));
    try std.testing.expect(isHostname("sub.example.com"));
    try std.testing.expect(isHostname("localhost"));
    try std.testing.expect(!isHostname(""));
    try std.testing.expect(!isHostname("-invalid.com"));
}

test "Validator validateAll" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    try validator.custom("email", isEmail);
    try validator.custom("port", isPort);
    try validator.range("age", 0, 150);

    var values = std.StringHashMap([]const u8).init(std.testing.allocator);
    defer values.deinit();

    try values.put("email", "invalid");
    try values.put("port", "abc");
    try values.put("age", "200");

    const results = try validator.validateAll(values);
    defer std.testing.allocator.free(results);

    // All three should fail
    try std.testing.expectEqual(@as(usize, 3), results.len);
}

test "Validator pattern validation" {
    var validator = Validator.init(std.testing.allocator);
    defer validator.deinit();

    try validator.pattern("code", "^[A-Z][0-9]+$");

    try std.testing.expect(validator.validate("code", "A123").valid);
    try std.testing.expect(validator.validate("code", "Z9").valid);
    try std.testing.expect(!validator.validate("code", "123").valid);
    try std.testing.expect(!validator.validate("code", "abc").valid);
}
