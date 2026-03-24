// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DNS Name Parsing Utilities for Security Modules
//!
//! Shared helper functions for parsing DNS names in wire format,
//! used by TSIG (RFC 2845) and SIG(0) (RFC 2931) modules.
//!
//! These functions parse DNS names into human-readable dotted strings
//! (e.g., "example.com") with compression pointer support, distinct
//! from the core Name.parse() which returns wire-format Name structs.

const std = @import("std");

/// Maximum compression pointer hops to prevent infinite loops (RFC 1035)
pub const max_compression_hops: u8 = 16;

/// Maximum DNS name length per RFC 1035 Section 2.3.4
pub const max_name_length: usize = 255;

/// Parse result containing the human-readable name and the offset after parsing
pub const ParseNameResult = struct {
    name: []const u8,
    offset: usize,
};

/// Parse a DNS name from wire format into a human-readable dotted string.
///
/// Handles compression pointers (RFC 1035 Section 4.1.4) with loop detection.
/// Returns an allocated string that the caller must free.
///
/// SECURITY: Limits compression pointer hops to prevent infinite loops
/// from maliciously crafted packets (CWE-835).
/// SECURITY: Enforces max_name_length (255 bytes) per RFC 1035 (CWE-130).
pub fn parseName(allocator: std.mem.Allocator, data: []const u8, start: usize) !ParseNameResult {
    var name_buf: std.ArrayList(u8) = .empty;
    errdefer name_buf.deinit(allocator);

    var offset = start;
    var followed_ptr = false;
    var final_offset = start;
    var pointer_hops: u8 = 0;
    var total_name_len: usize = 0;

    while (offset < data.len) {
        const len = data[offset];

        if (len == 0) {
            if (!followed_ptr) final_offset = offset + 1;
            break;
        }

        if (len & 0xC0 == 0xC0) {
            // Compression pointer - check for loop
            pointer_hops += 1;
            if (pointer_hops > max_compression_hops) {
                return error.CompressionLoopDetected;
            }
            if (offset + 1 >= data.len) return error.InvalidName;
            const ptr = (@as(u16, len & 0x3F) << 8) | data[offset + 1];
            if (!followed_ptr) final_offset = offset + 2;
            followed_ptr = true;
            offset = ptr;
            continue;
        }

        if (offset + 1 + len > data.len) return error.InvalidName;

        // Check max name length (length byte + label)
        total_name_len += 1 + len;
        if (total_name_len > max_name_length) {
            return error.NameTooLong;
        }

        if (name_buf.items.len > 0) {
            try name_buf.append(allocator, '.');
        }
        try name_buf.appendSlice(allocator, data[offset + 1 .. offset + 1 + len]);
        offset += 1 + len;
    }

    return .{
        .name = try name_buf.toOwnedSlice(allocator),
        .offset = final_offset,
    };
}

/// Skip over a DNS name in wire format without parsing it.
/// Returns the offset immediately after the name.
pub fn skipName(data: []const u8, start: usize) !usize {
    var offset = start;
    while (offset < data.len) {
        const len = data[offset];
        if (len == 0) return offset + 1;
        if (len & 0xC0 == 0xC0) return offset + 2;
        offset += 1 + len;
    }
    return error.InvalidName;
}

/// Skip over a DNS resource record in wire format.
/// Skips the name, type, class, TTL, and RDATA.
pub fn skipRR(data: []const u8, start: usize) !usize {
    const offset = try skipName(data, start);
    if (offset + 10 > data.len) return error.InvalidRR;
    const rdlength = std.mem.readInt(u16, data[offset + 8 ..][0..2], .big);
    return offset + 10 + rdlength;
}

/// Encode a DNS name in wire format (preserving case).
pub fn encodeName(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), name: []const u8) !void {
    var iter = std.mem.splitScalar(u8, name, '.');
    while (iter.next()) |label| {
        if (label.len == 0) continue;
        try buffer.append(allocator, @intCast(label.len));
        try buffer.appendSlice(allocator, label);
    }
    try buffer.append(allocator, 0);
}

/// Encode a DNS name in wire format, lowercasing all labels.
/// Used by TSIG for canonical name comparison (RFC 2845 Section 2.4).
pub fn encodeNameLower(allocator: std.mem.Allocator, buffer: *std.ArrayList(u8), name: []const u8) !void {
    var iter = std.mem.splitScalar(u8, name, '.');
    while (iter.next()) |label| {
        if (label.len == 0) continue;
        try buffer.append(allocator, @intCast(label.len));
        for (label) |c| {
            try buffer.append(allocator, std.ascii.toLower(c));
        }
    }
    try buffer.append(allocator, 0);
}

// ============================================================================
// Tests
// ============================================================================

test "parseName - simple name" {
    const allocator = std.testing.allocator;
    // Wire format for "example.com" = \x07example\x03com\x00
    const data = "\x07example\x03com\x00";
    const result = try parseName(allocator, data, 0);
    defer allocator.free(result.name);
    try std.testing.expectEqualStrings("example.com", result.name);
    try std.testing.expectEqual(@as(usize, 13), result.offset);
}

test "parseName - root name" {
    const allocator = std.testing.allocator;
    const data = "\x00";
    const result = try parseName(allocator, data, 0);
    defer allocator.free(result.name);
    try std.testing.expectEqualStrings("", result.name);
    try std.testing.expectEqual(@as(usize, 1), result.offset);
}

test "parseName - compression pointer" {
    const allocator = std.testing.allocator;
    // Wire: \x07example\x03com\x00 followed by pointer \xC0\x00
    const data = "\x07example\x03com\x00\xC0\x00";
    const result = try parseName(allocator, data, 13);
    defer allocator.free(result.name);
    try std.testing.expectEqualStrings("example.com", result.name);
    try std.testing.expectEqual(@as(usize, 15), result.offset);
}

test "skipName - simple name" {
    const data = "\x07example\x03com\x00extra";
    const offset = try skipName(data, 0);
    try std.testing.expectEqual(@as(usize, 13), offset);
}

test "skipName - compressed name" {
    const data = "\x07example\x03com\x00\xC0\x00extra";
    const offset = try skipName(data, 13);
    try std.testing.expectEqual(@as(usize, 15), offset);
}

test "skipRR - basic resource record" {
    // Name: root (\x00), then 10 bytes header (type, class, TTL, rdlength=0)
    const data = "\x00" ++ "\x00\x01" ++ "\x00\x01" ++ "\x00\x00\x00\x00" ++ "\x00\x00";
    const offset = try skipRR(data, 0);
    try std.testing.expectEqual(@as(usize, 11), offset);
}

test "encodeName - simple name" {
    const allocator = std.testing.allocator;
    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(allocator);
    try encodeName(allocator, &buffer, "example.com");
    try std.testing.expectEqualSlices(u8, "\x07example\x03com\x00", buffer.items);
}

test "encodeNameLower - lowercases labels" {
    const allocator = std.testing.allocator;
    var buffer: std.ArrayList(u8) = .empty;
    defer buffer.deinit(allocator);
    try encodeNameLower(allocator, &buffer, "EXAMPLE.COM");
    try std.testing.expectEqualSlices(u8, "\x07example\x03com\x00", buffer.items);
}
