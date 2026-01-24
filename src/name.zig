// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DNS Name Handling
//!
//! RFC 1035 Section 3.1: Name Space Definitions
//! RFC 1035 Section 4.1.4: Message Compression

const std = @import("std");

/// Maximum DNS name length (RFC 1035 Section 2.3.4)
pub const max_name_length = 255;

/// Maximum DNS label length (RFC 1035 Section 2.3.4)
pub const max_label_length = 63;

/// Compression pointer marker (RFC 1035 Section 4.1.4)
const compression_marker: u8 = 0xC0;

/// DNS Name representation
/// Handles both uncompressed and compressed (pointer) formats
pub const Name = struct {
    /// Raw label data (length-prefixed labels ending with 0)
    labels: []const u8,

    /// Total length of the name in wire format
    wire_length: usize,

    /// Whether this name was compressed (contained pointers)
    compressed: bool = false,

    const Self = @This();

    /// Parse a DNS name from wire format
    /// Handles compression pointers (RFC 1035 Section 4.1.4)
    pub fn parse(data: []const u8, offset: usize) !Self {
        if (offset >= data.len) {
            return error.InvalidOffset;
        }

        var pos = offset;
        var wire_len: usize = 0;
        var compressed = false;
        var first_pointer_pos: ?usize = null;

        // Follow the name, handling compression
        while (pos < data.len) {
            const len_byte = data[pos];

            // Check for end of name
            if (len_byte == 0) {
                if (first_pointer_pos == null) {
                    wire_len += 1; // Include the null terminator
                }
                break;
            }

            // Check for compression pointer
            if ((len_byte & compression_marker) == compression_marker) {
                if (pos + 1 >= data.len) {
                    return error.InvalidCompression;
                }

                compressed = true;
                if (first_pointer_pos == null) {
                    first_pointer_pos = pos;
                    wire_len += 2; // Pointer is 2 bytes
                }

                // Calculate pointer offset
                const ptr_offset = (@as(u16, len_byte & 0x3F) << 8) | data[pos + 1];
                if (ptr_offset >= pos) {
                    return error.ForwardPointer;
                }
                pos = ptr_offset;
                continue;
            }

            // Regular label
            const label_len = len_byte;
            if (label_len > max_label_length) {
                return error.LabelTooLong;
            }

            if (pos + 1 + label_len > data.len) {
                return error.UnexpectedEnd;
            }

            if (first_pointer_pos == null) {
                wire_len += 1 + label_len; // Length byte + label data
            }

            pos += 1 + label_len;
        }

        const end_offset = if (first_pointer_pos) |p| p + 2 else offset + wire_len;

        return Self{
            .labels = data[offset..end_offset],
            .wire_length = wire_len,
            .compressed = compressed,
        };
    }

    /// Encode a name from a string (e.g., "example.com") to wire format
    pub fn encode(allocator: std.mem.Allocator, domain: []const u8) ![]u8 {
        if (domain.len > max_name_length) {
            return error.NameTooLong;
        }

        // Handle root domain
        if (domain.len == 0 or (domain.len == 1 and domain[0] == '.')) {
            const result = try allocator.alloc(u8, 1);
            result[0] = 0;
            return result;
        }

        // Count required size
        var size: usize = 1; // Null terminator
        var iter = std.mem.splitScalar(u8, domain, '.');
        while (iter.next()) |label| {
            if (label.len == 0) continue;
            if (label.len > max_label_length) {
                return error.LabelTooLong;
            }
            size += 1 + label.len; // Length byte + label
        }

        const result = try allocator.alloc(u8, size);
        errdefer allocator.free(result);

        var pos: usize = 0;
        iter = std.mem.splitScalar(u8, domain, '.');
        while (iter.next()) |label| {
            if (label.len == 0) continue;
            result[pos] = @intCast(label.len);
            pos += 1;
            @memcpy(result[pos..][0..label.len], label);
            pos += label.len;
        }
        result[pos] = 0; // Null terminator

        return result;
    }

    /// Convert wire format name to human-readable string (e.g., "example.com")
    pub fn toString(self: Self, allocator: std.mem.Allocator, full_message: ?[]const u8) ![]u8 {
        var result: std.ArrayList(u8) = .empty;
        defer result.deinit(allocator);

        var pos: usize = 0;
        var data = self.labels;
        var first = true;

        while (pos < data.len) {
            const len_byte = data[pos];

            if (len_byte == 0) {
                break;
            }

            // Handle compression pointer
            if ((len_byte & compression_marker) == compression_marker) {
                if (full_message) |msg| {
                    if (pos + 1 >= data.len) {
                        return error.InvalidCompression;
                    }
                    const ptr_offset = (@as(u16, len_byte & 0x3F) << 8) | data[pos + 1];
                    data = msg[ptr_offset..];
                    pos = 0;
                    continue;
                } else {
                    return error.CompressionRequiresFullMessage;
                }
            }

            const label_len = len_byte;
            if (pos + 1 + label_len > data.len) {
                return error.UnexpectedEnd;
            }

            if (!first) {
                try result.append(allocator, '.');
            }
            first = false;

            try result.appendSlice(allocator, data[pos + 1 ..][0..label_len]);
            pos += 1 + label_len;
        }

        // Return root if empty
        if (result.items.len == 0) {
            try result.append(allocator, '.');
        }

        return try result.toOwnedSlice(allocator);
    }

    /// Get the number of labels in the name
    pub fn labelCount(self: Self, full_message: ?[]const u8) usize {
        var count: usize = 0;
        var pos: usize = 0;
        var data = self.labels;

        while (pos < data.len) {
            const len_byte = data[pos];

            if (len_byte == 0) {
                break;
            }

            if ((len_byte & compression_marker) == compression_marker) {
                if (full_message) |msg| {
                    const ptr_offset = (@as(u16, len_byte & 0x3F) << 8) | data[pos + 1];
                    data = msg[ptr_offset..];
                    pos = 0;
                    continue;
                } else {
                    break;
                }
            }

            count += 1;
            pos += 1 + len_byte;
        }

        return count;
    }

    /// Compare two names for equality (case-insensitive per RFC 1035)
    pub fn eql(self: Self, other: Self, self_msg: ?[]const u8, other_msg: ?[]const u8) bool {
        var allocator = std.heap.page_allocator;

        const self_str = self.toString(allocator, self_msg) catch return false;
        defer allocator.free(self_str);

        const other_str = other.toString(allocator, other_msg) catch return false;
        defer allocator.free(other_str);

        return std.ascii.eqlIgnoreCase(self_str, other_str);
    }

    // ============================================================
    // RFC 7816: QNAME Minimization
    // ============================================================

    /// Get the parent domain by removing the leftmost label
    /// Returns null if this is already the root domain
    pub fn parent(self: Self, allocator: std.mem.Allocator, full_message: ?[]const u8) !?[]u8 {
        var pos: usize = 0;
        var data = self.labels;
        var first_label_len: usize = 0;

        // Handle compression first
        while (pos < data.len) {
            const len_byte = data[pos];

            if (len_byte == 0) {
                break;
            }

            if ((len_byte & compression_marker) == compression_marker) {
                if (full_message) |msg| {
                    if (pos + 1 >= data.len) {
                        return error.InvalidCompression;
                    }
                    const ptr_offset = (@as(u16, len_byte & 0x3F) << 8) | data[pos + 1];
                    data = msg[ptr_offset..];
                    pos = 0;
                    continue;
                } else {
                    return error.CompressionRequiresFullMessage;
                }
            }

            first_label_len = len_byte;
            break;
        }

        // If already root, return null
        if (first_label_len == 0) {
            return null;
        }

        // Convert to string first, then remove first label
        const full_str = try self.toString(allocator, full_message);
        defer allocator.free(full_str);

        // Find first dot
        const dot_pos = std.mem.indexOfScalar(u8, full_str, '.');
        if (dot_pos) |dp| {
            if (dp + 1 < full_str.len) {
                return try allocator.dupe(u8, full_str[dp + 1 ..]);
            }
        }

        // Only one label, return root
        return try allocator.dupe(u8, ".");
    }

    /// Get minimized QNAME for QNAME minimization (RFC 7816)
    /// Returns just the leftmost label prepended to the zone suffix
    /// Example: for "www.example.com" with zone "com", returns "example.com"
    pub fn minimizedName(self: Self, allocator: std.mem.Allocator, zone: []const u8, full_message: ?[]const u8) ![]u8 {
        const full_str = try self.toString(allocator, full_message);
        defer allocator.free(full_str);

        // If zone is root or empty, return first label
        if (zone.len == 0 or (zone.len == 1 and zone[0] == '.')) {
            // Return the TLD (last label before root)
            var iter = std.mem.splitBackwardsScalar(u8, full_str, '.');
            if (iter.next()) |tld| {
                if (tld.len > 0) {
                    return try allocator.dupe(u8, tld);
                }
            }
            return try allocator.dupe(u8, full_str);
        }

        // Check if full_str ends with zone
        if (std.ascii.endsWithIgnoreCase(full_str, zone)) {
            const prefix_len = full_str.len - zone.len;
            if (prefix_len > 0) {
                // Remove trailing dot from prefix if present
                var prefix_end = prefix_len;
                if (prefix_end > 0 and full_str[prefix_end - 1] == '.') {
                    prefix_end -= 1;
                }

                // Find the last label of the prefix
                const prefix = full_str[0..prefix_end];
                if (std.mem.lastIndexOfScalar(u8, prefix, '.')) |last_dot| {
                    // Return last label + zone
                    const label = prefix[last_dot + 1 ..];
                    return try std.fmt.allocPrint(allocator, "{s}.{s}", .{ label, zone });
                } else {
                    // prefix is the last remaining label
                    return try std.fmt.allocPrint(allocator, "{s}.{s}", .{ prefix, zone });
                }
            }
        }

        // Fallback: return full name
        return try allocator.dupe(u8, full_str);
    }

    /// Extract zone cut from a name at a given depth
    /// depth=0 returns root, depth=1 returns TLD, etc.
    pub fn zoneAtDepth(self: Self, allocator: std.mem.Allocator, depth: usize, full_message: ?[]const u8) ![]u8 {
        const full_str = try self.toString(allocator, full_message);
        defer allocator.free(full_str);

        if (depth == 0) {
            return try allocator.dupe(u8, ".");
        }

        // Split into labels and count from the right
        var labels: [128][]const u8 = undefined;
        var label_count: usize = 0;

        var iter = std.mem.splitScalar(u8, full_str, '.');
        while (iter.next()) |label| {
            if (label.len > 0 and label_count < 128) {
                labels[label_count] = label;
                label_count += 1;
            }
        }

        if (label_count == 0) {
            return try allocator.dupe(u8, ".");
        }

        // Calculate how many labels from the right to include
        const include_count = @min(depth, label_count);
        const start_index = label_count - include_count;

        // Build result
        var result: std.ArrayList(u8) = .empty;
        defer result.deinit(allocator);

        for (start_index..label_count) |i| {
            if (result.items.len > 0) {
                try result.append(allocator, '.');
            }
            try result.appendSlice(allocator, labels[i]);
        }

        return try result.toOwnedSlice(allocator);
    }
};

// ============================================================
// 0x20 Case Randomization (DNS Cache Poisoning Protection)
// ============================================================

/// Apply 0x20 case randomization to a domain name
/// Randomly varies the case of ASCII letters to detect spoofed responses
pub fn applyCase0x20(allocator: std.mem.Allocator, domain: []const u8, random: std.Random) ![]u8 {
    const result = try allocator.alloc(u8, domain.len);
    errdefer allocator.free(result);

    for (domain, 0..) |c, i| {
        if (std.ascii.isAlphabetic(c)) {
            // Randomly choose upper or lower case
            if (random.boolean()) {
                result[i] = std.ascii.toUpper(c);
            } else {
                result[i] = std.ascii.toLower(c);
            }
        } else {
            result[i] = c;
        }
    }

    return result;
}

/// Encode a name with 0x20 case randomization applied
pub fn encodeWithCase0x20(allocator: std.mem.Allocator, domain: []const u8, random: std.Random) ![]u8 {
    const randomized = try applyCase0x20(allocator, domain, random);
    defer allocator.free(randomized);

    return Name.encode(allocator, randomized);
}

/// Verify that a response name matches the query name (case-sensitive for 0x20)
/// Returns true if the names match exactly (same case)
pub fn verifyCase0x20(query_name: []const u8, response_name: []const u8) bool {
    if (query_name.len != response_name.len) {
        return false;
    }

    for (query_name, response_name) |q, r| {
        if (q != r) {
            return false;
        }
    }

    return true;
}

/// Extract the QNAME from a DNS message (for 0x20 verification)
pub fn extractQname(allocator: std.mem.Allocator, message: []const u8) ![]u8 {
    if (message.len < 12) {
        return error.MessageTooShort;
    }

    // Skip header, parse QNAME
    var pos: usize = 12;
    var result: std.ArrayList(u8) = .empty;
    defer result.deinit(allocator);

    var first = true;
    while (pos < message.len) {
        const len_byte = message[pos];

        if (len_byte == 0) {
            break;
        }

        // Don't follow compression pointers for 0x20 verification
        if ((len_byte & compression_marker) == compression_marker) {
            break;
        }

        if (len_byte > max_label_length) {
            return error.LabelTooLong;
        }

        if (pos + 1 + len_byte > message.len) {
            return error.UnexpectedEnd;
        }

        if (!first) {
            try result.append(allocator, '.');
        }
        first = false;

        try result.appendSlice(allocator, message[pos + 1 ..][0..len_byte]);
        pos += 1 + len_byte;
    }

    return try result.toOwnedSlice(allocator);
}

test "Name.encode simple domain" {
    const allocator = std.testing.allocator;
    const encoded = try Name.encode(allocator, "example.com");
    defer allocator.free(encoded);

    try std.testing.expectEqualSlices(u8, &[_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
    }, encoded);
}

test "Name.encode root domain" {
    const allocator = std.testing.allocator;
    const encoded = try Name.encode(allocator, "");
    defer allocator.free(encoded);

    try std.testing.expectEqualSlices(u8, &[_]u8{0}, encoded);
}

test "Name.parse and toString" {
    const allocator = std.testing.allocator;
    const wire_data = [_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
    };

    const name = try Name.parse(&wire_data, 0);
    const str = try name.toString(allocator, null);
    defer allocator.free(str);

    try std.testing.expectEqualStrings("example.com", str);
}

test "Name.labelCount" {
    const wire_data = [_]u8{
        3,   'w', 'w', 'w',
        7,   'e', 'x', 'a',
        'm', 'p', 'l', 'e',
        3,   'c', 'o', 'm',
        0,
    };

    const name = try Name.parse(&wire_data, 0);
    try std.testing.expectEqual(@as(usize, 3), name.labelCount(null));
}

test "Name.parse with compression" {
    // Message with compression: second name points to first
    const wire_data = [_]u8{
        // Name 1: example.com at offset 0
        7,   'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3,   'c', 'o', 'm', 0,
        // Name 2: www.<pointer to offset 0> at offset 13
          3,   'w', 'w',
        'w',
        0xC0, 0x00, // Pointer to offset 0
    };

    // Parse the compressed name
    const name = try Name.parse(&wire_data, 13);
    try std.testing.expect(name.compressed);
    try std.testing.expectEqual(@as(usize, 6), name.wire_length);

    const allocator = std.testing.allocator;
    const str = try name.toString(allocator, &wire_data);
    defer allocator.free(str);

    try std.testing.expectEqualStrings("www.example.com", str);
}

// ============================================================
// Tests for QNAME Minimization (RFC 7816)
// ============================================================

test "Name.parent" {
    const allocator = std.testing.allocator;
    const wire_data = [_]u8{
        3,   'w', 'w', 'w',
        7,   'e', 'x', 'a',
        'm', 'p', 'l', 'e',
        3,   'c', 'o', 'm',
        0,
    };

    const name = try Name.parse(&wire_data, 0);

    // Get parent: www.example.com -> example.com
    const parent1 = try name.parent(allocator, null);
    try std.testing.expect(parent1 != null);
    defer allocator.free(parent1.?);
    try std.testing.expectEqualStrings("example.com", parent1.?);
}

test "Name.zoneAtDepth" {
    const allocator = std.testing.allocator;
    const wire_data = [_]u8{
        3,   'w', 'w', 'w',
        7,   'e', 'x', 'a',
        'm', 'p', 'l', 'e',
        3,   'c', 'o', 'm',
        0,
    };

    const name = try Name.parse(&wire_data, 0);

    // depth=0: root
    const zone0 = try name.zoneAtDepth(allocator, 0, null);
    defer allocator.free(zone0);
    try std.testing.expectEqualStrings(".", zone0);

    // depth=1: com
    const zone1 = try name.zoneAtDepth(allocator, 1, null);
    defer allocator.free(zone1);
    try std.testing.expectEqualStrings("com", zone1);

    // depth=2: example.com
    const zone2 = try name.zoneAtDepth(allocator, 2, null);
    defer allocator.free(zone2);
    try std.testing.expectEqualStrings("example.com", zone2);

    // depth=3: www.example.com (full)
    const zone3 = try name.zoneAtDepth(allocator, 3, null);
    defer allocator.free(zone3);
    try std.testing.expectEqualStrings("www.example.com", zone3);
}

test "Name.minimizedName" {
    const allocator = std.testing.allocator;
    const wire_data = [_]u8{
        3,   'w', 'w', 'w',
        7,   'e', 'x', 'a',
        'm', 'p', 'l', 'e',
        3,   'c', 'o', 'm',
        0,
    };

    const name = try Name.parse(&wire_data, 0);

    // Minimize www.example.com with zone "com" -> example.com
    const min1 = try name.minimizedName(allocator, "com", null);
    defer allocator.free(min1);
    try std.testing.expectEqualStrings("example.com", min1);

    // Minimize www.example.com with zone "example.com" -> www.example.com
    const min2 = try name.minimizedName(allocator, "example.com", null);
    defer allocator.free(min2);
    try std.testing.expectEqualStrings("www.example.com", min2);
}

// ============================================================
// Tests for 0x20 Case Randomization
// ============================================================

test "applyCase0x20" {
    const allocator = std.testing.allocator;

    // Use a fixed seed for deterministic testing
    var prng = std.Random.DefaultPrng.init(12345);
    const random = prng.random();

    const result = try applyCase0x20(allocator, "example.com", random);
    defer allocator.free(result);

    // Result should have same length
    try std.testing.expectEqual(@as(usize, 11), result.len);

    // Result should be case-insensitive equal to original
    try std.testing.expect(std.ascii.eqlIgnoreCase("example.com", result));

    // Dots should be preserved
    try std.testing.expectEqual(@as(u8, '.'), result[7]);
}

test "verifyCase0x20" {
    // Exact match
    try std.testing.expect(verifyCase0x20("ExAmPlE.cOm", "ExAmPlE.cOm"));

    // Case mismatch (spoofed response)
    try std.testing.expect(!verifyCase0x20("ExAmPlE.cOm", "example.com"));

    // Length mismatch
    try std.testing.expect(!verifyCase0x20("example.com", "example.co"));
}

test "extractQname" {
    const allocator = std.testing.allocator;

    // Build a minimal DNS message with QNAME
    const message = [_]u8{
        // Header (12 bytes)
        0x12, 0x34, // ID
        0x01, 0x00, // Flags (standard query)
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
        // Question section
        7, 'E', 'x', 'A', 'm', 'P', 'l', 'E', // Randomized case
        3, 'C', 'o', 'M',
        0, // End of name
        0x00, 0x01, // QTYPE: A
        0x00, 0x01, // QCLASS: IN
    };

    const qname = try extractQname(allocator, &message);
    defer allocator.free(qname);

    try std.testing.expectEqualStrings("ExAmPlE.CoM", qname);
}

test "encodeWithCase0x20" {
    const allocator = std.testing.allocator;

    var prng = std.Random.DefaultPrng.init(54321);
    const random = prng.random();

    const encoded = try encodeWithCase0x20(allocator, "test.example.com", random);
    defer allocator.free(encoded);

    // Should be valid wire format
    try std.testing.expectEqual(@as(u8, 0), encoded[encoded.len - 1]); // Null terminator

    // Parse it back and verify case-insensitive match
    const name = try Name.parse(encoded, 0);
    const str = try name.toString(allocator, null);
    defer allocator.free(str);

    try std.testing.expect(std.ascii.eqlIgnoreCase("test.example.com", str));
}
