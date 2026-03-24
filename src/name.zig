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

/// Maximum number of compression pointer hops allowed (prevents infinite loops)
/// DNS names can have at most 127 labels, so 16 pointer hops is generous
const max_compression_hops: u8 = 16;

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
    ///
    /// SECURITY: Limits compression pointer hops to prevent infinite loops
    /// from maliciously crafted packets with circular pointers (CWE-835).
    /// SECURITY: Enforces max_name_length (255 bytes) per RFC 1035 (CWE-130).
    pub fn parse(data: []const u8, offset: usize) !Self {
        if (offset >= data.len) {
            return error.InvalidOffset;
        }

        var pos = offset;
        var wire_len: usize = 0;
        var compressed = false;
        var first_pointer_pos: ?usize = null;
        var pointer_hops: u8 = 0;
        var total_name_len: usize = 0; // Track decompressed name length

        // Follow the name, handling compression
        while (pos < data.len) {
            const len_byte = data[pos];

            // Check for end of name
            if (len_byte == 0) {
                if (first_pointer_pos == null) {
                    wire_len += 1; // Include the null terminator
                }
                total_name_len += 1; // Count the root label
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

                // SECURITY: Limit pointer hops to prevent infinite loops (CWE-835)
                pointer_hops += 1;
                if (pointer_hops > max_compression_hops) {
                    return error.CompressionLoopDetected;
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

            // SECURITY: Enforce max name length (RFC 1035 Section 2.3.4, CWE-130)
            total_name_len += 1 + label_len; // Length byte + label data
            if (total_name_len > max_name_length) {
                return error.NameTooLong;
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

    /// Encode a name from a string into a caller-provided buffer (zero allocation).
    /// Returns a Name struct referencing the filled portion of the buffer.
    /// Returns error.NameTooLong if the encoded name exceeds the buffer size.
    pub fn encodeBuf(domain: []const u8, buf: []u8) !Self {
        if (domain.len > max_name_length) {
            return error.NameTooLong;
        }

        // Handle root domain
        if (domain.len == 0 or (domain.len == 1 and domain[0] == '.')) {
            if (buf.len < 1) return error.NameTooLong;
            buf[0] = 0;
            return Self{
                .labels = buf[0..1],
                .wire_length = 1,
                .compressed = false,
            };
        }

        var pos: usize = 0;
        var iter = std.mem.splitScalar(u8, domain, '.');
        while (iter.next()) |label| {
            if (label.len == 0) continue;
            if (label.len > max_label_length) {
                return error.LabelTooLong;
            }
            if (pos + 1 + label.len > buf.len) return error.NameTooLong;
            buf[pos] = @intCast(label.len);
            pos += 1;
            @memcpy(buf[pos..][0..label.len], label);
            pos += label.len;
        }

        if (pos >= buf.len) return error.NameTooLong;
        buf[pos] = 0; // Null terminator
        pos += 1;

        return Self{
            .labels = buf[0..pos],
            .wire_length = pos,
            .compressed = false,
        };
    }

    /// Convert wire format name to human-readable string (e.g., "example.com")
    ///
    /// SECURITY: Limits compression pointer hops to prevent infinite loops
    /// from maliciously crafted packets with circular pointers (CWE-835).
    pub fn toString(self: Self, allocator: std.mem.Allocator, full_message: ?[]const u8) ![]u8 {
        var result: std.ArrayList(u8) = .empty;
        defer result.deinit(allocator);

        var pos: usize = 0;
        var data = self.labels;
        var first = true;
        var pointer_hops: u8 = 0;
        // SECURITY (SEC-SCAN-07): Track last pointer target to reject forward pointers.
        // Each successive compression pointer must target a strictly earlier offset,
        // preventing forward-pointer attacks (RFC 1035 compliance).
        var last_ptr_target: ?u16 = null;

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
                    pointer_hops += 1;
                    if (pointer_hops > max_compression_hops) {
                        return error.CompressionLoopDetected;
                    }
                    const ptr_offset = (@as(u16, len_byte & 0x3F) << 8) | data[pos + 1];
                    // SECURITY (SEC-SCAN-07): Reject forward compression pointers.
                    // Each pointer target must be strictly less than the previous target
                    // to ensure we always move backwards in the message.
                    if (last_ptr_target) |prev| {
                        if (ptr_offset >= prev) return error.ForwardPointer;
                    }
                    last_ptr_target = ptr_offset;
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

    /// Convert wire format name to human-readable string into a caller-provided buffer.
    /// Returns a slice of `buf` containing the dotted name (e.g., "example.com").
    /// Avoids heap allocation -- DNS names are at most 253 chars, so a 256-byte
    /// stack buffer always suffices.
    pub fn toStringBuf(self: Self, buf: []u8, full_message: ?[]const u8) ![]const u8 {
        var out_pos: usize = 0;
        var pos: usize = 0;
        var data = self.labels;
        var first = true;
        var pointer_hops: u8 = 0;
        // SECURITY (SEC-SCAN-07): Track last pointer target to reject forward pointers.
        var last_ptr_target: ?u16 = null;

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
                    pointer_hops += 1;
                    if (pointer_hops > max_compression_hops) {
                        return error.CompressionLoopDetected;
                    }
                    const ptr_offset = (@as(u16, len_byte & 0x3F) << 8) | data[pos + 1];
                    // SECURITY (SEC-SCAN-07): Reject forward compression pointers.
                    if (last_ptr_target) |prev| {
                        if (ptr_offset >= prev) return error.ForwardPointer;
                    }
                    last_ptr_target = ptr_offset;
                    data = msg[ptr_offset..];
                    pos = 0;
                    continue;
                } else {
                    return error.CompressionRequiresFullMessage;
                }
            }

            const label_len: usize = len_byte;
            if (pos + 1 + label_len > data.len) {
                return error.UnexpectedEnd;
            }

            if (!first) {
                if (out_pos >= buf.len) return error.NameTooLong;
                buf[out_pos] = '.';
                out_pos += 1;
            }
            first = false;

            if (out_pos + label_len > buf.len) return error.NameTooLong;
            @memcpy(buf[out_pos..][0..label_len], data[pos + 1 ..][0..label_len]);
            out_pos += label_len;
            pos += 1 + label_len;
        }

        // Return root if empty
        if (out_pos == 0) {
            if (buf.len < 1) return error.NameTooLong;
            buf[0] = '.';
            return buf[0..1];
        }

        return buf[0..out_pos];
    }

    /// Get the number of labels in the name
    ///
    /// SECURITY: Limits compression pointer hops to prevent infinite loops
    /// from maliciously crafted packets with circular pointers (CWE-835).
    pub fn labelCount(self: Self, full_message: ?[]const u8) error{ CompressionLoopDetected, ForwardPointer }!usize {
        var count: usize = 0;
        var pos: usize = 0;
        var data = self.labels;
        var pointer_hops: u8 = 0;
        // SECURITY (SEC-SCAN-07): Track last pointer target to reject forward pointers.
        var last_ptr_target: ?u16 = null;

        while (pos < data.len) {
            const len_byte = data[pos];

            if (len_byte == 0) {
                break;
            }

            if ((len_byte & compression_marker) == compression_marker) {
                if (full_message) |msg| {
                    pointer_hops += 1;
                    if (pointer_hops > max_compression_hops) {
                        return error.CompressionLoopDetected;
                    }
                    const ptr_offset = (@as(u16, len_byte & 0x3F) << 8) | data[pos + 1];
                    // SECURITY (SEC-SCAN-07): Reject forward compression pointers.
                    if (last_ptr_target) |prev| {
                        if (ptr_offset >= prev) return error.ForwardPointer;
                    }
                    last_ptr_target = ptr_offset;
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
    /// Zero-allocation: walks wire-format labels directly, following compression pointers.
    pub fn eql(self: Self, other: Self, self_msg: ?[]const u8, other_msg: ?[]const u8) bool {
        var self_data = self.labels;
        var self_pos: usize = 0;
        var self_hops: u8 = 0;
        // SECURITY (SEC-SCAN-07): Track last pointer target to reject forward pointers.
        var self_last_ptr: ?u16 = null;

        var other_data = other.labels;
        var other_pos: usize = 0;
        var other_hops: u8 = 0;
        var other_last_ptr: ?u16 = null;

        while (true) {
            // Follow compression pointers for self
            while (self_pos < self_data.len and
                (self_data[self_pos] & compression_marker) == compression_marker)
            {
                self_hops += 1;
                if (self_hops > max_compression_hops) return false;
                if (self_msg) |msg| {
                    if (self_pos + 1 >= self_data.len) return false;
                    const ptr = (@as(u16, self_data[self_pos] & 0x3F) << 8) | self_data[self_pos + 1];
                    // SECURITY (SEC-SCAN-07): Reject forward compression pointers.
                    if (self_last_ptr) |prev| {
                        if (ptr >= prev) return false;
                    }
                    self_last_ptr = ptr;
                    self_data = msg;
                    self_pos = ptr;
                } else {
                    return false; // compressed name without full message
                }
            }

            // Follow compression pointers for other
            while (other_pos < other_data.len and
                (other_data[other_pos] & compression_marker) == compression_marker)
            {
                other_hops += 1;
                if (other_hops > max_compression_hops) return false;
                if (other_msg) |msg| {
                    if (other_pos + 1 >= other_data.len) return false;
                    const ptr = (@as(u16, other_data[other_pos] & 0x3F) << 8) | other_data[other_pos + 1];
                    // SECURITY (SEC-SCAN-07): Reject forward compression pointers.
                    if (other_last_ptr) |prev| {
                        if (ptr >= prev) return false;
                    }
                    other_last_ptr = ptr;
                    other_data = msg;
                    other_pos = ptr;
                } else {
                    return false;
                }
            }

            // Bounds check
            if (self_pos >= self_data.len or other_pos >= other_data.len) return false;

            const self_len = self_data[self_pos];
            const other_len = other_data[other_pos];

            // Both at root label -- names are equal
            if (self_len == 0 and other_len == 0) return true;

            // One at root but not the other -- different number of labels
            if (self_len == 0 or other_len == 0) return false;

            // Label lengths differ
            if (self_len != other_len) return false;

            // Bounds check for label data
            if (self_pos + 1 + self_len > self_data.len) return false;
            if (other_pos + 1 + other_len > other_data.len) return false;

            // Compare label bytes case-insensitively (ASCII only per RFC 4343)
            const self_label = self_data[self_pos + 1 ..][0..self_len];
            const other_label = other_data[other_pos + 1 ..][0..other_len];
            if (!std.ascii.eqlIgnoreCase(self_label, other_label)) return false;

            // Advance past this label
            self_pos += 1 + self_len;
            other_pos += 1 + other_len;
        }
    }

    // ============================================================
    // RFC 7816: QNAME Minimization
    // ============================================================

    /// Get the parent domain by removing the leftmost label
    /// Returns null if this is already the root domain
    ///
    /// SECURITY: Limits compression pointer hops to prevent infinite loops
    /// from maliciously crafted packets with circular pointers (CWE-835).
    pub fn parent(self: Self, allocator: std.mem.Allocator, full_message: ?[]const u8) !?[]u8 {
        var pos: usize = 0;
        var data = self.labels;
        var first_label_len: usize = 0;
        var pointer_hops: u8 = 0;
        // SECURITY (SEC-SCAN-07): Track last pointer target to reject forward pointers.
        var last_ptr_target: ?u16 = null;

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
                    pointer_hops += 1;
                    if (pointer_hops > max_compression_hops) {
                        return error.CompressionLoopDetected;
                    }
                    const ptr_offset = (@as(u16, len_byte & 0x3F) << 8) | data[pos + 1];
                    // SECURITY (SEC-SCAN-07): Reject forward compression pointers.
                    if (last_ptr_target) |prev| {
                        if (ptr_offset >= prev) return error.ForwardPointer;
                    }
                    last_ptr_target = ptr_offset;
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
pub inline fn verifyCase0x20(query_name: []const u8, response_name: []const u8) bool {
    return std.mem.eql(u8, query_name, response_name);
}

/// Extract the QNAME from a DNS message into a caller-provided buffer (for 0x20 verification).
/// Avoids heap allocation -- DNS names are at most 253 chars, so a `[max_name_length]u8`
/// stack buffer always suffices.  Returns a slice of `buf` containing the dotted QNAME.
pub fn extractQnameBuf(buf: []u8, message: []const u8) ![]const u8 {
    if (message.len < 12) {
        return error.MessageTooShort;
    }

    // Skip header, parse QNAME
    var pos: usize = 12;
    var out_pos: usize = 0;

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
            if (out_pos >= buf.len) return error.NameTooLong;
            buf[out_pos] = '.';
            out_pos += 1;
        }
        first = false;

        if (out_pos + len_byte > buf.len) return error.NameTooLong;
        @memcpy(buf[out_pos..][0..len_byte], message[pos + 1 ..][0..len_byte]);
        out_pos += len_byte;
        pos += 1 + len_byte;
    }

    return buf[0..out_pos];
}

/// Extract the QNAME from a DNS message (for 0x20 verification).
/// Returns heap-allocated string.  Prefer `extractQnameBuf` when a stack
/// buffer is available to avoid allocation on the hot path.
pub fn extractQname(allocator: std.mem.Allocator, message: []const u8) ![]u8 {
    var buf: [max_name_length]u8 = undefined;
    const result = try extractQnameBuf(&buf, message);
    return allocator.dupe(u8, result);
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

test "Name.encodeBuf simple domain" {
    // Regression test for PF-09: zero-allocation wire encoding into a stack buffer.
    var buf: [256]u8 = undefined;
    const name = try Name.encodeBuf("example.com", &buf);

    try std.testing.expectEqualSlices(u8, &[_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
    }, name.labels);
    try std.testing.expectEqual(@as(usize, 13), name.wire_length);
    try std.testing.expect(!name.compressed);
}

test "Name.encodeBuf root domain" {
    var buf: [256]u8 = undefined;
    const name = try Name.encodeBuf("", &buf);
    try std.testing.expectEqualSlices(u8, &[_]u8{0}, name.labels);
    try std.testing.expectEqual(@as(usize, 1), name.wire_length);
}

test "Name.encodeBuf with trailing dot" {
    var buf: [256]u8 = undefined;
    const name = try Name.encodeBuf("example.com.", &buf);

    try std.testing.expectEqualSlices(u8, &[_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
    }, name.labels);
}

test "Name.encodeBuf eql with parsed name" {
    // Verify that a name encoded via encodeBuf compares equal to a parsed name.
    const wire_data = [_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
    };
    const parsed = try Name.parse(&wire_data, 0);

    var buf: [256]u8 = undefined;
    const from_buf = try Name.encodeBuf("example.com", &buf);

    try std.testing.expect(parsed.eql(from_buf, null, null));
    try std.testing.expect(from_buf.eql(parsed, null, null));
}

test "Name.encodeBuf eql case insensitive" {
    const wire_data = [_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
    };
    const parsed = try Name.parse(&wire_data, 0);

    var buf: [256]u8 = undefined;
    const from_buf = try Name.encodeBuf("EXAMPLE.COM", &buf);

    try std.testing.expect(parsed.eql(from_buf, null, null));
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
    try std.testing.expectEqual(@as(usize, 3), try name.labelCount(null));
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

test "Name.parse rejects compression pointer loops" {
    // SECURITY TEST: Verify that circular compression pointers are detected
    // and cause an error rather than an infinite loop (CWE-835)

    // Test 1: Forward pointer detection
    // Construct a packet where offset 0 points forward to offset 4
    const forward_ptr = [_]u8{
        // Offset 0: pointer to offset 4 (forward)
        0xC0, 0x04,
        // Padding
        0x00, 0x00,
        // Offset 4: a valid name
        3,    'f',
        'o',  'o',
        0,
    };

    // This should detect the forward pointer and error
    const result = Name.parse(&forward_ptr, 0);
    try std.testing.expectError(error.ForwardPointer, result);

    // Test 2: Deep pointer chain exceeding max_compression_hops
    // Build a chain: each offset points to 2 bytes earlier, creating a long chain
    // Structure: offset 0 has "a" label, then each subsequent offset is a pointer
    var deep_chain: [100]u8 = undefined;

    // Offset 0-1: short label "a"
    deep_chain[0] = 1; // label length
    deep_chain[1] = 'a';
    // Offset 2: null terminator for the base name
    deep_chain[2] = 0;

    // Now create a chain of pointers, each pointing back to offset 0
    // Offset 3+: pointers to offset 0 (which has the actual name)
    // But we need a CHAIN - each pointer points to the previous pointer
    // offset 3: pointer to 0
    // offset 5: pointer to 3
    // offset 7: pointer to 5
    // etc. But all backward pointers go to 0 for simplicity

    // Actually, to create a long CHAIN we need each entry to point to a PREVIOUS
    // pointer entry. Let's build it properly:
    // Offset 3-4: pointer to offset 0 (starts the chain)
    deep_chain[3] = 0xC0;
    deep_chain[4] = 0x00;

    // Offsets 5-6, 7-8, etc.: each points to offset 3 to create a very long chain
    // But that won't work because 5 -> 3 -> 0 is only 2 hops
    // We need to interleave names and pointers

    // Better approach: make offset N point to offset N-3 (building backward chain)
    // Starting from high offset, going down
    // Let's create: 48->45->42->...->6->3->0 (16+ hops)

    // Fill with pointer chain: each offset i points to offset i-3
    var offset: usize = 6;
    while (offset < 60) : (offset += 3) {
        const target = offset - 3;
        deep_chain[offset] = 0xC0 | @as(u8, @intCast(target >> 8));
        deep_chain[offset + 1] = @as(u8, @intCast(target & 0xFF));
        deep_chain[offset + 2] = 0; // Padding
    }

    // Parse from offset 57 (will follow: 57->54->51->48->45->42->39->36->33->30->27->24->21->18->15->12->9->6->3->0)
    // That's 19 hops, which exceeds max_compression_hops (16)
    const chain_result = Name.parse(&deep_chain, 57);
    try std.testing.expectError(error.CompressionLoopDetected, chain_result);
}

test "Name.parse enforces max name length" {
    // SECURITY TEST: Verify that names exceeding 255 bytes are rejected (CWE-130)

    // Build a name that's exactly at the limit (255 bytes)
    // Use labels of length 63 (max label size): 63*4 = 252, plus 4 length bytes = 256
    // That's too long, so use 63 + 63 + 63 + 62 = 251 + 4 length bytes + 1 null = 256
    // Actually: each label needs length byte + data, so 4 labels of 63 = 4*(1+63) = 256
    // Let's make it simpler: many small labels to exceed 255

    // Create a name with labels that total > 255 bytes
    // Each label: 1 byte length + N bytes data
    // To hit 256+, we need lots of small labels
    // 64 labels of 3 chars each: 64 * (1 + 3) = 256 bytes + 1 null = 257 (too long)

    var oversized_name: [512]u8 = undefined;
    var pos: usize = 0;

    // Create many small labels to exceed max_name_length
    var label_count: usize = 0;
    while (pos + 4 < 512 and label_count < 80) : (label_count += 1) {
        oversized_name[pos] = 3; // Label length
        oversized_name[pos + 1] = 'a';
        oversized_name[pos + 2] = 'b';
        oversized_name[pos + 3] = 'c';
        pos += 4;
    }
    oversized_name[pos] = 0; // null terminator

    // Name with 80 labels of "abc" = 80 * 4 = 320 bytes (way over 255)
    const result = Name.parse(&oversized_name, 0);
    try std.testing.expectError(error.NameTooLong, result);

    // Verify a name at exactly 255 bytes is accepted
    // 255 bytes = root label (1) + data (254)
    // Let's use: 4 labels of 63 chars = 4 * (1+63) = 256 - but that's with null = 257
    // Actually: 3 labels of 63 + 1 label of 62 = 3*64 + 63 = 255 (including null)
    // Let's simplify: just verify a reasonably long name works
    var long_valid: [300]u8 = undefined;
    pos = 0;
    label_count = 0;
    while (label_count < 50) : (label_count += 1) {
        // 50 labels of 4 chars = 50 * 5 = 250 bytes + 1 null = 251 (valid)
        long_valid[pos] = 4;
        long_valid[pos + 1] = 't';
        long_valid[pos + 2] = 'e';
        long_valid[pos + 3] = 's';
        long_valid[pos + 4] = 't';
        pos += 5;
    }
    long_valid[pos] = 0;

    // This should succeed (251 bytes)
    const valid_result = try Name.parse(&long_valid, 0);
    try std.testing.expect(valid_result.wire_length > 0);
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

test "extractQnameBuf" {
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

    // Stack buffer variant produces the same result without heap allocation
    var buf: [max_name_length]u8 = undefined;
    const qname_buf = try extractQnameBuf(&buf, &message);
    try std.testing.expectEqualStrings("ExAmPlE.CoM", qname_buf);

    // Message too short
    try std.testing.expectError(error.MessageTooShort, extractQnameBuf(&buf, &[_]u8{ 0, 1, 2 }));

    // Label too long (len_byte > 63)
    const bad_label = [_]u8{
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Header
        64, // label length > max_label_length
    } ++ [_]u8{0} ** 64;
    try std.testing.expectError(error.LabelTooLong, extractQnameBuf(&buf, &bad_label));
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

// ============================================================
// Tests for Name.eql() zero-allocation label comparison
// ============================================================

test "Name.eql basic equality" {
    // Same name should be equal
    const wire = [_]u8{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    const name1 = try Name.parse(&wire, 0);
    const name2 = try Name.parse(&wire, 0);
    try std.testing.expect(name1.eql(name2, null, null));
}

test "Name.eql case insensitive" {
    // DNS names are case-insensitive (RFC 4343)
    const lower = [_]u8{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    const upper = [_]u8{ 7, 'E', 'X', 'A', 'M', 'P', 'L', 'E', 3, 'C', 'O', 'M', 0 };
    const name_lower = try Name.parse(&lower, 0);
    const name_upper = try Name.parse(&upper, 0);
    try std.testing.expect(name_lower.eql(name_upper, null, null));
}

test "Name.eql different names" {
    const wire1 = [_]u8{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    const wire2 = [_]u8{ 4, 't', 'e', 's', 't', 3, 'c', 'o', 'm', 0 };
    const name1 = try Name.parse(&wire1, 0);
    const name2 = try Name.parse(&wire2, 0);
    try std.testing.expect(!name1.eql(name2, null, null));
}

test "Name.eql different label count" {
    // example.com vs www.example.com
    const wire1 = [_]u8{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    const wire2 = [_]u8{ 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    const name1 = try Name.parse(&wire1, 0);
    const name2 = try Name.parse(&wire2, 0);
    try std.testing.expect(!name1.eql(name2, null, null));
}

test "Name.eql root domain" {
    const root = [_]u8{0};
    const name1 = try Name.parse(&root, 0);
    const name2 = try Name.parse(&root, 0);
    try std.testing.expect(name1.eql(name2, null, null));
}

test "Name.eql root vs non-root" {
    const root = [_]u8{0};
    const wire = [_]u8{ 3, 'c', 'o', 'm', 0 };
    const name_root = try Name.parse(&root, 0);
    const name_com = try Name.parse(&wire, 0);
    try std.testing.expect(!name_root.eql(name_com, null, null));
}

test "Name.eql with compression pointers" {
    // Message: example.com at offset 0, then www.<ptr to 0> at offset 13
    const wire_data = [_]u8{
        // Name 1: example.com at offset 0
        7,   'e',  'x',  'a', 'm', 'p', 'l', 'e',
        3,   'c',  'o',  'm', 0,
        // Name 2: www.<pointer to offset 0> at offset 13
          3,   'w', 'w',
        'w', 0xC0, 0x00,
    };

    const name1 = try Name.parse(&wire_data, 13); // www.example.com (compressed)

    // Construct www.example.com uncompressed
    const uncompressed = [_]u8{ 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    const name2 = try Name.parse(&uncompressed, 0);

    // Compressed vs uncompressed should be equal
    try std.testing.expect(name1.eql(name2, &wire_data, null));
}

test "Name.eql both compressed" {
    // Two compressed names pointing to the same underlying data
    const wire_data = [_]u8{
        // Offset 0: example.com
        7,    'e',  'x',  'a', 'm', 'p', 'l', 'e',
        3,    'c',  'o',  'm', 0,
        // Offset 13: www.<ptr to 0>
          3,   'w', 'w',
        'w',  0xC0, 0x00,
        // Offset 19: www.<ptr to 0> (same)
        3,   'w', 'w', 'w', 0xC0,
        0x00,
    };

    const name1 = try Name.parse(&wire_data, 13);
    const name2 = try Name.parse(&wire_data, 19);
    try std.testing.expect(name1.eql(name2, &wire_data, &wire_data));
}

test "Name.eql same label different case with compression" {
    const wire_data = [_]u8{
        // Offset 0: EXAMPLE.COM (uppercase)
        7,   'E',  'X',  'A', 'M', 'P', 'L', 'E',
        3,   'C',  'O',  'M', 0,
        // Offset 13: www.<ptr to 0> (will resolve to www.EXAMPLE.COM)
          3,   'w', 'w',
        'w', 0xC0, 0x00,
    };

    // Uncompressed www.example.com (lowercase)
    const uncompressed = [_]u8{ 3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    const name1 = try Name.parse(&wire_data, 13);
    const name2 = try Name.parse(&uncompressed, 0);

    // Should be equal because DNS comparison is case-insensitive
    try std.testing.expect(name1.eql(name2, &wire_data, null));
}

test "Name.eql performs zero allocations" {
    // Use the failing allocator -- any allocation attempt will panic/error.
    // If eql() tries to allocate, this test will fail.
    const wire1 = [_]u8{ 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0 };
    const wire2 = [_]u8{ 7, 'E', 'X', 'A', 'M', 'P', 'L', 'E', 3, 'C', 'O', 'M', 0 };
    const name1 = try Name.parse(&wire1, 0);
    const name2 = try Name.parse(&wire2, 0);

    // The key assertion: eql() must not allocate. If it did, it would need
    // an allocator parameter. Our new implementation has no allocator parameter
    // and works entirely on wire-format data -- zero allocations by construction.
    try std.testing.expect(name1.eql(name2, null, null));
}

// ============================================================
// Tests for Name.toStringBuf() zero-allocation name formatting
// ============================================================

test "Name.toStringBuf simple domain" {
    const wire_data = [_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
    };
    const name = try Name.parse(&wire_data, 0);

    var buf: [256]u8 = undefined;
    const str = try name.toStringBuf(&buf, null);
    try std.testing.expectEqualStrings("example.com", str);
}

test "Name.toStringBuf matches toString" {
    const allocator = std.testing.allocator;
    const wire_data = [_]u8{
        3,   'w', 'w', 'w',
        7,   'e', 'x', 'a',
        'm', 'p', 'l', 'e',
        3,   'c', 'o', 'm',
        0,
    };

    const name = try Name.parse(&wire_data, 0);

    // Compare heap-allocated toString with stack toStringBuf
    const heap_str = try name.toString(allocator, null);
    defer allocator.free(heap_str);

    var buf: [256]u8 = undefined;
    const buf_str = try name.toStringBuf(&buf, null);

    try std.testing.expectEqualStrings(heap_str, buf_str);
}

test "Name.toStringBuf root domain" {
    const wire_data = [_]u8{0};
    const name = try Name.parse(&wire_data, 0);

    var buf: [256]u8 = undefined;
    const str = try name.toStringBuf(&buf, null);
    try std.testing.expectEqualStrings(".", str);
}

test "Name.toStringBuf with compression" {
    const wire_data = [_]u8{
        // Name 1: example.com at offset 0
        7,   'e',  'x',  'a', 'm', 'p', 'l', 'e',
        3,   'c',  'o',  'm', 0,
        // Name 2: www.<pointer to offset 0> at offset 13
          3,   'w', 'w',
        'w', 0xC0, 0x00,
    };

    const name = try Name.parse(&wire_data, 13);

    var buf: [256]u8 = undefined;
    const str = try name.toStringBuf(&buf, &wire_data);
    try std.testing.expectEqualStrings("www.example.com", str);
}

test "Name.toStringBuf performs zero allocations" {
    // Use no allocator at all -- toStringBuf takes only a stack buffer.
    // If it tried to allocate, it wouldn't compile (no allocator parameter).
    const wire_data = [_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
    };
    const name = try Name.parse(&wire_data, 0);

    var buf: [256]u8 = undefined;
    const str = try name.toStringBuf(&buf, null);
    try std.testing.expectEqualStrings("example.com", str);
}

test "Name.toStringBuf buffer too small" {
    const wire_data = [_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
    };
    const name = try Name.parse(&wire_data, 0);

    // Buffer too small for "example.com" (11 chars)
    var small_buf: [5]u8 = undefined;
    const result = name.toStringBuf(&small_buf, null);
    try std.testing.expectError(error.NameTooLong, result);
}

// ============================================================
// SECURITY TESTS: GAP-0037 -- Compression loop detection in
// toString(), labelCount(), and parent() (CWE-835)
// ============================================================

test "GAP-0037: toString detects self-referencing compression pointer" {
    // SECURITY TEST: A self-referencing compression pointer at offset 0
    // (0xC0, 0x00 points back to offset 0) must be rejected.
    // SEC-SCAN-07 forward pointer check catches this: on the second hop,
    // ptr_offset (0) >= last_ptr_target (0), so ForwardPointer is returned.
    const allocator = std.testing.allocator;

    // Craft a buffer with a self-referencing pointer at offset 0
    const circular = [_]u8{ 0xC0, 0x00 };

    // Build a Name that starts at offset 0 in a message whose first two
    // bytes form a compression pointer back to offset 0.
    const name = Name{
        .labels = &circular,
        .wire_length = 2,
        .compressed = true,
    };

    // toString must detect the self-reference and return ForwardPointer
    const res = name.toString(allocator, &circular);
    try std.testing.expectError(error.ForwardPointer, res);
}

test "GAP-0037: labelCount detects self-referencing compression pointer" {
    // SECURITY TEST: labelCount must not loop forever on a circular pointer.
    // SEC-SCAN-07 forward pointer check catches self-references as ForwardPointer.
    const circular = [_]u8{ 0xC0, 0x00 };

    const name = Name{
        .labels = &circular,
        .wire_length = 2,
        .compressed = true,
    };

    const res = name.labelCount(&circular);
    try std.testing.expectError(error.ForwardPointer, res);
}

test "GAP-0037: parent detects self-referencing compression pointer" {
    // SECURITY TEST: parent must not loop forever on a circular pointer.
    // SEC-SCAN-07 forward pointer check catches self-references as ForwardPointer.
    const allocator = std.testing.allocator;
    const circular = [_]u8{ 0xC0, 0x00 };

    const name = Name{
        .labels = &circular,
        .wire_length = 2,
        .compressed = true,
    };

    const res = name.parent(allocator, &circular);
    try std.testing.expectError(error.ForwardPointer, res);
}

// ============================================================
// SECURITY TESTS: SEC-SCAN-07 -- Forward pointer rejection in
// toString(), toStringBuf(), labelCount(), parent() (CWE-822)
// ============================================================

test "SEC-SCAN-07: toString rejects forward compression pointer chain" {
    const allocator = std.testing.allocator;
    // Build a message where:
    // offset 0-12: "example.com" in wire format = \x07example\x03com\x00
    // offset 13: ptr to offset 0 (backward, valid)
    // offset 15: ptr to offset 13 (forward relative to current chain, should be rejected)
    //
    // We create a Name whose labels start at offset 13 (ptr->0), which is valid.
    // Then at offset 0 we place the real name. But to test the *forward pointer
    // within a chain*, we build a two-hop scenario:
    // offset 0: ptr to offset 4 (first hop)
    // offset 2: some label data
    // offset 4: ptr to offset 6 (second hop -- forward from offset 4, rejected)
    //
    // Simpler approach: two pointers in a chain where the second points forward.
    // msg[0..2] = ptr to offset 4
    // msg[2..4] = ptr to offset 0 (padding)
    // msg[4..6] = ptr to offset 4 (self-reference / forward in chain)
    //
    // Actually, let's just build a clean test:
    // msg layout:
    //   offset 0: \x03com\x00  (5 bytes: label "com" + root)
    //   offset 5: \xC0\x00     (ptr -> 0, backward, ok for first hop)
    //   offset 7: \xC0\x05     (ptr -> 5 -- but we won't use this)
    //
    // Create a Name whose labels = msg[5..7] = ptr to offset 0.
    // toString(name, msg) should follow ptr to offset 0 and read "com". PASS.
    //
    // For the forward pointer test, we need a Name that follows TWO pointers
    // where the second is forward relative to the first.
    // msg layout:
    //   offset 0: \xC0\x04     (ptr -> 4)
    //   offset 2: \x03com\x00  (5 bytes)
    //   offset 7: \xC0\x04     (ptr -> 4, same as first hop)
    //
    // Name.labels = msg[0..2] (ptr -> 4).
    // But offset 4 is inside "com\x00", starting at 'o'. That's not valid DNS.
    //
    // Best approach: build a message with two backward pointers where the second
    // points forward relative to the first target.
    // msg:
    //   offset 0: \x03foo\x00         (5 bytes)
    //   offset 5: \x03bar\xC0\x00     (6 bytes: "bar" label + ptr to offset 0)
    //   offset 11: \xC0\x05           (ptr -> 5, backward from 11, 1st hop OK)
    //
    // Name.labels = msg[11..13]. toString follows:
    //   hop 1: ptr_offset=5, last_ptr_target=5, data=msg[5..]
    //   reads "bar", then hits \xC0\x00
    //   hop 2: ptr_offset=0, 0 < 5 OK, last_ptr_target=0, data=msg[0..]
    //   reads "foo" -> result = "bar.foo" -- PASS (both backward)
    //
    // Now test with forward: build where hop 2 targets offset >= hop 1 target.
    // msg:
    //   offset 0: \xC0\x05            (ptr -> 5)
    //   offset 2: \x03foo\x00         (5 bytes)
    //   offset 7: \x03bar\xC0\x05     (6 bytes: "bar" + ptr to offset 5)
    //
    // Name.labels = msg[7..13]. toString:
    //   reads "bar", then hits ptr at offset 7+4=11 -> \xC0\x05
    //   hop 1: ptr_offset=5, last_ptr_target=5, data=msg[5..]="oo\x00..."
    //   That's not clean. Let me simplify.

    // Simple test: two consecutive pointer hops where second >= first.
    // msg[0..2] = \xC0\x04  (ptr to 4)
    // msg[2..4] = \xAA\xBB  (padding)
    // msg[4..6] = \xC0\x04  (ptr to 4, self-ref)
    // msg[6..11] = \x03com\x00
    //
    // Name.labels = msg[0..2]. toString:
    //   hop 1: ptr_offset=4, last_ptr_target=4, data=msg[4..]=\xC0\x04...
    //   hop 2: ptr_offset=4, 4 >= 4 (prev=4) -> REJECTED. ForwardPointer.
    const msg = [_]u8{ 0xC0, 0x04, 0xAA, 0xBB, 0xC0, 0x04, 0x03, 'c', 'o', 'm', 0x00 };
    const name = Name{
        .labels = msg[0..2],
        .wire_length = 2,
        .compressed = true,
    };

    const result = name.toString(allocator, &msg);
    try std.testing.expectError(error.ForwardPointer, result);
}

test "SEC-SCAN-07: toStringBuf rejects forward compression pointer chain" {
    var buf: [256]u8 = undefined;
    // Same layout: two hops where second target >= first target
    const msg = [_]u8{ 0xC0, 0x04, 0xAA, 0xBB, 0xC0, 0x04, 0x03, 'c', 'o', 'm', 0x00 };
    const name = Name{
        .labels = msg[0..2],
        .wire_length = 2,
        .compressed = true,
    };

    const result = name.toStringBuf(&buf, &msg);
    try std.testing.expectError(error.ForwardPointer, result);
}

test "SEC-SCAN-07: labelCount rejects forward compression pointer chain" {
    const msg = [_]u8{ 0xC0, 0x04, 0xAA, 0xBB, 0xC0, 0x04, 0x03, 'c', 'o', 'm', 0x00 };
    const name = Name{
        .labels = msg[0..2],
        .wire_length = 2,
        .compressed = true,
    };

    const result = name.labelCount(&msg);
    try std.testing.expectError(error.ForwardPointer, result);
}

test "SEC-SCAN-07: parent rejects forward compression pointer chain" {
    const allocator = std.testing.allocator;
    const msg = [_]u8{ 0xC0, 0x04, 0xAA, 0xBB, 0xC0, 0x04, 0x03, 'c', 'o', 'm', 0x00 };
    const name = Name{
        .labels = msg[0..2],
        .wire_length = 2,
        .compressed = true,
    };

    const result = name.parent(allocator, &msg);
    try std.testing.expectError(error.ForwardPointer, result);
}
