// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DNS Question Section
//!
//! RFC 1035 Section 4.1.2: Question Section Format
//!
//!                                     1  1  1  1  1  1
//!       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                                               |
//!     /                     QNAME                     /
//!     /                                               /
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                     QTYPE                     |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                     QCLASS                    |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

const std = @import("std");
const name_mod = @import("name");
const types_mod = @import("types");

pub const Name = name_mod.Name;
pub const Type = types_mod.Type;
pub const Class = types_mod.Class;

/// DNS Question (RFC 1035 Section 4.1.2)
pub const Question = struct {
    /// Query name
    qname: Name,

    /// Query type
    qtype: Type,

    /// Query class
    qclass: Class,

    /// Total wire length of this question
    wire_length: usize,

    const Self = @This();

    /// Parse a question from wire format
    pub fn parse(data: []const u8, offset: usize) !Self {
        if (offset >= data.len) {
            return error.InvalidOffset;
        }

        const qname = try Name.parse(data, offset);
        const name_end = offset + qname.wire_length;

        if (name_end + 4 > data.len) {
            return error.UnexpectedEnd;
        }

        const qtype_bytes = data[name_end..][0..2];
        const qclass_bytes = data[name_end + 2 ..][0..2];

        return Self{
            .qname = qname,
            .qtype = Type.fromInt(std.mem.readInt(u16, qtype_bytes, .big)),
            .qclass = Class.fromInt(std.mem.readInt(u16, qclass_bytes, .big)),
            .wire_length = qname.wire_length + 4,
        };
    }

    /// Encode a question to wire format
    pub fn encode(self: Self, allocator: std.mem.Allocator, domain: []const u8) ![]u8 {
        const encoded_name = try Name.encode(allocator, domain);
        errdefer allocator.free(encoded_name);

        const result = try allocator.alloc(u8, encoded_name.len + 4);
        errdefer allocator.free(result);

        @memcpy(result[0..encoded_name.len], encoded_name);
        allocator.free(encoded_name);

        std.mem.writeInt(u16, result[result.len - 4 ..][0..2], self.qtype.toInt(), .big);
        std.mem.writeInt(u16, result[result.len - 2 ..][0..2], self.qclass.toInt(), .big);

        return result;
    }

    /// Create a new question
    pub fn new(qtype: Type, qclass: Class) Self {
        return Self{
            .qname = undefined,
            .qtype = qtype,
            .qclass = qclass,
            .wire_length = 0,
        };
    }

    /// Get the question name as a string
    pub fn getName(self: Self, allocator: std.mem.Allocator, full_message: ?[]const u8) ![]u8 {
        return self.qname.toString(allocator, full_message);
    }
};

/// Build a DNS query for a given domain and type
pub fn buildQuery(allocator: std.mem.Allocator, domain: []const u8, qtype: Type, qclass: Class) ![]u8 {
    const encoded_name = try Name.encode(allocator, domain);
    defer allocator.free(encoded_name);

    const result = try allocator.alloc(u8, encoded_name.len + 4);
    @memcpy(result[0..encoded_name.len], encoded_name);
    std.mem.writeInt(u16, result[encoded_name.len..][0..2], qtype.toInt(), .big);
    std.mem.writeInt(u16, result[encoded_name.len + 2 ..][0..2], qclass.toInt(), .big);

    return result;
}

test "Question.parse" {
    const data = [_]u8{
        // Name: example.com
        7,    'e', 'x', 'a', 'm', 'p',  'l',  'e',
        3,    'c', 'o', 'm', 0,
        // QTYPE: A (1)
          0x00, 0x01,
        // QCLASS: IN (1)
        0x00,
        0x01,
    };

    const question = try Question.parse(&data, 0);

    try std.testing.expectEqual(Type.a, question.qtype);
    try std.testing.expectEqual(Class.in, question.qclass);
    try std.testing.expectEqual(@as(usize, 17), question.wire_length);

    const allocator = std.testing.allocator;
    const name_str = try question.getName(allocator, null);
    defer allocator.free(name_str);

    try std.testing.expectEqualStrings("example.com", name_str);
}

test "buildQuery" {
    const allocator = std.testing.allocator;
    const query = try buildQuery(allocator, "example.com", .a, .in);
    defer allocator.free(query);

    try std.testing.expectEqualSlices(u8, &[_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
        0x00, 0x01, // A
        0x00, 0x01, // IN
    }, query);
}

test "Question for AAAA record" {
    const data = [_]u8{
        // Name: ipv6.example.com
        4,    'i',  'p', 'v',  '6',
        7,    'e',  'x', 'a',  'm',
        'p',  'l',  'e', 3,    'c',
        'o',  'm',  0,
        // QTYPE: AAAA (28)
          0x00, 0x1C,
        // QCLASS: IN (1)
        0x00, 0x01,
    };

    const question = try Question.parse(&data, 0);

    try std.testing.expectEqual(Type.aaaa, question.qtype);
    try std.testing.expectEqual(Class.in, question.qclass);
}
