// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DNS Message Header
//!
//! RFC 1035 Section 4.1.1: Header Section Format
//!
//! The header contains the following fields:
//!
//!                                     1  1  1  1  1  1
//!       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                      ID                       |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                    QDCOUNT                    |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                    ANCOUNT                    |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                    NSCOUNT                    |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                    ARCOUNT                    |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

const std = @import("std");

/// DNS header size in bytes
pub const header_size = 12;

/// DNS Operation Codes (RFC 1035 Section 4.1.1)
pub const Opcode = enum(u4) {
    /// Standard query
    query = 0,
    /// Inverse query (obsolete)
    iquery = 1,
    /// Server status request
    status = 2,
    /// Notify (RFC 1996)
    notify = 4,
    /// Dynamic update (RFC 2136)
    update = 5,
    /// DNS Stateful Operations (RFC 8490)
    dso = 6,
    _,
};

/// DNS Response Codes (RFC 1035 Section 4.1.1)
pub const ResponseCode = enum(u4) {
    /// No error condition
    no_error = 0,
    /// Format error
    format_error = 1,
    /// Server failure
    server_failure = 2,
    /// Name error (NXDOMAIN)
    name_error = 3,
    /// Not implemented
    not_implemented = 4,
    /// Query refused
    refused = 5,
    /// Name exists when it should not (RFC 2136)
    yxdomain = 6,
    /// RR set exists when it should not (RFC 2136)
    yxrrset = 7,
    /// RR set that should exist does not (RFC 2136)
    nxrrset = 8,
    /// Server not authoritative (RFC 2136)
    not_auth = 9,
    /// Name not contained in zone (RFC 2136)
    not_zone = 10,
    _,

    pub const nxdomain = ResponseCode.name_error;
};

/// DNS Message Header (RFC 1035 Section 4.1.1)
pub const Header = struct {
    /// Transaction ID
    id: u16,

    /// Query/Response flag: false = query, true = response
    qr: bool,

    /// Operation code
    opcode: Opcode,

    /// Authoritative answer flag
    aa: bool,

    /// Truncation flag
    tc: bool,

    /// Recursion desired flag
    rd: bool,

    /// Recursion available flag
    ra: bool,

    /// Reserved bits (must be zero)
    z: u3,

    /// Response code
    rcode: ResponseCode,

    /// Number of questions
    qdcount: u16,

    /// Number of answer records
    ancount: u16,

    /// Number of authority records
    nscount: u16,

    /// Number of additional records
    arcount: u16,

    const Self = @This();

    /// Parse header from wire format
    pub fn parse(data: []const u8) !Self {
        if (data.len < header_size) {
            return error.HeaderTooShort;
        }

        const flags = std.mem.readInt(u16, data[2..4], .big);

        return Self{
            .id = std.mem.readInt(u16, data[0..2], .big),
            .qr = (flags >> 15) & 1 == 1,
            .opcode = @enumFromInt(@as(u4, @truncate((flags >> 11) & 0xF))),
            .aa = (flags >> 10) & 1 == 1,
            .tc = (flags >> 9) & 1 == 1,
            .rd = (flags >> 8) & 1 == 1,
            .ra = (flags >> 7) & 1 == 1,
            .z = @truncate((flags >> 4) & 0x7),
            .rcode = @enumFromInt(@as(u4, @truncate(flags & 0xF))),
            .qdcount = std.mem.readInt(u16, data[4..6], .big),
            .ancount = std.mem.readInt(u16, data[6..8], .big),
            .nscount = std.mem.readInt(u16, data[8..10], .big),
            .arcount = std.mem.readInt(u16, data[10..12], .big),
        };
    }

    /// Encode header to wire format
    pub fn encode(self: Self, buffer: []u8) !void {
        if (buffer.len < header_size) {
            return error.BufferTooSmall;
        }

        std.mem.writeInt(u16, buffer[0..2], self.id, .big);

        var flags: u16 = 0;
        flags |= @as(u16, @intFromBool(self.qr)) << 15;
        flags |= @as(u16, @intFromEnum(self.opcode)) << 11;
        flags |= @as(u16, @intFromBool(self.aa)) << 10;
        flags |= @as(u16, @intFromBool(self.tc)) << 9;
        flags |= @as(u16, @intFromBool(self.rd)) << 8;
        flags |= @as(u16, @intFromBool(self.ra)) << 7;
        flags |= @as(u16, self.z) << 4;
        flags |= @as(u16, @intFromEnum(self.rcode));
        std.mem.writeInt(u16, buffer[2..4], flags, .big);

        std.mem.writeInt(u16, buffer[4..6], self.qdcount, .big);
        std.mem.writeInt(u16, buffer[6..8], self.ancount, .big);
        std.mem.writeInt(u16, buffer[8..10], self.nscount, .big);
        std.mem.writeInt(u16, buffer[10..12], self.arcount, .big);
    }

    /// Create a new query header
    pub fn newQuery(id: u16, rd: bool) Self {
        return Self{
            .id = id,
            .qr = false,
            .opcode = .query,
            .aa = false,
            .tc = false,
            .rd = rd,
            .ra = false,
            .z = 0,
            .rcode = .no_error,
            .qdcount = 0,
            .ancount = 0,
            .nscount = 0,
            .arcount = 0,
        };
    }

    /// Create a response header from a query header
    pub fn newResponse(query: Self, rcode: ResponseCode) Self {
        return Self{
            .id = query.id,
            .qr = true,
            .opcode = query.opcode,
            .aa = false,
            .tc = false,
            .rd = query.rd,
            .ra = true,
            .z = 0,
            .rcode = rcode,
            .qdcount = query.qdcount,
            .ancount = 0,
            .nscount = 0,
            .arcount = 0,
        };
    }

    /// Check if this is a query
    pub fn isQuery(self: Self) bool {
        return !self.qr;
    }

    /// Check if this is a response
    pub fn isResponse(self: Self) bool {
        return self.qr;
    }

    /// Check if the response indicates success
    pub fn isSuccess(self: Self) bool {
        return self.rcode == .no_error;
    }

    /// Check if the name was not found
    pub fn isNxdomain(self: Self) bool {
        return self.rcode == .name_error;
    }
};

test "Header.parse" {
    // Example DNS query header
    const data = [_]u8{
        0x12, 0x34, // ID
        0x01, 0x00, // Flags: QR=0, Opcode=0, AA=0, TC=0, RD=1, RA=0, Z=0, RCODE=0
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
    };

    const header = try Header.parse(&data);

    try std.testing.expectEqual(@as(u16, 0x1234), header.id);
    try std.testing.expect(!header.qr);
    try std.testing.expectEqual(Opcode.query, header.opcode);
    try std.testing.expect(!header.aa);
    try std.testing.expect(!header.tc);
    try std.testing.expect(header.rd);
    try std.testing.expect(!header.ra);
    try std.testing.expectEqual(@as(u3, 0), header.z);
    try std.testing.expectEqual(ResponseCode.no_error, header.rcode);
    try std.testing.expectEqual(@as(u16, 1), header.qdcount);
    try std.testing.expectEqual(@as(u16, 0), header.ancount);
}

test "Header.encode" {
    var header = Header.newQuery(0x1234, true);
    header.qdcount = 1;

    var buffer: [header_size]u8 = undefined;
    try header.encode(&buffer);

    try std.testing.expectEqual(@as(u8, 0x12), buffer[0]);
    try std.testing.expectEqual(@as(u8, 0x34), buffer[1]);
    try std.testing.expectEqual(@as(u8, 0x01), buffer[2]); // RD=1
    try std.testing.expectEqual(@as(u8, 0x00), buffer[3]);
}

test "Header round-trip" {
    const original = Header{
        .id = 0xABCD,
        .qr = true,
        .opcode = .query,
        .aa = true,
        .tc = false,
        .rd = true,
        .ra = true,
        .z = 0,
        .rcode = .no_error,
        .qdcount = 1,
        .ancount = 2,
        .nscount = 3,
        .arcount = 4,
    };

    var buffer: [header_size]u8 = undefined;
    try original.encode(&buffer);

    const parsed = try Header.parse(&buffer);

    try std.testing.expectEqual(original.id, parsed.id);
    try std.testing.expectEqual(original.qr, parsed.qr);
    try std.testing.expectEqual(original.opcode, parsed.opcode);
    try std.testing.expectEqual(original.aa, parsed.aa);
    try std.testing.expectEqual(original.tc, parsed.tc);
    try std.testing.expectEqual(original.rd, parsed.rd);
    try std.testing.expectEqual(original.ra, parsed.ra);
    try std.testing.expectEqual(original.rcode, parsed.rcode);
    try std.testing.expectEqual(original.qdcount, parsed.qdcount);
    try std.testing.expectEqual(original.ancount, parsed.ancount);
    try std.testing.expectEqual(original.nscount, parsed.nscount);
    try std.testing.expectEqual(original.arcount, parsed.arcount);
}
