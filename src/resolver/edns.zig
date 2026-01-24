// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! EDNS(0) - Extension Mechanisms for DNS
//!
//! RFC 6891: Extension Mechanisms for DNS (EDNS(0))

const std = @import("std");

/// EDNS OPT pseudo-record
pub const EdnsOpt = struct {
    /// UDP payload size (default 1232 for IPv6 safe)
    udp_payload_size: u16 = 1232,
    /// Extended RCODE (high 8 bits)
    extended_rcode: u8 = 0,
    /// EDNS version
    version: u8 = 0,
    /// DNSSEC OK flag
    dnssec_ok: bool = false,
    /// Z field (reserved)
    z: u15 = 0,
    /// Options data
    options: []const u8 = &[_]u8{},

    const Self = @This();

    /// Wire format size (without options)
    pub const base_size: usize = 11;

    /// Encode to wire format
    pub fn encode(self: Self, allocator: std.mem.Allocator) ![]u8 {
        const size = base_size + self.options.len;
        const buf = try allocator.alloc(u8, size);
        errdefer allocator.free(buf);

        buf[0] = 0; // root name
        std.mem.writeInt(u16, buf[1..3], 41, .big); // OPT
        std.mem.writeInt(u16, buf[3..5], self.udp_payload_size, .big);

        var ttl: u32 = 0;
        ttl |= (@as(u32, self.extended_rcode) << 24);
        ttl |= (@as(u32, self.version) << 16);
        if (self.dnssec_ok) ttl |= (1 << 15);
        ttl |= self.z;
        std.mem.writeInt(u32, buf[5..9], ttl, .big);

        std.mem.writeInt(u16, buf[9..11], @intCast(self.options.len), .big);

        if (self.options.len > 0) {
            @memcpy(buf[11..][0..self.options.len], self.options);
        }

        return buf;
    }

    /// Parse from wire format
    pub fn parse(data: []const u8, offset: usize) !Self {
        if (offset + base_size > data.len) {
            return error.UnexpectedEnd;
        }

        if (data[offset] != 0) return error.InvalidOptRecord;

        const rtype = std.mem.readInt(u16, data[offset + 1 ..][0..2], .big);
        if (rtype != 41) return error.InvalidOptRecord;

        const udp_size = std.mem.readInt(u16, data[offset + 3 ..][0..2], .big);
        const ttl = std.mem.readInt(u32, data[offset + 5 ..][0..4], .big);
        const rdlen = std.mem.readInt(u16, data[offset + 9 ..][0..2], .big);

        if (offset + base_size + rdlen > data.len) {
            return error.UnexpectedEnd;
        }

        return Self{
            .udp_payload_size = udp_size,
            .extended_rcode = @truncate(ttl >> 24),
            .version = @truncate((ttl >> 16) & 0xFF),
            .dnssec_ok = (ttl & (1 << 15)) != 0,
            .z = @truncate(ttl & 0x7FFF),
            .options = if (rdlen > 0) data[offset + base_size ..][0..rdlen] else &[_]u8{},
        };
    }
};

/// Check if response indicates EDNS not supported
pub fn isEdnsNotSupported(data: []const u8) bool {
    if (data.len < 12) return false;
    const rcode = data[3] & 0x0F;
    if (rcode != 1) return false; // FORMERR
    const arcount = std.mem.readInt(u16, data[10..12], .big);
    return arcount == 0;
}

test "EdnsOpt encode" {
    const allocator = std.testing.allocator;

    const opt = EdnsOpt{
        .udp_payload_size = 1232,
        .dnssec_ok = true,
    };

    const wire = try opt.encode(allocator);
    defer allocator.free(wire);

    try std.testing.expectEqual(@as(usize, EdnsOpt.base_size), wire.len);
    try std.testing.expectEqual(@as(u8, 0), wire[0]);
}

test "EdnsOpt roundtrip" {
    const allocator = std.testing.allocator;

    const original = EdnsOpt{ .udp_payload_size = 4096 };
    const wire = try original.encode(allocator);
    defer allocator.free(wire);

    const parsed = try EdnsOpt.parse(wire, 0);
    try std.testing.expectEqual(original.udp_payload_size, parsed.udp_payload_size);
}
