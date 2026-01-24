//! RFC 3596 Test Suite
//!
//! DNS Extensions to Support IP Version 6

const std = @import("std");
const dns = @import("dns");
const types_mod = @import("types");
const record_mod = @import("record");

test "RFC 3596 - AAAA record type value" {
    // AAAA record type is 28
    try std.testing.expectEqual(@as(u16, 28), types_mod.Type.aaaa.toInt());
}

test "RFC 3596 - AAAA record parsing" {
    const aaaa_rr = [_]u8{
        // NAME: ipv6.example.com
        4,    'i',  'p',  'v',  '6',
        7,    'e',  'x',  'a',  'm',
        'p',  'l',  'e',  3,    'c',
        'o',  'm',  0,
        // TYPE: AAAA (28)
           0x00, 0x1C,
        // CLASS: IN (1)
        0x00, 0x01,
        // TTL: 3600
        0x00, 0x00, 0x0E,
        0x10,
        // RDLENGTH: 16
        0x00, 0x10,
        // RDATA: 2001:0db8:85a3:0000:0000:8a2e:0370:7334
        0x20, 0x01,
        0x0d, 0xb8, 0x85, 0xa3, 0x00,
        0x00, 0x00, 0x00, 0x8a, 0x2e,
        0x03, 0x70, 0x73, 0x34,
    };

    const rr = try record_mod.ResourceRecord.parse(&aaaa_rr, 0);

    try std.testing.expectEqual(types_mod.Type.aaaa, rr.rtype);
    try std.testing.expectEqual(@as(u16, 16), rr.rdlength);

    const addr = try rr.parseAAAA();
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00,
        0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34,
    }, &addr);
}

test "RFC 3596 - AAAA record wrong length" {
    const bad_aaaa = [_]u8{
        // NAME: test.com
        4,    't',  'e',  's',  't',
        3,    'c',  'o',  'm',  0,
        // TYPE: AAAA (28)
        0x00, 0x1C,
        // CLASS: IN (1)
        0x00, 0x01,
        // TTL: 300
        0x00,
        0x00, 0x01, 0x2C,
        // RDLENGTH: 4 (WRONG - should be 16)
        0x00, 0x04,
        // RDATA: only 4 bytes
        0x01, 0x02, 0x03, 0x04,
    };

    const rr = try record_mod.ResourceRecord.parse(&bad_aaaa, 0);
    const result = rr.parseAAAA();
    try std.testing.expectError(error.InvalidRdataLength, result);
}

test "RFC 3596 - IPv6 loopback address" {
    const loopback_rr = [_]u8{
        // NAME: localhost
        9,    'l',  'o',  'c',  'a',  'l',  'h',  'o',  's',  't',
        0,
        // TYPE: AAAA
           0x00, 0x1C,
        // CLASS: IN
        0x00, 0x01,
        // TTL: 0
        0x00, 0x00, 0x00, 0x00,
        // RDLENGTH: 16
        0x00,
        0x10,
        // RDATA: ::1 (loopback)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };

    const rr = try record_mod.ResourceRecord.parse(&loopback_rr, 0);
    const addr = try rr.parseAAAA();

    // All zeros except last byte
    for (addr[0..15]) |b| {
        try std.testing.expectEqual(@as(u8, 0), b);
    }
    try std.testing.expectEqual(@as(u8, 1), addr[15]);
}

test "RFC 3596 - IPv6 any address" {
    const any_rr = [_]u8{
        // NAME: any
        3,    'a',  'n',  'y',
        0,
        // TYPE: AAAA
           0x00, 0x1C,
        // CLASS: IN
        0x00,
        0x01,
        // TTL: 0
        0x00, 0x00, 0x00,
        0x00,
        // RDLENGTH: 16
        0x00, 0x10,
        // RDATA: :: (any address, all zeros)
        0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00,
    };

    const rr = try record_mod.ResourceRecord.parse(&any_rr, 0);
    const addr = try rr.parseAAAA();

    // All zeros
    for (addr) |b| {
        try std.testing.expectEqual(@as(u8, 0), b);
    }
}
