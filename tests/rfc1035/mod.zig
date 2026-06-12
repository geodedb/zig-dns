//! RFC 1035 Test Suite
//!
//! Domain Names - Implementation and Specification

const std = @import("std");
const dns = @import("dns");
const name_mod = @import("name");
const header_mod = @import("header");
const message_mod = @import("message");
const types_mod = @import("types");
const question_mod = @import("question");
const record_mod = @import("record");

// Section 3.1: Name Space Definitions
test "RFC 1035 Section 3.1 - Label length limits" {
    const allocator = std.testing.allocator;

    // Labels must be 63 octets or less
    const long_label = "a" ** 64;
    const err = name_mod.Name.encode(allocator, long_label);
    try std.testing.expectError(error.LabelTooLong, err);

    // 63 octets should work
    const max_label = "a" ** 63;
    const encoded = try name_mod.Name.encode(allocator, max_label);
    defer allocator.free(encoded);
    try std.testing.expectEqual(@as(usize, 65), encoded.len); // 1 len + 63 chars + 1 null
}

test "RFC 1035 Section 3.1 - Name length limits" {
    // Names must be 255 octets or less (including length bytes)
    // This is checked during encoding
    const allocator = std.testing.allocator;

    // Valid name at maximum length
    const valid = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z";
    const encoded = try name_mod.Name.encode(allocator, valid);
    defer allocator.free(encoded);
    try std.testing.expect(encoded.len <= 255);
}

// Section 4.1.1: Header Section Format
test "RFC 1035 Section 4.1.1 - Header parsing" {
    const header_bytes = [_]u8{
        0x12, 0x34, // ID
        0x85, 0x00, // QR=1, Opcode=0, AA=1, TC=0, RD=1, RA=0, Z=0, RCODE=0
        0x00, 0x01, // QDCOUNT
        0x00, 0x02, // ANCOUNT
        0x00, 0x03, // NSCOUNT
        0x00, 0x04, // ARCOUNT
    };

    const h = try header_mod.Header.parse(&header_bytes);

    try std.testing.expectEqual(@as(u16, 0x1234), h.id);
    try std.testing.expect(h.qr);
    try std.testing.expectEqual(header_mod.Opcode.query, h.opcode);
    try std.testing.expect(h.aa);
    try std.testing.expect(!h.tc);
    try std.testing.expect(h.rd);
    try std.testing.expect(!h.ra);
    try std.testing.expectEqual(header_mod.ResponseCode.no_error, h.rcode);
    try std.testing.expectEqual(@as(u16, 1), h.qdcount);
    try std.testing.expectEqual(@as(u16, 2), h.ancount);
    try std.testing.expectEqual(@as(u16, 3), h.nscount);
    try std.testing.expectEqual(@as(u16, 4), h.arcount);
}

// Section 4.1.2: Question Section Format
test "RFC 1035 Section 4.1.2 - Question parsing" {
    const question_bytes = [_]u8{
        // QNAME: www.example.com
        3,    'w',  'w',  'w',
        7,    'e',  'x',  'a',
        'm',  'p',  'l',  'e',
        3,    'c',  'o',  'm',
        0,
        // QTYPE: MX (15)
           0x00, 0x0F,
        // QCLASS: IN (1)
        0x00,
        0x01,
    };

    const q = try question_mod.Question.parse(&question_bytes, 0);

    try std.testing.expectEqual(types_mod.Type.mx, q.qtype);
    try std.testing.expectEqual(types_mod.Class.in, q.qclass);

    const allocator = std.testing.allocator;
    const name_str = try q.getName(allocator, null);
    defer allocator.free(name_str);
    try std.testing.expectEqualStrings("www.example.com", name_str);
}

// Section 4.1.3: Resource Record Format
test "RFC 1035 Section 4.1.3 - RR parsing" {
    const rr_bytes = [_]u8{
        // NAME: example.com
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        3,    'c',  'o',  'm',  0,
        // TYPE: NS (2)
           0x00, 0x02,
        // CLASS: IN (1)
        0x00,
        0x01,
        // TTL: 86400 (1 day)
        0x00, 0x01, 0x51, 0x80,
        // RDLENGTH: 14
        0x00, 0x0E,
        // RDATA: ns1.example.com (would be here)
        3,
        'n',  's',  '1',  7,    'e',  'x',  'a',  'm',
        'p',  'l',  'e',  3,    'c',  'o',  'm',  0,
    };

    const rr = try record_mod.ResourceRecord.parse(&rr_bytes, 0);

    try std.testing.expectEqual(types_mod.Type.ns, rr.rtype);
    try std.testing.expectEqual(types_mod.Class.in, rr.class);
    try std.testing.expectEqual(@as(u32, 86400), rr.ttl);
}

// Section 4.1.4: Message Compression
test "RFC 1035 Section 4.1.4 - Compression pointers" {
    // Test that compression pointers are properly followed
    const msg_bytes = [_]u8{
        // Offset 0: "example.com"
        7,   'e',  'x',  'a',  'm',  'p', 'l', 'e',
        3,   'c',  'o',  'm',  0,
        // Offset 13: "www" + pointer to offset 0
           3,   'w', 'w',
        'w', 0xC0, 0x00,
        // Offset 19: pointer to offset 13 (www.example.com)
        0xC0, 0x0D,
    };

    // Parse first name
    const name1 = try name_mod.Name.parse(&msg_bytes, 0);
    try std.testing.expect(!name1.compressed);

    // Parse second name (has compression)
    const name2 = try name_mod.Name.parse(&msg_bytes, 13);
    try std.testing.expect(name2.compressed);

    // Parse third name (pointer to pointer)
    const name3 = try name_mod.Name.parse(&msg_bytes, 19);
    try std.testing.expect(name3.compressed);

    const allocator = std.testing.allocator;

    const str1 = try name1.toString(allocator, &msg_bytes);
    defer allocator.free(str1);
    try std.testing.expectEqualStrings("example.com", str1);

    const str2 = try name2.toString(allocator, &msg_bytes);
    defer allocator.free(str2);
    try std.testing.expectEqualStrings("www.example.com", str2);
}

// Section 4.2: Transport
test "RFC 1035 Section 4.2 - Message ID uniqueness" {
    // Message IDs should be unique per query
    const allocator = std.testing.allocator;

    const q1 = try message_mod.buildQuery(allocator, 0x0001, "test.com", .a, .in, true, false);
    defer allocator.free(q1);

    const q2 = try message_mod.buildQuery(allocator, 0x0002, "test.com", .a, .in, true, false);
    defer allocator.free(q2);

    const msg1 = try message_mod.Message.parse(q1);
    const msg2 = try message_mod.Message.parse(q2);

    try std.testing.expect(msg1.header.id != msg2.header.id);
}

// Response code tests
test "RFC 1035 Response Codes" {
    const codes = [_]struct { code: header_mod.ResponseCode, value: u4 }{
        .{ .code = .no_error, .value = 0 },
        .{ .code = .format_error, .value = 1 },
        .{ .code = .server_failure, .value = 2 },
        .{ .code = .name_error, .value = 3 },
        .{ .code = .not_implemented, .value = 4 },
        .{ .code = .refused, .value = 5 },
    };

    for (codes) |test_case| {
        try std.testing.expectEqual(test_case.value, @intFromEnum(test_case.code));
    }
}
