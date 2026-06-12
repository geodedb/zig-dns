//! RFC 1035 Test Vectors
//!
//! Test vectors for DNS message parsing and encoding based on RFC 1035.

const std = @import("std");
const dns = @import("dns");
const message = @import("message");
const name_mod = @import("name");
const header = @import("header");
const types = @import("types");

test "parse standard query for example.com A record" {
    const query_bytes = [_]u8{
        // Header
        0xAA, 0xBB, // ID: 0xAABB
        0x01, 0x00, // Flags: RD=1
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        // Question: example.com A IN
        7,    'e',
        'x',  'a',
        'm',  'p',
        'l',  'e',
        3,    'c',
        'o',  'm',
        0,
        0x00, 0x01, // QTYPE: A
        0x00, 0x01, // QCLASS: IN
    };

    const msg = try message.Message.parse(&query_bytes);

    try std.testing.expectEqual(@as(u16, 0xAABB), msg.header.id);
    try std.testing.expect(!msg.header.qr);
    try std.testing.expect(msg.header.rd);
    try std.testing.expectEqual(@as(u16, 1), msg.header.qdcount);
    try std.testing.expectEqual(@as(u16, 0), msg.header.ancount);
}

test "parse standard response with A record" {
    const response_bytes = [_]u8{
        // Header
        0xAA, 0xBB, // ID: 0xAABB
        0x81, 0x80, // Flags: QR=1, RD=1, RA=1
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x01, // ANCOUNT: 1
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        // Question: example.com A IN
        7,    'e',
        'x',  'a',
        'm',  'p',
        'l',  'e',
        3,    'c',
        'o',  'm',
        0,
        0x00, 0x01, // QTYPE: A
        0x00, 0x01, // QCLASS: IN
        // Answer: example.com A IN 300 93.184.216.34
        0xC0, 0x0C, // Name: pointer to offset 12
        0x00, 0x01, // TYPE: A
        0x00, 0x01, // CLASS: IN
        0x00, 0x00, 0x01, 0x2C, // TTL: 300
        0x00, 0x04, // RDLENGTH: 4
        93, 184, 216, 34, // RDATA
    };

    const msg = try message.Message.parse(&response_bytes);

    try std.testing.expect(msg.header.qr);
    try std.testing.expect(msg.header.rd);
    try std.testing.expect(msg.header.ra);
    try std.testing.expectEqual(@as(u16, 1), msg.header.ancount);
    try std.testing.expect(msg.isSuccess());

    var ans_iter = msg.answers();
    const answer = (try ans_iter.next()).?;

    try std.testing.expectEqual(types.Type.a, answer.rtype);
    try std.testing.expectEqual(@as(u32, 300), answer.ttl);

    const ip = try answer.parseA();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 93, 184, 216, 34 }, &ip);
}

test "parse NXDOMAIN response" {
    const nxdomain_bytes = [_]u8{
        // Header
        0xCC, 0xDD, // ID
        0x81, 0x83, // Flags: QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
        // Question: nonexistent.example.com A IN
        11,   'n',
        'o',  'n',
        'e',  'x',
        'i',  's',
        't',  'e',
        'n',  't',
        7,    'e',
        'x',  'a',
        'm',  'p',
        'l',  'e',
        3,    'c',
        'o',  'm',
        0,
        0x00, 0x01, // QTYPE: A
        0x00, 0x01, // QCLASS: IN
    };

    const msg = try message.Message.parse(&nxdomain_bytes);

    try std.testing.expect(msg.isNxdomain());
    try std.testing.expect(!msg.isSuccess());
    try std.testing.expectEqual(header.ResponseCode.name_error, msg.header.rcode);
}

test "name encoding and decoding round-trip" {
    const allocator = std.testing.allocator;

    const domains = [_][]const u8{
        "example.com",
        "www.example.com",
        "a.b.c.d.example.com",
        "test",
        "", // root
    };

    for (domains) |domain| {
        const encoded = try name_mod.Name.encode(allocator, domain);
        defer allocator.free(encoded);

        const parsed = try name_mod.Name.parse(encoded, 0);
        const decoded = try parsed.toString(allocator, null);
        defer allocator.free(decoded);

        if (domain.len == 0) {
            try std.testing.expectEqualStrings(".", decoded);
        } else {
            try std.testing.expectEqualStrings(domain, decoded);
        }
    }
}

test "name compression parsing" {
    // Message with compressed name: www.example.com where "example.com" is compressed
    const data = [_]u8{
        // First name at offset 0: example.com
        7,   'e',  'x',  'a', 'm', 'p', 'l', 'e',
        3,   'c',  'o',  'm', 0,
        // Second name at offset 13: www.<pointer to 0>
          3,   'w', 'w',
        'w', 0xC0, 0x00,
    };

    const name2 = try name_mod.Name.parse(&data, 13);
    try std.testing.expect(name2.compressed);

    const allocator = std.testing.allocator;
    const str = try name2.toString(allocator, &data);
    defer allocator.free(str);

    try std.testing.expectEqualStrings("www.example.com", str);
}

test "header flags encoding" {
    const h = header.Header{
        .id = 0x1234,
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
        .nscount = 0,
        .arcount = 1,
    };

    var buffer: [12]u8 = undefined;
    try h.encode(&buffer);

    // Verify flags byte 2: QR=1, Opcode=0, AA=1, TC=0, RD=1 => 0x85
    try std.testing.expectEqual(@as(u8, 0x85), buffer[2]);
    // Verify flags byte 3: RA=1, Z=0, RCODE=0 => 0x80
    try std.testing.expectEqual(@as(u8, 0x80), buffer[3]);

    // Parse back
    const parsed = try header.Header.parse(&buffer);
    try std.testing.expectEqual(h.id, parsed.id);
    try std.testing.expectEqual(h.qr, parsed.qr);
    try std.testing.expectEqual(h.aa, parsed.aa);
    try std.testing.expectEqual(h.rd, parsed.rd);
    try std.testing.expectEqual(h.ra, parsed.ra);
}

test "build DNS query message" {
    const allocator = std.testing.allocator;
    const query = try message.buildQuery(allocator, 0x5678, "test.example.com", .a, .in, true, false);
    defer allocator.free(query);

    const msg = try message.Message.parse(query);

    try std.testing.expectEqual(@as(u16, 0x5678), msg.header.id);
    try std.testing.expect(!msg.header.qr);
    try std.testing.expect(msg.header.rd);
    try std.testing.expectEqual(@as(u16, 1), msg.header.qdcount);

    var q_iter = msg.questions();
    const q = (try q_iter.next()).?;
    try std.testing.expectEqual(types.Type.a, q.qtype);
    try std.testing.expectEqual(types.Class.in, q.qclass);
}
