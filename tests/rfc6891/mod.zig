//! RFC 6891 Test Suite
//!
//! Extension Mechanisms for DNS (EDNS(0))

const std = @import("std");
const dns = @import("dns");
const edns_mod = @import("edns");
const message_mod = @import("message");
const types_mod = @import("types");

test "RFC 6891 - OPT record type value" {
    // OPT record type is 41
    try std.testing.expectEqual(@as(u16, 41), types_mod.Type.opt.toInt());
}

test "RFC 6891 - OPT record parsing" {
    // UDP payload size in CLASS field, flags in TTL
    const opt = edns_mod.OptRecord.parse(
        4096, // UDP payload size
        0x00008000, // TTL: DO bit set
        &[_]u8{}, // No options
    );

    try std.testing.expectEqual(@as(u16, 4096), opt.udp_payload_size);
    try std.testing.expectEqual(@as(u8, 0), opt.extended_rcode);
    try std.testing.expectEqual(@as(u8, 0), opt.version);
    try std.testing.expect(opt.dnssec_ok);
}

test "RFC 6891 - OPT record without DNSSEC" {
    const opt = edns_mod.OptRecord.parse(
        1232, // Smaller UDP payload
        0x00000000, // No flags
        &[_]u8{},
    );

    try std.testing.expectEqual(@as(u16, 1232), opt.udp_payload_size);
    try std.testing.expect(!opt.dnssec_ok);
}

test "RFC 6891 - EDNS version in OPT TTL" {
    // Version 1 in bits 16-23 of TTL
    const opt = edns_mod.OptRecord.parse(
        4096,
        0x00010000, // Version 1
        &[_]u8{},
    );

    try std.testing.expectEqual(@as(u8, 1), opt.version);
}

test "RFC 6891 - Extended RCODE in OPT TTL" {
    // Extended RCODE in bits 24-31 of TTL
    const opt = edns_mod.OptRecord.parse(
        4096,
        0x10000000, // Extended RCODE = 16
        &[_]u8{},
    );

    try std.testing.expectEqual(@as(u8, 16), opt.extended_rcode);
}

test "RFC 6891 - OPT record encoding" {
    const opt = edns_mod.OptRecord.default();
    var buffer: [64]u8 = undefined;

    const len = try opt.encode(&buffer);

    // Minimum OPT record: 1 (name) + 2 (type) + 2 (class) + 4 (ttl) + 2 (rdlength) = 11
    try std.testing.expectEqual(@as(usize, 11), len);

    // Check root name
    try std.testing.expectEqual(@as(u8, 0), buffer[0]);

    // Check type (OPT = 41)
    try std.testing.expectEqual(@as(u8, 0), buffer[1]);
    try std.testing.expectEqual(@as(u8, 41), buffer[2]);

    // Check class (UDP payload size = 4096 = 0x1000)
    try std.testing.expectEqual(@as(u8, 0x10), buffer[3]);
    try std.testing.expectEqual(@as(u8, 0x00), buffer[4]);
}

test "RFC 6891 - Option parsing" {
    const options = [_]u8{
        // Cookie option (code 10)
        0x00, 0x0A, // Option code
        0x00, 0x08, // Option length
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Cookie data
    };

    var iter = edns_mod.OptionIterator{ .data = &options, .offset = 0 };

    const opt = iter.next().?;
    try std.testing.expectEqual(edns_mod.OptionCode.cookie, opt.code);
    try std.testing.expectEqual(@as(usize, 8), opt.data.len);

    try std.testing.expect(iter.next() == null);
}

test "RFC 6891 - Multiple options" {
    const options = [_]u8{
        // Padding option (code 12)
        0x00, 0x0C,
        0x00, 0x04,
        0x00, 0x00,
        0x00, 0x00,
        // Cookie option (code 10)
        0x00, 0x0A,
        0x00, 0x08,
        0x11, 0x22,
        0x33, 0x44,
        0x55, 0x66,
        0x77, 0x88,
    };

    var iter = edns_mod.OptionIterator{ .data = &options, .offset = 0 };

    const opt1 = iter.next().?;
    try std.testing.expectEqual(edns_mod.OptionCode.padding, opt1.code);

    const opt2 = iter.next().?;
    try std.testing.expectEqual(edns_mod.OptionCode.cookie, opt2.code);

    try std.testing.expect(iter.next() == null);
}

test "RFC 6891 - Default UDP payload size" {
    try std.testing.expectEqual(@as(u16, 4096), edns_mod.OptRecord.default_udp_size);
}

test "RFC 6891 - Option codes" {
    try std.testing.expectEqual(@as(u16, 8), edns_mod.OptionCode.client_subnet.toInt());
    try std.testing.expectEqual(@as(u16, 10), edns_mod.OptionCode.cookie.toInt());
    try std.testing.expectEqual(@as(u16, 11), edns_mod.OptionCode.tcp_keepalive.toInt());
    try std.testing.expectEqual(@as(u16, 12), edns_mod.OptionCode.padding.toInt());
    try std.testing.expectEqual(@as(u16, 15), edns_mod.OptionCode.extended_error.toInt());
}
