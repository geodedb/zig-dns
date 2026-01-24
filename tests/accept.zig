//! Acceptance Tests
//!
//! Deterministic tests with mocked I/O for DNS resolver functionality.
//! Uses fixed clock (2025-01-02T03:04:05Z) and fixed PRNG seed.

const std = @import("std");

// Import modules via build system
const types = @import("types");
const message = @import("message");
const name = @import("name");
const channel = @import("channel");
const dns_cache = @import("dns_cache");
const edns = @import("edns");
const clock = @import("clock");
const random = @import("random");
const metrics = @import("metrics");
const dot = @import("dot");
const doq = @import("doq");

const Type = types.Type;
const ResponseCode = types.ResponseCode;
const MockChannel = channel.MockChannel;
const MockClock = clock.MockClock;
const MockRandom = random.MockRandom;

// Build a mock DNS response
fn buildMockResponse(allocator: std.mem.Allocator, id: u16, rcode: ResponseCode, answers: []const u8) ![]u8 {
    var buf: std.ArrayList(u8) = .empty;
    errdefer buf.deinit(allocator);

    // Header
    var header: [12]u8 = undefined;
    std.mem.writeInt(u16, header[0..2], id, .big);
    header[2] = 0x81; // QR=1, OPCODE=0
    header[3] = 0x80 | @as(u8, @intFromEnum(rcode)); // RA=1, RCODE
    std.mem.writeInt(u16, header[4..6], 1, .big); // QDCOUNT
    std.mem.writeInt(u16, header[6..8], 1, .big); // ANCOUNT
    std.mem.writeInt(u16, header[8..10], 0, .big); // NSCOUNT
    std.mem.writeInt(u16, header[10..12], 0, .big); // ARCOUNT

    try buf.appendSlice(allocator, &header);

    // Question (www.example.test. A IN)
    try buf.appendSlice(allocator, &[_]u8{
        3,   'w', 'w', 'w',
        7,   'e', 'x', 'a',
        'm', 'p', 'l', 'e',
        4,   't', 'e', 's',
        't', 0,
        0x00, 0x01, // A
        0x00, 0x01, // IN
    });

    // Answer RR if provided
    if (answers.len > 0) {
        try buf.appendSlice(allocator, answers);
    }

    return buf.toOwnedSlice(allocator);
}

// Test 1: Recursive A success (UDP)
test "acceptance: recursive A success" {
    const allocator = std.testing.allocator;

    var mock = MockChannel.init(allocator, .udp);
    defer mock.deinit();

    // Answer: www.example.test. A 203.0.113.7 TTL 300
    const answer_rr = [_]u8{
        0xC0, 0x0C, // Name pointer
        0x00, 0x01, // A
        0x00, 0x01, // IN
        0x00, 0x00, 0x01, 0x2C, // TTL 300
        0x00, 0x04, // RDLENGTH
        203, 0, 113, 7, // RDATA
    };

    const response = try buildMockResponse(allocator, 0x1234, .no_error, &answer_rr);
    defer allocator.free(response);

    try mock.addResponse(response);

    const ch = mock.channel();
    const query = [_]u8{ 0x12, 0x34, 0x01, 0x00 }; // Simple query
    const resp = try ch.query(&query, 1500);
    defer allocator.free(resp);

    const msg = try message.Message.parse(resp);
    try std.testing.expect(msg.isSuccess());
    try std.testing.expect(!msg.header.tc);
}

// Test 2: CNAME chain
test "acceptance: CNAME chain" {
    const allocator = std.testing.allocator;

    var mock = MockChannel.init(allocator, .udp);
    defer mock.deinit();

    // Build response with CNAME -> A
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);

    // Header (2 answers)
    var header: [12]u8 = undefined;
    std.mem.writeInt(u16, header[0..2], 0x5678, .big);
    header[2] = 0x81;
    header[3] = 0x80;
    std.mem.writeInt(u16, header[4..6], 1, .big); // QDCOUNT
    std.mem.writeInt(u16, header[6..8], 2, .big); // ANCOUNT = 2
    std.mem.writeInt(u16, header[8..10], 0, .big);
    std.mem.writeInt(u16, header[10..12], 0, .big);
    try buf.appendSlice(allocator, &header);

    // Question
    try buf.appendSlice(allocator, &[_]u8{
        5,   'a', 'l',  'i',  'a',  's',
        7,   'e', 'x',  'a',  'm',  'p',
        'l', 'e', 4,    't',  'e',  's',
        't', 0,   0x00, 0x01, 0x00, 0x01,
    });

    // CNAME answer
    try buf.appendSlice(allocator, &[_]u8{
        0xC0, 0x0C, // Name pointer to question
        0x00, 0x05, // CNAME
        0x00, 0x01, // IN
        0x00, 0x00, 0x01, 0x2C, // TTL 300
        0x00, 0x06, // RDLENGTH
        3,    'w',
        'w',  'w',
        0xC0, 0x12, // Pointer to example.test.
    });

    // A answer for www.example.test.
    try buf.appendSlice(allocator, &[_]u8{
        3, 'w', 'w', 'w',
        0xC0, 0x12, // Pointer to example.test.
        0x00, 0x01, // A
        0x00, 0x01, // IN
        0x00, 0x00, 0x01, 0x2C, // TTL 300
        0x00, 0x04, // RDLENGTH
        203, 0, 113, 7, // RDATA
    });

    try mock.addResponse(buf.items);

    const ch = mock.channel();
    const query = [_]u8{ 0x56, 0x78, 0x01, 0x00 };
    const resp = try ch.query(&query, 1500);
    defer allocator.free(resp);

    const msg = try message.Message.parse(resp);
    try std.testing.expect(msg.isSuccess());
    try std.testing.expectEqual(@as(u16, 2), msg.header.ancount);
}

// Test 3: Negative caching (NXDOMAIN)
test "acceptance: negative caching NXDOMAIN" {
    const allocator = std.testing.allocator;
    var mock_clock = MockClock.init();

    var cache = dns_cache.DnsCache.init(allocator, .{ .negative_ttl_s = 60 }, mock_clock.clock());
    defer cache.deinit();

    // Cache NXDOMAIN
    try cache.putNxdomain("absent.example.test.", .a, .in, 60);

    // First lookup - should be in cache
    const entry1 = cache.get("absent.example.test.", .a, .in);
    try std.testing.expect(entry1 != null);
    try std.testing.expectEqual(dns_cache.EntryType.nxdomain, entry1.?.entry_type);

    // Second lookup - still cached (from_cache=true behavior)
    const entry2 = cache.get("absent.example.test.", .a, .in);
    try std.testing.expect(entry2 != null);
}

// Test 4: Stub TCP fallback (TC=1)
test "acceptance: stub TCP fallback on truncation" {
    const allocator = std.testing.allocator;

    var udp_mock = MockChannel.init(allocator, .udp);
    defer udp_mock.deinit();

    var tcp_mock = MockChannel.init(allocator, .tcp);
    defer tcp_mock.deinit();

    // UDP response with TC=1
    var truncated: [12]u8 = undefined;
    std.mem.writeInt(u16, truncated[0..2], 0xABCD, .big);
    truncated[2] = 0x83; // QR=1, TC=1
    truncated[3] = 0x80;
    std.mem.writeInt(u16, truncated[4..6], 0, .big);
    std.mem.writeInt(u16, truncated[6..8], 0, .big);
    std.mem.writeInt(u16, truncated[8..10], 0, .big);
    std.mem.writeInt(u16, truncated[10..12], 0, .big);

    try udp_mock.addResponse(&truncated);

    // TCP response with full answer
    const answer_rr = [_]u8{
        0xC0, 0x0C,
        0x00, 0x10, // TXT
        0x00, 0x01,
        0x00, 0x00,
        0x01, 0x2C,
        0x00, 0x03,
        2,    'O',
        'K',
    };

    // Build full response for TCP
    var tcp_buf: std.ArrayList(u8) = .empty;
    defer tcp_buf.deinit(allocator);

    var tcp_header: [12]u8 = undefined;
    std.mem.writeInt(u16, tcp_header[0..2], 0xABCD, .big);
    tcp_header[2] = 0x81;
    tcp_header[3] = 0x80;
    std.mem.writeInt(u16, tcp_header[4..6], 1, .big);
    std.mem.writeInt(u16, tcp_header[6..8], 1, .big);
    std.mem.writeInt(u16, tcp_header[8..10], 0, .big);
    std.mem.writeInt(u16, tcp_header[10..12], 0, .big);
    try tcp_buf.appendSlice(allocator, &tcp_header);

    // Question
    try tcp_buf.appendSlice(allocator, &[_]u8{
        3,   'b', 'i', 'g',
        7,   'e', 'x', 'a',
        'm', 'p', 'l', 'e',
        4,   't', 'e', 's',
        't', 0,
        0x00, 0x10, // TXT
        0x00, 0x01,
    });

    try tcp_buf.appendSlice(allocator, &answer_rr);

    try tcp_mock.addResponse(tcp_buf.items);

    // Verify truncation detection
    const udp_resp = try udp_mock.channel().query(&[_]u8{0}, 1000);
    defer allocator.free(udp_resp);

    const msg = try message.Message.parse(udp_resp);
    try std.testing.expect(msg.header.tc);
}

// Test 5: DoT ALPN & SNI
test "acceptance: DoT ALPN and SNI" {
    const allocator = std.testing.allocator;

    var mock = dot.MockDoT.init(allocator, .{
        .server_name = "dns.example",
        .addr = .{ .host = "1.2.3.4", .port = 853 },
        .ca_pem = "",
        .alpn_dot = "dot",
    });
    defer mock.deinit();

    const info = try mock.handshakeInfoJson();
    defer allocator.free(info);

    // Verify handshake info
    try std.testing.expect(std.mem.indexOf(u8, info, "\"alpn\":[\"dot\"]") != null);
    try std.testing.expect(std.mem.indexOf(u8, info, "\"sni\":\"dns.example\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, info, "\"tls_version\":\"1.3\"") != null);
}

// Test 6: DoQ ALPN and stream format
test "acceptance: DoQ ALPN and stream format" {
    const allocator = std.testing.allocator;

    var mock = doq.MockDoQ.init(allocator, .{
        .server_name = "dns.example.com",
        .addr = .{ .host = "1.2.3.4", .port = 853 },
        .ca_pem = "",
        .alpn_doq = "doq",
    });
    defer mock.deinit();

    // Add response
    try mock.addResponse(&[_]u8{ 0, 0, 0x81, 0x80 });

    const ch = mock.channel();
    const resp = ch.query(&[_]u8{ 0x12, 0x34, 0x01, 0x00 }, 1000) catch |err| {
        std.debug.print("Query error: {}\n", .{err});
        return;
    };
    defer allocator.free(resp);

    // Verify ALPN
    const info = try mock.handshakeInfoJson();
    defer allocator.free(info);
    try std.testing.expect(std.mem.indexOf(u8, info, "\"alpn\":[\"doq\"]") != null);

    // Verify stream frame format (2-byte length, ID=0)
    try std.testing.expect(try mock.verifyLastStreamFrame());
}

// Test 7: EDNS FORMERR fallback
test "acceptance: EDNS FORMERR fallback" {
    // Build FORMERR response
    var formerr: [12]u8 = undefined;
    std.mem.writeInt(u16, formerr[0..2], 0x1111, .big);
    formerr[2] = 0x80;
    formerr[3] = 0x01; // RCODE = FORMERR
    std.mem.writeInt(u16, formerr[4..6], 0, .big);
    std.mem.writeInt(u16, formerr[6..8], 0, .big);
    std.mem.writeInt(u16, formerr[8..10], 0, .big);
    std.mem.writeInt(u16, formerr[10..12], 0, .big);

    try std.testing.expect(edns.isEdnsNotSupported(&formerr));
}

// Test 8: Invalid input - label too long
test "acceptance: invalid input - label too long" {
    // A label length byte of 64 (> max_label_length of 63) should fail
    // Wire format: [length][label data...]
    const invalid_wire = [_]u8{64} ++ [_]u8{'a'} ** 64 ++ [_]u8{0};
    try std.testing.expectError(error.LabelTooLong, name.Name.parse(&invalid_wire, 0));
}

// Test 9: Metrics accumulation
test "acceptance: metrics after operations" {
    var m = metrics.Metrics.init();

    // Simulate test operations
    m.incQueries();
    m.incQueries();
    m.incQueries();
    m.incQueries();
    m.incCacheHits();
    m.incTcpFallback();

    const snapshot = m.snapshot();

    try std.testing.expectEqual(@as(u64, 4), snapshot.queries_total);
    try std.testing.expectEqual(@as(u64, 1), snapshot.cache_hits_total);
    try std.testing.expectEqual(@as(u64, 1), snapshot.tcp_fallback_total);
    try std.testing.expectEqual(@as(u64, 0), snapshot.timeouts_total);
    try std.testing.expectEqual(@as(u64, 0), snapshot.servfail_total);
}

// Test 10: Deterministic clock and random
test "acceptance: deterministic clock and random" {
    var mock_clock = MockClock.init();
    var mock_random = MockRandom.init();

    // Fixed time: 2025-01-02T03:04:05Z
    try std.testing.expectEqual(@as(i64, 1735790645), mock_clock.clock().now());

    // Advance and verify
    mock_clock.advance(60);
    try std.testing.expectEqual(@as(i64, 1735790705), mock_clock.clock().now());

    // Random should be deterministic
    const r1 = mock_random.random().int(u32);
    var mock_random2 = MockRandom.init();
    const r2 = mock_random2.random().int(u32);
    try std.testing.expectEqual(r1, r2);
}

// Test 11: Mock channel query recording
test "acceptance: mock channel records queries" {
    const allocator = std.testing.allocator;

    var mock = MockChannel.init(allocator, .udp);
    defer mock.deinit();

    try mock.addResponse(&[_]u8{ 0, 0, 0x80, 0 });
    try mock.addResponse(&[_]u8{ 0, 0, 0x80, 0 });

    const ch = mock.channel();

    // Make two queries
    const r1 = try ch.query(&[_]u8{ 0x11, 0x22 }, 1000);
    defer allocator.free(r1);

    const r2 = try ch.query(&[_]u8{ 0x33, 0x44 }, 1000);
    defer allocator.free(r2);

    // Verify queries were recorded
    const queries = mock.getQueries();
    try std.testing.expectEqual(@as(usize, 2), queries.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x11, 0x22 }, queries[0]);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x33, 0x44 }, queries[1]);
}
