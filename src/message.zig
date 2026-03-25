// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DNS Message
//!
//! RFC 1035 Section 4: Messages
//!
//! Complete DNS message handling including header, question, answer,
//! authority, and additional sections.

const std = @import("std");
const name_mod = @import("name");
const header_mod = @import("header");
const question_mod = @import("question");
const record_mod = @import("record");
const types_mod = @import("types");

pub const Name = name_mod.Name;
pub const Header = header_mod.Header;
pub const Question = question_mod.Question;
pub const ResourceRecord = record_mod.ResourceRecord;
pub const Type = types_mod.Type;
pub const Class = types_mod.Class;

/// Maximum DNS message size for UDP
pub const max_udp_size = 512;

/// Maximum DNS message size with EDNS
pub const max_edns_size = 65535;

/// Maximum number of records allowed per section (qdcount, ancount, nscount, arcount).
/// This bounds-checks against malicious or malformed messages that claim an
/// unreasonably large record count, preventing CPU-bound parse loops.
/// Normal DNS messages rarely exceed a few hundred records per section;
/// 4096 is generous enough for legitimate zone transfers while still
/// protecting against abuse.
pub const max_section_count = 4096;

/// DNS Message (RFC 1035 Section 4)
pub const Message = struct {
    /// Raw message data.
    /// IMPORTANT: This is a borrowed reference to the caller's buffer.
    /// The caller must ensure the underlying memory outlives this Message.
    /// The Message does NOT own this memory and will NOT free it.
    data: []const u8,

    /// Message header
    header: Header,

    /// Offset where questions begin
    question_offset: usize,

    /// Cached byte offset where answer records begin
    answer_offset: usize,

    /// Cached byte offset where authority records begin
    authority_offset: usize,

    /// Cached byte offset where additional records begin
    additional_offset: usize,

    const Self = @This();

    /// Parse a DNS message from wire format.
    /// Eagerly computes section offsets so that answers(), authority(),
    /// and additional() are O(1) on every call.
    pub fn parse(data: []const u8) !Self {
        const header = try Header.parse(data);

        // ADV-05: Reject messages with unreasonably large section counts
        // to prevent CPU-bound parse loops from malicious/malformed packets.
        if (header.qdcount > max_section_count or
            header.ancount > max_section_count or
            header.nscount > max_section_count or
            header.arcount > max_section_count)
        {
            return error.MessageTooLarge;
        }

        // Compute answer_offset by skipping questions
        var offset: usize = header_mod.header_size;
        var q_remaining = header.qdcount;
        while (q_remaining > 0) : (q_remaining -= 1) {
            const q = try Question.parse(data, offset);
            offset += q.wire_length;
        }
        const answer_off = offset;

        // Compute authority_offset by skipping answers
        var an_remaining = header.ancount;
        while (an_remaining > 0) : (an_remaining -= 1) {
            const rr = try ResourceRecord.parse(data, offset);
            offset += rr.wire_length;
        }
        const authority_off = offset;

        // Compute additional_offset by skipping authority
        var ns_remaining = header.nscount;
        while (ns_remaining > 0) : (ns_remaining -= 1) {
            const rr = try ResourceRecord.parse(data, offset);
            offset += rr.wire_length;
        }
        const additional_off = offset;

        return Self{
            .data = data,
            .header = header,
            .question_offset = header_mod.header_size,
            .answer_offset = answer_off,
            .authority_offset = authority_off,
            .additional_offset = additional_off,
        };
    }

    /// Iterate over questions
    pub fn questions(self: Self) QuestionIterator {
        return QuestionIterator{
            .message = self,
            .offset = self.question_offset,
            .remaining = self.header.qdcount,
        };
    }

    /// Iterate over answer records (O(1) -- uses cached offset)
    pub fn answers(self: Self) RecordIterator {
        return RecordIterator{
            .message = self,
            .offset = self.answer_offset,
            .remaining = self.header.ancount,
        };
    }

    /// Iterate over authority records (O(1) -- uses cached offset)
    pub fn authority(self: Self) RecordIterator {
        return RecordIterator{
            .message = self,
            .offset = self.authority_offset,
            .remaining = self.header.nscount,
        };
    }

    /// Iterate over additional records (O(1) -- uses cached offset)
    pub fn additional(self: Self) RecordIterator {
        return RecordIterator{
            .message = self,
            .offset = self.additional_offset,
            .remaining = self.header.arcount,
        };
    }

    /// Get all answer records of a specific type
    pub fn getAnswers(self: Self, allocator: std.mem.Allocator, rtype: Type) ![]ResourceRecord {
        var result: std.ArrayList(ResourceRecord) = .empty;
        errdefer result.deinit(allocator);

        var iter = self.answers();
        while (try iter.next()) |rr| {
            if (rr.rtype == rtype) {
                try result.append(allocator, rr);
            }
        }

        return result.toOwnedSlice(allocator);
    }

    /// Check if the response is successful
    pub fn isSuccess(self: Self) bool {
        return self.header.isSuccess();
    }

    /// Check if the name was not found
    pub fn isNxdomain(self: Self) bool {
        return self.header.isNxdomain();
    }
};

/// Iterator over DNS questions
pub const QuestionIterator = struct {
    message: Message,
    offset: usize,
    remaining: u16,

    const Self = @This();

    pub fn next(self: *Self) !?Question {
        if (self.remaining == 0) {
            return null;
        }

        const q = try Question.parse(self.message.data, self.offset);
        self.offset += q.wire_length;
        self.remaining -= 1;

        return q;
    }
};

/// Iterator over DNS resource records
pub const RecordIterator = struct {
    message: Message,
    offset: usize,
    remaining: u16,

    const Self = @This();

    pub fn next(self: *Self) !?ResourceRecord {
        if (self.remaining == 0) {
            return null;
        }

        const rr = try ResourceRecord.parse(self.message.data, self.offset);
        self.offset += rr.wire_length;
        self.remaining -= 1;

        return rr;
    }
};

/// DNS Message Builder
pub const MessageBuilder = struct {
    allocator: std.mem.Allocator,
    buffer: std.ArrayList(u8),
    header: Header,
    questions_written: u16,
    answers_written: u16,
    authority_written: u16,
    additional_written: u16,

    const Self = @This();

    /// Create a new message builder for a query
    pub fn initQuery(allocator: std.mem.Allocator, id: u16, rd: bool) !Self {
        var builder = Self{
            .allocator = allocator,
            .buffer = .empty,
            .header = Header.newQuery(id, rd),
            .questions_written = 0,
            .answers_written = 0,
            .authority_written = 0,
            .additional_written = 0,
        };

        // Reserve space for header
        try builder.buffer.appendNTimes(allocator, 0, header_mod.header_size);

        return builder;
    }

    /// Create a new message builder for a response
    pub fn initResponse(allocator: std.mem.Allocator, query: Message, rcode: header_mod.ResponseCode) !Self {
        var builder = Self{
            .allocator = allocator,
            .buffer = .empty,
            .header = Header.newResponse(query.header, rcode),
            .questions_written = 0,
            .answers_written = 0,
            .authority_written = 0,
            .additional_written = 0,
        };

        // Reserve space for header
        try builder.buffer.appendNTimes(allocator, 0, header_mod.header_size);

        return builder;
    }

    /// Add a question
    /// PF-NEW-13: Encode directly into a stack buffer using Name.encodeBuf,
    /// avoiding the intermediate heap allocation from question_mod.buildQuery.
    pub fn addQuestion(self: *Self, domain: []const u8, qtype: Type, qclass: Class) !void {
        // DNS names are at most 255 bytes in wire format + 4 bytes for qtype/qclass
        var buf: [name_mod.max_name_length + 4]u8 = undefined;
        const name = try Name.encodeBuf(domain, buf[0..name_mod.max_name_length]);
        const name_len = name.wire_length;
        std.mem.writeInt(u16, buf[name_len..][0..2], qtype.toInt(), .big);
        std.mem.writeInt(u16, buf[name_len + 2 ..][0..2], qclass.toInt(), .big);

        try self.buffer.appendSlice(self.allocator, buf[0 .. name_len + 4]);
        self.questions_written += 1;
    }

    /// Finalize and return the message
    pub fn finish(self: *Self) ![]u8 {
        // Update header counts
        self.header.qdcount = self.questions_written;
        self.header.ancount = self.answers_written;
        self.header.nscount = self.authority_written;
        self.header.arcount = self.additional_written;

        // Write header
        try self.header.encode(self.buffer.items[0..header_mod.header_size]);

        return try self.buffer.toOwnedSlice(self.allocator);
    }

    /// Free resources
    pub fn deinit(self: *Self) void {
        self.buffer.deinit(self.allocator);
    }
};

/// Build a simple DNS query message
pub fn buildQuery(allocator: std.mem.Allocator, id: u16, domain: []const u8, qtype: Type, qclass: Class, rd: bool) ![]u8 {
    var builder = try MessageBuilder.initQuery(allocator, id, rd);
    errdefer builder.deinit();

    try builder.addQuestion(domain, qtype, qclass);

    return builder.finish();
}

/// Maximum size of a single-question DNS query: 12 (header) + 255 (name) + 4 (qtype/qclass).
pub const max_query_size = header_mod.header_size + name_mod.max_name_length + 4;

/// Build a simple DNS query into a caller-provided buffer (zero heap allocation).
/// Buffer must be at least max_query_size (271) bytes.
/// Returns a slice of `buf` containing the encoded query.
pub fn buildQueryBuf(buf: *[max_query_size]u8, id: u16, domain: []const u8, qtype: Type, qclass: Class, rd: bool) ![]u8 {
    // Encode header
    var header = Header.newQuery(id, rd);
    header.qdcount = 1;
    try header.encode(buf[0..header_mod.header_size]);

    // Encode question name directly into buffer after header
    const name = try Name.encodeBuf(domain, buf[header_mod.header_size..][0..name_mod.max_name_length]);
    const q_start = header_mod.header_size + name.wire_length;
    std.mem.writeInt(u16, buf[q_start..][0..2], qtype.toInt(), .big);
    std.mem.writeInt(u16, buf[q_start + 2 ..][0..2], qclass.toInt(), .big);

    return buf[0 .. q_start + 4];
}

test "Message.parse simple query" {
    // DNS query for example.com A record
    const data = [_]u8{
        // Header
        0x12, 0x34, // ID
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

    const msg = try Message.parse(&data);

    try std.testing.expectEqual(@as(u16, 0x1234), msg.header.id);
    try std.testing.expect(!msg.header.qr);
    try std.testing.expect(msg.header.rd);
    try std.testing.expectEqual(@as(u16, 1), msg.header.qdcount);

    var q_iter = msg.questions();
    const q = (try q_iter.next()).?;
    try std.testing.expectEqual(Type.a, q.qtype);
    try std.testing.expectEqual(Class.in, q.qclass);
}

test "Message.parse response with answer" {
    // DNS response for example.com A record
    const data = [_]u8{
        // Header
        0x12, 0x34, // ID
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
        0xC0, 0x0C, // Name pointer to offset 12
        0x00, 0x01, // TYPE: A
        0x00, 0x01, // CLASS: IN
        0x00, 0x00, 0x01, 0x2C, // TTL: 300
        0x00, 0x04, // RDLENGTH: 4
        93, 184, 216, 34, // RDATA
    };

    const msg = try Message.parse(&data);

    try std.testing.expect(msg.header.qr);
    try std.testing.expectEqual(@as(u16, 1), msg.header.ancount);
    try std.testing.expect(msg.isSuccess());

    var ans_iter = msg.answers();
    const ans = (try ans_iter.next()).?;
    try std.testing.expectEqual(Type.a, ans.rtype);

    const addr = try ans.parseA();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 93, 184, 216, 34 }, &addr);
}

test "buildQuery" {
    const allocator = std.testing.allocator;
    const query = try buildQuery(allocator, 0x1234, "example.com", .a, .in, true);
    defer allocator.free(query);

    const msg = try Message.parse(query);
    try std.testing.expectEqual(@as(u16, 0x1234), msg.header.id);
    try std.testing.expect(!msg.header.qr);
    try std.testing.expect(msg.header.rd);
    try std.testing.expectEqual(@as(u16, 1), msg.header.qdcount);
}

test "Message section offsets are cached - multiple calls yield same results" {
    // DNS response with 1 question, 1 answer, 1 authority (NS), 1 additional (A)
    const data = [_]u8{
        // Header
        0x12, 0x34, // ID
        0x81, 0x80, // Flags: QR=1, RD=1, RA=1
        0x00, 0x01, // QDCOUNT: 1
        0x00, 0x01, // ANCOUNT: 1
        0x00, 0x01, // NSCOUNT: 1
        0x00, 0x01, // ARCOUNT: 1
        // Question: example.com A IN (offset 12)
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
        0xC0, 0x0C, // Name pointer to offset 12
        0x00, 0x01, // TYPE: A
        0x00, 0x01, // CLASS: IN
        0x00, 0x00, 0x01, 0x2C, // TTL: 300
        0x00, 0x04, // RDLENGTH: 4
        93, 184, 216, 34, // RDATA
        // Authority: example.com NS ns1.example.com
        0xC0, 0x0C, // Name pointer to offset 12
        0x00, 0x02, // TYPE: NS
        0x00, 0x01, // CLASS: IN
        0x00, 0x00, 0x0E, 0x10, // TTL: 3600
        0x00, 0x06, // RDLENGTH: 6
        3,    'n',
        's',  '1',
        0xC0, 0x0C, // pointer to example.com
        // Additional: ns1.example.com A 1.2.3.4
        3,    'n',
        's',  '1',
        0xC0, 0x0C, // pointer to example.com
        0x00, 0x01, // TYPE: A
        0x00, 0x01, // CLASS: IN
        0x00, 0x00, 0x0E, 0x10, // TTL: 3600
        0x00, 0x04, // RDLENGTH: 4
        1,    2,
        3,    4,
    };

    const msg = try Message.parse(&data);

    // Verify cached offsets are set
    try std.testing.expect(msg.answer_offset > msg.question_offset);
    try std.testing.expect(msg.authority_offset > msg.answer_offset);
    try std.testing.expect(msg.additional_offset > msg.authority_offset);

    // Call answers() twice, verify both return same first record
    {
        var iter1 = msg.answers();
        const rr1 = (try iter1.next()).?;
        var iter2 = msg.answers();
        const rr2 = (try iter2.next()).?;
        try std.testing.expectEqual(rr1.rtype, rr2.rtype);
        try std.testing.expectEqual(Type.a, rr1.rtype);
        const addr = try rr1.parseA();
        try std.testing.expectEqualSlices(u8, &[_]u8{ 93, 184, 216, 34 }, &addr);
    }

    // Call authority() twice, verify both return same record
    {
        var iter1 = msg.authority();
        const rr1 = (try iter1.next()).?;
        var iter2 = msg.authority();
        const rr2 = (try iter2.next()).?;
        try std.testing.expectEqual(rr1.rtype, rr2.rtype);
        try std.testing.expectEqual(Type.ns, rr1.rtype);
    }

    // Call additional() twice, verify both return same record
    {
        var iter1 = msg.additional();
        const rr1 = (try iter1.next()).?;
        var iter2 = msg.additional();
        const rr2 = (try iter2.next()).?;
        try std.testing.expectEqual(rr1.rtype, rr2.rtype);
        try std.testing.expectEqual(Type.a, rr1.rtype);
        const addr = try rr1.parseA();
        try std.testing.expectEqualSlices(u8, &[_]u8{ 1, 2, 3, 4 }, &addr);
    }
}

test "Message section offsets with empty sections" {
    // DNS query with 1 question, no answers/authority/additional
    const data = [_]u8{
        // Header
        0x12, 0x34, // ID
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

    const msg = try Message.parse(&data);

    // All section offsets point to end of question section
    try std.testing.expectEqual(msg.answer_offset, msg.authority_offset);
    try std.testing.expectEqual(msg.authority_offset, msg.additional_offset);

    // answers() returns no records
    var ans_iter = msg.answers();
    try std.testing.expect(try ans_iter.next() == null);

    // authority() returns no records
    var auth_iter = msg.authority();
    try std.testing.expect(try auth_iter.next() == null);

    // additional() returns no records
    var add_iter = msg.additional();
    try std.testing.expect(try add_iter.next() == null);
}

test "Message.parse rejects excessive section counts" {
    // Craft a header with ANCOUNT exceeding max_section_count (4096).
    // We set ANCOUNT to 0xFFFF (65535) which far exceeds the limit.
    const data = [_]u8{
        // Header
        0x12, 0x34, // ID
        0x81, 0x80, // Flags: QR=1, RD=1, RA=1
        0x00, 0x00, // QDCOUNT: 0
        0xFF, 0xFF, // ANCOUNT: 65535 (exceeds max_section_count)
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
    };

    try std.testing.expectError(error.MessageTooLarge, Message.parse(&data));
}

test "Message.parse rejects excessive qdcount" {
    const data = [_]u8{
        0x12, 0x34, // ID
        0x01, 0x00, // Flags
        0xFF, 0xFF, // QDCOUNT: 65535
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
    };

    try std.testing.expectError(error.MessageTooLarge, Message.parse(&data));
}

test "Message.parse rejects excessive nscount" {
    const data = [_]u8{
        0x12, 0x34, // ID
        0x81, 0x80, // Flags
        0x00, 0x00, // QDCOUNT: 0
        0x00, 0x00, // ANCOUNT: 0
        0x10, 0x01, // NSCOUNT: 4097 (just over max_section_count)
        0x00, 0x00, // ARCOUNT: 0
    };

    try std.testing.expectError(error.MessageTooLarge, Message.parse(&data));
}

test "Message.parse rejects excessive arcount" {
    const data = [_]u8{
        0x12, 0x34, // ID
        0x81, 0x80, // Flags
        0x00, 0x00, // QDCOUNT: 0
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x10, 0x01, // ARCOUNT: 4097
    };

    try std.testing.expectError(error.MessageTooLarge, Message.parse(&data));
}

test "Message.parse accepts count at max_section_count boundary" {
    // QDCOUNT = 4096 (0x1000) should be accepted (not exceed max).
    // It will fail later during question parsing due to insufficient data,
    // but it should NOT fail with MessageTooLarge.
    const data = [_]u8{
        0x12, 0x34, // ID
        0x01, 0x00, // Flags
        0x10, 0x00, // QDCOUNT: 4096 (exactly max_section_count)
        0x00, 0x00, // ANCOUNT: 0
        0x00, 0x00, // NSCOUNT: 0
        0x00, 0x00, // ARCOUNT: 0
    };

    // Should not get MessageTooLarge; will get a different error from trying
    // to parse 4096 questions from 0 bytes of data.
    const result = Message.parse(&data);
    if (result) |_| {
        // If it somehow parsed (unlikely), that's fine -- no MessageTooLarge
    } else |err| {
        try std.testing.expect(err != error.MessageTooLarge);
    }
}
