// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DNS Resource Records
//!
//! RFC 1035 Section 4.1.3: Resource Record Format
//!
//!                                     1  1  1  1  1  1
//!       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                                               |
//!     /                                               /
//!     /                      NAME                     /
//!     |                                               |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                      TYPE                     |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                     CLASS                     |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                      TTL                      |
//!     |                                               |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     |                   RDLENGTH                    |
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//!     /                     RDATA                     /
//!     /                                               /
//!     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

const std = @import("std");
const name_mod = @import("name");
const types_mod = @import("types");

pub const Name = name_mod.Name;
pub const Type = types_mod.Type;
pub const Class = types_mod.Class;

/// DNS Resource Record (RFC 1035 Section 4.1.3)
///
/// **Aliasing invariant:** The `rdata` field is always a sub-slice of the
/// original DNS wire-format message buffer passed to `parse()`.  Methods
/// that accept a `full_message` parameter (e.g. `parseName`, `parseMX`,
/// `parseSOA`, `parseSRV`, `parseSVCB`, `parseRRSIG`, `parseNSEC`) rely
/// on this: they compute the byte offset of `rdata` within `full_message`
/// via pointer arithmetic (`@intFromPtr(rdata.ptr) - @intFromPtr(full_message.ptr)`).
/// Callers **must** pass the same buffer (or a buffer whose `.ptr` matches)
/// that was originally supplied to `ResourceRecord.parse()`.
pub const ResourceRecord = struct {
    /// Domain name
    name: Name,

    /// Record type
    rtype: Type,

    /// Record class
    class: Class,

    /// Time to live in seconds
    ttl: u32,

    /// Length of RDATA
    rdlength: u16,

    /// Record data (raw bytes, sub-slice of the wire-format message buffer)
    rdata: []const u8,

    /// Total wire length of this record
    wire_length: usize,

    const Self = @This();

    /// Compute the byte offset of `self.rdata` within `full_message`, plus
    /// an optional `additional_offset` into the rdata payload.
    ///
    /// **Invariant (DG-04):** The returned offset must point within
    /// `full_message` (i.e., be less than `full_message.len`).  This is
    /// guaranteed when `self.rdata` is a sub-slice of `full_message`, which
    /// holds for all records produced by `ResourceRecord.parse()`.
    ///
    /// Returns `error.InvalidOffset` if the computed offset would exceed
    /// the message buffer length, which indicates a violation of the
    /// aliasing invariant (e.g., `full_message` is not the original buffer).
    fn rdataOffset(self: Self, full_message: []const u8, additional_offset: usize) !usize {
        const rdata_addr = @intFromPtr(self.rdata.ptr);
        const msg_addr = @intFromPtr(full_message.ptr);
        // Guard: rdata must point within (or at the end of) full_message.
        if (rdata_addr < msg_addr) return error.InvalidOffset;
        const base_offset = rdata_addr - msg_addr;
        const result = base_offset + additional_offset;
        if (result > full_message.len) return error.InvalidOffset;
        return result;
    }

    /// Parse a resource record from wire format
    pub fn parse(data: []const u8, offset: usize) !Self {
        if (offset >= data.len) {
            return error.InvalidOffset;
        }

        const rr_name = try Name.parse(data, offset);
        var pos = offset + rr_name.wire_length;

        if (pos + 10 > data.len) {
            return error.UnexpectedEnd;
        }

        const rtype = Type.fromInt(std.mem.readInt(u16, data[pos..][0..2], .big));
        const class = Class.fromInt(std.mem.readInt(u16, data[pos + 2 ..][0..2], .big));
        const ttl = std.mem.readInt(u32, data[pos + 4 ..][0..4], .big);
        const rdlength = std.mem.readInt(u16, data[pos + 8 ..][0..2], .big);

        pos += 10;

        if (pos + rdlength > data.len) {
            return error.UnexpectedEnd;
        }

        const rdata = data[pos..][0..rdlength];

        return Self{
            .name = rr_name,
            .rtype = rtype,
            .class = class,
            .ttl = ttl,
            .rdlength = rdlength,
            .rdata = rdata,
            .wire_length = rr_name.wire_length + 10 + rdlength,
        };
    }

    /// Get the record name as a string
    pub fn getName(self: Self, allocator: std.mem.Allocator, full_message: ?[]const u8) ![]u8 {
        return self.name.toString(allocator, full_message);
    }

    /// Parse RDATA as an IPv4 address (A record)
    pub fn parseA(self: Self) ![4]u8 {
        if (self.rtype != .a) {
            return error.WrongRecordType;
        }
        if (self.rdlength != 4) {
            return error.InvalidRdataLength;
        }
        return self.rdata[0..4].*;
    }

    /// Parse RDATA as an IPv6 address (AAAA record)
    pub fn parseAAAA(self: Self) ![16]u8 {
        if (self.rtype != .aaaa) {
            return error.WrongRecordType;
        }
        if (self.rdlength != 16) {
            return error.InvalidRdataLength;
        }
        return self.rdata[0..16].*;
    }

    /// Parse RDATA as a domain name (CNAME, NS, PTR)
    pub fn parseName(self: Self, full_message: []const u8) !Name {
        switch (self.rtype) {
            .cname, .ns, .ptr, .dname => {},
            else => return error.WrongRecordType,
        }

        return Name.parse(full_message, try self.rdataOffset(full_message, 0));
    }

    /// Parse RDATA as MX record
    pub const MxData = struct {
        preference: u16,
        exchange: Name,
    };

    pub fn parseMX(self: Self, full_message: []const u8) !MxData {
        if (self.rtype != .mx) {
            return error.WrongRecordType;
        }
        if (self.rdlength < 3) {
            return error.InvalidRdataLength;
        }

        const preference = std.mem.readInt(u16, self.rdata[0..2], .big);

        // Parse the exchange name (starts after 2-byte preference field)
        const exchange = try Name.parse(full_message, try self.rdataOffset(full_message, 2));

        return MxData{
            .preference = preference,
            .exchange = exchange,
        };
    }

    /// Parse RDATA as SOA record
    pub const SoaData = struct {
        mname: Name,
        rname: Name,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    };

    pub fn parseSOA(self: Self, full_message: []const u8) !SoaData {
        if (self.rtype != .soa) {
            return error.WrongRecordType;
        }

        var offset = try self.rdataOffset(full_message, 0);

        const mname = try Name.parse(full_message, offset);
        offset += mname.wire_length;

        const rname = try Name.parse(full_message, offset);
        offset += rname.wire_length;

        if (offset + 20 > full_message.len) {
            return error.UnexpectedEnd;
        }

        return SoaData{
            .mname = mname,
            .rname = rname,
            .serial = std.mem.readInt(u32, full_message[offset..][0..4], .big),
            .refresh = std.mem.readInt(u32, full_message[offset + 4 ..][0..4], .big),
            .retry = std.mem.readInt(u32, full_message[offset + 8 ..][0..4], .big),
            .expire = std.mem.readInt(u32, full_message[offset + 12 ..][0..4], .big),
            .minimum = std.mem.readInt(u32, full_message[offset + 16 ..][0..4], .big),
        };
    }

    /// Parse RDATA as TXT record (returns list of strings)
    pub fn parseTXT(self: Self, allocator: std.mem.Allocator) ![][]const u8 {
        if (self.rtype != .txt) {
            return error.WrongRecordType;
        }

        var strings: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (strings.items) |s| {
                allocator.free(s);
            }
            strings.deinit(allocator);
        }

        var pos: usize = 0;
        while (pos < self.rdata.len) {
            const len = self.rdata[pos];
            pos += 1;

            if (pos + len > self.rdata.len) {
                return error.InvalidRdataLength;
            }

            const str = try allocator.dupe(u8, self.rdata[pos..][0..len]);
            try strings.append(allocator, str);
            pos += len;
        }

        return try strings.toOwnedSlice(allocator);
    }

    /// Format IPv4 address as string (heap-allocated).
    /// Prefer `formatABuf` when a stack buffer is available.
    pub fn formatA(self: Self, allocator: std.mem.Allocator) ![]u8 {
        var buf: [15]u8 = undefined; // max "255.255.255.255"
        const result = try self.formatABuf(&buf);
        return allocator.dupe(u8, result);
    }

    /// Format IPv4 address into a caller-provided buffer.
    /// Returns a slice of `buf` containing the dotted-decimal string.
    /// Buffer must be at least 15 bytes (max IPv4 string "255.255.255.255").
    pub fn formatABuf(self: Self, buf: []u8) ![]const u8 {
        const addr = try self.parseA();
        return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{
            addr[0], addr[1], addr[2], addr[3],
        }) catch return error.NameTooLong;
    }

    /// Format IPv6 address as string (heap-allocated).
    /// Prefer `formatAAAABuf` when a stack buffer is available.
    pub fn formatAAAA(self: Self, allocator: std.mem.Allocator) ![]u8 {
        var buf: [39]u8 = undefined; // max "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx"
        const result = try self.formatAAAABuf(&buf);
        return allocator.dupe(u8, result);
    }

    /// Format IPv6 address into a caller-provided buffer.
    /// Returns a slice of `buf` containing the colon-hex string.
    /// Buffer must be at least 39 bytes (max IPv6 string length).
    pub fn formatAAAABuf(self: Self, buf: []u8) ![]const u8 {
        const addr = try self.parseAAAA();
        return std.fmt.bufPrint(buf, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
            addr[0],  addr[1],  addr[2],  addr[3],
            addr[4],  addr[5],  addr[6],  addr[7],
            addr[8],  addr[9],  addr[10], addr[11],
            addr[12], addr[13], addr[14], addr[15],
        }) catch return error.NameTooLong;
    }

    // ============================================================
    // RFC 2782: SRV Records (Service Locator)
    // ============================================================

    /// SRV record data (RFC 2782)
    ///
    /// Wire format:
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |                   PRIORITY                    |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |                    WEIGHT                     |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |                     PORT                      |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   /                    TARGET                     /
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    pub const SrvData = struct {
        /// Priority (lower = preferred)
        priority: u16,
        /// Weight for load balancing among same priority
        weight: u16,
        /// TCP/UDP port for the service
        port: u16,
        /// Target hostname (must not be an alias)
        target: Name,
    };

    pub fn parseSRV(self: Self, full_message: []const u8) !SrvData {
        if (self.rtype != .srv) {
            return error.WrongRecordType;
        }
        if (self.rdlength < 7) {
            return error.InvalidRdataLength;
        }

        const priority = std.mem.readInt(u16, self.rdata[0..2], .big);
        const weight = std.mem.readInt(u16, self.rdata[2..4], .big);
        const port = std.mem.readInt(u16, self.rdata[4..6], .big);

        // Parse the target name (starts after 6-byte priority/weight/port fields)
        const target = try Name.parse(full_message, try self.rdataOffset(full_message, 6));

        return SrvData{
            .priority = priority,
            .weight = weight,
            .port = port,
            .target = target,
        };
    }

    // ============================================================
    // RFC 8659: CAA Records (Certification Authority Authorization)
    // ============================================================

    /// CAA record data (RFC 8659)
    ///
    /// Wire format:
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |         FLAGS        |      TAG LENGTH       |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   /                      TAG                     /
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   /                     VALUE                    /
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    pub const CaaData = struct {
        /// Flags byte (bit 0 = critical flag)
        flags: u8,
        /// Property tag (e.g., "issue", "issuewild", "iodef")
        tag: []const u8,
        /// Property value
        value: []const u8,

        /// Returns true if the critical bit is set
        pub fn isCritical(self: CaaData) bool {
            return (self.flags & 0x80) != 0;
        }
    };

    pub fn parseCAA(self: Self) !CaaData {
        if (self.rtype != .caa) {
            return error.WrongRecordType;
        }
        if (self.rdlength < 2) {
            return error.InvalidRdataLength;
        }

        const flags = self.rdata[0];
        const tag_length = self.rdata[1];

        if (2 + tag_length > self.rdlength) {
            return error.InvalidRdataLength;
        }

        const tag = self.rdata[2..][0..tag_length];
        const value = self.rdata[2 + tag_length ..];

        return CaaData{
            .flags = flags,
            .tag = tag,
            .value = value,
        };
    }

    // ============================================================
    // RFC 6698: TLSA Records (TLS Authentication)
    // ============================================================

    /// TLSA certificate usage values (RFC 6698 Section 2.1.1)
    pub const TlsaCertUsage = enum(u8) {
        /// CA constraint
        pkix_ta = 0,
        /// Service certificate constraint
        pkix_ee = 1,
        /// Trust anchor assertion
        dane_ta = 2,
        /// Domain-issued certificate
        dane_ee = 3,
        _,
    };

    /// TLSA selector values (RFC 6698 Section 2.1.2)
    pub const TlsaSelector = enum(u8) {
        /// Full certificate
        full_cert = 0,
        /// SubjectPublicKeyInfo
        spki = 1,
        _,
    };

    /// TLSA matching type values (RFC 6698 Section 2.1.3)
    pub const TlsaMatchingType = enum(u8) {
        /// No hash (exact match)
        full = 0,
        /// SHA-256 hash
        sha256 = 1,
        /// SHA-512 hash
        sha512 = 2,
        _,
    };

    /// TLSA record data (RFC 6698)
    ///
    /// Wire format:
    ///   +--+--+--+--+--+--+--+--+
    ///   |   Certificate Usage   |
    ///   +--+--+--+--+--+--+--+--+
    ///   |       Selector        |
    ///   +--+--+--+--+--+--+--+--+
    ///   |    Matching Type      |
    ///   +--+--+--+--+--+--+--+--+
    ///   /                       /
    ///   /  Certificate Association Data  /
    ///   /                       /
    ///   +--+--+--+--+--+--+--+--+
    pub const TlsaData = struct {
        /// Certificate usage
        usage: TlsaCertUsage,
        /// Selector
        selector: TlsaSelector,
        /// Matching type
        matching_type: TlsaMatchingType,
        /// Certificate association data (hash or full cert)
        cert_data: []const u8,
    };

    pub fn parseTLSA(self: Self) !TlsaData {
        if (self.rtype != .tlsa) {
            return error.WrongRecordType;
        }
        if (self.rdlength < 3) {
            return error.InvalidRdataLength;
        }

        return TlsaData{
            .usage = @enumFromInt(self.rdata[0]),
            .selector = @enumFromInt(self.rdata[1]),
            .matching_type = @enumFromInt(self.rdata[2]),
            .cert_data = self.rdata[3..],
        };
    }

    // ============================================================
    // RFC 9460: SVCB and HTTPS Records (Service Binding)
    // ============================================================

    /// SVCB/HTTPS parameter keys (RFC 9460 Section 14.3.2)
    pub const SvcParamKey = enum(u16) {
        /// Mandatory keys
        mandatory = 0,
        /// Additional Locator Protocol Negotiation (ALPN)
        alpn = 1,
        /// No default ALPN
        no_default_alpn = 2,
        /// Port for alternative endpoint
        port = 3,
        /// IPv4 address hints
        ipv4hint = 4,
        /// Encrypted Client Hello (ECH) configuration
        ech = 5,
        /// IPv6 address hints
        ipv6hint = 6,
        /// DNS over Designated Resolver
        dohpath = 7,
        /// Target is HTTPS
        ohttp = 8,
        _,
    };

    /// A single SVCB parameter
    pub const SvcParam = struct {
        key: SvcParamKey,
        value: []const u8,
    };

    /// SVCB/HTTPS record data (RFC 9460)
    ///
    /// Wire format:
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |                   PRIORITY                    |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   /                    TARGET                     /
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   /                 SvcParams (optional)          /
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    pub const SvcbData = struct {
        /// SvcPriority (0 = AliasMode, >0 = ServiceMode)
        priority: u16,
        /// Target hostname (TargetName)
        target: Name,
        /// Raw parameters data (unparsed)
        params_data: []const u8,
        /// Offset to params data in full message (for iteration)
        params_offset: usize,

        /// Returns true if this is an AliasMode SVCB record
        pub fn isAlias(self: SvcbData) bool {
            return self.priority == 0;
        }
    };

    pub fn parseSVCB(self: Self, full_message: []const u8) !SvcbData {
        if (self.rtype != .svcb and self.rtype != .https) {
            return error.WrongRecordType;
        }
        if (self.rdlength < 3) {
            return error.InvalidRdataLength;
        }

        const priority = std.mem.readInt(u16, self.rdata[0..2], .big);

        // Parse the target name (starts after 2-byte priority field)
        const target_offset = try self.rdataOffset(full_message, 2);

        const target = try Name.parse(full_message, target_offset);

        const params_start = 2 + target.wire_length;
        const params_data = if (params_start < self.rdlength)
            self.rdata[params_start..]
        else
            self.rdata[0..0];

        return SvcbData{
            .priority = priority,
            .target = target,
            .params_data = params_data,
            .params_offset = target_offset + target.wire_length,
        };
    }

    /// Iterator for SVCB parameters
    pub const SvcParamIterator = struct {
        data: []const u8,
        pos: usize,

        pub fn next(self: *SvcParamIterator) ?SvcParam {
            if (self.pos + 4 > self.data.len) {
                return null;
            }

            const key: SvcParamKey = @enumFromInt(
                std.mem.readInt(u16, self.data[self.pos..][0..2], .big),
            );
            const length = std.mem.readInt(u16, self.data[self.pos + 2 ..][0..2], .big);
            self.pos += 4;

            if (self.pos + length > self.data.len) {
                return null;
            }

            const value = self.data[self.pos..][0..length];
            self.pos += length;

            return SvcParam{
                .key = key,
                .value = value,
            };
        }
    };

    /// Get an iterator over SVCB parameters
    pub fn svcbParams(self: Self, full_message: []const u8) !SvcParamIterator {
        const svcb = try self.parseSVCB(full_message);
        return SvcParamIterator{
            .data = svcb.params_data,
            .pos = 0,
        };
    }

    /// Parse ALPN values from SVCB parameter
    pub fn parseSvcbAlpn(value: []const u8, allocator: std.mem.Allocator) ![][]const u8 {
        var alpns: std.ArrayList([]const u8) = .empty;
        errdefer {
            for (alpns.items) |a| {
                allocator.free(a);
            }
            alpns.deinit(allocator);
        }

        var pos: usize = 0;
        while (pos < value.len) {
            const len = value[pos];
            pos += 1;
            if (pos + len > value.len) {
                return error.InvalidRdataLength;
            }
            const alpn = try allocator.dupe(u8, value[pos..][0..len]);
            try alpns.append(allocator, alpn);
            pos += len;
        }

        return try alpns.toOwnedSlice(allocator);
    }

    /// Parse IPv4 hints from SVCB parameter
    pub fn parseSvcbIpv4Hint(value: []const u8, allocator: std.mem.Allocator) ![][4]u8 {
        if (value.len % 4 != 0) {
            return error.InvalidRdataLength;
        }
        const count = value.len / 4;
        const result = try allocator.alloc([4]u8, count);
        errdefer allocator.free(result);
        for (0..count) |i| {
            result[i] = value[i * 4 ..][0..4].*;
        }
        return result;
    }

    /// Parse IPv6 hints from SVCB parameter
    pub fn parseSvcbIpv6Hint(value: []const u8, allocator: std.mem.Allocator) ![][16]u8 {
        if (value.len % 16 != 0) {
            return error.InvalidRdataLength;
        }
        const count = value.len / 16;
        const result = try allocator.alloc([16]u8, count);
        errdefer allocator.free(result);
        for (0..count) |i| {
            result[i] = value[i * 16 ..][0..16].*;
        }
        return result;
    }

    /// Parse port from SVCB parameter
    pub fn parseSvcbPort(value: []const u8) !u16 {
        if (value.len != 2) {
            return error.InvalidRdataLength;
        }
        return std.mem.readInt(u16, value[0..2], .big);
    }

    // ============================================================
    // RFC 4034: DNSSEC Resource Records
    // ============================================================

    /// DNSSEC Algorithm Numbers (RFC 4034, RFC 5702, RFC 6605, RFC 8080)
    pub const DnssecAlgorithm = enum(u8) {
        /// RSA/MD5 (deprecated, insecure)
        rsamd5 = 1,
        /// Diffie-Hellman (not for signing)
        dh = 2,
        /// DSA/SHA-1 (deprecated)
        dsa = 3,
        /// Reserved
        reserved4 = 4,
        /// RSA/SHA-1 (legacy, should support)
        rsasha1 = 5,
        /// DSA-NSEC3-SHA1
        dsa_nsec3_sha1 = 6,
        /// RSASHA1-NSEC3-SHA1
        rsasha1_nsec3_sha1 = 7,
        /// RSA/SHA-256 (MUST support)
        rsasha256 = 8,
        /// Reserved
        reserved9 = 9,
        /// RSA/SHA-512
        rsasha512 = 10,
        /// Reserved
        reserved11 = 11,
        /// ECDSA P-256/SHA-256
        ecdsap256sha256 = 13,
        /// ECDSA P-384/SHA-384
        ecdsap384sha384 = 14,
        /// Ed25519 (SHOULD support)
        ed25519 = 15,
        /// Ed448
        ed448 = 16,
        /// Indirect (for DNSKEY pointing to external key)
        indirect = 252,
        /// Private algorithm (domain name)
        privatedns = 253,
        /// Private algorithm (OID)
        privateoid = 254,
        _,

        pub fn isSupported(self: DnssecAlgorithm) bool {
            return switch (self) {
                .rsasha256, .ecdsap256sha256, .ed25519 => true,
                .rsasha1, .rsasha512, .ecdsap384sha384 => true,
                else => false,
            };
        }
    };

    /// DNSSEC Digest Types (RFC 4034, RFC 4509, RFC 6605)
    pub const DigestType = enum(u8) {
        /// Reserved
        reserved = 0,
        /// SHA-1 (legacy)
        sha1 = 1,
        /// SHA-256 (MUST support)
        sha256 = 2,
        /// GOST R 34.11-94
        gost = 3,
        /// SHA-384
        sha384 = 4,
        _,
    };

    /// DNSKEY Flags (RFC 4034 Section 2.1.1)
    pub const DnskeyFlags = struct {
        raw: u16,

        /// Zone Key flag (bit 7) - key can sign zone data
        pub fn isZoneKey(self: DnskeyFlags) bool {
            return (self.raw & 0x0100) != 0;
        }

        /// Secure Entry Point flag (bit 15) - key is a KSK
        pub fn isSep(self: DnskeyFlags) bool {
            return (self.raw & 0x0001) != 0;
        }

        /// Revoke flag (bit 8) - key is revoked (RFC 5011)
        pub fn isRevoked(self: DnskeyFlags) bool {
            return (self.raw & 0x0080) != 0;
        }
    };

    /// DNSKEY record data (RFC 4034 Section 2)
    ///
    /// Wire format:
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |                    FLAGS                      |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |       PROTOCOL      |       ALGORITHM         |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   /                  PUBLIC KEY                   /
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    pub const DnskeyData = struct {
        /// Flags
        flags: DnskeyFlags,
        /// Protocol (must be 3 for DNSSEC)
        protocol: u8,
        /// Algorithm
        algorithm: DnssecAlgorithm,
        /// Public key data
        public_key: []const u8,

        /// Check if this is a Key Signing Key (KSK)
        pub fn isKsk(self: DnskeyData) bool {
            return self.flags.isZoneKey() and self.flags.isSep();
        }

        /// Check if this is a Zone Signing Key (ZSK)
        pub fn isZsk(self: DnskeyData) bool {
            return self.flags.isZoneKey() and !self.flags.isSep();
        }
    };

    pub fn parseDNSKEY(self: Self) !DnskeyData {
        if (self.rtype != .dnskey) {
            return error.WrongRecordType;
        }
        if (self.rdlength < 4) {
            return error.InvalidRdataLength;
        }

        return DnskeyData{
            .flags = .{ .raw = std.mem.readInt(u16, self.rdata[0..2], .big) },
            .protocol = self.rdata[2],
            .algorithm = @enumFromInt(self.rdata[3]),
            .public_key = self.rdata[4..],
        };
    }

    /// RRSIG record data (RFC 4034 Section 3)
    ///
    /// Wire format:
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |                  TYPE COVERED                 |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |       ALGORITHM     |        LABELS           |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |                  ORIGINAL TTL                 |
    ///   |                                               |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |               SIGNATURE EXPIRATION            |
    ///   |                                               |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |               SIGNATURE INCEPTION             |
    ///   |                                               |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |                    KEY TAG                    |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   /                  SIGNER'S NAME                /
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   /                    SIGNATURE                  /
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    pub const RrsigData = struct {
        /// Type of RRset covered by this signature
        type_covered: Type,
        /// Algorithm used
        algorithm: DnssecAlgorithm,
        /// Number of labels in original owner name
        labels: u8,
        /// Original TTL of covered RRset
        original_ttl: u32,
        /// Signature expiration (Unix timestamp)
        sig_expiration: u32,
        /// Signature inception (Unix timestamp)
        sig_inception: u32,
        /// Key tag for identifying DNSKEY
        key_tag: u16,
        /// Signer's name (zone name)
        signer: Name,
        /// Signature data
        signature: []const u8,
        /// Offset to signature in rdata
        sig_offset: usize,

        /// Check if signature is currently valid (not expired, not future)
        pub fn isValid(self: RrsigData, current_time: u32) bool {
            return current_time >= self.sig_inception and
                current_time <= self.sig_expiration;
        }
    };

    pub fn parseRRSIG(self: Self, full_message: []const u8) !RrsigData {
        if (self.rtype != .rrsig) {
            return error.WrongRecordType;
        }
        if (self.rdlength < 18) {
            return error.InvalidRdataLength;
        }

        const type_covered = Type.fromInt(std.mem.readInt(u16, self.rdata[0..2], .big));
        const algorithm: DnssecAlgorithm = @enumFromInt(self.rdata[2]);
        const labels = self.rdata[3];
        const original_ttl = std.mem.readInt(u32, self.rdata[4..8], .big);
        const sig_expiration = std.mem.readInt(u32, self.rdata[8..12], .big);
        const sig_inception = std.mem.readInt(u32, self.rdata[12..16], .big);
        const key_tag = std.mem.readInt(u16, self.rdata[16..18], .big);

        // Parse signer's name (starts after 18-byte fixed fields)
        const signer = try Name.parse(full_message, try self.rdataOffset(full_message, 18));
        const sig_offset = 18 + signer.wire_length;

        if (sig_offset > self.rdlength) {
            return error.InvalidRdataLength;
        }

        return RrsigData{
            .type_covered = type_covered,
            .algorithm = algorithm,
            .labels = labels,
            .original_ttl = original_ttl,
            .sig_expiration = sig_expiration,
            .sig_inception = sig_inception,
            .key_tag = key_tag,
            .signer = signer,
            .signature = self.rdata[sig_offset..],
            .sig_offset = sig_offset,
        };
    }

    /// DS record data (RFC 4034 Section 5)
    ///
    /// Wire format:
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |                    KEY TAG                    |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |       ALGORITHM     |      DIGEST TYPE        |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   /                     DIGEST                    /
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    pub const DsData = struct {
        /// Key tag of the DNSKEY RR
        key_tag: u16,
        /// Algorithm of the DNSKEY RR
        algorithm: DnssecAlgorithm,
        /// Digest type
        digest_type: DigestType,
        /// Digest of the DNSKEY RR
        digest: []const u8,
    };

    pub fn parseDS(self: Self) !DsData {
        if (self.rtype != .ds) {
            return error.WrongRecordType;
        }
        if (self.rdlength < 4) {
            return error.InvalidRdataLength;
        }

        return DsData{
            .key_tag = std.mem.readInt(u16, self.rdata[0..2], .big),
            .algorithm = @enumFromInt(self.rdata[2]),
            .digest_type = @enumFromInt(self.rdata[3]),
            .digest = self.rdata[4..],
        };
    }

    /// NSEC record data (RFC 4034 Section 4)
    ///
    /// Wire format:
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   /                  NEXT DOMAIN                  /
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   /                   TYPE BITMAPS                /
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    pub const NsecData = struct {
        /// Next domain name in canonical order
        next_domain: Name,
        /// Type bitmaps (raw format)
        type_bitmaps: []const u8,
    };

    pub fn parseNSEC(self: Self, full_message: []const u8) !NsecData {
        if (self.rtype != .nsec) {
            return error.WrongRecordType;
        }
        if (self.rdlength < 1) {
            return error.InvalidRdataLength;
        }

        const next_domain = try Name.parse(full_message, try self.rdataOffset(full_message, 0));

        const bitmap_start = next_domain.wire_length;
        const type_bitmaps = if (bitmap_start < self.rdlength)
            self.rdata[bitmap_start..]
        else
            self.rdata[0..0];

        return NsecData{
            .next_domain = next_domain,
            .type_bitmaps = type_bitmaps,
        };
    }

    /// NSEC3 record data (RFC 5155 Section 3)
    ///
    /// Wire format:
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |   HASH ALGORITHM    |         FLAGS           |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |                  ITERATIONS                   |
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |   SALT LENGTH       |         SALT            /
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   |  HASH LENGTH        |      NEXT HASHED OWNER  /
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ///   /                   TYPE BITMAPS                /
    ///   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    pub const Nsec3HashAlgorithm = enum(u8) {
        reserved = 0,
        sha1 = 1,
        _,
    };

    pub const Nsec3Data = struct {
        /// Hash algorithm
        hash_algorithm: Nsec3HashAlgorithm,
        /// Flags (bit 0 = opt-out)
        flags: u8,
        /// Iterations
        iterations: u16,
        /// Salt
        salt: []const u8,
        /// Next hashed owner name (binary)
        next_hashed_owner: []const u8,
        /// Type bitmaps
        type_bitmaps: []const u8,

        /// Check if opt-out flag is set
        pub fn isOptOut(self: Nsec3Data) bool {
            return (self.flags & 0x01) != 0;
        }
    };

    pub fn parseNSEC3(self: Self) !Nsec3Data {
        if (self.rtype != .nsec3) {
            return error.WrongRecordType;
        }
        if (self.rdlength < 5) {
            return error.InvalidRdataLength;
        }

        const hash_algorithm: Nsec3HashAlgorithm = @enumFromInt(self.rdata[0]);
        const flags = self.rdata[1];
        const iterations = std.mem.readInt(u16, self.rdata[2..4], .big);
        const salt_length = self.rdata[4];

        var pos: usize = 5;
        if (pos + salt_length > self.rdlength) {
            return error.InvalidRdataLength;
        }
        const salt = self.rdata[pos..][0..salt_length];
        pos += salt_length;

        if (pos >= self.rdlength) {
            return error.InvalidRdataLength;
        }
        const hash_length = self.rdata[pos];
        pos += 1;

        if (pos + hash_length > self.rdlength) {
            return error.InvalidRdataLength;
        }
        const next_hashed_owner = self.rdata[pos..][0..hash_length];
        pos += hash_length;

        const type_bitmaps = if (pos < self.rdlength)
            self.rdata[pos..]
        else
            self.rdata[0..0];

        return Nsec3Data{
            .hash_algorithm = hash_algorithm,
            .flags = flags,
            .iterations = iterations,
            .salt = salt,
            .next_hashed_owner = next_hashed_owner,
            .type_bitmaps = type_bitmaps,
        };
    }

    /// NSEC3PARAM record data (RFC 5155 Section 4)
    pub const Nsec3ParamData = struct {
        /// Hash algorithm
        hash_algorithm: Nsec3HashAlgorithm,
        /// Flags (should be 0)
        flags: u8,
        /// Iterations
        iterations: u16,
        /// Salt
        salt: []const u8,
    };

    pub fn parseNSEC3PARAM(self: Self) !Nsec3ParamData {
        if (self.rtype != .nsec3param) {
            return error.WrongRecordType;
        }
        if (self.rdlength < 5) {
            return error.InvalidRdataLength;
        }

        const salt_length = self.rdata[4];
        if (5 + salt_length > self.rdlength) {
            return error.InvalidRdataLength;
        }

        return Nsec3ParamData{
            .hash_algorithm = @enumFromInt(self.rdata[0]),
            .flags = self.rdata[1],
            .iterations = std.mem.readInt(u16, self.rdata[2..4], .big),
            .salt = self.rdata[5..][0..salt_length],
        };
    }

    /// Check if a type is present in NSEC/NSEC3 type bitmaps
    pub fn hasTypeInBitmap(type_bitmaps: []const u8, rtype: Type) bool {
        const type_value = rtype.toInt();
        const window = type_value / 256;
        const bit_offset = type_value % 256;
        const byte_offset = bit_offset / 8;
        const bit = @as(u8, 0x80) >> @intCast(bit_offset % 8);

        var pos: usize = 0;
        while (pos + 2 <= type_bitmaps.len) {
            const win = type_bitmaps[pos];
            const bitmap_len = type_bitmaps[pos + 1];
            pos += 2;

            if (pos + bitmap_len > type_bitmaps.len) {
                return false;
            }

            if (win == window) {
                if (byte_offset < bitmap_len) {
                    return (type_bitmaps[pos + byte_offset] & bit) != 0;
                }
                return false;
            }

            pos += bitmap_len;
        }

        return false;
    }

    /// Calculate DNSKEY key tag (RFC 4034 Appendix B)
    pub fn calculateKeyTag(rdata: []const u8) u16 {
        var ac: u32 = 0;
        var i: usize = 0;
        while (i < rdata.len) : (i += 1) {
            if (i & 1 != 0) {
                ac += rdata[i];
            } else {
                ac += @as(u32, rdata[i]) << 8;
            }
        }
        ac += (ac >> 16) & 0xFFFF;
        return @intCast(ac & 0xFFFF);
    }
};

test "ResourceRecord.parse A record" {
    const data = [_]u8{
        // Name: example.com
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        3,    'c',  'o',  'm',  0,
        // TYPE: A (1)
           0x00, 0x01,
        // CLASS: IN (1)
        0x00,
        0x01,
        // TTL: 300
        0x00, 0x00, 0x01, 0x2C,
        // RDLENGTH: 4
        0x00, 0x04,
        // RDATA: 93.184.216.34
        93,
        184,  216,  34,
    };

    const rr = try ResourceRecord.parse(&data, 0);

    try std.testing.expectEqual(Type.a, rr.rtype);
    try std.testing.expectEqual(Class.in, rr.class);
    try std.testing.expectEqual(@as(u32, 300), rr.ttl);
    try std.testing.expectEqual(@as(u16, 4), rr.rdlength);

    const addr = try rr.parseA();
    try std.testing.expectEqualSlices(u8, &[_]u8{ 93, 184, 216, 34 }, &addr);
}

test "ResourceRecord.formatA" {
    const data = [_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
        0x00, 0x01, // A
        0x00, 0x01, // IN
        0x00, 0x00, 0x01, 0x2C, // TTL
        0x00, 0x04, // RDLENGTH
        93, 184, 216, 34, // RDATA
    };

    const allocator = std.testing.allocator;
    const rr = try ResourceRecord.parse(&data, 0);
    const formatted = try rr.formatA(allocator);
    defer allocator.free(formatted);

    try std.testing.expectEqualStrings("93.184.216.34", formatted);
}

test "ResourceRecord.formatABuf" {
    const data = [_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
        0x00, 0x01, // A
        0x00, 0x01, // IN
        0x00, 0x00, 0x01, 0x2C, // TTL
        0x00, 0x04, // RDLENGTH
        93, 184, 216, 34, // RDATA
    };

    const rr = try ResourceRecord.parse(&data, 0);

    // Stack buffer variant avoids heap allocation
    var buf: [15]u8 = undefined;
    const result = try rr.formatABuf(&buf);
    try std.testing.expectEqualStrings("93.184.216.34", result);

    // Result is a slice of the buffer, not heap memory
    try std.testing.expect(@intFromPtr(result.ptr) >= @intFromPtr(&buf));
    try std.testing.expect(@intFromPtr(result.ptr) < @intFromPtr(&buf) + buf.len);
}

test "ResourceRecord.formatAAAABuf" {
    const data = [_]u8{
        // Name: ipv6.example.com
        4,    'i',  'p',  'v',  '6',
        7,    'e',  'x',  'a',  'm',
        'p',  'l',  'e',  3,    'c',
        'o',  'm',  0,
        // TYPE: AAAA (28)
           0x00, 0x1C,
        // CLASS: IN (1)
        0x00, 0x01,
        // TTL: 600
        0x00, 0x00, 0x02,
        0x58,
        // RDLENGTH: 16
        0x00, 0x10,
        // RDATA: 2606:2800:0220:0001:0248:1893:25c8:1946
        0x26, 0x06,
        0x28, 0x00, 0x02, 0x20, 0x00,
        0x01, 0x02, 0x48, 0x18, 0x93,
        0x25, 0xc8, 0x19, 0x46,
    };

    const rr = try ResourceRecord.parse(&data, 0);

    // Stack buffer variant avoids heap allocation
    var buf: [39]u8 = undefined;
    const result = try rr.formatAAAABuf(&buf);
    try std.testing.expectEqualStrings("2606:2800:0220:0001:0248:1893:25c8:1946", result);

    // Result is a slice of the buffer, not heap memory
    try std.testing.expect(@intFromPtr(result.ptr) >= @intFromPtr(&buf));
    try std.testing.expect(@intFromPtr(result.ptr) < @intFromPtr(&buf) + buf.len);
}

test "ResourceRecord.parse AAAA record" {
    const data = [_]u8{
        // Name: ipv6.example.com (compressed)
        4,    'i',  'p',  'v',  '6',
        7,    'e',  'x',  'a',  'm',
        'p',  'l',  'e',  3,    'c',
        'o',  'm',  0,
        // TYPE: AAAA (28)
           0x00, 0x1C,
        // CLASS: IN (1)
        0x00, 0x01,
        // TTL: 600
        0x00, 0x00, 0x02,
        0x58,
        // RDLENGTH: 16
        0x00, 0x10,
        // RDATA: 2606:2800:220:1:248:1893:25c8:1946
        0x26, 0x06,
        0x28, 0x00, 0x02, 0x20, 0x00,
        0x01, 0x02, 0x48, 0x18, 0x93,
        0x25, 0xc8, 0x19, 0x46,
    };

    const rr = try ResourceRecord.parse(&data, 0);

    try std.testing.expectEqual(Type.aaaa, rr.rtype);
    try std.testing.expectEqual(@as(u16, 16), rr.rdlength);

    const addr = try rr.parseAAAA();
    try std.testing.expectEqualSlices(u8, &[_]u8{
        0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01,
        0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46,
    }, &addr);
}

test "ResourceRecord.parseTXT" {
    const data = [_]u8{
        // Name: example.com
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        3,    'c',  'o',  'm',  0,
        // TYPE: TXT (16)
           0x00, 0x10,
        // CLASS: IN (1)
        0x00,
        0x01,
        // TTL: 3600
        0x00, 0x00, 0x0E, 0x10,
        // RDLENGTH: 12
        0x00, 0x0C,
        // RDATA: "hello world"
        11,
        'h',  'e',  'l',  'l',  'o',  ' ',  'w',  'o',
        'r',  'l',  'd',
    };

    const allocator = std.testing.allocator;
    const rr = try ResourceRecord.parse(&data, 0);
    const txt_strings = try rr.parseTXT(allocator);
    defer {
        for (txt_strings) |s| {
            allocator.free(s);
        }
        allocator.free(txt_strings);
    }

    try std.testing.expectEqual(@as(usize, 1), txt_strings.len);
    try std.testing.expectEqualStrings("hello world", txt_strings[0]);
}

// ============================================================
// Tests for new record types (Phase 1)
// ============================================================

test "ResourceRecord.parseSRV" {
    // SRV record for _http._tcp.example.com -> server.example.com:80
    const data = [_]u8{
        // Name: _http._tcp.example.com
        5,    '_',  'h',  't',  't',  'p',
        4,    '_',  't',  'c',  'p',  7,
        'e',  'x',  'a',  'm',  'p',  'l',
        'e',  3,    'c',  'o',  'm',  0,
        // TYPE: SRV (33)
        0x00, 0x21,
        // CLASS: IN (1)
        0x00, 0x01,
        // TTL: 3600
        0x00, 0x00,
        0x0E, 0x10,
        // RDLENGTH: 22
        0x00, 0x16,
        // Priority: 10
        0x00, 0x0A,
        // Weight: 20
        0x00, 0x14,
        // Port: 80
        0x00, 0x50,
        // Target: server.example.com
        6,    's',
        'e',  'r',  'v',  'e',  'r',  7,
        'e',  'x',  'a',  'm',  'p',  'l',
        'e',  3,    'c',  'o',  'm',  0,
    };

    const rr = try ResourceRecord.parse(&data, 0);
    try std.testing.expectEqual(Type.srv, rr.rtype);

    const srv = try rr.parseSRV(&data);
    try std.testing.expectEqual(@as(u16, 10), srv.priority);
    try std.testing.expectEqual(@as(u16, 20), srv.weight);
    try std.testing.expectEqual(@as(u16, 80), srv.port);

    const allocator = std.testing.allocator;
    const target_str = try srv.target.toString(allocator, &data);
    defer allocator.free(target_str);
    try std.testing.expectEqualStrings("server.example.com", target_str);
}

test "ResourceRecord.parseCAA" {
    // CAA record: example.com 0 issue "letsencrypt.org"
    const data = [_]u8{
        // Name: example.com
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        3,    'c',  'o',  'm',  0,
        // TYPE: CAA (257)
           0x01, 0x01,
        // CLASS: IN (1)
        0x00,
        0x01,
        // TTL: 3600
        0x00, 0x00, 0x0E, 0x10,
        // RDLENGTH: 22
        0x00, 0x16,
        // Flags: 0
        0x00,
        // Tag length: 5
        0x05,
        // Tag: "issue"
        'i',  's',  's',  'u',  'e',
        // Value: "letsencrypt.org"
         'l',  'e',
        't',  's',  'e',  'n',  'c',  'r',  'y',  'p',
        't',  '.',  'o',  'r',  'g',
    };

    const rr = try ResourceRecord.parse(&data, 0);
    try std.testing.expectEqual(Type.caa, rr.rtype);

    const caa = try rr.parseCAA();
    try std.testing.expectEqual(@as(u8, 0), caa.flags);
    try std.testing.expect(!caa.isCritical());
    try std.testing.expectEqualStrings("issue", caa.tag);
    try std.testing.expectEqualStrings("letsencrypt.org", caa.value);
}

test "ResourceRecord.parseCAA critical" {
    // CAA record with critical flag set
    // RDLENGTH = 1 (flags) + 1 (tag len) + 5 (tag) + 4 (value) = 11
    const data = [_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
        0x01, 0x01, // CAA
        0x00, 0x01, // IN
        0x00, 0x00, 0x0E, 0x10, // TTL
        0x00, 0x0B, // RDLENGTH: 11
        0x80, // Flags: critical
        0x05, // Tag length
        'i',
        's',
        's',
        'u',
        'e',
        't',
        'e',
        's',
        't',
    };

    const rr = try ResourceRecord.parse(&data, 0);
    const caa = try rr.parseCAA();
    try std.testing.expectEqual(@as(u8, 0x80), caa.flags);
    try std.testing.expect(caa.isCritical());
}

test "ResourceRecord.parseTLSA" {
    // TLSA record: 3 1 1 <sha256 hash>
    const sha256_hash = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };

    const data = [_]u8{
        // Name: _443._tcp.example.com
        4,    '_',  '4',  '4',  '3',
        4,    '_',  't',  'c',  'p',
        7,    'e',  'x',  'a',  'm',
        'p',  'l',  'e',  3,    'c',
        'o',  'm',  0,
        // TYPE: TLSA (52)
           0x00, 0x34,
        // CLASS: IN (1)
        0x00, 0x01,
        // TTL: 3600
        0x00, 0x00, 0x0E,
        0x10,
        // RDLENGTH: 35 (3 header + 32 hash)
        0x00, 0x23,
        // Usage: 3 (DANE-EE)
        0x03,
        // Selector: 1 (SPKI)
        0x01,
        // Matching Type: 1 (SHA-256)
        0x01,
    } ++ sha256_hash;

    const rr = try ResourceRecord.parse(&data, 0);
    try std.testing.expectEqual(Type.tlsa, rr.rtype);

    const tlsa = try rr.parseTLSA();
    try std.testing.expectEqual(ResourceRecord.TlsaCertUsage.dane_ee, tlsa.usage);
    try std.testing.expectEqual(ResourceRecord.TlsaSelector.spki, tlsa.selector);
    try std.testing.expectEqual(ResourceRecord.TlsaMatchingType.sha256, tlsa.matching_type);
    try std.testing.expectEqual(@as(usize, 32), tlsa.cert_data.len);
    try std.testing.expectEqualSlices(u8, &sha256_hash, tlsa.cert_data);
}

test "ResourceRecord.parseSVCB basic" {
    // SVCB record: example.com 1 . alpn=h2
    const data = [_]u8{
        // Name: example.com
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        3,    'c',  'o',  'm',  0,
        // TYPE: SVCB (64)
           0x00, 0x40,
        // CLASS: IN (1)
        0x00,
        0x01,
        // TTL: 3600
        0x00, 0x00, 0x0E, 0x10,
        // RDLENGTH: 10
        0x00, 0x0A,
        // Priority: 1
        0x00,
        0x01,
        // Target: . (root = same as owner)
        0x00,
        // SvcParams:
        // alpn (key=1) length=3 value=[2, 'h', '2']
        0x00, 0x01, // key: alpn
        0x00, 0x03, // length: 3
        0x02, 'h', '2', // value: [length-prefixed "h2"]
    };

    const rr = try ResourceRecord.parse(&data, 0);
    try std.testing.expectEqual(Type.svcb, rr.rtype);

    const svcb = try rr.parseSVCB(&data);
    try std.testing.expectEqual(@as(u16, 1), svcb.priority);
    try std.testing.expect(!svcb.isAlias());

    // Iterate params
    var iter = try rr.svcbParams(&data);
    const param = iter.next();
    try std.testing.expect(param != null);
    try std.testing.expectEqual(ResourceRecord.SvcParamKey.alpn, param.?.key);

    // Parse ALPN
    const allocator = std.testing.allocator;
    const alpns = try ResourceRecord.parseSvcbAlpn(param.?.value, allocator);
    defer {
        for (alpns) |a| allocator.free(a);
        allocator.free(alpns);
    }
    try std.testing.expectEqual(@as(usize, 1), alpns.len);
    try std.testing.expectEqualStrings("h2", alpns[0]);

    // No more params
    try std.testing.expect(iter.next() == null);
}

test "ResourceRecord.parseSVCB alias mode" {
    // SVCB alias record: alias.example.com 0 target.example.com
    const data = [_]u8{
        // Name: alias.example.com
        5,    'a',  'l',  'i',  'a',  's',
        7,    'e',  'x',  'a',  'm',  'p',
        'l',  'e',  3,    'c',  'o',  'm',
        0,
        // TYPE: SVCB (64)
           0x00, 0x40,
        // CLASS: IN (1)
        0x00, 0x01,
        // TTL: 3600
        0x00,
        0x00, 0x0E, 0x10,
        // RDLENGTH: 21
        0x00, 0x15,
        // Priority: 0 (alias mode)
        0x00,
        0x00,
        // Target: target.example.com
        6,    't',  'a',  'r',  'g',
        'e',  't',  7,    'e',  'x',  'a',
        'm',  'p',  'l',  'e',  3,    'c',
        'o',  'm',  0,
    };

    const rr = try ResourceRecord.parse(&data, 0);
    const svcb = try rr.parseSVCB(&data);

    try std.testing.expectEqual(@as(u16, 0), svcb.priority);
    try std.testing.expect(svcb.isAlias());

    const allocator = std.testing.allocator;
    const target_str = try svcb.target.toString(allocator, &data);
    defer allocator.free(target_str);
    try std.testing.expectEqualStrings("target.example.com", target_str);
}

// ============================================================
// DNSSEC Record Type Tests
// ============================================================

test "ResourceRecord.parseDNSKEY" {
    // DNSKEY record: KSK with RSA/SHA-256
    const data = [_]u8{
        // Name: example.com
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        3,    'c',  'o',  'm',  0,
        // TYPE: DNSKEY (48)
           0x00, 0x30,
        // CLASS: IN (1)
        0x00,
        0x01,
        // TTL: 3600
        0x00, 0x00, 0x0E, 0x10,
        // RDLENGTH: 12
        0x00, 0x0C,
        // Flags: 257 (Zone Key + SEP = KSK)
        0x01,
        0x01,
        // Protocol: 3
        0x03,
        // Algorithm: 8 (RSA/SHA-256)
        0x08,
        // Public key (8 bytes placeholder)
        0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08,
    };

    const rr = try ResourceRecord.parse(&data, 0);
    try std.testing.expectEqual(Type.dnskey, rr.rtype);

    const dnskey = try rr.parseDNSKEY();
    try std.testing.expectEqual(@as(u16, 257), dnskey.flags.raw);
    try std.testing.expect(dnskey.flags.isZoneKey());
    try std.testing.expect(dnskey.flags.isSep());
    try std.testing.expect(!dnskey.flags.isRevoked());
    try std.testing.expect(dnskey.isKsk());
    try std.testing.expect(!dnskey.isZsk());
    try std.testing.expectEqual(@as(u8, 3), dnskey.protocol);
    try std.testing.expectEqual(ResourceRecord.DnssecAlgorithm.rsasha256, dnskey.algorithm);
    try std.testing.expectEqual(@as(usize, 8), dnskey.public_key.len);
}

test "ResourceRecord.parseDNSKEY ZSK" {
    // ZSK (Zone Signing Key) - Zone Key flag but no SEP
    const data = [_]u8{
        7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
        3, 'c', 'o', 'm', 0,
        0x00, 0x30, // DNSKEY
        0x00, 0x01, // IN
        0x00, 0x00, 0x0E, 0x10, // TTL
        0x00, 0x08, // RDLENGTH
        0x01, 0x00, // Flags: 256 (Zone Key only)
        0x03, // Protocol
        0x08, // Algorithm
        0x01, 0x02, 0x03, 0x04, // Public key
    };

    const rr = try ResourceRecord.parse(&data, 0);
    const dnskey = try rr.parseDNSKEY();

    try std.testing.expect(dnskey.flags.isZoneKey());
    try std.testing.expect(!dnskey.flags.isSep());
    try std.testing.expect(!dnskey.isKsk());
    try std.testing.expect(dnskey.isZsk());
}

test "ResourceRecord.parseDS" {
    // DS record with SHA-256 digest
    const sha256_digest = [_]u8{
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    };

    const data = [_]u8{
        // Name: example.com
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        3,    'c',  'o',  'm',  0,
        // TYPE: DS (43)
           0x00, 0x2B,
        // CLASS: IN (1)
        0x00,
        0x01,
        // TTL: 3600
        0x00, 0x00, 0x0E, 0x10,
        // RDLENGTH: 36 (4 header + 32 digest)
        0x00, 0x24,
        // Key tag: 12345
        0x30,
        0x39,
        // Algorithm: 8 (RSA/SHA-256)
        0x08,
        // Digest type: 2 (SHA-256)
        0x02,
    } ++ sha256_digest;

    const rr = try ResourceRecord.parse(&data, 0);
    try std.testing.expectEqual(Type.ds, rr.rtype);

    const ds = try rr.parseDS();
    try std.testing.expectEqual(@as(u16, 12345), ds.key_tag);
    try std.testing.expectEqual(ResourceRecord.DnssecAlgorithm.rsasha256, ds.algorithm);
    try std.testing.expectEqual(ResourceRecord.DigestType.sha256, ds.digest_type);
    try std.testing.expectEqual(@as(usize, 32), ds.digest.len);
    try std.testing.expectEqualSlices(u8, &sha256_digest, ds.digest);
}

test "ResourceRecord.parseNSEC3" {
    // NSEC3 record
    const data = [_]u8{
        // Name: hash.example.com
        4,    'h',  'a',  's',  'h',
        7,    'e',  'x',  'a',  'm',
        'p',  'l',  'e',  3,    'c',
        'o',  'm',  0,
        // TYPE: NSEC3 (50)
           0x00, 0x32,
        // CLASS: IN (1)
        0x00, 0x01,
        // TTL: 3600
        0x00, 0x00, 0x0E,
        0x10,
        // RDLENGTH: 30 (1+1+2+1+4+1+20=30)
        0x00, 0x1E,
        // Hash algorithm: 1 (SHA-1)
        0x01,
        // Flags: 1 (opt-out)
        0x01,
        // Iterations: 10
        0x00, 0x0A,
        // Salt length: 4
        0x04,
        // Salt
        0xAA, 0xBB,
        0xCC, 0xDD,
        // Hash length: 20
        0x14,
        // Next hashed owner (20 bytes)
        0x01, 0x02,
        0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C,
        0x0D, 0x0E, 0x0F, 0x10, 0x11,
        0x12, 0x13,
        0x14,
        // Type bitmaps (empty for simplicity)
    };

    const rr = try ResourceRecord.parse(&data, 0);
    try std.testing.expectEqual(Type.nsec3, rr.rtype);

    const nsec3 = try rr.parseNSEC3();
    try std.testing.expectEqual(ResourceRecord.Nsec3HashAlgorithm.sha1, nsec3.hash_algorithm);
    try std.testing.expect(nsec3.isOptOut());
    try std.testing.expectEqual(@as(u16, 10), nsec3.iterations);
    try std.testing.expectEqual(@as(usize, 4), nsec3.salt.len);
    try std.testing.expectEqual(@as(usize, 20), nsec3.next_hashed_owner.len);
}

test "ResourceRecord.hasTypeInBitmap" {
    // Type bitmap encoding: window 0, length 7, bits for A(1), NS(2), SOA(6), MX(15), TXT(16), AAAA(28), RRSIG(46)
    // Window 0 covers types 0-255
    // A(1) = bit 1 in byte 0  = 0x40
    // NS(2) = bit 2 in byte 0 = 0x20
    // SOA(6) = bit 6 in byte 0 = 0x02
    // MX(15) = bit 7 in byte 1 = 0x01
    // TXT(16) = bit 0 in byte 2 = 0x80
    // AAAA(28) = bit 4 in byte 3 = 0x08
    // RRSIG(46) = bit 6 in byte 5 = 0x02
    const type_bitmaps = [_]u8{
        0x00, 0x06, // window 0, length 6
        0x62, // byte 0: A(1), NS(2), SOA(6) = 0x40 + 0x20 + 0x02
        0x01, // byte 1: MX(15)
        0x80, // byte 2: TXT(16)
        0x08, // byte 3: AAAA(28)
        0x00, // byte 4: nothing
        0x02, // byte 5: RRSIG(46)
    };

    try std.testing.expect(ResourceRecord.hasTypeInBitmap(&type_bitmaps, .a));
    try std.testing.expect(ResourceRecord.hasTypeInBitmap(&type_bitmaps, .ns));
    try std.testing.expect(ResourceRecord.hasTypeInBitmap(&type_bitmaps, .soa));
    try std.testing.expect(ResourceRecord.hasTypeInBitmap(&type_bitmaps, .mx));
    try std.testing.expect(ResourceRecord.hasTypeInBitmap(&type_bitmaps, .txt));
    try std.testing.expect(ResourceRecord.hasTypeInBitmap(&type_bitmaps, .aaaa));
    try std.testing.expect(ResourceRecord.hasTypeInBitmap(&type_bitmaps, .rrsig));
    try std.testing.expect(!ResourceRecord.hasTypeInBitmap(&type_bitmaps, .cname));
    try std.testing.expect(!ResourceRecord.hasTypeInBitmap(&type_bitmaps, .ptr));
}

test "ResourceRecord.calculateKeyTag" {
    // Test key tag calculation
    // Example DNSKEY RDATA
    const dnskey_rdata = [_]u8{
        0x01, 0x01, // Flags: 257
        0x03, // Protocol: 3
        0x08, // Algorithm: 8
        0x03, 0x01, 0x00, 0x01, // Public key exponent + modulus start
    };

    const tag = ResourceRecord.calculateKeyTag(&dnskey_rdata);
    // The key tag should be a non-zero value
    try std.testing.expect(tag != 0);
}

test "DnssecAlgorithm.isSupported" {
    try std.testing.expect(ResourceRecord.DnssecAlgorithm.rsasha256.isSupported());
    try std.testing.expect(ResourceRecord.DnssecAlgorithm.ecdsap256sha256.isSupported());
    try std.testing.expect(ResourceRecord.DnssecAlgorithm.ed25519.isSupported());
    try std.testing.expect(!ResourceRecord.DnssecAlgorithm.rsamd5.isSupported());
    try std.testing.expect(!ResourceRecord.DnssecAlgorithm.dsa.isSupported());
}

test "ResourceRecord.parseHTTPS with params" {
    // HTTPS record with multiple params
    // RDLENGTH = 2 (priority) + 1 (target) + 10 (alpn) + 6 (port) = 19
    const data = [_]u8{
        // Name: example.com
        7,    'e',  'x',  'a',  'm',  'p',  'l',  'e',
        3,    'c',  'o',  'm',  0,
        // TYPE: HTTPS (65)
           0x00, 0x41,
        // CLASS: IN (1)
        0x00,
        0x01,
        // TTL: 3600
        0x00, 0x00, 0x0E, 0x10,
        // RDLENGTH: 19
        0x00, 0x13,
        // Priority: 1
        0x00,
        0x01,
        // Target: . (root)
        0x00,
        // SvcParams:
        // alpn (key=1) length=6 value=[2,'h','2',2,'h','3']
        0x00, 0x01, 0x00, 0x06, 0x02, 'h',
        '2',  0x02, 'h',  '3',
        // port (key=3) length=2 value=443
         0x00, 0x03, 0x00, 0x02,
        0x01, 0xBB,
    };

    const rr = try ResourceRecord.parse(&data, 0);
    try std.testing.expectEqual(Type.https, rr.rtype);

    const svcb = try rr.parseSVCB(&data);
    try std.testing.expectEqual(@as(u16, 1), svcb.priority);

    // Iterate params
    var iter = try rr.svcbParams(&data);

    // First param: alpn
    const alpn_param = iter.next();
    try std.testing.expect(alpn_param != null);
    try std.testing.expectEqual(ResourceRecord.SvcParamKey.alpn, alpn_param.?.key);

    const allocator = std.testing.allocator;
    const alpns = try ResourceRecord.parseSvcbAlpn(alpn_param.?.value, allocator);
    defer {
        for (alpns) |a| allocator.free(a);
        allocator.free(alpns);
    }
    try std.testing.expectEqual(@as(usize, 2), alpns.len);
    try std.testing.expectEqualStrings("h2", alpns[0]);
    try std.testing.expectEqualStrings("h3", alpns[1]);

    // Second param: port
    const port_param = iter.next();
    try std.testing.expect(port_param != null);
    try std.testing.expectEqual(ResourceRecord.SvcParamKey.port, port_param.?.key);
    const port = try ResourceRecord.parseSvcbPort(port_param.?.value);
    try std.testing.expectEqual(@as(u16, 443), port);

    // No more params
    try std.testing.expect(iter.next() == null);
}

test "ResourceRecord.parseSvcbIpv4Hint single address" {
    const allocator = std.testing.allocator;
    // Single IPv4 address: 192.168.1.1
    const value = [_]u8{ 192, 168, 1, 1 };
    const hints = try ResourceRecord.parseSvcbIpv4Hint(&value, allocator);
    defer allocator.free(hints);

    try std.testing.expectEqual(@as(usize, 1), hints.len);
    try std.testing.expectEqual([4]u8{ 192, 168, 1, 1 }, hints[0]);
}

test "ResourceRecord.parseSvcbIpv4Hint multiple addresses" {
    const allocator = std.testing.allocator;
    // Two IPv4 addresses: 10.0.0.1, 10.0.0.2
    const value = [_]u8{ 10, 0, 0, 1, 10, 0, 0, 2 };
    const hints = try ResourceRecord.parseSvcbIpv4Hint(&value, allocator);
    defer allocator.free(hints);

    try std.testing.expectEqual(@as(usize, 2), hints.len);
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 1 }, hints[0]);
    try std.testing.expectEqual([4]u8{ 10, 0, 0, 2 }, hints[1]);
}

test "ResourceRecord.parseSvcbIpv4Hint invalid length" {
    const allocator = std.testing.allocator;
    // 5 bytes is not a multiple of 4
    const value = [_]u8{ 10, 0, 0, 1, 10 };
    try std.testing.expectError(error.InvalidRdataLength, ResourceRecord.parseSvcbIpv4Hint(&value, allocator));
}

test "ResourceRecord.parseSvcbIpv4Hint empty value" {
    const allocator = std.testing.allocator;
    const value = [_]u8{};
    const hints = try ResourceRecord.parseSvcbIpv4Hint(&value, allocator);
    defer allocator.free(hints);

    try std.testing.expectEqual(@as(usize, 0), hints.len);
}

test "ResourceRecord.parseSvcbIpv6Hint single address" {
    const allocator = std.testing.allocator;
    // Single IPv6 address: ::1 (loopback)
    const value = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const hints = try ResourceRecord.parseSvcbIpv6Hint(&value, allocator);
    defer allocator.free(hints);

    try std.testing.expectEqual(@as(usize, 1), hints.len);
    const expected = [16]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    try std.testing.expectEqual(expected, hints[0]);
}

test "ResourceRecord.parseSvcbIpv6Hint multiple addresses" {
    const allocator = std.testing.allocator;
    // Two IPv6 addresses
    var value: [32]u8 = undefined;
    // First: 2001:db8::1
    value[0] = 0x20;
    value[1] = 0x01;
    value[2] = 0x0d;
    value[3] = 0xb8;
    @memset(value[4..15], 0);
    value[15] = 0x01;
    // Second: 2001:db8::2
    value[16] = 0x20;
    value[17] = 0x01;
    value[18] = 0x0d;
    value[19] = 0xb8;
    @memset(value[20..31], 0);
    value[31] = 0x02;

    const hints = try ResourceRecord.parseSvcbIpv6Hint(&value, allocator);
    defer allocator.free(hints);

    try std.testing.expectEqual(@as(usize, 2), hints.len);
    try std.testing.expectEqual(@as(u8, 0x20), hints[0][0]);
    try std.testing.expectEqual(@as(u8, 0x01), hints[0][15]);
    try std.testing.expectEqual(@as(u8, 0x02), hints[1][15]);
}

test "ResourceRecord.parseSvcbIpv6Hint invalid length" {
    const allocator = std.testing.allocator;
    // 17 bytes is not a multiple of 16
    var value: [17]u8 = undefined;
    @memset(&value, 0);
    try std.testing.expectError(error.InvalidRdataLength, ResourceRecord.parseSvcbIpv6Hint(&value, allocator));
}

test "ResourceRecord.parseSvcbIpv6Hint empty value" {
    const allocator = std.testing.allocator;
    const value = [_]u8{};
    const hints = try ResourceRecord.parseSvcbIpv6Hint(&value, allocator);
    defer allocator.free(hints);

    try std.testing.expectEqual(@as(usize, 0), hints.len);
}
