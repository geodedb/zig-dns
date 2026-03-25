// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! DNS Types and Constants
//!
//! RFC 1035 Section 3.2: RR Definitions
//! RFC 3596: AAAA records
//! RFC 2782: SRV records
//! RFC 4034: DNSSEC types

const std = @import("std");

/// DNS Resource Record Types (RFC 1035 Section 3.2.2)
pub const Type = enum(u16) {
    /// RFC 1035: IPv4 host address
    a = 1,
    /// RFC 1035: Authoritative name server
    ns = 2,
    /// RFC 1035: Mail destination (obsolete, use MX)
    md = 3,
    /// RFC 1035: Mail forwarder (obsolete, use MX)
    mf = 4,
    /// RFC 1035: Canonical name for an alias
    cname = 5,
    /// RFC 1035: Start of authority
    soa = 6,
    /// RFC 1035: Mailbox domain name (experimental)
    mb = 7,
    /// RFC 1035: Mail group member (experimental)
    mg = 8,
    /// RFC 1035: Mail rename domain name (experimental)
    mr = 9,
    /// RFC 1035: Null RR (experimental)
    null = 10,
    /// RFC 1035: Well known service description
    wks = 11,
    /// RFC 1035: Domain name pointer
    ptr = 12,
    /// RFC 1035: Host information
    hinfo = 13,
    /// RFC 1035: Mailbox or mail list information
    minfo = 14,
    /// RFC 1035: Mail exchange
    mx = 15,
    /// RFC 1035: Text strings
    txt = 16,
    /// RFC 1183: Responsible person
    rp = 17,
    /// RFC 1183: AFS database location
    afsdb = 18,
    /// RFC 1183: X.25 PSDN address
    x25 = 19,
    /// RFC 1183: ISDN address
    isdn = 20,
    /// RFC 1183: Route through
    rt = 21,
    /// RFC 1706: NSAP address
    nsap = 22,
    /// RFC 1348: NSAP pointer
    nsap_ptr = 23,
    /// RFC 4034: Signature
    sig = 24,
    /// RFC 4034: Key
    key = 25,
    /// RFC 2163: X.400 mail mapping
    px = 26,
    /// RFC 1712: Geographical position
    gpos = 27,
    /// RFC 3596: IPv6 host address
    aaaa = 28,
    /// RFC 1876: Location information
    loc = 29,
    /// RFC 2535: Next domain (obsolete)
    nxt = 30,
    /// RFC 2782: Service locator
    srv = 33,
    /// RFC 2915: Naming authority pointer
    naptr = 35,
    /// RFC 2230: Key exchange
    kx = 36,
    /// RFC 4398: Certificate
    cert = 37,
    /// RFC 2874: IPv6 address (obsolete)
    a6 = 38,
    /// RFC 2672: DNAME
    dname = 39,
    /// RFC 2671: OPT (EDNS0)
    opt = 41,
    /// RFC 3123: Address prefix list
    apl = 42,
    /// RFC 4034: Delegation signer
    ds = 43,
    /// RFC 4255: SSH key fingerprint
    sshfp = 44,
    /// RFC 4025: IPsec key
    ipseckey = 45,
    /// RFC 4034: DNSSEC signature
    rrsig = 46,
    /// RFC 4034: Next secure
    nsec = 47,
    /// RFC 4034: DNS key
    dnskey = 48,
    /// RFC 4701: DHCP identifier
    dhcid = 49,
    /// RFC 5155: NSEC3
    nsec3 = 50,
    /// RFC 5155: NSEC3 parameters
    nsec3param = 51,
    /// RFC 6698: TLSA
    tlsa = 52,
    /// RFC 7208: Sender policy framework
    spf = 99,
    /// RFC 7043: EUI-48 address
    eui48 = 108,
    /// RFC 7043: EUI-64 address
    eui64 = 109,
    /// RFC 2930: Transaction key
    tkey = 249,
    /// RFC 2845: Transaction signature
    tsig = 250,
    /// RFC 1035: Incremental zone transfer
    ixfr = 251,
    /// RFC 1035: Zone transfer
    axfr = 252,
    /// RFC 1035: Mailbox-related records (MB, MG, MR)
    mailb = 253,
    /// RFC 1035: Mail agent RRs (obsolete)
    maila = 254,
    /// RFC 1035: Request for all records
    any = 255,
    /// RFC 7553: URI
    uri = 256,
    /// RFC 7929: Certification authority authorization
    caa = 257,
    /// RFC 8659: DNS-based service binding
    svcb = 64,
    /// RFC 8659: HTTPS service binding
    https = 65,

    _,

    pub fn fromInt(value: u16) Type {
        return @enumFromInt(value);
    }

    pub fn toInt(self: Type) u16 {
        return @intFromEnum(self);
    }
};

/// DNS Class Types (RFC 1035 Section 3.2.4)
pub const Class = enum(u16) {
    /// RFC 1035: Internet
    in = 1,
    /// RFC 1035: CSNET (obsolete)
    cs = 2,
    /// RFC 1035: CHAOS
    ch = 3,
    /// RFC 1035: Hesiod
    hs = 4,
    /// RFC 2136: None (for prerequisites)
    none = 254,
    /// RFC 1035: Any class
    any = 255,

    _,

    pub fn fromInt(value: u16) Class {
        return @enumFromInt(value);
    }

    pub fn toInt(self: Class) u16 {
        return @intFromEnum(self);
    }
};

/// DNS Operation Codes (RFC 1035 Section 4.1.1)
pub const Opcode = enum(u4) {
    /// RFC 1035: Standard query
    query = 0,
    /// RFC 1035: Inverse query (obsolete)
    iquery = 1,
    /// RFC 1035: Server status request
    status = 2,
    /// RFC 1996: Notify
    notify = 4,
    /// RFC 2136: Dynamic update
    update = 5,
    /// RFC 8490: DNS Stateful Operations
    dso = 6,

    _,
};

/// DNS Response Codes (RFC 1035 Section 4.1.1)
/// Note: Extended RCODEs (16+) are carried in EDNS OPT records
pub const ResponseCode = enum(u4) {
    /// RFC 1035: No error condition
    no_error = 0,
    /// RFC 1035: Format error
    format_error = 1,
    /// RFC 1035: Server failure
    server_failure = 2,
    /// RFC 1035: Name error (NXDOMAIN)
    name_error = 3,
    /// RFC 1035: Not implemented
    not_implemented = 4,
    /// RFC 1035: Refused
    refused = 5,
    /// RFC 2136: Name exists when it should not
    yxdomain = 6,
    /// RFC 2136: RR set exists when it should not
    yxrrset = 7,
    /// RFC 2136: RR set that should exist does not
    nxrrset = 8,
    /// RFC 2136: Not authorized
    not_auth = 9,
    /// RFC 2136: Name not contained in zone
    not_zone = 10,
    /// RFC 8490: DSO-TYPE not implemented
    dso_type_ni = 11,

    _,

    /// Alias for name_error (NXDOMAIN)
    pub const nxdomain = ResponseCode.name_error;
};

/// Maximum DNS name length (RFC 1035 Section 2.3.4)
pub const max_name_length = 255;

/// Maximum DNS label length (RFC 1035 Section 2.3.4)
pub const max_label_length = 63;

/// Maximum DNS message size for UDP (RFC 1035)
pub const max_udp_message_size = 512;

/// Default EDNS UDP payload size
pub const default_edns_udp_size = 4096;

/// DNS port (RFC 1035)
pub const dns_port = 53;

/// DNS over TLS port (RFC 7858)
pub const dot_port = 853;

/// DNS over HTTPS port (RFC 8484)
pub const doh_port = 443;

/// Maximum number of spurious (non-matching source) packets to discard before
/// returning an error. Prevents CPU pinning from flood attacks (SEC-AUDIT-02).
/// Used by stub resolver, recursive resolver, and UDP transport receive loops.
pub const max_spurious_discards: u32 = 1000;

/// Tracks spurious packet discards and enforces the discard limit (SEC-AUDIT-02).
/// Each UDP receive loop should create one of these and call `increment()` for
/// every packet received from a non-matching source address.
pub const SpuriousDiscardCounter = struct {
    count: u32 = 0,

    /// Record a spurious packet. Returns `error.TooManySpuriousPackets` if the
    /// discard limit has been reached, signalling that the receive loop should
    /// abort to prevent CPU pinning from flood attacks.
    pub fn increment(self: *SpuriousDiscardCounter) error{TooManySpuriousPackets}!void {
        self.count += 1;
        if (self.count >= max_spurious_discards) {
            return error.TooManySpuriousPackets;
        }
    }
};

test "Type enum values" {
    try std.testing.expectEqual(@as(u16, 1), Type.a.toInt());
    try std.testing.expectEqual(@as(u16, 28), Type.aaaa.toInt());
    try std.testing.expectEqual(@as(u16, 5), Type.cname.toInt());
    try std.testing.expectEqual(@as(u16, 15), Type.mx.toInt());
    try std.testing.expectEqual(@as(u16, 16), Type.txt.toInt());
}

test "Class enum values" {
    try std.testing.expectEqual(@as(u16, 1), Class.in.toInt());
    try std.testing.expectEqual(@as(u16, 255), Class.any.toInt());
}

test "ResponseCode aliases" {
    try std.testing.expectEqual(ResponseCode.name_error, ResponseCode.nxdomain);
}

test "QR-R02: SpuriousDiscardCounter allows discards below limit" {
    var counter = SpuriousDiscardCounter{};
    // Incrementing below the limit should succeed without error
    var i: u32 = 0;
    while (i < max_spurious_discards - 1) : (i += 1) {
        try counter.increment();
    }
    try std.testing.expectEqual(max_spurious_discards - 1, counter.count);
}

test "QR-R02: SpuriousDiscardCounter returns TooManySpuriousPackets at limit" {
    var counter = SpuriousDiscardCounter{};
    // Drive the counter to exactly the limit
    var i: u32 = 0;
    while (i < max_spurious_discards - 1) : (i += 1) {
        try counter.increment();
    }
    // The next increment (reaching max_spurious_discards) must return the error
    try std.testing.expectError(error.TooManySpuriousPackets, counter.increment());
    try std.testing.expectEqual(max_spurious_discards, counter.count);
}

test "QR-R02: SpuriousDiscardCounter starts at zero" {
    const counter = SpuriousDiscardCounter{};
    try std.testing.expectEqual(@as(u32, 0), counter.count);
}
