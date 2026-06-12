// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2025 CodePros

//! Random Number Generator Abstraction
//!
//! Provides a mockable PRNG interface for deterministic testing.

const std = @import("std");

/// Mock PRNG with fixed seed for deterministic testing
pub const MockRandom = struct {
    prng: std.Random.DefaultPrng,

    const Self = @This();

    /// Fixed seed for reproducible tests
    pub const default_seed: u64 = 0x123456789ABCDEF0;

    pub fn init() Self {
        return initWithSeed(default_seed);
    }

    pub fn initWithSeed(seed: u64) Self {
        return Self{
            .prng = std.Random.DefaultPrng.init(seed),
        };
    }

    /// Get underlying std.Random for compatibility
    pub fn random(self: *Self) std.Random {
        return self.prng.random();
    }
};

/// Error type for random initialization failures
pub const RandomError = error{
    /// Failed to obtain cryptographically secure entropy from the OS.
    /// This indicates a serious system configuration issue.
    EntropyUnavailable,
};

/// Fill `buf` with cryptographically secure OS entropy.
///
/// SECURITY: Fails fast instead of falling back to weak entropy sources
/// (like timestamps) because predictable random numbers would enable DNS
/// cache poisoning attacks through transaction ID prediction.
/// See: RFC 5452, CWE-330. Callers MUST propagate the error — never
/// `catch unreachable` on entropy (GAP-0851).
pub fn fillSecure(buf: []u8) RandomError!void {
    const io = std.Io.Threaded.global_single_threaded.io();
    std.Io.randomSecure(io, buf) catch {
        return RandomError.EntropyUnavailable;
    };
}

/// Draw a uniformly random `u16` from OS entropy (e.g. for DNS
/// transaction IDs). Fails fast if secure entropy is unavailable.
pub fn systemRandomU16() RandomError!u16 {
    var buf: [2]u8 = undefined;
    try fillSecure(&buf);
    return std.mem.readInt(u16, &buf, .little);
}

/// System PRNG using OS entropy
pub const SystemRandom = struct {
    prng: std.Random.DefaultPrng,

    const Self = @This();

    /// Initialize with OS entropy. Returns error if secure entropy is unavailable.
    ///
    /// SECURITY: This function fails-fast instead of falling back to weak entropy
    /// sources (like timestamps) because predictable random numbers would enable
    /// DNS cache poisoning attacks through transaction ID prediction.
    pub fn init() RandomError!Self {
        var seed: u64 = undefined;
        try fillSecure(std.mem.asBytes(&seed));
        return Self{
            .prng = std.Random.DefaultPrng.init(seed),
        };
    }

    pub fn random(self: *Self) std.Random {
        return self.prng.random();
    }
};

test "systemRandomU16 returns ok and varies across calls" {
    // Must succeed on any system with working OS entropy.
    _ = try systemRandomU16();

    // 16 consecutive draws must produce at least 2 distinct values.
    // P(all 16 equal) = (1/65536)^15 — effectively impossible.
    var values: [16]u16 = undefined;
    for (&values) |*v| v.* = try systemRandomU16();
    var distinct: bool = false;
    for (values[1..]) |v| {
        if (v != values[0]) {
            distinct = true;
            break;
        }
    }
    try std.testing.expect(distinct);
}

test "MockRandom deterministic" {
    var rng1 = MockRandom.init();
    var rng2 = MockRandom.init();

    const v1 = rng1.random().int(u32);
    const v2 = rng2.random().int(u32);
    try std.testing.expectEqual(v1, v2);
}

test "SystemRandom.init succeeds on normal system" {
    // This test verifies that SystemRandom.init() works on systems with entropy
    // On systems without /dev/urandom or equivalent, this test would fail
    // which is the desired behavior - we want to detect entropy issues early
    var rng = try SystemRandom.init();
    const val = rng.random().int(u64);
    // Just verify we got some value (entropy should give us non-zero most of the time)
    _ = val;
}

test "SystemRandom produces different values" {
    var rng = try SystemRandom.init();
    const val1 = rng.random().int(u64);
    const val2 = rng.random().int(u64);
    // With 64 bits of entropy, collision is astronomically unlikely
    try std.testing.expect(val1 != val2);
}
