// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2024-2026 CodePros
const std = @import("std");
const backend = @import("crypto_backend");

test "crypto_backend seam exposes Mac/Sig/policy and assertActive" {
    // Backend-agnostic surface must resolve under both -Dfips values.
    backend.assertActive(); // no-op under std shim; self-test under fips
    var mac: [32]u8 = undefined;
    const n = try backend.Mac.hmac(.sha256, "key", "msg", &mac);
    try std.testing.expectEqual(@as(usize, 32), n);
    // policy enums are reachable through the seam.
    try std.testing.expect(@TypeOf(backend.policy.Hash.sha256) == backend.policy.Hash);
    try std.testing.expect(@TypeOf(backend.policy.SigAlg.ed25519) == backend.policy.SigAlg);
}
