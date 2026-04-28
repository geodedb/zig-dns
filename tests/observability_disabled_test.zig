//! Verifies the no-op invariant when -Dwith_otel=false (the default).
//!
//! dns publishes its public surface as the "dns" module rooted at
//! src/lib.zig. The seam is exposed as `dns.observability` so this test
//! can drive the disabled-mode invariants through the public root.

const std = @import("std");
const dns = @import("dns");

test "build_options.with_otel exists and defaults to false" {
    const build_options = @import("build_options");
    try std.testing.expect(@hasDecl(build_options, "with_otel"));
    // The "default" assertion only holds for the disabled build. When
    // the operator forces -Dwith_otel=true, this test runs against the
    // enabled module and must skip rather than misreport the default.
    if (build_options.with_otel) return error.SkipZigTest;
    try std.testing.expectEqual(false, build_options.with_otel);
}

test "observability.enabled tracks build_options.with_otel" {
    const build_options = @import("build_options");
    try std.testing.expectEqual(build_options.with_otel, dns.observability.enabled);
}

test "client/server seams are no-ops when otel disabled" {
    if (dns.observability.enabled) return error.SkipZigTest;
    var span = dns.observability.startClientSpan(.{
        .method = "GET",
        .route = "/",
        .url = "https://example.test/",
    });
    dns.observability.endClientSpan(span, 200);
    // Belt-and-suspenders: the seam's `endClientSpan` already covers
    // the lifecycle; this line just verifies the no-op fallback's
    // signature matches the real API's `Span.end(?u64) void`.
    span.end(null);

    var sspan = dns.observability.startServerSpan(.{
        .method = "GET",
        .route = "/",
        .url = "/",
    });
    dns.observability.endServerSpan(sspan, 200);
    sspan.end(null);
}

test "DNS query span helper is a no-op when otel disabled" {
    if (dns.observability.enabled) return error.SkipZigTest;
    var span = dns.observability.startQuerySpan(
        std.testing.allocator,
        "A",
        "example.test",
    );
    dns.observability.endQuerySpan(span, true, "");
    span.end(null);
}
