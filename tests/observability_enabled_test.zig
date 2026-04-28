//! Verifies one DNS query span lands in an in-memory recorder when
//! `-Dwith_otel=true`. Skips under the disabled build.
//!
//! NOTE: deviation from template — we exercise the seam directly via
//! the in-memory recorder rather than driving a real DNS query. dns
//! query paths require network access, and the seam's behaviour is
//! identical: `startQuerySpan` -> `endQuerySpan` enters and leaves one
//! tracer span.
//!
//! The `otel` module is only added to this test root when
//! `-Dwith_otel=true`. To compile cleanly under both flag values we
//! gate the otel-namespace identifiers behind `comptime if (enabled)`
//! and stub the alias to an empty struct when the flag is off — that
//! branch is dead code in the disabled build but the import resolves.

const std = @import("std");
const build_options = @import("build_options");
const dns = @import("dns");

const otel = if (build_options.with_otel) @import("otel") else struct {};

test "one DNS query span recorded when otel enabled" {
    if (!dns.observability.enabled) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var resource = try otel.sdk.resource.defaultResource(allocator);
    defer resource.deinit();
    try resource.attributes.putString(otel.semconv.service_name, "dns-test");

    var recorder = otel.exporters.in_memory.Recorder.init(allocator);
    defer recorder.deinit();
    var tp = try otel.sdk.trace.TracerProvider.init(allocator, .{
        .resource = &resource,
        .default_exporter = recorder.spanExporter(),
    });
    defer tp.deinit();

    var tracer = tp.tracer(.{ .name = "dns-test" });
    dns.observability.global.tracer = &tracer;
    defer dns.observability.global.tracer = null;

    const span = dns.observability.startQuerySpan(allocator, "A", "example.test");
    dns.observability.endQuerySpan(span, true, "");

    try tp.forceFlush(1_000);
    try std.testing.expectEqual(@as(usize, 1), recorder.spans.items.len);

    // Verify span name shape: "DNS {qtype} {qname}".
    const recorded = recorder.spans.items[0];
    try std.testing.expectEqualStrings("DNS A example.test", recorded.name);

    // Verify the dns.question.name attribute landed on the span. The
    // in-memory recorder stores attributes as `[]KV` (string-stringified
    // key/value pairs) — see otel/src/exporters/in_memory.zig:30.
    var found_attr: ?[]const u8 = null;
    for (recorded.attribute_kv) |kv| {
        if (std.mem.eql(u8, kv.key, "dns.question.name")) {
            found_attr = kv.value;
            break;
        }
    }
    const attr_value = found_attr orelse return error.MissingDnsQuestionNameAttribute;
    try std.testing.expectEqualStrings("example.test", attr_value);
}
