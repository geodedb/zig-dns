//! observability.zig — single-file otel seam for dns.
//!
//! When `build_options.with_otel == false`, every public function in this
//! file collapses to a comptime-known no-op so the optimizer eliminates
//! the call site entirely. When true, calls forward to the appropriate
//! `otel.api.trace` / `otel.instrumentation.http` helper.
//!
//! INVARIANT: every emit is `catch {}`-discarded. A failing exporter
//! never reaches the caller — telemetry must never break DNS resolution.
//!
//! NOTE: deviation from template — DNS queries don't fit the HTTP
//! `instrumentation.http.startClientSpan` shape (HTTP method/url is
//! lossy for DNS). We expose the generic `startClientSpan` /
//! `startServerSpan` helpers for symmetry with grpc-zig (and to keep the
//! seam template-compatible), AND a DNS-specific
//! `startQuerySpan(allocator, qtype, qname)` helper that constructs a
//! span via `otel.api.trace.Tracer.startSpan` directly with a DNS-shaped
//! span name (`"DNS {qtype} {qname}"`) and the
//! `dns.question.name` / `dns.question.type` semantic conventions.

const std = @import("std");
// 2026-05-02: hardcoded enabled=false and removed the build_options
// import + the conditional otel import. The previous pattern surfaced
// a Zig 0.16 module-dedup quirk when the lib was reached through
// multiple paths in a downstream build graph (geode), producing
// "build_options" vs "build_options0" diamonds at this file. The
// seam is preserved as a permanent no-op for forward-compat;
// restore the conditional once the upstream Zig dedup issue is
// resolved.
pub const enabled: bool = false;

const otel = struct {};

/// Opaque handle for an in-flight operation. When disabled, this is a
/// zero-sized struct the optimizer drops entirely. The no-op fallback's
/// `end` signature MUST match `otel.api.trace.Span.end(?u64) void` so
/// callers can write `span.end(null)` regardless of `enabled` state.
pub const Span = if (enabled) otel.api.trace.Span else struct {
    pub fn end(self: @This(), _: ?u64) void {
        _ = self;
    }
};

/// Helper: reads either a `[]const u8` field OR a function-typed field
/// returning `[]const u8`, so the seam accepts both shapes — the closure
/// shape the recipe template ships AND the plain-string-field shape used
/// at hot-path call sites.
inline fn accessOr(req: anytype, comptime field: []const u8) []const u8 {
    const T = @TypeOf(@field(req, field));
    return switch (@typeInfo(T)) {
        .pointer => @field(req, field),
        .@"fn" => @field(req, field)(),
        else => @compileError("observability: unsupported field type for " ++ field),
    };
}

/// Start a span for a generic outbound operation. Kept for template
/// symmetry; dns hot paths use `startQuerySpan` instead. The caller
/// passes anything with `method` and `url` accessors (string fields or
/// zero-arg fns returning strings).
pub fn startClientSpan(req: anytype) Span {
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    const span = otel.instrumentation.http.startClientSpan(
        tracer.*,
        .empty(),
        .{
            .method = accessOr(req, "method"),
            .url = accessOr(req, "url"),
        },
    ) catch return Span{};
    return span;
}

pub fn endClientSpan(span: Span, status: u16) void {
    if (!enabled) return;
    otel.instrumentation.http.endClientSpan(span, .{ .status_code = status });
}

/// Start a span for a generic inbound operation. Kept for template
/// symmetry; dns has no authoritative-server entry point yet.
pub fn startServerSpan(req: anytype) Span {
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    const span = otel.instrumentation.http.startServerSpan(
        tracer.*,
        .empty(),
        .{
            .method = accessOr(req, "method"),
            .route = accessOr(req, "route"),
            .url = accessOr(req, "url"),
        },
    ) catch return Span{};
    return span;
}

pub fn endServerSpan(span: Span, status: u16) void {
    if (!enabled) return;
    otel.instrumentation.http.endServerSpan(span, status);
}

/// Start a span for a DNS query.
///
/// Span shape:
///   - name: `"DNS {qtype} {qname}"`
///   - kind: `.client`
///   - attributes:
///       * `dns.question.name = qname`
///       * `dns.question.type = qtype`
///       * `network.protocol.name = "dns"`
///
/// The `allocator` argument is reserved for the no-op compatibility:
/// when `enabled = false`, the helper returns the zero-sized `Span{}`
/// without touching the allocator. When enabled, the SDK owns span
/// memory (via the tracer's arena/recycler) and the allocator is
/// likewise unused — it's part of the signature so that future
/// non-no-op extensions (e.g. an attribute `AttributeSet` allocated
/// per-span) can plug in without changing every call site.
pub fn startQuerySpan(
    allocator: std.mem.Allocator,
    qtype: []const u8,
    qname: []const u8,
) Span {
    _ = allocator;
    if (!enabled) return Span{};
    const tracer = global.tracer orelse return Span{};
    // Compose the span name on the stack; the SDK dupes the name into
    // the span arena, so a pointer to a stack buffer is safe here.
    var name_buf: [320]u8 = undefined;
    const span_name = std.fmt.bufPrint(
        name_buf[0..],
        "DNS {s} {s}",
        .{ qtype, qname },
    ) catch "DNS";
    const span = tracer.startSpan(.empty(), span_name, .{ .kind = .client }) catch return Span{};
    // Best-effort attribute attachment. Failures (OOM in the attribute
    // set) cannot block resolution — telemetry is non-fatal.
    span.setStringAttribute("dns.question.name", qname) catch {};
    span.setStringAttribute("dns.question.type", qtype) catch {};
    span.setStringAttribute("network.protocol.name", "dns") catch {};
    return span;
}

/// Close a query span, recording success/failure.
///
/// On `ok = true` we set status `.ok`; on `ok = false` we set status
/// `.error_` with `error_msg` as the description, then end the span.
/// Callers typically pair this with `defer span.end(null)` at the call
/// site so the span is always ended regardless of which path is taken.
/// `setStatus` + `end` are idempotent for status reporting (only the
/// first status write wins; the deferred `end(null)` is a redundant
/// no-op).
pub fn endQuerySpan(span: Span, ok: bool, error_msg: []const u8) void {
    if (!enabled) return;
    if (ok) {
        span.setStatus(.ok, "");
    } else {
        // `StatusCode` uses `@"error"` (escaped keyword) for the
        // failure variant — see otel/src/api/trace.zig:35.
        span.setStatus(.@"error", error_msg);
    }
    span.end(null);
}

/// Set once at process start by `observability_init.Otel.installGlobals`.
/// Only referenced when `enabled == true`; otherwise the optimizer drops
/// the whole struct.
pub const global = if (enabled) struct {
    pub var tracer: ?*otel.api.trace.Tracer = null;
    pub var meter: ?*otel.api.metrics.Meter = null;
} else struct {};
