//! zdig - A dig-like DNS query tool built on zigdns
//!
//! Usage: zdig [@server] [name] [type] [options]
//!
//! Examples:
//!   zdig example.com              - Query A record for example.com
//!   zdig example.com AAAA         - Query AAAA record
//!   zdig @8.8.8.8 example.com MX  - Query MX using specific server
//!   zdig +short example.com       - Short output format
//!   zdig +tcp example.com         - Force TCP

const std = @import("std");
const dns = @import("dns");
const cli = @import("cli");
const net_compat = @import("net_compat");

const Allocator = std.mem.Allocator;

/// 0.16.0 compat: CSPRNG via Io (std.crypto.random was removed).
fn csprngInt(comptime T: type) T {
    var buf: [@sizeOf(T)]u8 = undefined;
    const io_inst = std.Io.Threaded.global_single_threaded.io();
    std.Io.randomSecure(io_inst, &buf) catch unreachable;
    return std.mem.readInt(T, &buf, .little);
}

/// 0.16.0 compat: monotonic millisecond timestamp via Io Clock.
fn milliTimestamp() i64 {
    const io_inst = std.Io.Threaded.global_single_threaded.io();
    const ts = std.Io.Clock.awake.now(io_inst);
    return ts.toMilliseconds();
}

/// Query options
const QueryOptions = struct {
    /// DNS server to query (default: 8.8.8.8)
    server: []const u8 = "8.8.8.8",
    /// Server port
    port: u16 = 53,
    /// Query type
    qtype: dns.types.Type = .a,
    /// Query class
    qclass: dns.types.Class = .in,
    /// Query name
    name: []const u8 = "",
    /// Use TCP instead of UDP
    use_tcp: bool = false,
    /// Short output (just answers)
    short: bool = false,
    /// Show trace (delegation path)
    trace: bool = false,
    /// Disable recursion
    no_recurse: bool = false,
    /// Request DNSSEC records
    dnssec: bool = false,
    /// JSON output format
    json: bool = false,
    /// Show query time
    stats: bool = true,
    /// Timeout in seconds
    timeout: u32 = 5,
    /// Number of retries
    retries: u32 = 3,
    /// Show all sections
    all: bool = true,
    /// Show question section
    question: bool = true,
    /// Show answer section
    answer: bool = true,
    /// Show authority section
    authority: bool = true,
    /// Show additional section
    additional: bool = true,
    /// Show comments
    comments: bool = true,
};

/// Buffered stdout writer context
const StdoutContext = struct {
    file_writer: ?std.Io.File.Writer = null,
    buffer: [4096]u8 = [_]u8{0} ** 4096,

    const Self = @This();

    pub fn writer(self: *Self) *std.Io.Writer {
        if (self.file_writer == null) {
            const io = std.Io.Threaded.global_single_threaded.io();
            self.file_writer = std.Io.File.stdout().writer(io, &self.buffer);
        }
        return &self.file_writer.?.interface;
    }

    pub fn flush(self: *Self) !void {
        if (self.file_writer) |*fw| {
            try fw.interface.flush();
        }
    }
};

// ============================================================================
// CLI Command Definition
// ============================================================================

// Root command
const root_cmd = cli.Command{
    .name = "zdig",
    .summary = "A dig-like DNS query tool built on zigdns",
    .long_help =
    \\zdig is a DNS query tool similar to dig, built on the zigdns library.
    \\
    \\Arguments are parsed in a dig-compatible way:
    \\  @server   - DNS server to query (e.g., @8.8.8.8)
    \\  name      - Domain name to look up
    \\  type      - Query type (A, AAAA, MX, NS, TXT, SOA, etc.)
    \\  +option   - Query options (see below)
    \\
    \\Query options (dig-style):
    \\  +tcp          Use TCP instead of UDP
    \\  +short        Show only answer data
    \\  +trace        Trace delegation from root
    \\  +[no]recurse  Toggle recursive query
    \\  +dnssec       Request DNSSEC records
    \\  +json         Output in JSON format
    \\  +[no]stats    Toggle query statistics
    \\  +[no]all      Toggle all sections
    \\  +[no]comments Toggle comment lines
    \\  +[no]question Toggle question section (alias: +qr)
    \\  +[no]answer   Toggle answer section (alias: +an)
    \\  +[no]authority Toggle authority section (alias: +au)
    \\  +[no]additional Toggle additional section (alias: +ad)
    ,
    .examples = &.{
        "zdig example.com",
        "zdig example.com MX",
        "zdig @1.1.1.1 example.com AAAA",
        "zdig +short example.com",
        "zdig +trace example.com",
        "zdig +tcp --json google.com",
        "zdig completion --shell bash > /etc/bash_completion.d/zdig",
    },
    .flags = &.{
        cli.FlagSpec{
            .name = "port",
            .short = 'p',
            .help = "Server port",
            .ftype = .int,
            .default_str = "53",
            .env = "ZDIG_PORT",
        },
        cli.FlagSpec{
            .name = "timeout",
            .short = 't',
            .help = "Query timeout in seconds",
            .ftype = .int,
            .default_str = "5",
            .env = "ZDIG_TIMEOUT",
        },
        cli.FlagSpec{
            .name = "retries",
            .short = 'r',
            .help = "Number of retries",
            .ftype = .int,
            .default_str = "3",
            .env = "ZDIG_RETRIES",
        },
        cli.FlagSpec{
            .name = "server",
            .short = 's',
            .help = "DNS server to query (alternative to @server)",
            .ftype = .string,
            .default_str = "8.8.8.8",
            .env = "ZDIG_SERVER",
        },
    },
    .subcommands = &.{
        &completion_cmd,
        &man_cmd,
    },
    .run = runQuery,
};

// Completion command - generate shell completion scripts
const completion_cmd = cli.Command{
    .name = "completion",
    .summary = "Generate shell completion script",
    .long_help =
    \\Generate a shell completion script for zdig.
    \\
    \\To enable completions:
    \\
    \\  Bash:
    \\    zdig completion --shell bash > /etc/bash_completion.d/zdig
    \\    # or for user-local:
    \\    zdig completion --shell bash >> ~/.bashrc
    \\
    \\  Zsh:
    \\    zdig completion --shell zsh > "${fpath[1]}/_zdig"
    \\
    \\  Fish:
    \\    zdig completion --shell fish > ~/.config/fish/completions/zdig.fish
    ,
    .examples = &.{
        "zdig completion --shell bash",
        "zdig completion --shell zsh > _zdig",
        "zdig completion --shell fish > zdig.fish",
    },
    .flags = &.{
        cli.FlagSpec{
            .name = "shell",
            .short = 's',
            .help = "Shell type (bash, zsh, fish)",
            .ftype = .string,
            .required = true,
        },
    },
    .run = completionRun,
};

// Man page command
const man_cmd = cli.Command{
    .name = "man",
    .summary = "Generate man page",
    .long_help =
    \\Generate a man page for zdig in roff format.
    \\
    \\To install the man page:
    \\  zdig man > /usr/local/share/man/man1/zdig.1
    \\  mandb  # update man database
    ,
    .examples = &.{
        "zdig man",
        "zdig man > zdig.1",
    },
    .run = manRun,
};

fn completionRun(ctx: *cli.Context) !void {
    const shell = ctx.getString("shell") orelse "bash";

    if (std.mem.eql(u8, shell, "bash")) {
        const script = try cli.completion.bash.generate(&root_cmd, ctx.allocator);
        defer ctx.allocator.free(script);
        try ctx.stdout.writeAll(script);
    } else if (std.mem.eql(u8, shell, "zsh")) {
        const script = try cli.completion.zsh.generate(&root_cmd, ctx.allocator);
        defer ctx.allocator.free(script);
        try ctx.stdout.writeAll(script);
    } else if (std.mem.eql(u8, shell, "fish")) {
        const script = try cli.completion.fish.generate(&root_cmd, ctx.allocator);
        defer ctx.allocator.free(script);
        try ctx.stdout.writeAll(script);
    } else {
        try ctx.err("Error: Unknown shell '{s}'. Supported: bash, zsh, fish\n", .{shell});
    }
}

fn manRun(ctx: *cli.Context) !void {
    const man_page = try cli.generateMan(&root_cmd, ctx.allocator);
    defer ctx.allocator.free(man_page);
    try ctx.stdout.writeAll(man_page);
}

fn runQuery(ctx: *cli.Context) !void {
    var options = QueryOptions{};

    // Get flag values
    options.port = @intCast(ctx.getInt("port") orelse 53);
    options.timeout = @intCast(ctx.getInt("timeout") orelse 5);
    options.retries = @intCast(ctx.getInt("retries") orelse 3);

    // Get server from --server flag (can be overridden by @server positional)
    if (ctx.getString("server")) |server| {
        options.server = server;
    }

    // Integrate with CLI library's global --json flag
    if (ctx.json) {
        options.json = true;
    }

    // Parse positional arguments (dig-style)
    for (ctx.positionals.items) |arg| {
        if (arg.len == 0) continue;

        // Check for +option style flags
        if (arg[0] == '+') {
            parseOption(&options, arg[1..]);
            continue;
        }

        // Check for @server (overrides --server flag)
        if (arg[0] == '@') {
            options.server = arg[1..];
            continue;
        }

        // Check if it's a query type
        if (parseQueryType(arg)) |qtype| {
            options.qtype = qtype;
            continue;
        }

        // Check if it's a query class
        if (parseQueryClass(arg)) |qclass| {
            options.qclass = qclass;
            continue;
        }

        // Otherwise it's the name
        if (options.name.len == 0) {
            options.name = arg;
        }
    }

    // Validate we have a name to query
    if (options.name.len == 0) {
        try ctx.err("Error: No domain name specified\n\n", .{});
        try ctx.err("Usage: zdig [@server] [name] [type] [options]\n", .{});
        try ctx.err("Try 'zdig --help' for more information.\n", .{});
        // GAP-0881: returning an error makes cli.run exit non-zero (1)
        // instead of silently succeeding with no query performed.
        return error.MissingQueryName;
    }

    // Perform the query
    if (options.trace) {
        try performTrace(ctx.allocator, &options);
    } else {
        try performQuery(ctx.allocator, &options);
    }
}

fn parseOption(options: *QueryOptions, opt: []const u8) void {
    // Handle +option and +nooption style
    const is_no = std.mem.startsWith(u8, opt, "no");
    const name = if (is_no) opt[2..] else opt;
    const value = !is_no;

    if (std.mem.eql(u8, name, "tcp")) {
        options.use_tcp = value;
    } else if (std.mem.eql(u8, name, "short")) {
        options.short = value;
    } else if (std.mem.eql(u8, name, "trace")) {
        options.trace = value;
    } else if (std.mem.eql(u8, name, "recurse")) {
        options.no_recurse = !value;
    } else if (std.mem.eql(u8, name, "dnssec")) {
        options.dnssec = value;
    } else if (std.mem.eql(u8, name, "json")) {
        options.json = value;
    } else if (std.mem.eql(u8, name, "stats")) {
        options.stats = value;
    } else if (std.mem.eql(u8, name, "all")) {
        options.all = value;
        options.question = value;
        options.answer = value;
        options.authority = value;
        options.additional = value;
        options.comments = value;
    } else if (std.mem.eql(u8, name, "question") or std.mem.eql(u8, name, "qr")) {
        options.question = value;
    } else if (std.mem.eql(u8, name, "answer") or std.mem.eql(u8, name, "an")) {
        options.answer = value;
    } else if (std.mem.eql(u8, name, "authority") or std.mem.eql(u8, name, "au")) {
        options.authority = value;
    } else if (std.mem.eql(u8, name, "additional") or std.mem.eql(u8, name, "ad")) {
        options.additional = value;
    } else if (std.mem.eql(u8, name, "comments") or std.mem.eql(u8, name, "cmd")) {
        options.comments = value;
    }
}

fn parseQueryType(s: []const u8) ?dns.types.Type {
    var buf: [16]u8 = undefined;
    const upper = asciiUpper(s, &buf);

    if (std.mem.eql(u8, upper, "A")) return .a;
    if (std.mem.eql(u8, upper, "AAAA")) return .aaaa;
    if (std.mem.eql(u8, upper, "CNAME")) return .cname;
    if (std.mem.eql(u8, upper, "MX")) return .mx;
    if (std.mem.eql(u8, upper, "NS")) return .ns;
    if (std.mem.eql(u8, upper, "PTR")) return .ptr;
    if (std.mem.eql(u8, upper, "SOA")) return .soa;
    if (std.mem.eql(u8, upper, "SRV")) return .srv;
    if (std.mem.eql(u8, upper, "TXT")) return .txt;
    if (std.mem.eql(u8, upper, "ANY")) return .any;
    if (std.mem.eql(u8, upper, "AXFR")) return .axfr;
    if (std.mem.eql(u8, upper, "CAA")) return .caa;
    if (std.mem.eql(u8, upper, "DNSKEY")) return .dnskey;
    if (std.mem.eql(u8, upper, "DS")) return .ds;
    if (std.mem.eql(u8, upper, "HTTPS")) return .https;
    if (std.mem.eql(u8, upper, "NAPTR")) return .naptr;
    if (std.mem.eql(u8, upper, "OPT")) return .opt;
    if (std.mem.eql(u8, upper, "RRSIG")) return .rrsig;
    if (std.mem.eql(u8, upper, "SSHFP")) return .sshfp;
    if (std.mem.eql(u8, upper, "SVCB")) return .svcb;
    if (std.mem.eql(u8, upper, "TLSA")) return .tlsa;
    if (std.mem.eql(u8, upper, "NSEC")) return .nsec;
    if (std.mem.eql(u8, upper, "NSEC3")) return .nsec3;

    return null;
}

fn parseQueryClass(s: []const u8) ?dns.types.Class {
    var buf: [16]u8 = undefined;
    const upper = asciiUpper(s, &buf);

    if (std.mem.eql(u8, upper, "IN")) return .in;
    if (std.mem.eql(u8, upper, "CH") or std.mem.eql(u8, upper, "CHAOS")) return .ch;
    if (std.mem.eql(u8, upper, "HS") or std.mem.eql(u8, upper, "HESIOD")) return .hs;
    if (std.mem.eql(u8, upper, "ANY")) return .any;

    return null;
}

fn asciiUpper(s: []const u8, buf: []u8) []const u8 {
    const len = @min(s.len, buf.len);
    for (s[0..len], 0..) |c, i| {
        buf[i] = std.ascii.toUpper(c);
    }
    return buf[0..len];
}

/// Write attacker-controlled bytes (record names, TXT/CAA character-strings)
/// to a terminal-bound writer with control and non-ASCII bytes escaped as
/// `\DDD`, mirroring dig's RFC 1035 §5.1 presentation format. Prevents ANSI/
/// OSC terminal-escape injection from malicious DNS responses (SEC-SR-5,
/// CWE-150). The JSON output path uses escapeJsonString instead.
fn writeSanitized(writer: anytype, bytes: []const u8) !void {
    for (bytes) |b| {
        switch (b) {
            '\\' => try writer.writeAll("\\\\"),
            '"' => try writer.writeAll("\\\""),
            // Printable ASCII except '"' (0x22) and '\\' (0x5C), handled above.
            0x20, 0x21, 0x23...0x5B, 0x5D...0x7E => try writer.writeByte(b),
            // Control bytes (incl. ESC/BEL), DEL, and non-ASCII -> \DDD decimal.
            else => try writer.print("\\{d:0>3}", .{b}),
        }
    }
}

/// Escape a string for JSON output (SEC-GAP-054: CWE-117)
fn escapeJsonString(allocator: Allocator, input: []const u8) ![]u8 {
    var escape_count: usize = 0;
    for (input) |c| {
        if (c == '"' or c == '\\' or c < 0x20) escape_count += 1;
    }
    if (escape_count == 0) return try allocator.dupe(u8, input);

    var output = try allocator.alloc(u8, input.len + escape_count * 5);
    errdefer allocator.free(output);

    var out_idx: usize = 0;
    for (input) |c| {
        if (c == '"') {
            output[out_idx] = '\\';
            output[out_idx + 1] = '"';
            out_idx += 2;
        } else if (c == '\\') {
            output[out_idx] = '\\';
            output[out_idx + 1] = '\\';
            out_idx += 2;
        } else if (c == '\n') {
            output[out_idx] = '\\';
            output[out_idx + 1] = 'n';
            out_idx += 2;
        } else if (c == '\r') {
            output[out_idx] = '\\';
            output[out_idx + 1] = 'r';
            out_idx += 2;
        } else if (c == '\t') {
            output[out_idx] = '\\';
            output[out_idx + 1] = 't';
            out_idx += 2;
        } else if (c < 0x20) {
            const hex = "0123456789abcdef";
            output[out_idx] = '\\';
            output[out_idx + 1] = 'u';
            output[out_idx + 2] = '0';
            output[out_idx + 3] = '0';
            output[out_idx + 4] = hex[c >> 4];
            output[out_idx + 5] = hex[c & 0x0F];
            out_idx += 6;
        } else {
            output[out_idx] = c;
            out_idx += 1;
        }
    }
    return allocator.realloc(output, out_idx);
}

fn performQuery(allocator: Allocator, options: *const QueryOptions) !void {
    var stdout = StdoutContext{};
    // stdout flush on function exit is best-effort; output may already be partially written.
    defer stdout.flush() catch {};
    const writer = stdout.writer();

    // Record start time
    const query_start = milliTimestamp();

    // Generate cryptographically secure query ID (SEC-GAP-035: CWE-330)
    const id: u16 = csprngInt(u16);

    // Build the query message using the library's buildQuery function
    const query_data = try dns.message.buildQuery(allocator, id, options.name, options.qtype, options.qclass, !options.no_recurse, options.dnssec);
    defer allocator.free(query_data);

    // Send query and get response
    const response_data = try sendQuery(allocator, options, query_data);
    defer allocator.free(response_data);

    const query_time = milliTimestamp() - query_start;

    // Parse response
    const response = try dns.message.Message.parse(response_data);

    // Validate response (SEC-GAP-043: CWE-345)
    // 1. Validate transaction ID matches
    if (response.header.id != id) {
        return error.TransactionIdMismatch;
    }

    // 2. Validate question section matches our query
    if (response.header.qdcount > 0) {
        var q_iter = response.questions();
        if (try q_iter.next()) |q| {
            // Validate QTYPE matches
            if (q.qtype != options.qtype) {
                return error.QuestionTypeMismatch;
            }
            // Validate QCLASS matches
            if (q.qclass != options.qclass) {
                return error.QuestionClassMismatch;
            }
            // Validate QNAME matches (compare the wire format representations)
            const q_name_str = try q.qname.toString(allocator, response_data);
            defer allocator.free(q_name_str);

            // Normalize both names for comparison (remove trailing dots)
            const query_name_normalized = if (options.name.len > 0 and options.name[options.name.len - 1] == '.')
                options.name[0 .. options.name.len - 1]
            else
                options.name;

            const response_name_normalized = if (q_name_str.len > 0 and q_name_str[q_name_str.len - 1] == '.')
                q_name_str[0 .. q_name_str.len - 1]
            else
                q_name_str;

            if (!std.ascii.eqlIgnoreCase(query_name_normalized, response_name_normalized)) {
                return error.QuestionNameMismatch;
            }
        }
    }

    // Output the response
    if (options.json) {
        try outputJson(allocator, writer, response, response_data);
    } else if (options.short) {
        try outputShort(allocator, writer, response, response_data);
    } else {
        try outputDigStyle(allocator, writer, response, response_data, options, query_time, query_data.len, response_data.len);
    }
}

fn sendQuery(allocator: Allocator, options: *const QueryOptions, query_data: []const u8) ![]u8 {
    // Parse server address
    const address = try net_compat.Address.parseIp4(options.server, options.port);

    if (options.use_tcp) {
        return sendTcp(allocator, address, query_data, options.timeout);
    } else {
        return sendUdp(allocator, address, query_data, options.timeout);
    }
}

fn sendUdp(allocator: Allocator, address: net_compat.Address, query_data: []const u8, timeout_secs: u32) ![]u8 {
    const sock = try net_compat.socket(std.posix.AF.INET, std.posix.SOCK.DGRAM, 0);
    defer net_compat.close(sock);

    // Set timeout
    const timeout_us: i64 = @as(i64, timeout_secs) * 1_000_000;
    const timeout = std.posix.timeval{
        .sec = @intCast(@divFloor(timeout_us, 1_000_000)),
        .usec = @intCast(@mod(timeout_us, 1_000_000)),
    };
    try std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));

    // Send query
    _ = try net_compat.sendto(sock, query_data, 0, &address.any, address.getOsSockLen());

    // Receive response with source validation (SEC-GAP-042)
    const response_buf = try allocator.alloc(u8, 65535);
    errdefer allocator.free(response_buf);

    // Capture source address to validate it matches expected server
    var source_addr: std.posix.sockaddr = undefined;
    var source_addr_len: std.posix.socklen_t = @sizeOf(@TypeOf(source_addr));

    // On any error return below, the errdefer above frees response_buf
    // exactly once; explicit frees here would double-free (GAP-0875).
    const recv_len = try net_compat.recvfrom(sock, response_buf, 0, &source_addr, &source_addr_len);

    // Validate source address matches the server we queried (CWE-345)
    if (!addressMatches(&address.any, &source_addr)) {
        return error.SourceAddressMismatch;
    }

    // Resize to actual length
    return allocator.realloc(response_buf, recv_len);
}

/// Validate that two socket addresses match (for response source validation)
fn addressMatches(expected: *const std.posix.sockaddr, received: *const std.posix.sockaddr) bool {
    // Check address family
    if (expected.family != received.family) return false;

    if (expected.family == std.posix.AF.INET) {
        const expected_in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(expected));
        const received_in: *const std.posix.sockaddr.in = @ptrCast(@alignCast(received));
        // Compare IPv4 address and port
        return expected_in.addr == received_in.addr and expected_in.port == received_in.port;
    } else if (expected.family == std.posix.AF.INET6) {
        const expected_in6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(expected));
        const received_in6: *const std.posix.sockaddr.in6 = @ptrCast(@alignCast(received));
        // Compare IPv6 address and port
        return std.mem.eql(u8, &expected_in6.addr, &received_in6.addr) and
            expected_in6.port == received_in6.port;
    }

    return false;
}

fn sendTcp(allocator: Allocator, address: net_compat.Address, query_data: []const u8, timeout_secs: u32) ![]u8 {
    const sock = try net_compat.socket(std.posix.AF.INET, std.posix.SOCK.STREAM, 0);
    defer net_compat.close(sock);

    // Set timeouts (SEC-GAP-047: CWE-400)
    const timeout_us: i64 = @as(i64, timeout_secs) * 1_000_000;
    const timeout = std.posix.timeval{
        .sec = @intCast(@divFloor(timeout_us, 1_000_000)),
        .usec = @intCast(@mod(timeout_us, 1_000_000)),
    };

    // Set send timeout
    try std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&timeout));
    // Set receive timeout
    try std.posix.setsockopt(sock, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));

    // Connect (timeout controlled by OS, typically ~75 seconds)
    // For finer control, would need non-blocking socket + select/poll
    try net_compat.connect(sock, &address.any, address.getOsSockLen());

    // TCP DNS uses 2-byte length prefix
    var len_buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &len_buf, @intCast(query_data.len), .big);
    _ = try net_compat.send(sock, &len_buf, 0);
    _ = try net_compat.send(sock, query_data, 0);

    // Read response length with exact-read loop (SEC-GAP-046: CWE-400)
    var recv_len_buf: [2]u8 = undefined;
    var len_bytes_read: usize = 0;
    while (len_bytes_read < 2) {
        const n = try net_compat.recv(sock, recv_len_buf[len_bytes_read..], 0);
        if (n == 0) return error.ConnectionClosed;
        len_bytes_read += n;
    }
    const response_len = std.mem.readInt(u16, &recv_len_buf, .big);

    // Read response
    const response_buf = try allocator.alloc(u8, response_len);
    errdefer allocator.free(response_buf);

    var total_read: usize = 0;
    while (total_read < response_len) {
        const n = try net_compat.recv(sock, response_buf[total_read..], 0);
        if (n == 0) return error.ConnectionClosed;
        total_read += n;
    }

    return response_buf;
}

fn outputShort(allocator: Allocator, writer: anytype, response: dns.message.Message, data: []const u8) !void {
    var iter = response.answers();
    while (try iter.next()) |rr| {
        try outputRDataShort(allocator, writer, rr, data);
        try writer.writeAll("\n");
    }
}

fn outputRDataShort(allocator: Allocator, writer: anytype, rr: dns.record.ResourceRecord, data: []const u8) !void {
    switch (rr.rtype) {
        .a => {
            const addr = try rr.parseA();
            try writer.print("{d}.{d}.{d}.{d}", .{ addr[0], addr[1], addr[2], addr[3] });
        },
        .aaaa => {
            const addr = try rr.parseAAAA();
            var i: usize = 0;
            while (i < 16) : (i += 2) {
                if (i > 0) try writer.writeAll(":");
                try writer.print("{x:0>2}{x:0>2}", .{ addr[i], addr[i + 1] });
            }
        },
        .cname, .ns, .ptr => {
            const name = try rr.parseName(data);
            const name_str = try name.toString(allocator, data);
            defer allocator.free(name_str);
            try writeSanitized(writer, name_str);
        },
        .mx => {
            const mx = try rr.parseMX(data);
            const exchange_str = try mx.exchange.toString(allocator, data);
            defer allocator.free(exchange_str);
            try writer.print("{d} ", .{mx.preference});
            try writeSanitized(writer, exchange_str);
        },
        .txt => {
            const txt = try rr.parseTXT(allocator);
            defer {
                for (txt) |s| allocator.free(s);
                allocator.free(txt);
            }
            for (txt) |segment| {
                try writer.writeByte('"');
                try writeSanitized(writer, segment);
                try writer.writeByte('"');
            }
        },
        .soa => {
            const soa = try rr.parseSOA(data);
            const mname_str = try soa.mname.toString(allocator, data);
            defer allocator.free(mname_str);
            const rname_str = try soa.rname.toString(allocator, data);
            defer allocator.free(rname_str);
            try writeSanitized(writer, mname_str);
            try writer.writeByte(' ');
            try writeSanitized(writer, rname_str);
            try writer.print(" {d} {d} {d} {d} {d}", .{
                soa.serial,
                soa.refresh,
                soa.retry,
                soa.expire,
                soa.minimum,
            });
        },
        .srv => {
            const srv = try rr.parseSRV(data);
            const target_str = try srv.target.toString(allocator, data);
            defer allocator.free(target_str);
            try writer.print("{d} {d} {d} ", .{
                srv.priority,
                srv.weight,
                srv.port,
            });
            try writeSanitized(writer, target_str);
        },
        .caa => {
            const caa = try rr.parseCAA();
            try writer.print("{d} ", .{caa.flags});
            try writeSanitized(writer, caa.tag);
            try writer.writeAll(" \"");
            try writeSanitized(writer, caa.value);
            try writer.writeByte('"');
        },
        else => {
            // For other types, show raw hex
            try writer.writeAll("\\# ");
            try writer.print("{d} ", .{rr.rdlength});
            for (rr.rdata) |b| {
                try writer.print("{x:0>2}", .{b});
            }
        },
    }
}

fn outputDigStyle(allocator: Allocator, writer: anytype, response: dns.message.Message, data: []const u8, options: *const QueryOptions, query_time: i64, query_size: usize, response_size: usize) !void {
    const header = response.header;

    // Header comment
    if (options.comments) {
        try writer.writeAll("\n; <<>> zdig 1.0 <<>> ");
        try writer.print("{s}", .{options.name});
        if (options.qtype != .a) {
            try writer.print(" {s}", .{@tagName(options.qtype)});
        }
        try writer.writeAll("\n");

        // Global options
        try writer.writeAll(";; global options: +cmd\n");

        // Got answer header
        try writer.writeAll(";; Got answer:\n");

        // Header section
        try writer.print(";; ->>HEADER<<- opcode: {s}, status: {s}, id: {d}\n", .{
            @tagName(header.opcode),
            @tagName(header.rcode),
            header.id,
        });

        // Flags
        try writer.writeAll(";; flags:");
        if (header.qr) try writer.writeAll(" qr");
        if (header.aa) try writer.writeAll(" aa");
        if (header.tc) try writer.writeAll(" tc");
        if (header.rd) try writer.writeAll(" rd");
        if (header.ra) try writer.writeAll(" ra");

        try writer.print("; QUERY: {d}, ANSWER: {d}, AUTHORITY: {d}, ADDITIONAL: {d}\n\n", .{
            header.qdcount,
            header.ancount,
            header.nscount,
            header.arcount,
        });
    }

    // Question section
    if (options.question and header.qdcount > 0) {
        try writer.writeAll(";; QUESTION SECTION:\n");
        var q_iter = response.questions();
        while (try q_iter.next()) |q| {
            const q_name = try q.qname.toString(allocator, data);
            defer allocator.free(q_name);
            try writer.writeByte(';');
            try writeSanitized(writer, q_name);
            try writer.print(".\t\t\t{s}\t{s}\n", .{
                @tagName(q.qclass),
                @tagName(q.qtype),
            });
        }
        try writer.writeAll("\n");
    }

    // Answer section
    if (options.answer and header.ancount > 0) {
        try writer.writeAll(";; ANSWER SECTION:\n");
        var ans_iter = response.answers();
        while (try ans_iter.next()) |rr| {
            try outputResourceRecord(allocator, writer, rr, data);
        }
        try writer.writeAll("\n");
    }

    // Authority section
    if (options.authority and header.nscount > 0) {
        try writer.writeAll(";; AUTHORITY SECTION:\n");
        var auth_iter = response.authority();
        while (try auth_iter.next()) |rr| {
            try outputResourceRecord(allocator, writer, rr, data);
        }
        try writer.writeAll("\n");
    }

    // Additional section
    if (options.additional and header.arcount > 0) {
        try writer.writeAll(";; ADDITIONAL SECTION:\n");
        var add_iter = response.additional();
        while (try add_iter.next()) |rr| {
            // Skip OPT pseudo-records in display
            if (rr.rtype == .opt) continue;
            try outputResourceRecord(allocator, writer, rr, data);
        }
        try writer.writeAll("\n");
    }

    // Query stats
    if (options.stats) {
        try writer.print(";; Query time: {d} msec\n", .{query_time});
        try writer.print(";; SERVER: {s}#{d}({s})\n", .{ options.server, options.port, options.server });

        // Current time
        const io_inst = std.Io.Threaded.global_single_threaded.io();
        const now = std.Io.Clock.real.now(io_inst);
        const epoch_secs: u64 = @intCast(now.toSeconds());
        const epoch = std.time.epoch.EpochSeconds{ .secs = epoch_secs };
        const day = epoch.getEpochDay();
        const year_day = day.calculateYearDay();
        const month_day = year_day.calculateMonthDay();
        try writer.print(";; WHEN: {d}-{d:0>2}-{d:0>2}\n", .{
            year_day.year,
            @intFromEnum(month_day.month),
            month_day.day_index + 1,
        });

        try writer.print(";; MSG SIZE  rcvd: {d}\n", .{response_size});
        _ = query_size;
    }
}

fn outputResourceRecord(allocator: Allocator, writer: anytype, rr: dns.record.ResourceRecord, data: []const u8) !void {
    const rr_name = try rr.name.toString(allocator, data);
    defer allocator.free(rr_name);

    try writeSanitized(writer, rr_name);
    try writer.print(".\t{d}\t{s}\t{s}\t", .{
        rr.ttl,
        @tagName(rr.class),
        @tagName(rr.rtype),
    });
    try outputRDataShort(allocator, writer, rr, data);
    try writer.writeAll("\n");
}

fn outputJson(allocator: Allocator, writer: anytype, response: dns.message.Message, data: []const u8) !void {
    try writer.writeAll("{\n");

    // Header
    try writer.writeAll("  \"header\": {\n");
    try writer.print("    \"id\": {d},\n", .{response.header.id});
    try writer.print("    \"opcode\": \"{s}\",\n", .{@tagName(response.header.opcode)});
    try writer.print("    \"rcode\": \"{s}\",\n", .{@tagName(response.header.rcode)});
    try writer.print("    \"qr\": {s},\n", .{if (response.header.qr) "true" else "false"});
    try writer.print("    \"aa\": {s},\n", .{if (response.header.aa) "true" else "false"});
    try writer.print("    \"tc\": {s},\n", .{if (response.header.tc) "true" else "false"});
    try writer.print("    \"rd\": {s},\n", .{if (response.header.rd) "true" else "false"});
    try writer.print("    \"ra\": {s}\n", .{if (response.header.ra) "true" else "false"});
    try writer.writeAll("  },\n");

    // Questions
    try writer.writeAll("  \"question\": [\n");
    var q_iter = response.questions();
    var q_first = true;
    while (try q_iter.next()) |q| {
        if (!q_first) try writer.writeAll(",\n");
        q_first = false;
        const q_name = try q.qname.toString(allocator, data);
        defer allocator.free(q_name);
        // Escape qname for JSON (SEC-GAP-054: CWE-117)
        const q_name_escaped = try escapeJsonString(allocator, q_name);
        defer allocator.free(q_name_escaped);
        try writer.print("    {{\"name\": \"{s}\", \"type\": \"{s}\", \"class\": \"{s}\"}}", .{
            q_name_escaped,
            @tagName(q.qtype),
            @tagName(q.qclass),
        });
    }
    try writer.writeAll("\n  ],\n");

    // Answers
    try writer.writeAll("  \"answer\": [\n");
    var ans_iter = response.answers();
    var ans_first = true;
    while (try ans_iter.next()) |rr| {
        if (!ans_first) try writer.writeAll(",\n");
        ans_first = false;
        try outputJsonRR(allocator, writer, rr, data);
    }
    try writer.writeAll("\n  ],\n");

    // Authority
    try writer.writeAll("  \"authority\": [\n");
    var auth_iter = response.authority();
    var auth_first = true;
    while (try auth_iter.next()) |rr| {
        if (!auth_first) try writer.writeAll(",\n");
        auth_first = false;
        try outputJsonRR(allocator, writer, rr, data);
    }
    try writer.writeAll("\n  ],\n");

    // Additional
    try writer.writeAll("  \"additional\": [\n");
    var add_iter = response.additional();
    var add_first = true;
    while (try add_iter.next()) |rr| {
        if (rr.rtype == .opt) continue;
        if (!add_first) try writer.writeAll(",\n");
        add_first = false;
        try outputJsonRR(allocator, writer, rr, data);
    }
    try writer.writeAll("\n  ]\n");

    try writer.writeAll("}\n");
}

fn outputJsonRR(allocator: Allocator, writer: anytype, rr: dns.record.ResourceRecord, data: []const u8) !void {
    const rr_name = try rr.name.toString(allocator, data);
    defer allocator.free(rr_name);
    // Escape rr_name for JSON (SEC-GAP-054: CWE-117)
    const rr_name_escaped = try escapeJsonString(allocator, rr_name);
    defer allocator.free(rr_name_escaped);

    try writer.print("    {{\"name\": \"{s}\", \"type\": \"{s}\", \"class\": \"{s}\", \"ttl\": {d}, \"data\": \"", .{
        rr_name_escaped,
        @tagName(rr.rtype),
        @tagName(rr.class),
        rr.ttl,
    });
    try outputRDataShort(allocator, writer, rr, data);
    try writer.writeAll("\"}");
}

fn performTrace(allocator: Allocator, options: *const QueryOptions) !void {
    var stdout = StdoutContext{};
    // stdout flush on function exit is best-effort; output may already be partially written.
    defer stdout.flush() catch {};
    const writer = stdout.writer();

    try writer.writeAll("\n; <<>> zdig 1.0 <<>> +trace ");
    try writer.print("{s}\n", .{options.name});
    try writer.writeAll(";; global options: +cmd\n\n");

    // Start from root servers
    var current_server_buf: [64]u8 = undefined;
    var current_server: []const u8 = "198.41.0.4"; // a.root-servers.net
    var depth: u32 = 0;
    const max_depth = 20;

    while (depth < max_depth) {
        // Generate cryptographically secure query ID (SEC-GAP-035: CWE-330)
        const id: u16 = csprngInt(u16);

        // Build non-recursive query
        const query_data = try dns.message.buildQuery(allocator, id, options.name, options.qtype, options.qclass, false, options.dnssec);
        defer allocator.free(query_data);

        // Parse server address
        const address = net_compat.Address.parseIp4(current_server, 53) catch {
            try writer.print(";; Cannot parse server: {s}\n", .{current_server});
            return;
        };

        const response_data = sendUdp(allocator, address, query_data, 5) catch |err| {
            try writer.print(";; Query to {s} failed: {}\n", .{ current_server, err });
            return;
        };
        defer allocator.free(response_data);

        const response = dns.message.Message.parse(response_data) catch |err| {
            try writer.print(";; Parse error from {s}: {}\n", .{ current_server, err });
            return;
        };

        // Print what we got
        try writer.print(";; Received from {s}:\n", .{current_server});

        if (response.header.ancount > 0) {
            // Got answer - we're done
            var ans_iter = response.answers();
            while (try ans_iter.next()) |rr| {
                try outputResourceRecord(allocator, writer, rr, response_data);
            }
            break;
        }

        if (response.header.nscount > 0) {
            // Print NS referrals
            var ns_iter = response.authority();
            while (try ns_iter.next()) |rr| {
                try outputResourceRecord(allocator, writer, rr, response_data);
            }
            try writer.writeAll("\n");

            // Find IP for one of the NS servers in additional section
            var found_ip = false;
            var add_iter = response.additional();
            while (try add_iter.next()) |add| {
                if (add.rtype == .a) {
                    const ip = try add.parseA();
                    const ip_str = try std.fmt.bufPrint(&current_server_buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
                    current_server = ip_str;
                    found_ip = true;
                    break;
                }
            }

            if (!found_ip) {
                try writer.writeAll(";; No glue records found, stopping trace\n");
                break;
            }
        } else {
            try writer.writeAll(";; No answers or referrals\n");
            break;
        }

        depth += 1;
    }
}

// ============================================================================
// Main Entry Point
// ============================================================================

pub fn main(init: std.process.Init) !void {
    var gpa: std.heap.DebugAllocator(.{}) = .init;
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const argv0 = try init.minimal.args.toSlice(allocator);
    defer allocator.free(argv0);
    const argv = try allocator.alloc([]const u8, argv0.len);
    defer allocator.free(argv);
    for (argv0, 0..) |a, i| argv[i] = a;

    const exit_code = try cli.run(&root_cmd, argv, allocator);
    std.process.exit(exit_code);
}

// ============================================================================
// Tests for security-sensitive pure functions (CI-04)
// ============================================================================

const testing = std.testing;

test "escapeJsonString: normal ASCII string passes through unchanged" {
    const result = try escapeJsonString(testing.allocator, "hello world");
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("hello world", result);
}

test "escapeJsonString: empty string" {
    const result = try escapeJsonString(testing.allocator, "");
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("", result);
}

test "escapeJsonString: escapes double quotes" {
    const result = try escapeJsonString(testing.allocator, "say \"hello\"");
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("say \\\"hello\\\"", result);
}

test "escapeJsonString: escapes backslashes" {
    const result = try escapeJsonString(testing.allocator, "path\\to\\file");
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("path\\\\to\\\\file", result);
}

test "escapeJsonString: escapes newline" {
    const result = try escapeJsonString(testing.allocator, "line1\nline2");
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("line1\\nline2", result);
}

test "escapeJsonString: escapes carriage return" {
    const result = try escapeJsonString(testing.allocator, "line1\rline2");
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("line1\\rline2", result);
}

test "escapeJsonString: escapes tab" {
    const result = try escapeJsonString(testing.allocator, "col1\tcol2");
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("col1\\tcol2", result);
}

test "escapeJsonString: escapes control characters as unicode" {
    // NUL byte (0x00) should become \u0000
    const result = try escapeJsonString(testing.allocator, "\x00");
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("\\u0000", result);
}

test "escapeJsonString: escapes BEL control character" {
    // BEL (0x07) should become \u0007
    const result = try escapeJsonString(testing.allocator, "\x07");
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("\\u0007", result);
}

test "escapeJsonString: mixed escapes" {
    const result = try escapeJsonString(testing.allocator, "a\"b\\c\nd\x01e");
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("a\\\"b\\\\c\\nd\\u0001e", result);
}

test "writeSanitized: printable ASCII passes through (SEC-SR-5)" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try writeSanitized(&aw.writer, "hello world!");
    try testing.expectEqualStrings("hello world!", aw.written());
}

test "writeSanitized: escapes terminal control bytes (SEC-SR-5)" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    // A malicious TXT/CAA/name payload: ESC + OSC window-title injection + BEL.
    try writeSanitized(&aw.writer, "\x1b]0;pwned\x07");
    // No raw ESC (0x1b) or BEL (0x07) may reach the terminal.
    try testing.expect(std.mem.indexOfScalar(u8, aw.written(), 0x1b) == null);
    try testing.expect(std.mem.indexOfScalar(u8, aw.written(), 0x07) == null);
    try testing.expectEqualStrings("\\027]0;pwned\\007", aw.written());
}

test "writeSanitized: escapes quote and backslash (SEC-SR-5)" {
    var aw: std.Io.Writer.Allocating = .init(testing.allocator);
    defer aw.deinit();
    try writeSanitized(&aw.writer, "a\"b\\c");
    try testing.expectEqualStrings("a\\\"b\\\\c", aw.written());
}

test "addressMatches: IPv4 same address and port matches" {
    const addr1 = net_compat.Address.initIp4(.{ 192, 168, 1, 1 }, 53);
    const addr2 = net_compat.Address.initIp4(.{ 192, 168, 1, 1 }, 53);
    try testing.expect(addressMatches(&addr1.any, &addr2.any));
}

test "addressMatches: IPv4 different address does not match" {
    const addr1 = net_compat.Address.initIp4(.{ 192, 168, 1, 1 }, 53);
    const addr2 = net_compat.Address.initIp4(.{ 192, 168, 1, 2 }, 53);
    try testing.expect(!addressMatches(&addr1.any, &addr2.any));
}

test "addressMatches: IPv4 different port does not match" {
    const addr1 = net_compat.Address.initIp4(.{ 192, 168, 1, 1 }, 53);
    const addr2 = net_compat.Address.initIp4(.{ 192, 168, 1, 1 }, 5353);
    try testing.expect(!addressMatches(&addr1.any, &addr2.any));
}

test "addressMatches: IPv6 same address and port matches" {
    const addr1 = net_compat.Address.initIp6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 }, 53, 0, 0);
    const addr2 = net_compat.Address.initIp6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 }, 53, 0, 0);
    try testing.expect(addressMatches(&addr1.any, &addr2.any));
}

test "addressMatches: IPv6 different address does not match" {
    const addr1 = net_compat.Address.initIp6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 }, 53, 0, 0);
    const addr2 = net_compat.Address.initIp6(.{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02 }, 53, 0, 0);
    try testing.expect(!addressMatches(&addr1.any, &addr2.any));
}

test "addressMatches: IPv4 vs IPv6 family mismatch does not match" {
    const addr_v4 = net_compat.Address.initIp4(.{ 192, 168, 1, 1 }, 53);
    const addr_v6 = net_compat.Address.initIp6(.{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1 }, 53, 0, 0);
    try testing.expect(!addressMatches(&addr_v4.any, &addr_v6.any));
}
