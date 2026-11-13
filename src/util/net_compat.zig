//! std.net compatibility shim for Zig 0.16.0.
//!
//! `std.net` was restructured in 0.16.0 into `std.Io.net.IpAddress`, which
//! has a materially different API. Until the transport layer is migrated,
//! this module provides the pre-0.16 `std.net.Address`/`Ip4Address`/
//! `Ip6Address` surface on top of `std.posix.sockaddr`, and a minimal
//! `Stream` type backed by raw sockets.
//!
//! Based on `std/net.zig` from Zig 0.15.2.

const std = @import("std");
const builtin = @import("builtin");
const mem = std.mem;
const posix = std.posix;
const native_endian = builtin.cpu.arch.endian();
const native_os = builtin.os.tag;

pub const has_unix_sockets = switch (native_os) {
    .linux, .macos, .freebsd, .netbsd, .openbsd, .dragonfly, .haiku => true,
    else => false,
};

pub const IPParseError = error{
    Overflow,
    InvalidEnd,
    InvalidCharacter,
    Incomplete,
};

pub const IPv4ParseError = IPParseError || error{NonCanonical};
pub const IPv6ParseError = IPParseError || error{InvalidIpv4Mapping};

pub const Address = extern union {
    any: posix.sockaddr,
    in: Ip4Address,
    in6: Ip6Address,

    pub fn parseIp(name: []const u8, port: u16) !Address {
        if (parseIp4(name, port)) |ip4| return ip4 else |err| switch (err) {
            error.Overflow,
            error.InvalidEnd,
            error.InvalidCharacter,
            error.Incomplete,
            error.NonCanonical,
            => {},
        }

        if (parseIp6(name, port)) |ip6| return ip6 else |err| switch (err) {
            error.Overflow,
            error.InvalidEnd,
            error.InvalidCharacter,
            error.Incomplete,
            error.InvalidIpv4Mapping,
            => {},
        }

        return error.InvalidIPAddressFormat;
    }

    pub fn parseIp4(buf: []const u8, port: u16) IPv4ParseError!Address {
        return .{ .in = try Ip4Address.parse(buf, port) };
    }

    pub fn parseIp6(buf: []const u8, port: u16) IPv6ParseError!Address {
        return .{ .in6 = try Ip6Address.parse(buf, port) };
    }

    pub fn initIp4(addr: [4]u8, port: u16) Address {
        return .{ .in = Ip4Address.init(addr, port) };
    }

    pub fn initIp6(addr: [16]u8, port: u16, flowinfo: u32, scope_id: u32) Address {
        return .{ .in6 = Ip6Address.init(addr, port, flowinfo, scope_id) };
    }

    pub fn getPort(self: Address) u16 {
        return switch (self.any.family) {
            posix.AF.INET => self.in.getPort(),
            posix.AF.INET6 => self.in6.getPort(),
            else => unreachable,
        };
    }

    pub fn setPort(self: *Address, port: u16) void {
        switch (self.any.family) {
            posix.AF.INET => self.in.setPort(port),
            posix.AF.INET6 => self.in6.setPort(port),
            else => unreachable,
        }
    }

    pub fn initPosix(addr: *align(4) const posix.sockaddr) Address {
        switch (addr.family) {
            posix.AF.INET => return Address{ .in = Ip4Address{ .sa = @as(*const posix.sockaddr.in, @ptrCast(addr)).* } },
            posix.AF.INET6 => return Address{ .in6 = Ip6Address{ .sa = @as(*const posix.sockaddr.in6, @ptrCast(addr)).* } },
            else => unreachable,
        }
    }

    pub fn eql(a: Address, b: Address) bool {
        const a_bytes = @as([*]const u8, @ptrCast(&a.any))[0..a.getOsSockLen()];
        const b_bytes = @as([*]const u8, @ptrCast(&b.any))[0..b.getOsSockLen()];
        return mem.eql(u8, a_bytes, b_bytes);
    }

    pub fn getOsSockLen(self: Address) posix.socklen_t {
        return switch (self.any.family) {
            posix.AF.INET => self.in.getOsSockLen(),
            posix.AF.INET6 => self.in6.getOsSockLen(),
            else => unreachable,
        };
    }
};

pub const Ip4Address = extern struct {
    sa: posix.sockaddr.in,

    pub fn parse(buf: []const u8, port: u16) IPv4ParseError!Ip4Address {
        var result: Ip4Address = .{
            .sa = .{
                .port = mem.nativeToBig(u16, port),
                .addr = undefined,
            },
        };
        const out_ptr = mem.asBytes(&result.sa.addr);

        var x: u8 = 0;
        var index: u8 = 0;
        var saw_any_digits = false;
        var has_zero_prefix = false;
        for (buf) |c| {
            if (c == '.') {
                if (!saw_any_digits) return error.InvalidCharacter;
                if (index == 3) return error.InvalidEnd;
                out_ptr[index] = x;
                index += 1;
                x = 0;
                saw_any_digits = false;
                has_zero_prefix = false;
            } else if (c >= '0' and c <= '9') {
                if (c == '0' and !saw_any_digits) {
                    has_zero_prefix = true;
                } else if (has_zero_prefix) {
                    return error.NonCanonical;
                }
                saw_any_digits = true;
                x = try std.math.mul(u8, x, 10);
                x = try std.math.add(u8, x, c - '0');
            } else {
                return error.InvalidCharacter;
            }
        }
        if (index == 3 and saw_any_digits) {
            out_ptr[index] = x;
            return result;
        }

        return error.Incomplete;
    }

    pub fn init(addr: [4]u8, port: u16) Ip4Address {
        return Ip4Address{
            .sa = posix.sockaddr.in{
                .port = mem.nativeToBig(u16, port),
                .addr = @as(*align(1) const u32, @ptrCast(&addr)).*,
            },
        };
    }

    pub fn getPort(self: Ip4Address) u16 {
        return mem.bigToNative(u16, self.sa.port);
    }

    pub fn setPort(self: *Ip4Address, port: u16) void {
        self.sa.port = mem.nativeToBig(u16, port);
    }

    pub fn getOsSockLen(self: Ip4Address) posix.socklen_t {
        _ = self;
        return @sizeOf(posix.sockaddr.in);
    }
};

pub const Ip6Address = extern struct {
    sa: posix.sockaddr.in6,

    pub fn parse(buf: []const u8, port: u16) IPv6ParseError!Ip6Address {
        var result = Ip6Address{
            .sa = posix.sockaddr.in6{
                .scope_id = 0,
                .port = mem.nativeToBig(u16, port),
                .flowinfo = 0,
                .addr = undefined,
            },
        };
        var ip_slice: *[16]u8 = result.sa.addr[0..];

        var tail: [16]u8 = undefined;

        var x: u16 = 0;
        var saw_any_digits = false;
        var index: u8 = 0;
        var scope_id = false;
        var abbrv = false;
        for (buf, 0..) |c, i| {
            if (scope_id) {
                if (c >= '0' and c <= '9') {
                    const digit = c - '0';
                    {
                        const ov = @mulWithOverflow(result.sa.scope_id, 10);
                        if (ov[1] != 0) return error.Overflow;
                        result.sa.scope_id = ov[0];
                    }
                    {
                        const ov = @addWithOverflow(result.sa.scope_id, digit);
                        if (ov[1] != 0) return error.Overflow;
                        result.sa.scope_id = ov[0];
                    }
                } else {
                    return error.InvalidCharacter;
                }
            } else if (c == ':') {
                if (!saw_any_digits) {
                    if (abbrv) return error.InvalidCharacter;
                    if (i != 0) abbrv = true;
                    @memset(ip_slice[index..], 0);
                    ip_slice = tail[0..];
                    index = 0;
                    continue;
                }
                if (index == 14) return error.InvalidEnd;
                ip_slice[index] = @as(u8, @truncate(x >> 8));
                index += 1;
                ip_slice[index] = @as(u8, @truncate(x));
                index += 1;

                x = 0;
                saw_any_digits = false;
            } else if (c == '%') {
                if (!saw_any_digits) return error.InvalidCharacter;
                scope_id = true;
                saw_any_digits = false;
            } else if (c == '.') {
                if (!abbrv or ip_slice[0] != 0xff or ip_slice[1] != 0xff) {
                    return error.InvalidIpv4Mapping;
                }
                const start_index = mem.lastIndexOfScalar(u8, buf[0..i], ':').? + 1;
                const addr = (Ip4Address.parse(buf[start_index..], 0) catch {
                    return error.InvalidIpv4Mapping;
                }).sa.addr;
                ip_slice = result.sa.addr[0..];
                ip_slice[10] = 0xff;
                ip_slice[11] = 0xff;

                const ptr = mem.sliceAsBytes(@as(*const [1]u32, &addr)[0..]);

                ip_slice[12] = ptr[0];
                ip_slice[13] = ptr[1];
                ip_slice[14] = ptr[2];
                ip_slice[15] = ptr[3];
                return result;
            } else {
                const digit = try std.fmt.charToDigit(c, 16);
                {
                    const ov = @mulWithOverflow(x, 16);
                    if (ov[1] != 0) return error.Overflow;
                    x = ov[0];
                }
                {
                    const ov = @addWithOverflow(x, digit);
                    if (ov[1] != 0) return error.Overflow;
                    x = ov[0];
                }
                saw_any_digits = true;
            }
        }

        if (!saw_any_digits and !abbrv) return error.Incomplete;
        if (!abbrv and index < 14) return error.Incomplete;

        if (index == 14) {
            ip_slice[14] = @as(u8, @truncate(x >> 8));
            ip_slice[15] = @as(u8, @truncate(x));
            return result;
        } else {
            ip_slice[index] = @as(u8, @truncate(x >> 8));
            index += 1;
            ip_slice[index] = @as(u8, @truncate(x));
            index += 1;
            @memcpy(result.sa.addr[16 - index ..][0..index], ip_slice[0..index]);
            return result;
        }
    }

    pub fn init(addr: [16]u8, port: u16, flowinfo: u32, scope_id: u32) Ip6Address {
        return Ip6Address{
            .sa = posix.sockaddr.in6{
                .addr = addr,
                .port = mem.nativeToBig(u16, port),
                .flowinfo = flowinfo,
                .scope_id = scope_id,
            },
        };
    }

    pub fn getPort(self: Ip6Address) u16 {
        return mem.bigToNative(u16, self.sa.port);
    }

    pub fn setPort(self: *Ip6Address, port: u16) void {
        self.sa.port = mem.nativeToBig(u16, port);
    }

    pub fn getOsSockLen(self: Ip6Address) posix.socklen_t {
        _ = self;
        return @sizeOf(posix.sockaddr.in6);
    }
};

/// Minimal Stream shim over a raw fd. Only exposes what the DNS resolver
/// zone transfer path actually calls.
pub const Stream = struct {
    handle: posix.socket_t,

    pub fn close(self: Stream) void {
        _ = std.os.linux.close(self.handle);
    }

    pub fn writeAll(self: Stream, bytes: []const u8) !void {
        var i: usize = 0;
        while (i < bytes.len) {
            const rc = std.os.linux.write(self.handle, bytes[i..].ptr, bytes.len - i);
            const n: isize = @bitCast(rc);
            if (n <= 0) return error.BrokenPipe;
            i += @intCast(n);
        }
    }

    pub fn read(self: Stream, buf: []u8) !usize {
        const rc = std.os.linux.read(self.handle, buf.ptr, buf.len);
        const n: isize = @bitCast(rc);
        if (n < 0) return error.ReadFailed;
        return @intCast(n);
    }
};

pub fn tcpConnectToAddress(address: Address) !Stream {
    const sockfd_rc = std.os.linux.socket(
        @intCast(address.any.family),
        std.os.linux.SOCK.STREAM | std.os.linux.SOCK.CLOEXEC,
        std.os.linux.IPPROTO.TCP,
    );
    const sockfd_i: isize = @bitCast(sockfd_rc);
    if (sockfd_i < 0) return error.SocketCreateFailed;
    const sockfd: posix.socket_t = @intCast(sockfd_i);
    errdefer _ = std.os.linux.close(sockfd);

    const rc = std.os.linux.connect(sockfd, &address.any, address.getOsSockLen());
    const rci: isize = @bitCast(rc);
    if (rci != 0) return error.ConnectionFailed;

    return .{ .handle = sockfd };
}

// ============================================================================
// std.posix shims for removed 0.16.0 functions
// ============================================================================

/// std.posix.close removed in 0.16.0 — use std.os.linux.close.
pub fn close(fd: posix.fd_t) void {
    _ = std.os.linux.close(fd);
}

pub const SocketError = error{
    AddressFamilyNotSupported,
    ProtocolNotSupported,
    ProtocolFamilyNotAvailable,
    AccessDenied,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    SocketTypeNotSupported,
    Unexpected,
};

/// std.posix.socket removed in 0.16.0 — wrap std.os.linux.socket.
pub fn socket(domain: u32, sock_type: u32, protocol: u32) SocketError!posix.socket_t {
    const rc = std.os.linux.socket(domain, sock_type, protocol);
    switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .ACCES => return error.AccessDenied,
        .AFNOSUPPORT => return error.AddressFamilyNotSupported,
        .INVAL => return error.ProtocolFamilyNotAvailable,
        .MFILE => return error.ProcessFdQuotaExceeded,
        .NFILE => return error.SystemFdQuotaExceeded,
        .NOBUFS => return error.SystemResources,
        .NOMEM => return error.SystemResources,
        .PROTONOSUPPORT => return error.ProtocolNotSupported,
        .PROTOTYPE => return error.SocketTypeNotSupported,
        else => |err| return posix.unexpectedErrno(err),
    }
}

pub const ConnectError = error{
    PermissionDenied,
    AddressInUse,
    AddressNotAvailable,
    AddressFamilyNotSupported,
    WouldBlock,
    ConnectionPending,
    ConnectionRefused,
    ConnectionResetByPeer,
    NetworkUnreachable,
    ConnectionTimedOut,
    FileNotFound,
    FileDescriptorNotASocket,
    AlreadyConnected,
    SystemResources,
    Unexpected,
};

/// std.posix.connect removed in 0.16.0 — wrap std.os.linux.connect.
pub fn connect(sock: posix.socket_t, sock_addr: *const posix.sockaddr, len: posix.socklen_t) ConnectError!void {
    const rc = std.os.linux.connect(sock, sock_addr, len);
    switch (posix.errno(rc)) {
        .SUCCESS => return,
        .ACCES, .PERM => return error.PermissionDenied,
        .ADDRINUSE => return error.AddressInUse,
        .ADDRNOTAVAIL => return error.AddressNotAvailable,
        .AFNOSUPPORT => return error.AddressFamilyNotSupported,
        .AGAIN, .INPROGRESS => return error.WouldBlock,
        .ALREADY => return error.ConnectionPending,
        .BADF => unreachable,
        .CONNREFUSED => return error.ConnectionRefused,
        .CONNRESET => return error.ConnectionResetByPeer,
        .FAULT => unreachable,
        .ISCONN => return error.AlreadyConnected,
        .NETUNREACH => return error.NetworkUnreachable,
        .NOTSOCK => return error.FileDescriptorNotASocket,
        .PROTOTYPE => return error.AddressFamilyNotSupported,
        .TIMEDOUT => return error.ConnectionTimedOut,
        .NOENT => return error.FileNotFound,
        else => |err| return posix.unexpectedErrno(err),
    }
}

/// std.posix.write removed in 0.16.0 — wrap std.os.linux.write.
pub fn write(fd: posix.fd_t, buf: []const u8) !usize {
    const rc = std.os.linux.write(fd, buf.ptr, buf.len);
    switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .AGAIN => return error.WouldBlock,
        .BADF => return error.NotOpenForWriting,
        .INTR => return error.WouldBlock,
        .INVAL => return error.InvalidArgument,
        .IO => return error.InputOutput,
        .NOSPC => return error.NoSpaceLeft,
        .PIPE => return error.BrokenPipe,
        .CONNRESET => return error.ConnectionResetByPeer,
        .NOTCONN => return error.NotConnected,
        else => |err| return posix.unexpectedErrno(err),
    }
}

/// std.posix.getsockoptError removed in 0.16.0.
pub fn getsockoptError(sock: posix.socket_t) !void {
    var err_code: i32 = 0;
    var optlen: posix.socklen_t = @sizeOf(i32);
    const rc = std.os.linux.getsockopt(
        sock,
        std.os.linux.SOL.SOCKET,
        std.os.linux.SO.ERROR,
        @ptrCast(&err_code),
        &optlen,
    );
    switch (posix.errno(rc)) {
        .SUCCESS => {},
        .BADF => unreachable,
        .FAULT => unreachable,
        .INVAL => unreachable,
        .NOPROTOOPT => unreachable,
        .NOTSOCK => unreachable,
        else => |err| return posix.unexpectedErrno(err),
    }
    if (err_code == 0) return;
    switch (@as(posix.E, @enumFromInt(err_code))) {
        .SUCCESS => return,
        .ACCES, .PERM => return error.PermissionDenied,
        .ADDRINUSE => return error.AddressInUse,
        .ADDRNOTAVAIL => return error.AddressNotAvailable,
        .AFNOSUPPORT => return error.AddressFamilyNotSupported,
        .AGAIN, .INPROGRESS => return error.WouldBlock,
        .ALREADY => return error.ConnectionPending,
        .CONNREFUSED => return error.ConnectionRefused,
        .CONNRESET => return error.ConnectionResetByPeer,
        .ISCONN => return error.AlreadyConnected,
        .NETUNREACH => return error.NetworkUnreachable,
        .NOTSOCK => return error.FileDescriptorNotASocket,
        .TIMEDOUT => return error.ConnectionTimedOut,
        .PROTOTYPE => return error.AddressFamilyNotSupported,
        .NOENT => return error.FileNotFound,
        else => |e| return posix.unexpectedErrno(e),
    }
}

pub const BindError = error{
    AccessDenied,
    AddressInUse,
    AddressNotAvailable,
    AddressFamilyNotSupported,
    SymLinkLoop,
    NameTooLong,
    FileNotFound,
    SystemResources,
    FileDescriptorNotASocket,
    AlreadyBound,
    ReadOnlyFileSystem,
    NotDir,
    Unexpected,
};

/// std.posix.bind removed in 0.16.0.
pub fn bind(sock: posix.socket_t, addr: *const posix.sockaddr, len: posix.socklen_t) BindError!void {
    const rc = std.os.linux.bind(sock, addr, len);
    switch (posix.errno(rc)) {
        .SUCCESS => return,
        .ACCES, .PERM => return error.AccessDenied,
        .ADDRINUSE => return error.AddressInUse,
        .BADF => unreachable,
        .INVAL => return error.AlreadyBound,
        .NOTSOCK => return error.FileDescriptorNotASocket,
        .ADDRNOTAVAIL => return error.AddressNotAvailable,
        .FAULT => unreachable,
        .LOOP => return error.SymLinkLoop,
        .NAMETOOLONG => return error.NameTooLong,
        .NOENT => return error.FileNotFound,
        .NOMEM => return error.SystemResources,
        .NOTDIR => return error.NotDir,
        .ROFS => return error.ReadOnlyFileSystem,
        .AFNOSUPPORT => return error.AddressFamilyNotSupported,
        else => |err| return posix.unexpectedErrno(err),
    }
}

pub const SendToError = error{
    AccessDenied,
    WouldBlock,
    FastOpenAlreadyInProgress,
    ConnectionResetByPeer,
    MessageTooBig,
    SystemResources,
    SocketNotConnected,
    UnreachableAddress,
    BrokenPipe,
    AddressFamilyNotSupported,
    AddressNotAvailable,
    NetworkUnreachable,
    NetworkSubsystemFailed,
    FileDescriptorNotASocket,
    Unexpected,
};

/// std.posix.sendto removed in 0.16.0.
pub fn sendto(
    sock: posix.socket_t,
    buf: []const u8,
    flags: u32,
    dest_addr: ?*const posix.sockaddr,
    addrlen: posix.socklen_t,
) SendToError!usize {
    // `std.os.linux.sendto` takes `?*const std.os.linux.sockaddr`. On Linux
    // that's the same type as `posix.sockaddr`, but on non-Linux targets
    // (macOS cross-compile) `posix.sockaddr == c.sockaddr`, so we have to
    // @ptrCast to bridge. These helpers only actually execute on Linux; the
    // cast only exists to make the call compile under cross-builds.
    const linux_dest: ?*const std.os.linux.sockaddr = @ptrCast(@alignCast(dest_addr));
    const rc = std.os.linux.sendto(sock, buf.ptr, buf.len, flags, linux_dest, addrlen);
    switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .ACCES => return error.AccessDenied,
        .AGAIN => return error.WouldBlock,
        .ALREADY => return error.FastOpenAlreadyInProgress,
        .BADF => unreachable,
        .CONNRESET => return error.ConnectionResetByPeer,
        .DESTADDRREQ => unreachable,
        .FAULT => unreachable,
        .INTR => return error.WouldBlock,
        .INVAL => unreachable,
        .ISCONN => unreachable,
        .MSGSIZE => return error.MessageTooBig,
        .NOBUFS => return error.SystemResources,
        .NOMEM => return error.SystemResources,
        .NOTCONN => return error.SocketNotConnected,
        .NOTSOCK => return error.FileDescriptorNotASocket,
        .OPNOTSUPP => unreachable,
        .PIPE => return error.BrokenPipe,
        .AFNOSUPPORT => return error.AddressFamilyNotSupported,
        .HOSTUNREACH, .NETUNREACH => return error.NetworkUnreachable,
        .ADDRNOTAVAIL => return error.AddressNotAvailable,
        else => |err| return posix.unexpectedErrno(err),
    }
}

pub const RecvFromError = error{
    WouldBlock,
    SystemResources,
    ConnectionRefused,
    SocketNotConnected,
    SocketNotBound,
    MessageTooBig,
    NetworkSubsystemFailed,
    ConnectionResetByPeer,
    ConnectionTimedOut,
    Unexpected,
};

/// std.posix.recvfrom removed in 0.16.0.
pub fn recvfrom(
    sock: posix.socket_t,
    buf: []u8,
    flags: u32,
    src_addr: ?*posix.sockaddr,
    addrlen: ?*posix.socklen_t,
) RecvFromError!usize {
    // See sendto above: bridge `posix.sockaddr` → `std.os.linux.sockaddr` for
    // non-Linux cross-compile targets. Runtime path is Linux-only.
    const linux_src: ?*std.os.linux.sockaddr = @ptrCast(@alignCast(src_addr));
    const rc = std.os.linux.recvfrom(sock, buf.ptr, buf.len, flags, linux_src, addrlen);
    switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .AGAIN => return error.WouldBlock,
        .BADF => unreachable,
        .CONNREFUSED => return error.ConnectionRefused,
        .FAULT => unreachable,
        .INVAL => unreachable,
        .NOTCONN => return error.SocketNotConnected,
        .NOTSOCK => unreachable,
        .INTR => return error.WouldBlock,
        .NOMEM => return error.SystemResources,
        .CONNRESET => return error.ConnectionResetByPeer,
        .TIMEDOUT => return error.ConnectionTimedOut,
        else => |err| return posix.unexpectedErrno(err),
    }
}

pub const SendError = error{
    AccessDenied,
    WouldBlock,
    FastOpenAlreadyInProgress,
    ConnectionResetByPeer,
    MessageTooBig,
    SystemResources,
    SocketNotConnected,
    BrokenPipe,
    FileDescriptorNotASocket,
    Unexpected,
};

/// std.posix.send removed in 0.16.0 — wrap sendto with null dest.
pub fn send(sock: posix.socket_t, buf: []const u8, flags: u32) SendError!usize {
    const rc = std.os.linux.sendto(sock, buf.ptr, buf.len, flags, null, 0);
    switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .ACCES => return error.AccessDenied,
        .AGAIN => return error.WouldBlock,
        .ALREADY => return error.FastOpenAlreadyInProgress,
        .BADF => unreachable,
        .CONNRESET => return error.ConnectionResetByPeer,
        .DESTADDRREQ => unreachable,
        .FAULT => unreachable,
        .INTR => return error.WouldBlock,
        .INVAL => unreachable,
        .ISCONN => unreachable,
        .MSGSIZE => return error.MessageTooBig,
        .NOBUFS => return error.SystemResources,
        .NOMEM => return error.SystemResources,
        .NOTCONN => return error.SocketNotConnected,
        .NOTSOCK => return error.FileDescriptorNotASocket,
        .OPNOTSUPP => unreachable,
        .PIPE => return error.BrokenPipe,
        else => |err| return posix.unexpectedErrno(err),
    }
}

pub const RecvError = error{
    WouldBlock,
    SystemResources,
    ConnectionRefused,
    SocketNotConnected,
    ConnectionResetByPeer,
    ConnectionTimedOut,
    Unexpected,
};

/// std.posix.recv removed in 0.16.0 — wrap recvfrom with null src.
pub fn recv(sock: posix.socket_t, buf: []u8, flags: u32) RecvError!usize {
    const rc = std.os.linux.recvfrom(sock, buf.ptr, buf.len, flags, null, null);
    switch (posix.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .AGAIN => return error.WouldBlock,
        .BADF => unreachable,
        .CONNREFUSED => return error.ConnectionRefused,
        .FAULT => unreachable,
        .INVAL => unreachable,
        .NOTCONN => return error.SocketNotConnected,
        .NOTSOCK => unreachable,
        .INTR => return error.WouldBlock,
        .NOMEM => return error.SystemResources,
        .CONNRESET => return error.ConnectionResetByPeer,
        .TIMEDOUT => return error.ConnectionTimedOut,
        else => |err| return posix.unexpectedErrno(err),
    }
}

// ---------------------------------------------------------------------------
// Address.eql across every family the union can hold (SONNY-6447)
// ---------------------------------------------------------------------------

/// An address whose family field is `family` and whose remaining bytes are
/// `fill`. Models what a receive path hands to `eql` when the kernel did not
/// (or could not) write an IP source address.
fn rawFamilyAddress(family: posix.sa_family_t, fill: u8) Address {
    var addr: Address = undefined;
    @memset(mem.asBytes(&addr), fill);
    addr.any.family = family;
    return addr;
}

test "Address.eql: IPv4 compares port and address" {
    const a = try Address.parseIp4("10.90.0.53", 53);
    try std.testing.expect(Address.eql(a, try Address.parseIp4("10.90.0.53", 53)));
    try std.testing.expect(!Address.eql(a, try Address.parseIp4("10.90.0.53", 5353)));
    try std.testing.expect(!Address.eql(a, try Address.parseIp4("10.90.0.54", 53)));
}

test "Address.eql: IPv6 compares port, address and scope" {
    const a = try Address.parseIp6("fe80::1%2", 53);
    try std.testing.expect(Address.eql(a, try Address.parseIp6("fe80::1%2", 53)));
    try std.testing.expect(!Address.eql(a, try Address.parseIp6("fe80::1%3", 53)));
    try std.testing.expect(!Address.eql(a, try Address.parseIp6("fe80::1%2", 54)));
    try std.testing.expect(!Address.eql(a, try Address.parseIp6("fe80::2%2", 53)));
}

test "Address.eql: IPv4 never equals IPv6, including its IPv4-mapped form" {
    const v4 = try Address.parseIp4("192.0.2.1", 53);
    const mapped = try Address.parseIp6("::ffff:192.0.2.1", 53);
    const v6 = try Address.parseIp6("2001:db8::1", 53);
    try std.testing.expect(!Address.eql(v4, mapped));
    try std.testing.expect(!Address.eql(mapped, v4));
    try std.testing.expect(!Address.eql(v4, v6));
    try std.testing.expect(!Address.eql(v6, v4));
    try std.testing.expect(Address.eql(mapped, try Address.parseIp6("::ffff:192.0.2.1", 53)));
}

test "Address.eql: a non-IP family is unequal to everything and never panics" {
    const v4 = try Address.parseIp4("10.90.0.53", 53);
    const v6 = try Address.parseIp6("2001:db8::53", 53);
    // AF_UNSPEC (zeroed storage), AF_UNIX (a datagram from an unnamed unix
    // peer), and 0xAAAA (Debug-mode `undefined` storage the kernel never
    // wrote) are the values a receive path can hold.
    const odd = [_]Address{
        rawFamilyAddress(posix.AF.UNSPEC, 0),
        rawFamilyAddress(posix.AF.UNIX, 0),
        rawFamilyAddress(0xAAAA, 0xAA),
        rawFamilyAddress(0xFFFF, 0xFF),
    };
    for (odd) |o| {
        try std.testing.expect(!Address.eql(o, v4));
        try std.testing.expect(!Address.eql(v4, o));
        try std.testing.expect(!Address.eql(o, v6));
        try std.testing.expect(!Address.eql(v6, o));
        for (odd) |p| try std.testing.expect(!Address.eql(o, p));
    }
}

test "recvfrom from a peer with no address leaves the source unset; eql rejects it" {
    if (native_os != .linux) return error.SkipZigTest;
    var fds: [2]i32 = undefined;
    const rc = std.os.linux.socketpair(posix.AF.UNIX, posix.SOCK.DGRAM, 0, &fds);
    try std.testing.expectEqual(posix.E.SUCCESS, posix.errno(rc));
    defer close(fds[0]);
    defer close(fds[1]);

    const payload = "dns-reply";
    try std.testing.expectEqual(payload.len, std.os.linux.write(fds[1], payload, payload.len));

    // Exactly the receive shape used by stub.zig, recursive.zig and
    // transports/udp.zig.
    var buffer: [64]u8 = undefined;
    var src_addr: Address = undefined;
    var src_len: posix.socklen_t = @sizeOf(Address);
    const n = try recvfrom(fds[0], &buffer, 0, &src_addr.any, &src_len);
    try std.testing.expectEqual(payload.len, n);
    // An unnamed peer reports a zero-length (or family-only) address: the
    // kernel never wrote an IP family into src_addr.
    try std.testing.expect(src_len < @sizeOf(posix.sockaddr.in));

    const server = try Address.parseIp4("10.90.0.53", 53);
    try std.testing.expect(!Address.eql(src_addr, server));
}
