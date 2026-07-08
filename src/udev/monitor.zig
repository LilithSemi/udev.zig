//! Netlink uevent monitor with an event-loop-first design.
//!
//! Primary integration: call `fd()` to get the raw file descriptor and register it
//! in your own epoll/wl_event_loop, then call `receiveDevice()` (drain until null)
//! whenever it signals readable.  `pollReadable()` is a convenience for callers that
//! have no external loop.
//!
//! A std.Io-native readiness await is intentionally deferred: Zig 0.16's std.Io does
//! not yet expose raw-fd readiness, so fd()+poll is the correct integration surface today.

const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const context = @import("context.zig");
const device_mod = @import("device.zig");
const uevent = @import("uevent.zig");
const udev_linux = @import("linux.zig");

pub const Context = context.Context;
pub const Device = device_mod.Device;

pub const Source = enum { kernel, udev };

// Raw syscall helpers (std.posix omits socket/bind/recvfrom/close in 0.16)

fn sysSocket(domain: u32, sock_type: u32, protocol: u32) !posix.fd_t {
    const rc = linux.socket(domain, sock_type, protocol);
    switch (linux.errno(rc)) {
        .SUCCESS => return @intCast(rc),
        .ACCES, .PERM => return error.PermissionDenied,
        .AFNOSUPPORT => return error.AddressFamilyNotSupported,
        .INVAL => return error.ProtocolFamilyNotAvailable,
        .MFILE, .NFILE => return error.ProcessFdQuotaExceeded,
        .NOBUFS, .NOMEM => return error.SystemResources,
        .PROTONOSUPPORT => return error.ProtocolNotSupported,
        else => |err| return posix.unexpectedErrno(err),
    }
}

fn sysBind(fd: posix.fd_t, addr: *const linux.sockaddr, addrlen: linux.socklen_t) !void {
    const rc = linux.bind(fd, addr, addrlen);
    switch (linux.errno(rc)) {
        .SUCCESS => {},
        .ACCES, .PERM => return error.PermissionDenied,
        .ADDRINUSE => return error.AddressInUse,
        .ADDRNOTAVAIL => return error.AddressNotAvailable,
        .INVAL => return error.InvalidArgument,
        .NOTSOCK => return error.NotASocket,
        else => |err| return posix.unexpectedErrno(err),
    }
}

fn sysClose(fd: posix.fd_t) void {
    _ = linux.close(fd);
}

const RecvFromError = error{
    WouldBlock,
    Interrupted,
    /// Netlink receive ring overflowed and the kernel dropped packets. Non-fatal: the socket
    /// stays usable and the next recv succeeds; some uevents were simply lost.
    Overflow,
    BadFd,
    BadAddress,
    InvalidArgument,
    Unexpected,
};

fn sysRecvfrom(
    fd: posix.fd_t,
    buf: []u8,
    flags: u32,
    addr: *linux.sockaddr.nl,
    addrlen: *linux.socklen_t,
) RecvFromError!usize {
    const rc = linux.recvfrom(fd, buf.ptr, buf.len, flags, @ptrCast(addr), addrlen);
    switch (linux.errno(rc)) {
        .SUCCESS => return rc,
        .AGAIN => return error.WouldBlock,
        .INTR => return error.Interrupted,
        .NOBUFS => return error.Overflow,
        .BADF => return error.BadFd,
        .FAULT => return error.BadAddress,
        .INVAL => return error.InvalidArgument,
        else => |err| return posix.unexpectedErrno(err),
    }
}

/// Try to set a large receive buffer to absorb event bursts during coldplug.
/// Attempts SO_RCVBUFFORCE first (requires CAP_NET_ADMIN), then falls back to SO_RCVBUF.
/// Both failing is degraded but not fatal; the socket still works with a smaller buffer.
fn trySetRcvBuf(fd: posix.fd_t, size: c_int) void {
    var val: c_int = size;
    const pval: [*]const u8 = @ptrCast(&val);
    const r1 = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVBUFFORCE, pval, @sizeOf(c_int));
    if (linux.errno(r1) == .SUCCESS) return;
    _ = linux.setsockopt(fd, linux.SOL.SOCKET, linux.SO.RCVBUF, pval, @sizeOf(c_int));
}

// Monitor

pub const Monitor = struct {
    fd_: posix.fd_t,
    ctx: *Context,
    source: Source,
    filter_arena: std.heap.ArenaAllocator,
    filters: std.ArrayListUnmanaged(Filter),

    pub const Filter = struct {
        subsystem: []const u8,
        devtype: ?[]const u8,
    };

    /// Open a NETLINK_KOBJECT_UEVENT socket bound to the group for `source`.
    pub fn initNetlink(ctx: *Context, source: Source) !Monitor {
        const group: u32 = @intFromEnum(
            if (source == .kernel) udev_linux.Group.kernel else udev_linux.Group.udev,
        );
        const sock_fd = try sysSocket(
            linux.AF.NETLINK,
            linux.SOCK.DGRAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
            udev_linux.netlink_kobject_uevent,
        );
        errdefer sysClose(sock_fd);

        const nl_addr = udev_linux.nlAddr(group);
        try sysBind(
            sock_fd,
            @as(*const linux.sockaddr, @ptrCast(&nl_addr)),
            @sizeOf(linux.sockaddr.nl),
        );

        // Request a large receive buffer (1 MiB) to absorb coldplug bursts.
        // RCVBUFFORCE bypasses rmem_max (needs CAP_NET_ADMIN); plain RCVBUF is the fallback.
        // Both failing is degraded, not fatal.
        trySetRcvBuf(sock_fd, 1024 * 1024);

        return .{
            .fd_ = sock_fd,
            .ctx = ctx,
            .source = source,
            .filter_arena = std.heap.ArenaAllocator.init(ctx.gpa),
            .filters = .empty,
        };
    }

    /// Close the socket and free filter storage.
    pub fn deinit(self: *Monitor) void {
        if (self.fd_ >= 0) {
            sysClose(self.fd_);
        }
        self.filter_arena.deinit();
    }

    /// Raw fd for the caller's epoll/poll loop (primary event-loop integration path).
    pub fn fd(self: *const Monitor) posix.fd_t {
        return self.fd_;
    }

    /// Append a subsystem/devtype filter. An empty filter list passes all devices.
    /// Strings are duped into the monitor's arena.
    pub fn addMatchSubsystemDevtype(
        self: *Monitor,
        subsystem: []const u8,
        devtype: ?[]const u8,
    ) !void {
        const alloc = self.filter_arena.allocator();
        const owned_sub = try alloc.dupe(u8, subsystem);
        const owned_dt: ?[]const u8 = if (devtype) |dt| try alloc.dupe(u8, dt) else null;
        try self.filters.append(alloc, .{ .subsystem = owned_sub, .devtype = owned_dt });
    }

    /// True if `dev` passes the current filter list (empty list = pass all).
    pub fn matchesFilters(self: *const Monitor, dev: *const Device) bool {
        if (self.filters.items.len == 0) return true;
        const dev_sub = dev.getProperty("SUBSYSTEM") orelse "";
        const dev_dt = dev.getProperty("DEVTYPE");
        for (self.filters.items) |f| {
            if (!std.mem.eql(u8, dev_sub, f.subsystem)) continue;
            if (f.devtype) |fdt| {
                if (dev_dt) |dt| {
                    if (std.mem.eql(u8, dt, fdt)) return true;
                }
            } else {
                return true;
            }
        }
        return false;
    }

    /// Non-blocking receive. Returns the next Device that passes the prefilter,
    /// or null when the socket is drained (EAGAIN/EWOULDBLOCK). Skips spoofed
    /// messages and non-device events transparently.
    pub fn receiveDevice(self: *Monitor) !?Device {
        var recv_buf: [8192]u8 = undefined;
        while (true) {
            var sender: linux.sockaddr.nl = undefined;
            var sender_len: linux.socklen_t = @sizeOf(linux.sockaddr.nl);
            // MSG.TRUNC makes recvfrom report the true datagram length even when it does not fit,
            // so we can detect and discard an oversized (truncated) message instead of mis-parsing.
            const n = sysRecvfrom(self.fd_, &recv_buf, linux.MSG.TRUNC, &sender, &sender_len) catch |err| switch (err) {
                error.WouldBlock => return null,
                error.Interrupted => continue, // signal mid-recv; retry
                error.Overflow => continue, // netlink ring overflow, events lost; keep draining
                else => return err,
            };

            // Oversized message truncated to the buffer: discard rather than parse a partial event.
            if (n > recv_buf.len) continue;

            // Security: kernel messages must come from pid 0 (the kernel) with a non-zero group.
            if (self.source == .kernel) {
                if (sender.pid != 0 or sender.groups == 0) continue;
            } else {
                // TODO: verify sender ucred uid==0 via SO_PASSCRED + recvmsg SCM_CREDENTIALS.
                // Checking sender.pid == 0 would be WRONG for the udev source: udevd multicasts
                // with a NON-ZERO nl_pid, so a pid check drops every real message. Applying no
                // sender filter here stays honest until the ucred check lands.
            }

            const msg = recv_buf[0..n];
            const maybe_dev = deviceFromMessage(self.ctx, self.source, msg) catch continue;
            var dev = maybe_dev orelse continue;

            if (!self.matchesFilters(&dev)) {
                dev.deinit();
                continue;
            }

            return dev;
        }
    }

    /// Blocking wait until the socket is readable or `timeout_ms` elapses.
    /// Returns true when data is available, false on timeout.
    /// Returns error.SocketError if the socket reports ERR, HUP, or NVAL so callers
    /// do not spin on a dead socket. Use `fd()` with epoll for a real event loop.
    pub fn pollReadable(self: *const Monitor, timeout_ms: i32) !bool {
        var pfds = [_]posix.pollfd{.{
            .fd = self.fd_,
            .events = posix.POLL.IN,
            .revents = 0,
        }};
        const n = try posix.poll(&pfds, timeout_ms);
        const revents = pfds[0].revents;
        const err_mask = @as(i16, posix.POLL.ERR) | @as(i16, posix.POLL.HUP) | @as(i16, posix.POLL.NVAL);
        if ((revents & err_mask) != 0) return error.SocketError;
        return n > 0 and (revents & @as(i16, posix.POLL.IN)) != 0;
    }

    /// Parse a raw netlink message buffer and construct a Device from its properties.
    /// Returns null if the buffer is not a device event. Exposed as pub for testing.
    pub fn deviceFromMessage(ctx: *Context, source: Source, buf: []const u8) !?Device {
        const parsed = switch (source) {
            .kernel => try uevent.parseKernel(buf),
            .udev => try uevent.parseUdev(buf),
        };

        const devpath = parsed.devpath orelse parsed.props.get("DEVPATH");

        // Not a device event if neither SUBSYSTEM nor devpath is present.
        if (parsed.props.get("SUBSYSTEM") == null and devpath == null) return null;

        return try Device.fromProps(ctx, devpath orelse "", parsed.props);
    }
};

// Tests

test "monitor builds Device from a kernel-format message" {
    var ctx = Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();
    const buf =
        "add@/devices/x/event0\x00" ++
        "ACTION=add\x00SUBSYSTEM=input\x00DEVNAME=input/event0\x00MAJOR=13\x00MINOR=64\x00";
    var dev = (try Monitor.deviceFromMessage(&ctx, .kernel, buf)).?;
    defer dev.deinit();
    try std.testing.expectEqualStrings("input", (try dev.subsystem()).?);
    try std.testing.expectEqualStrings("/dev/input/event0", dev.devnode().?);
}

test "monitor builds Device from a udev-format message" {
    var ctx = Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const props_str = "SUBSYSTEM=drm\x00DEVNAME=dri/card0\x00";
    // Header: 8 prefix + 4 magic + 4 header_size + 4 props_off + 4 props_len + 16 filter hashes.
    const hdr_size = 40;
    var buf: [hdr_size + props_str.len]u8 = undefined;
    @memcpy(buf[0..8], "libudev\x00");
    std.mem.writeInt(u32, buf[8..12], 0xfeedcafe, .little);
    std.mem.writeInt(u32, buf[12..16], hdr_size, .little); // header_size
    std.mem.writeInt(u32, buf[16..20], hdr_size, .little); // properties_off
    std.mem.writeInt(u32, buf[20..24], @as(u32, props_str.len), .little); // properties_len
    @memset(buf[24..40], 0); // 4 filter-hash u32s
    @memcpy(buf[hdr_size..][0..props_str.len], props_str);

    var dev = (try Monitor.deviceFromMessage(&ctx, .udev, buf[0..])).?;
    defer dev.deinit();
    try std.testing.expectEqualStrings("drm", (try dev.subsystem()).?);
    try std.testing.expectEqualStrings("/dev/dri/card0", dev.devnode().?);
}

test "monitor prefilter accepts matching subsystem and rejects others" {
    var ctx = Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    // Construct a Monitor without a real socket (fd_ = -1 is skipped on deinit).
    var mon: Monitor = .{
        .fd_ = -1,
        .ctx = &ctx,
        .source = .kernel,
        .filter_arena = std.heap.ArenaAllocator.init(std.testing.allocator),
        .filters = .empty,
    };
    defer mon.deinit();

    try mon.addMatchSubsystemDevtype("input", null);

    const input_buf =
        "add@/devices/x/event0\x00ACTION=add\x00SUBSYSTEM=input\x00";
    var input_dev = (try Monitor.deviceFromMessage(&ctx, .kernel, input_buf)).?;
    defer input_dev.deinit();

    const drm_buf =
        "add@/devices/x/card0\x00ACTION=add\x00SUBSYSTEM=drm\x00";
    var drm_dev = (try Monitor.deviceFromMessage(&ctx, .kernel, drm_buf)).?;
    defer drm_dev.deinit();

    try std.testing.expect(mon.matchesFilters(&input_dev));
    try std.testing.expect(!mon.matchesFilters(&drm_dev));
}

test "monitor smoke: open kernel monitor and drain once" {
    var ctx = Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    // Skip gracefully if we lack CAP_NET_ADMIN or the socket is not permitted.
    var mon = Monitor.initNetlink(&ctx, .kernel) catch |err| switch (err) {
        error.PermissionDenied => return,
        else => return err,
    };
    defer mon.deinit();

    try std.testing.expect(mon.fd() >= 0);

    // Non-blocking drain: null (empty) or a Device are both acceptable.
    var result = try mon.receiveDevice();
    if (result) |*dev| dev.deinit();
}
