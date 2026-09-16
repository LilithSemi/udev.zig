const std = @import("std");
const linux = std.os.linux;
const posix = std.posix;
const EventState = @import("../rules/runner.zig").EventState;
const Context = @import("../context.zig").Context;
const Monitor = @import("../monitor.zig").Monitor;
const udev_linux = @import("../linux.zig");

/// MurmurHash2 (seed 0) matches systemd's util_string_hash32, used for the libudev
/// monitor message filter hashes. Uses wrapping arithmetic.
pub fn stringHash32(s: []const u8) u32 {
    const m: u32 = 0x5bd1e995;
    const r: u5 = 24;
    var h: u32 = 0 ^ @as(u32, @truncate(s.len));
    var data = s;
    while (data.len >= 4) : (data = data[4..]) {
        var k = std.mem.readInt(u32, data[0..4], .little);
        k = k *% m;
        k ^= k >> r;
        k = k *% m;
        h = h *% m;
        h ^= k;
    }
    switch (data.len) {
        3 => {
            h ^= @as(u32, data[2]) << 16;
            h ^= @as(u32, data[1]) << 8;
            h ^= data[0];
            h = h *% m;
        },
        2 => {
            h ^= @as(u32, data[1]) << 8;
            h ^= data[0];
            h = h *% m;
        },
        1 => {
            h ^= data[0];
            h = h *% m;
        },
        else => {},
    }
    h ^= h >> 13;
    h = h *% m;
    h ^= h >> 15;
    return h;
}

/// Serialize an evaluated EventState into a libudev monitor message buffer (gpa-owned; caller frees).
/// Emits all state properties as KEY=VALUE\0, then synthesizes DEVLINKS= (space-joined /dev/<sym>)
/// and TAGS=:t1:t2: from the state.
pub fn serializeUdevMessage(
    gpa: std.mem.Allocator,
    state: *const EventState,
    subsystem: []const u8,
    devtype: ?[]const u8,
) ![]u8 {
    var blob: std.ArrayListUnmanaged(u8) = .empty;
    defer blob.deinit(gpa);

    var it = state.properties.iterator();
    while (it.next()) |kv| {
        try blob.appendSlice(gpa, kv.key_ptr.*);
        try blob.append(gpa, '=');
        try blob.appendSlice(gpa, kv.value_ptr.*);
        try blob.append(gpa, 0);
    }

    if (state.symlinks.items.len > 0) {
        try blob.appendSlice(gpa, "DEVLINKS=");
        for (state.symlinks.items, 0..) |sym, i| {
            if (i != 0) try blob.append(gpa, ' ');
            try blob.appendSlice(gpa, "/dev/");
            try blob.appendSlice(gpa, sym);
        }
        try blob.append(gpa, 0);
    }

    if (state.tags.count() > 0) {
        try blob.appendSlice(gpa, "TAGS=:");
        var tit = state.tags.iterator();
        while (tit.next()) |e| {
            try blob.appendSlice(gpa, e.key_ptr.*);
            try blob.append(gpa, ':');
        }
        try blob.append(gpa, 0);
    }

    const out = try gpa.alloc(u8, 40 + blob.items.len);
    errdefer gpa.free(out);
    @memcpy(out[0..8], "libudev\x00");
    // Big-endian magic, matching systemd. The remaining header fields are native order.
    std.mem.writeInt(u32, out[8..][0..4], 0xfeedcafe, .big);
    std.mem.writeInt(u32, out[12..][0..4], 40, .little);
    std.mem.writeInt(u32, out[16..][0..4], 40, .little);
    std.mem.writeInt(u32, out[20..][0..4], @intCast(blob.items.len), .little);
    std.mem.writeInt(u32, out[24..][0..4], stringHash32(subsystem), .little);
    std.mem.writeInt(u32, out[28..][0..4], if (devtype) |dt| stringHash32(dt) else 0, .little);
    @memset(out[32..40], 0);
    @memcpy(out[40..], blob.items);
    return out;
}

// Broadcaster

pub const Broadcaster = struct {
    fd_: posix.fd_t,

    /// Open a NETLINK_KOBJECT_UEVENT socket for sending to the udev multicast group.
    /// Binds with groups=0 (we send, we do not subscribe). CAP_NET_ADMIN is needed to
    /// actually multicast; init here just opens+binds the socket.
    pub fn init() !Broadcaster {
        const rc = linux.socket(
            linux.AF.NETLINK,
            linux.SOCK.DGRAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK,
            udev_linux.netlink_kobject_uevent,
        );
        const fd: posix.fd_t = switch (linux.errno(rc)) {
            .SUCCESS => @intCast(rc),
            .ACCES, .PERM => return error.PermissionDenied,
            else => |e| return posix.unexpectedErrno(e),
        };
        errdefer _ = linux.close(fd);

        const src = udev_linux.nlAddr(0);
        const brc = linux.bind(fd, @as(*const linux.sockaddr, @ptrCast(&src)), @sizeOf(linux.sockaddr.nl));
        switch (linux.errno(brc)) {
            .SUCCESS => {},
            .ACCES, .PERM => return error.PermissionDenied,
            else => |e| return posix.unexpectedErrno(e),
        }
        return .{ .fd_ = fd };
    }

    /// Send a serialized libudev message to the .udev multicast group.
    /// PermissionDenied (no CAP_NET_ADMIN) is surfaced so callers can tolerate it.
    pub fn send(self: *Broadcaster, buf: []const u8) !void {
        var dest = udev_linux.nlAddr(@intFromEnum(udev_linux.Group.udev));
        const rc = linux.sendto(
            self.fd_,
            buf.ptr,
            buf.len,
            0,
            @as(*const linux.sockaddr, @ptrCast(&dest)),
            @sizeOf(linux.sockaddr.nl),
        );
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .ACCES, .PERM => return error.PermissionDenied,
            else => |e| return posix.unexpectedErrno(e),
        }
    }

    pub fn deinit(self: *Broadcaster) void {
        if (self.fd_ >= 0) _ = linux.close(self.fd_);
    }
};

// Tests

test "stringHash32 determinism and distinctness" {
    try std.testing.expectEqual(stringHash32("block"), stringHash32("block"));
    try std.testing.expect(stringHash32("block") != stringHash32("input"));
}

test "Broadcaster smoke: open, send, tolerate unprivileged" {
    var b = Broadcaster.init() catch |e| switch (e) {
        error.PermissionDenied => return,
        else => return e,
    };
    defer b.deinit();
    try std.testing.expect(b.fd_ >= 0);
    var state = EventState.init(std.testing.allocator);
    defer state.deinit();
    try state.setProperty("SUBSYSTEM", "block");
    const msg = try serializeUdevMessage(std.testing.allocator, &state, "block", null);
    defer std.testing.allocator.free(msg);
    b.send(msg) catch {};
}

test "serializeUdevMessage round-trip through parseUdev" {
    var ctx = Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    try state.setProperty("SUBSYSTEM", "block");
    try state.setProperty("DEVNAME", "sda");
    try state.addSymlink("disk/by-id/x");

    const buf = try serializeUdevMessage(std.testing.allocator, &state, "block", null);
    defer std.testing.allocator.free(buf);

    var dev = (try Monitor.deviceFromMessage(&ctx, .udev, buf)).?;
    defer dev.deinit();

    try std.testing.expect(std.mem.eql(u8, (try dev.subsystem()).?, "block"));
    try std.testing.expectEqualStrings("/dev/sda", dev.devnode().?);
    const devlinks = dev.getProperty("DEVLINKS").?;
    try std.testing.expect(std.mem.indexOf(u8, devlinks, "/dev/disk/by-id/x") != null);
}
