//! node_actuator.zig - device-node actuator: applies an evaluated event outcome to the filesystem.
//! resolveNode + applySymlinks are the non-root-gated core. makeNode (mknod) and applyPerms (chown)
//! are root-gated. apply() orchestrates add/change/remove.
const std = @import("std");
const linux = std.os.linux;
const Device = @import("../device.zig").Device;
const EventState = @import("../rules/runner.zig").EventState;

/// `devname` borrows from the Device's arena: valid only while that Device is alive.
pub const NodeInfo = struct { devname: []const u8, kind: u32, major: u32, minor: u32 };

/// Resolve the /dev node facts from a Device. Returns null if the device has no DEVNAME
/// (or no MAJOR/MINOR). kind = IFBLK when subsystem=="block", else IFCHR.
pub fn resolveNode(dev: *Device) !?NodeInfo {
    const dn = dev.getProperty("DEVNAME") orelse return null;
    const kind: u32 = if (std.mem.eql(u8, (try dev.subsystem()) orelse "", "block"))
        linux.S.IFBLK
    else
        linux.S.IFCHR;
    const major = std.fmt.parseInt(u32, dev.getProperty("MAJOR") orelse return null, 10) catch return null;
    const minor = std.fmt.parseInt(u32, dev.getProperty("MINOR") orelse return null, 10) catch return null;
    return .{ .devname = dn, .kind = kind, .major = major, .minor = minor };
}

/// Create (create=true) or remove (create=false) each symlink under dev_root, pointing at devname.
/// Targets are RELATIVE: for a symlink path with N slashes, target = ("../" * N) ++ devname.
///   e.g. "disk/by-id/x" (2 slashes) -> target "../../sda".
/// On create: createDirPath the symlink's parent, deleteFile any existing link, then symLink.
/// On remove: deleteFile each link (ignore "not found").
pub fn applySymlinks(
    io: std.Io,
    gpa: std.mem.Allocator,
    dev_root: []const u8,
    devname: []const u8,
    symlinks: []const []const u8,
    create: bool,
) !void {
    for (symlinks) |sym| {
        const linkpath = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ dev_root, sym });
        defer gpa.free(linkpath);

        if (create) {
            var n: usize = 0;
            for (sym) |c| {
                if (c == '/') n += 1;
            }

            var target: std.ArrayListUnmanaged(u8) = .empty;
            defer target.deinit(gpa);
            for (0..n) |_| {
                try target.appendSlice(gpa, "../");
            }
            try target.appendSlice(gpa, devname);

            if (std.fs.path.dirname(linkpath)) |parent| {
                try std.Io.Dir.cwd().createDirPath(io, parent);
            }
            std.Io.Dir.cwd().deleteFile(io, linkpath) catch {};
            try std.Io.Dir.cwd().symLink(io, target.items, linkpath, .{});
        } else {
            std.Io.Dir.cwd().deleteFile(io, linkpath) catch {};
        }
    }
}

// Device-node creation + permission operations

/// Linux "new" 32-bit dev_t encoding used by the mknodat(2) syscall's dev argument.
/// For major < 256 and minor < 256 this reduces to (major << 8) | minor.
/// High bits of minor (> 0xFF) shift to bits 20+ via the third term.
fn makedev(major: u32, minor: u32) u32 {
    return (minor & 0xff) | (major << 8) | ((minor & ~@as(u32, 0xff)) << 12);
}

/// mknod the device node at <dev_root>/<node.devname>. Root-gated (needs CAP_MKNOD).
/// EEXIST is treated as success. Returns error.PermissionDenied when unprivileged.
pub fn makeNode(gpa: std.mem.Allocator, dev_root: []const u8, node: NodeInfo, mode: u32) !void {
    const pathZ = try std.fmt.allocPrintSentinel(gpa, "{s}/{s}", .{ dev_root, node.devname }, 0);
    defer gpa.free(pathZ);
    const rc = linux.mknodat(linux.AT.FDCWD, pathZ.ptr, node.kind | (mode & 0o7777), makedev(node.major, node.minor));
    switch (linux.errno(rc)) {
        .SUCCESS, .EXIST => {},
        .ACCES, .PERM => return error.PermissionDenied,
        else => |e| return std.posix.unexpectedErrno(e),
    }
}

/// chmod (if mode) and chown (if uid or gid) the node at <dev_root>/<devname>.
/// chown is root-gated: EPERM/EACCES are tolerated (ignored). chmod errors on a real failure.
pub fn applyPerms(
    gpa: std.mem.Allocator,
    dev_root: []const u8,
    devname: []const u8,
    mode: ?u32,
    uid: ?u32,
    gid: ?u32,
) !void {
    const pathZ = try std.fmt.allocPrintSentinel(gpa, "{s}/{s}", .{ dev_root, devname }, 0);
    defer gpa.free(pathZ);

    if (mode) |m| {
        const rc = linux.fchmodat(linux.AT.FDCWD, pathZ.ptr, m & 0o7777);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            else => |e| return std.posix.unexpectedErrno(e),
        }
    }

    if (uid != null or gid != null) {
        const rc = linux.fchownat(
            linux.AT.FDCWD,
            pathZ.ptr,
            uid orelse ~@as(u32, 0),
            gid orelse ~@as(u32, 0),
            0,
        );
        switch (linux.errno(rc)) {
            .SUCCESS, .PERM, .ACCES => {},
            else => |e| return std.posix.unexpectedErrno(e),
        }
    }
}

/// Look up a numeric id from a colon-separated database (passwd or group) by name.
/// Line format: "<name>:<x>:<id>:...". Returns the 3rd field parsed as u32, or null.
fn dbLookup(content: []const u8, name: []const u8) ?u32 {
    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, ':');
        const fname = fields.next() orelse continue;
        if (!std.mem.eql(u8, fname, name)) continue;
        _ = fields.next() orelse continue; // password field (x)
        const id_str = fields.next() orelse continue;
        return std.fmt.parseInt(u32, std.mem.trim(u8, id_str, " \t\r"), 10) catch null;
    }
    return null;
}

/// Resolve an OWNER/GROUP value (numeric or a name) to a numeric id.
/// Numeric strings pass through; names are looked up in db_path (/etc/passwd or /etc/group).
/// Returns null if unresolvable (missing file, unknown name). The caller then skips chown for it.
fn resolveId(gpa: std.mem.Allocator, io: std.Io, value: []const u8, db_path: []const u8) ?u32 {
    if (std.fmt.parseInt(u32, value, 10)) |n| return n else |_| {}
    const content = std.Io.Dir.cwd().readFileAlloc(io, db_path, gpa, .limited(1 << 20)) catch return null;
    defer gpa.free(content);
    return dbLookup(content, value);
}

pub const Action = enum { add, change, remove, other };
pub const Options = struct { dev_root: []const u8 = "/dev" };

/// Apply an evaluated event outcome to the filesystem.
pub fn apply(
    io: std.Io,
    gpa: std.mem.Allocator,
    dev: *Device,
    state: *const EventState,
    action: Action,
    opts: Options,
) !void {
    // Resolve owner/group: numeric passes through, names via /etc/passwd, /etc/group.
    const uid = if (state.owner) |o| resolveId(gpa, io, o, "/etc/passwd") else null;
    const gid = if (state.group) |g| resolveId(gpa, io, g, "/etc/group") else null;

    switch (action) {
        .add, .change => {
            if (try resolveNode(dev)) |node| {
                makeNode(gpa, opts.dev_root, node, state.mode orelse 0o600) catch |e| if (e != error.PermissionDenied) return e;
                applyPerms(gpa, opts.dev_root, node.devname, state.mode, uid, gid) catch {};
                try applySymlinks(io, gpa, opts.dev_root, node.devname, state.symlinks.items, true);
            }
        },
        .remove => {
            if (try resolveNode(dev)) |node| {
                try applySymlinks(io, gpa, opts.dev_root, node.devname, state.symlinks.items, false);
                const nodepath = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ opts.dev_root, node.devname });
                defer gpa.free(nodepath);
                std.Io.Dir.cwd().deleteFile(io, nodepath) catch {};
            }
        },
        .other => {},
    }
}

// Tests

test "resolveNode block device" {
    const uevent_mod = @import("../uevent.zig");
    const context_mod = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    const buf = "add@/devices/x/sda\x00SUBSYSTEM=block\x00MAJOR=8\x00MINOR=0\x00DEVNAME=sda\x00";
    const parsed = try uevent_mod.parseKernel(buf);
    var ctx = context_mod.Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    const info = (try resolveNode(&dev)).?;
    try std.testing.expectEqualStrings("sda", info.devname);
    try std.testing.expectEqual(linux.S.IFBLK, info.kind);
    try std.testing.expectEqual(@as(u32, 8), info.major);
    try std.testing.expectEqual(@as(u32, 0), info.minor);
}

test "resolveNode char device" {
    const uevent_mod = @import("../uevent.zig");
    const context_mod = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    const buf = "add@/devices/x/event0\x00SUBSYSTEM=input\x00MAJOR=13\x00MINOR=64\x00DEVNAME=event0\x00";
    const parsed = try uevent_mod.parseKernel(buf);
    var ctx = context_mod.Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    const info = (try resolveNode(&dev)).?;
    try std.testing.expectEqual(linux.S.IFCHR, info.kind);
}

test "resolveNode no DEVNAME returns null" {
    const uevent_mod = @import("../uevent.zig");
    const context_mod = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    const buf = "add@/devices/x/foo\x00SUBSYSTEM=acpi\x00MAJOR=8\x00MINOR=0\x00";
    const parsed = try uevent_mod.parseKernel(buf);
    var ctx = context_mod.Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    const result = try resolveNode(&dev);
    try std.testing.expect(result == null);
}

test "applySymlinks create and replace" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const dev_root = rp_buf[0..n];

    try applySymlinks(io, gpa, dev_root, "sda", &.{"disk/by-id/x"}, true);

    const linkpath = try std.fmt.allocPrint(gpa, "{s}/disk/by-id/x", .{dev_root});
    defer gpa.free(linkpath);

    // Verify symlink exists and points to correct relative target via readLink
    // (access follows symlinks so it fails on dangling links, whereas readLink checks the link itself).
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const ln = try std.Io.Dir.cwd().readLink(io, linkpath, &link_buf);
    try std.testing.expectEqualStrings("../../sda", link_buf[0..ln]);

    // Replace case: calling again must not error and target must still be correct.
    try applySymlinks(io, gpa, dev_root, "sda", &.{"disk/by-id/x"}, true);

    const ln2 = try std.Io.Dir.cwd().readLink(io, linkpath, &link_buf);
    try std.testing.expectEqualStrings("../../sda", link_buf[0..ln2]);
}

test "applySymlinks remove" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const dev_root = rp_buf[0..n];

    // Create then remove.
    try applySymlinks(io, gpa, dev_root, "sda", &.{"disk/by-id/x"}, true);
    try applySymlinks(io, gpa, dev_root, "sda", &.{"disk/by-id/x"}, false);

    const linkpath = try std.fmt.allocPrint(gpa, "{s}/disk/by-id/x", .{dev_root});
    defer gpa.free(linkpath);

    // Verify link is gone via readLink (returns FileNotFound on deleted symlink).
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().readLink(io, linkpath, &link_buf));
}

test "applyPerms chmod" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const dev_root = rp_buf[0..n];

    try tmp.dir.writeFile(io, .{ .sub_path = "sda", .data = "" });

    try applyPerms(gpa, dev_root, "sda", 0o640, null, null);

    const filepath = try std.fmt.allocPrint(gpa, "{s}/sda", .{dev_root});
    defer gpa.free(filepath);

    const st = try std.Io.Dir.cwd().statFile(io, filepath, .{});
    try std.testing.expectEqual(@as(u32, 0o640), st.permissions.toMode() & 0o7777);
}

test "apply remove e2e" {
    const uevent_mod = @import("../uevent.zig");
    const context_mod = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const dev_root = rp_buf[0..n];

    const buf = "add@/devices/x/sda\x00SUBSYSTEM=block\x00MAJOR=8\x00MINOR=0\x00DEVNAME=sda\x00";
    const parsed = try uevent_mod.parseKernel(buf);
    var ctx = context_mod.Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();
    try state.addSymlink("disk/by-id/x");

    // Pre-create the symlink and a stand-in regular file for the device node.
    try applySymlinks(io, gpa, dev_root, "sda", state.symlinks.items, true);
    try tmp.dir.writeFile(io, .{ .sub_path = "sda", .data = "" });

    try apply(io, gpa, &dev, &state, .remove, .{ .dev_root = dev_root });

    // Both symlink and node file must be gone.
    const linkpath = try std.fmt.allocPrint(gpa, "{s}/disk/by-id/x", .{dev_root});
    defer gpa.free(linkpath);
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().readLink(io, linkpath, &link_buf));

    const nodepath = try std.fmt.allocPrint(gpa, "{s}/sda", .{dev_root});
    defer gpa.free(nodepath);
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(io, nodepath, .{}));
}

test "makeNode root gated" {
    const uevent_mod = @import("../uevent.zig");
    const context_mod = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const dev_root = rp_buf[0..n];

    const buf = "add@/devices/x/sda\x00SUBSYSTEM=block\x00MAJOR=8\x00MINOR=0\x00DEVNAME=sda\x00";
    const parsed = try uevent_mod.parseKernel(buf);
    var ctx = context_mod.Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    const node = (try resolveNode(&dev)).?;

    makeNode(gpa, dev_root, node, 0o600) catch |e| {
        if (e != error.PermissionDenied) return e;
        return; // Unprivileged: mknod denied, test passes.
    };
    // makeNode succeeded (CAP_MKNOD present). Verify the node was created.
    const nodepath = try std.fmt.allocPrint(gpa, "{s}/sda", .{dev_root});
    defer gpa.free(nodepath);
    try std.Io.Dir.cwd().access(io, nodepath, .{});
}

test "dbLookup passwd" {
    const passwd = "root:x:0:0:root:/root:/bin/sh\nvideo:x:44:\nbin:x:1:1:bin:/:/sbin/nologin\n";
    try std.testing.expectEqual(@as(u32, 0), dbLookup(passwd, "root").?);
    try std.testing.expectEqual(@as(u32, 44), dbLookup(passwd, "video").?);
    try std.testing.expect(dbLookup(passwd, "nope") == null);
}

test "dbLookup group" {
    const group = "wheel:x:998:alice,bob\nvideo:x:44:carol\n";
    try std.testing.expectEqual(@as(u32, 44), dbLookup(group, "video").?);
    try std.testing.expectEqual(@as(u32, 998), dbLookup(group, "wheel").?);
}

test "resolveId numeric passthrough" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    try std.testing.expectEqual(@as(u32, 1000), resolveId(gpa, io, "1000", "/nonexistent").?);
    try std.testing.expect(resolveId(gpa, io, "definitelynotauser", "/nonexistent") == null);
}

test "resolveId from fixture file" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "passwd", .data = "media:x:1001:\n" });

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, "passwd", &rp_buf);
    const path = rp_buf[0..n];

    try std.testing.expectEqual(@as(u32, 1001), resolveId(gpa, io, "media", path).?);
}
