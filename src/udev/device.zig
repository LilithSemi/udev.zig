/// Sysfs device model for the pure-Zig udev reimplementation.
///
/// A Device owns a single ArenaAllocator (child of ctx.gpa). All strings
/// (syspath copy, property keys/values, cached sysattrs, devnode, subsystem)
/// live in that arena. `deinit()` frees the arena in one shot.
///
/// Calling `parent()` returns an independent Device with its own arena.
const std = @import("std");
const context = @import("context.zig");
const linux = @import("linux.zig");
const uevent = @import("uevent.zig");

pub const Context = context.Context;

pub const Device = struct {
    ctx: *Context,
    /// All owned memory for this Device lives here.
    arena: std.heap.ArenaAllocator,
    /// Owned copy of the absolute sysfs path (e.g. "/sys/devices/pci0/net/eth0").
    syspath_: []const u8,
    /// Parsed properties from `<syspath>/uevent` (newline-separated KEY=VALUE).
    /// Keys and values are duped into the arena.
    props: std.StringHashMapUnmanaged([]const u8),
    /// Lazily populated cache of sysattr file contents (keyed by attr name). A cached value of
    /// `null` records a confirmed miss so we do not re-stat a missing attr on every scan.
    sysattrs: std.StringHashMapUnmanaged(?[]const u8),
    /// Pre-computed "/dev/" ++ DEVNAME, or null if DEVNAME is absent.
    devnode_: ?[]const u8,
    /// Cached result of the subsystem symlink resolution.
    subsystem_resolved_: bool,
    subsystem_: ?[]const u8,
    /// Cached result of the driver symlink resolution.
    driver_resolved_: bool,
    driver_: ?[]const u8,

    // Construction / destruction

    /// Parse the device at `syspath` (absolute path to the sysfs device dir).
    /// Reads `<syspath>/uevent` and pre-computes derived fields.
    pub fn fromSyspath(ctx: *Context, path: []const u8) !Device {
        var arena = std.heap.ArenaAllocator.init(ctx.gpa);
        errdefer arena.deinit();
        const alloc = arena.allocator();

        // Dupe syspath so the Device owns the string.
        const owned_syspath = try alloc.dupe(u8, path);

        // Read the uevent file. Absence is not an error, so treat it as empty.
        var ue_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const ue_path = try std.fmt.bufPrint(&ue_path_buf, "{s}/uevent", .{path});
        const ue_content = std.Io.Dir.cwd().readFileAlloc(
            ctx.io,
            ue_path,
            alloc,
            .limited(64 * 1024),
        ) catch |err| switch (err) {
            error.FileNotFound => "",
            else => return err,
        };

        // Parse newline-separated KEY=VALUE lines.
        var props: std.StringHashMapUnmanaged([]const u8) = .empty;
        var lines = std.mem.tokenizeScalar(u8, ue_content, '\n');
        while (lines.next()) |line| {
            const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
            const key = try alloc.dupe(u8, line[0..eq]);
            const val = try alloc.dupe(u8, line[eq + 1 ..]);
            try props.put(alloc, key, val);
        }

        // Pre-compute devnode = "/dev/" ++ DEVNAME if present.
        const devnode_str: ?[]const u8 = if (props.get("DEVNAME")) |dn|
            try std.mem.concat(alloc, u8, &.{ "/dev/", dn })
        else
            null;

        return .{
            .ctx = ctx,
            .arena = arena,
            .syspath_ = owned_syspath,
            .props = props,
            .sysattrs = .empty,
            .devnode_ = devnode_str,
            .subsystem_resolved_ = false,
            .subsystem_ = null,
            .driver_resolved_ = false,
            .driver_ = null,
        };
    }

    /// Build a Device directly from a parsed netlink PropList without reading sysfs.
    /// Used by the monitor when a device may already be gone from the filesystem.
    /// Ownership mirrors fromSyspath: a new arena is created; caller must call deinit().
    pub fn fromProps(ctx: *Context, devpath: []const u8, props: uevent.PropList) !Device {
        var arena = std.heap.ArenaAllocator.init(ctx.gpa);
        errdefer arena.deinit();
        const alloc = arena.allocator();

        // syspath = "/sys" ++ devpath when devpath is non-empty, else "".
        const owned_syspath: []const u8 = if (devpath.len > 0)
            try std.mem.concat(alloc, u8, &.{ "/sys", devpath })
        else
            try alloc.dupe(u8, "");

        // Build the props map from the NUL-separated KEY=VALUE tokens.
        var prop_map: std.StringHashMapUnmanaged([]const u8) = .empty;
        var iter = props.iterator();
        while (iter.next()) |token| {
            const eq = std.mem.indexOfScalar(u8, token, '=') orelse continue;
            const key = try alloc.dupe(u8, token[0..eq]);
            const val = try alloc.dupe(u8, token[eq + 1 ..]);
            try prop_map.put(alloc, key, val);
        }

        // Pre-compute devnode.
        const devnode_str: ?[]const u8 = if (prop_map.get("DEVNAME")) |dn|
            try std.mem.concat(alloc, u8, &.{ "/dev/", dn })
        else
            null;

        // Pre-compute subsystem from props. Never attempt a sysfs readlink.
        const subsystem_str: ?[]const u8 = if (prop_map.get("SUBSYSTEM")) |sub|
            try alloc.dupe(u8, sub)
        else
            null;

        return .{
            .ctx = ctx,
            .arena = arena,
            .syspath_ = owned_syspath,
            .props = prop_map,
            .sysattrs = .empty,
            .devnode_ = devnode_str,
            .subsystem_resolved_ = true,
            .subsystem_ = subsystem_str,
            .driver_resolved_ = false,
            .driver_ = null,
        };
    }

    /// Release all memory owned by this Device. The Device must not be used
    /// after this call.
    pub fn deinit(self: *Device) void {
        self.arena.deinit();
    }

    // Accessors

    /// Basename of the sysfs path (e.g. "eth0").
    pub fn sysname(self: *const Device) []const u8 {
        return std.fs.path.basename(self.syspath_);
    }

    /// Subsystem name derived from readlink `<syspath>/subsystem`.
    /// Result is valid for the lifetime of the Device (cached in the arena).
    /// Returns null if the symlink is absent.
    pub fn subsystem(self: *Device) !?[]const u8 {
        if (self.subsystem_resolved_) return self.subsystem_;
        self.subsystem_resolved_ = true;

        var lp_buf: [std.fs.max_path_bytes]u8 = undefined;
        const lp = try std.fmt.bufPrint(&lp_buf, "{s}/subsystem", .{self.syspath_});

        var tgt_buf: [std.fs.max_path_bytes]u8 = undefined;
        const n = std.Io.Dir.cwd().readLink(self.ctx.io, lp, &tgt_buf) catch |err| switch (err) {
            error.FileNotFound, error.NotLink => {
                self.subsystem_ = null;
                return null;
            },
            else => return err,
        };
        const sub_name = linux.subsystemFromLink(tgt_buf[0..n]);
        self.subsystem_ = try self.arena.allocator().dupe(u8, sub_name);
        return self.subsystem_;
    }

    /// Driver name derived from readlink `<syspath>/driver`.
    /// Result is valid for the lifetime of the Device (cached in the arena).
    /// Returns null if the symlink is absent.
    pub fn driver(self: *Device) !?[]const u8 {
        if (self.driver_resolved_) return self.driver_;
        self.driver_resolved_ = true;

        var lp_buf: [std.fs.max_path_bytes]u8 = undefined;
        const lp = try std.fmt.bufPrint(&lp_buf, "{s}/driver", .{self.syspath_});

        var tgt_buf: [std.fs.max_path_bytes]u8 = undefined;
        const n = std.Io.Dir.cwd().readLink(self.ctx.io, lp, &tgt_buf) catch |err| switch (err) {
            error.FileNotFound, error.NotLink => {
                self.driver_ = null;
                return null;
            },
            else => return err,
        };
        const drv_name = std.fs.path.basename(tgt_buf[0..n]);
        self.driver_ = try self.arena.allocator().dupe(u8, drv_name);
        return self.driver_;
    }

    /// The device's absolute sysfs path (e.g. "/sys/devices/.../event0").
    pub fn syspath(self: *const Device) []const u8 {
        return self.syspath_;
    }

    /// Encoded device number (glibc makedev) from the MAJOR/MINOR properties, or null if absent.
    pub fn devnum(self: *const Device) ?u64 {
        const maj = self.props.get("MAJOR") orelse return null;
        const min = self.props.get("MINOR") orelse return null;
        const M = std.fmt.parseInt(u32, maj, 10) catch return null;
        const N = std.fmt.parseInt(u32, min, 10) catch return null;
        return (@as(u64, N & 0xff)) | (@as(u64, M & 0xfff) << 8) |
            (@as(u64, N & ~@as(u32, 0xff)) << 12) | (@as(u64, M & ~@as(u32, 0xfff)) << 32);
    }

    /// Value of the DEVTYPE property, or null.
    pub fn devtype(self: *const Device) ?[]const u8 {
        return self.props.get("DEVTYPE");
    }

    /// "/dev/" ++ DEVNAME property, or null if DEVNAME is absent.
    /// The slice is valid for the lifetime of the Device.
    pub fn devnode(self: *const Device) ?[]const u8 {
        return self.devnode_;
    }

    /// Look up a property by key. Slice is valid for the Device's lifetime.
    pub fn getProperty(self: *const Device, key: []const u8) ?[]const u8 {
        return self.props.get(key);
    }

    /// Read `<syspath>/<name>` on first call, trim one trailing newline, cache in
    /// the arena. Returns null if the file does not exist.
    /// Slice is valid for the Device's lifetime.
    pub fn getSysattr(self: *Device, name: []const u8) !?[]const u8 {
        // `get` returns `??[]const u8`; the outer optional is "is it cached", the inner is the
        // cached hit/miss. A cached miss (inner null) short-circuits the filesystem read.
        if (self.sysattrs.get(name)) |cached| return cached;

        const alloc = self.arena.allocator();
        const owned_key = try alloc.dupe(u8, name);

        var ap_buf: [std.fs.max_path_bytes]u8 = undefined;
        const ap = try std.fmt.bufPrint(&ap_buf, "{s}/{s}", .{ self.syspath_, name });

        const raw = std.Io.Dir.cwd().readFileAlloc(
            self.ctx.io,
            ap,
            alloc,
            .limited(64 * 1024),
        ) catch |err| switch (err) {
            error.FileNotFound => {
                try self.sysattrs.put(alloc, owned_key, null); // cache the miss
                return null;
            },
            else => return err,
        };

        // Trim exactly one trailing '\n' if present.
        const trimmed = if (raw.len > 0 and raw[raw.len - 1] == '\n')
            raw[0 .. raw.len - 1]
        else
            raw;

        try self.sysattrs.put(alloc, owned_key, trimmed);
        return trimmed;
    }

    // Hierarchy traversal

    /// Walk up sysfs parent directories until one contains a `uevent` file.
    /// Returns an independent Device (caller must deinit) or null at the top.
    pub fn parent(self: *Device) !?Device {
        var current: []const u8 = self.syspath_;
        while (true) {
            const parent_path = std.fs.path.dirname(current) orelse return null;
            if (parent_path.len == 0 or std.mem.eql(u8, parent_path, current)) return null;

            // Check whether <parent_path>/uevent exists.
            var ue_buf: [std.fs.max_path_bytes]u8 = undefined;
            const ue_path = std.fmt.bufPrint(&ue_buf, "{s}/uevent", .{parent_path}) catch return null;

            const found = blk: {
                std.Io.Dir.cwd().access(self.ctx.io, ue_path, .{}) catch {
                    break :blk false;
                };
                break :blk true;
            };

            if (!found) {
                current = parent_path;
                continue;
            }

            return try Device.fromSyspath(self.ctx, parent_path);
        }
    }

    /// Walk parents until one matches the given subsystem (and optional devtype).
    /// Returns an independent Device (caller must deinit) or null.
    pub fn parentWithSubsystem(self: *Device, sub: []const u8, dt: ?[]const u8) !?Device {
        var maybe: ?Device = try self.parent();
        while (maybe) |p| {
            // dev takes sole ownership of this ancestor. p is a by-value copy from the while
            // capture (same arena) and is never deinit'd, so there is no double-free.
            var dev = p;

            const s = dev.subsystem() catch |err| {
                dev.deinit();
                return err;
            };
            const sub_ok = s != null and std.mem.eql(u8, s.?, sub);

            const dt_ok = blk: {
                if (dt) |dtype| {
                    const d = dev.devtype() orelse break :blk false;
                    break :blk std.mem.eql(u8, d, dtype);
                }
                break :blk true;
            };

            if (sub_ok and dt_ok) return dev;

            maybe = dev.parent() catch |err| {
                dev.deinit();
                return err;
            };
            dev.deinit();
        }
        return null;
    }
};

// Tests

test "Device parses uevent props and derives fields" {
    const testfs = @import("testfs.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const syspath = try testfs.makeSysfs(&tmp, .{
        .name = "event0",
        .subsystem = "input",
        .uevent = "MAJOR=13\nMINOR=64\nDEVNAME=input/event0\n",
        .attrs = &.{.{ "name", "AT Keyboard" }},
    });
    defer std.testing.allocator.free(syspath);

    var ctx = Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    try std.testing.expectEqualStrings("event0", dev.sysname());
    try std.testing.expectEqualStrings("input", (try dev.subsystem()).?);
    try std.testing.expectEqualStrings("/dev/input/event0", dev.devnode().?);
    try std.testing.expectEqualStrings("13", dev.getProperty("MAJOR").?);
    try std.testing.expectEqualStrings("AT Keyboard", (try dev.getSysattr("name")).?);
    try std.testing.expect((try dev.getSysattr("missing")) == null);
}

test "Device.syspath and Device.devnum" {
    const testfs = @import("testfs.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const syspath_str = try testfs.makeSysfs(&tmp, .{
        .name = "event0",
        .subsystem = "input",
        .uevent = "MAJOR=13\nMINOR=64\n",
    });
    defer std.testing.allocator.free(syspath_str);

    var ctx = Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, syspath_str);
    defer dev.deinit();

    try std.testing.expectEqualStrings(syspath_str, dev.syspath());
    // makedev(13, 64): M=0x0d, N=0x40
    // = (0x40 & 0xff) | (0x0d & 0xfff)<<8 | 0 | 0 = 0x40 | 0xd00 = 0xd40
    try std.testing.expectEqual(@as(u64, 0xd40), dev.devnum().?);
}

test "Device.parent walks up to nearest uevent dir" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.testing.io;
    const gpa = std.testing.allocator;

    // Create parent device.
    try tmp.dir.createDirPath(io, "devices/parent0");
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/parent0/uevent", .data = "DEVTYPE=usb_device\n" });

    // Create child device nested inside parent.
    try tmp.dir.createDirPath(io, "devices/parent0/child1");
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/parent0/child1/uevent", .data = "" });

    // Use realPathFile + gpa.dupe so the slice len matches the allocation size
    // (realPathFileAlloc returns [:0]u8 which allocates len+1, causing a size
    // mismatch if the caller frees a plain []u8 with std.testing.allocator).
    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const rp_n1 = try tmp.dir.realPathFile(io, "devices/parent0", &rp_buf);
    const parent_abs = try gpa.dupe(u8, rp_buf[0..rp_n1]);
    defer gpa.free(parent_abs);
    const rp_n2 = try tmp.dir.realPathFile(io, "devices/parent0/child1", &rp_buf);
    const child_abs = try gpa.dupe(u8, rp_buf[0..rp_n2]);
    defer gpa.free(child_abs);

    var ctx = Context.init(gpa, io);
    defer ctx.deinit();

    var child = try Device.fromSyspath(&ctx, child_abs);
    defer child.deinit();

    const maybe_parent = try child.parent();
    try std.testing.expect(maybe_parent != null);
    var par = maybe_parent.?;
    defer par.deinit();

    try std.testing.expectEqualStrings("parent0", par.sysname());
}

test "Device.driver returns driver name from symlink" {
    const testfs = @import("testfs.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const syspath = try testfs.makeSysfs(&tmp, .{
        .name = "event0",
        .subsystem = "input",
        .uevent = "",
        .driver = "usbhid",
    });
    defer std.testing.allocator.free(syspath);

    var ctx = Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    try std.testing.expectEqualStrings("usbhid", (try dev.driver()).?);
}

test "Device.driver returns null when no driver symlink" {
    const testfs = @import("testfs.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const syspath = try testfs.makeSysfs(&tmp, .{
        .name = "event0",
        .subsystem = "input",
        .uevent = "",
    });
    defer std.testing.allocator.free(syspath);

    var ctx = Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    try std.testing.expect((try dev.driver()) == null);
}
