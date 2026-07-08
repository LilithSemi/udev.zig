//! daemon_core.zig - testable Daemon core: per-uevent pipeline.
//! Evaluate rules -> udev_db write/remove -> node_actuator apply.
//! The live netlink loop and rebroadcast come in later tasks.
const std = @import("std");
const rules = @import("../rules.zig");
const rules_loader = @import("rules_loader.zig");
const ExecRunner = @import("exec_runner.zig").ExecRunner;
const udev_db = @import("../udev_db.zig");
const node_actuator = @import("node_actuator.zig");
const link_db = @import("link_db.zig");
const hwdb = @import("../hwdb.zig");
const Device = @import("../device.zig").Device;
const netlink_broadcast = @import("netlink_broadcast.zig");
const Context = @import("../context.zig").Context;
const Enumerate = @import("../enumerate.zig").Enumerate;
const Watcher = @import("watcher.zig").Watcher;

pub const Options = struct {
    run_root: []const u8 = "/run/udev",
    dev_root: []const u8 = "/dev",
    rules_dirs: []const []const u8 = &rules_loader.default_dirs,
    helper_dirs: []const []const u8 = &.{ "/usr/lib/udev", "/lib/udev" },
    /// Milliseconds before a PROGRAM= helper is killed; 0 = no limit. Default matches real udev (180s).
    program_timeout_ms: u32 = 180_000,
};

pub const Daemon = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    ruleset: rules.RuleSet,
    hwdb: ?hwdb.Hwdb,
    opts: Options,
    broadcaster: ?*netlink_broadcast.Broadcaster = null,
    watcher: ?*Watcher = null,

    /// Load rules from disk + open hwdb best-effort. For the executable.
    pub fn init(gpa: std.mem.Allocator, io: std.Io, opts: Options) !Daemon {
        const ruleset = try rules_loader.load(gpa, io, .{ .dirs = opts.rules_dirs });
        const hw = hwdb.Hwdb.open(gpa, io, .{}) catch null;
        return .{ .gpa = gpa, .io = io, .ruleset = ruleset, .hwdb = hw, .opts = opts, .broadcaster = null, .watcher = null };
    }

    /// Inject a pre-parsed RuleSet (tests / embedding). hwdb = null.
    pub fn initWithRuleSet(gpa: std.mem.Allocator, io: std.Io, ruleset: rules.RuleSet, opts: Options) Daemon {
        return .{ .gpa = gpa, .io = io, .ruleset = ruleset, .hwdb = null, .opts = opts, .broadcaster = null, .watcher = null };
    }

    pub fn deinit(self: *Daemon) void {
        self.ruleset.deinit();
        if (self.hwdb) |*h| h.deinit();
    }

    /// Process every device currently present in sysfs (synthesizing ACTION=add),
    /// populating the udev db and /dev. `sys_root` overrides the sysfs root for
    /// tests (null = real /sys). Best-effort per device.
    pub fn coldplug(self: *Daemon, sys_root: ?[]const u8) !void {
        var ctx = Context.init(self.gpa, self.io);
        defer ctx.deinit();
        var en = Enumerate.init(&ctx);
        defer en.deinit();
        if (sys_root) |r| try en.setSysRoot(r);
        try en.scanDevices();
        var it = en.devices();
        while (it.next()) |syspath| {
            var dev = Device.fromSyspath(&ctx, syspath) catch continue;
            defer dev.deinit();
            if (dev.props.get("ACTION") == null) {
                const a = dev.arena.allocator();
                const k = a.dupe(u8, "ACTION") catch continue;
                const v = a.dupe(u8, "add") catch continue;
                dev.props.put(a, k, v) catch continue;
            }
            self.processDevice(&dev) catch continue;
        }
    }

    pub fn processDevice(self: *Daemon, dev: *Device) !void {
        var exec = ExecRunner{
            .gpa = self.gpa,
            .io = self.io,
            .hwdb = if (self.hwdb) |*h| h else null,
            .helper_dirs = self.opts.helper_dirs,
            .program_timeout_ms = self.opts.program_timeout_ms,
        };
        var state = try self.ruleset.apply(self.gpa, dev, exec.runner());
        defer state.deinit();

        const id = try udev_db.deviceId(self.gpa, dev);
        defer self.gpa.free(id);

        const action = actionFromDevice(dev);
        switch (action) {
            .add, .change => {
                try udev_db.write(self.gpa, self.io, self.opts.run_root, dev, &state, nowUsec());
                try node_actuator.apply(self.io, self.gpa, dev, &state, action, .{ .dev_root = self.opts.dev_root });
                if (try node_actuator.resolveNode(dev)) |node| {
                    for (state.symlinks.items) |sym| {
                        link_db.claim(self.io, self.gpa, self.opts.run_root, sym, id, state.options.link_priority, node.devname) catch {};
                        if (link_db.resolveOwner(self.gpa, self.io, self.opts.run_root, sym) catch null) |winner| {
                            defer self.gpa.free(winner);
                            node_actuator.applySymlinks(self.io, self.gpa, self.opts.dev_root, winner, &.{sym}, true) catch {};
                        }
                    }
                }
                if (state.options.watch == true) {
                    if (self.watcher) |wch| {
                        if (try node_actuator.resolveNode(dev)) |node| {
                            var pbuf: [std.fs.max_path_bytes]u8 = undefined;
                            // A bufPrint failure only skips the watch. It must not abort processDevice
                            // (that would drop the db write's broadcast below).
                            if (std.fmt.bufPrint(&pbuf, "{s}/{s}", .{ self.opts.dev_root, node.devname })) |nodepath| {
                                wch.addWatch(self.gpa, nodepath, dev.syspath()) catch {};
                            } else |_| {}
                        }
                    }
                }
            },
            .remove => {
                // Read the previously stored record to recover symlinks we must clean up.
                if (udev_db.read(self.gpa, self.io, self.opts.run_root, id)) |rec| {
                    var old_rec = rec;
                    defer old_rec.deinit();
                    for (old_rec.symlinks) |sym| {
                        state.addSymlink(sym) catch {};
                    }
                } else |_| {}
                try node_actuator.apply(self.io, self.gpa, dev, &state, .remove, .{ .dev_root = self.opts.dev_root });
                udev_db.remove(self.io, self.gpa, self.opts.run_root, id) catch {};
                if (try node_actuator.resolveNode(dev)) |node| {
                    _ = node;
                    for (state.symlinks.items) |sym| {
                        link_db.release(self.io, self.gpa, self.opts.run_root, sym, id);
                        if (link_db.resolveOwner(self.gpa, self.io, self.opts.run_root, sym) catch null) |winner| {
                            defer self.gpa.free(winner);
                            node_actuator.applySymlinks(self.io, self.gpa, self.opts.dev_root, winner, &.{sym}, true) catch {};
                        }
                        // else: no remaining claimant. node_actuator.apply(.remove) already deleted the symlink.
                    }
                }
                if (self.watcher) |wch| wch.removeBySyspath(self.gpa, dev.syspath());
            },
            .other => {
                try udev_db.write(self.gpa, self.io, self.opts.run_root, dev, &state, nowUsec());
            },
        }
        if (self.broadcaster) |b| {
            const sub = dev.getProperty("SUBSYSTEM") orelse "";
            const dt = dev.getProperty("DEVTYPE");
            const msg = netlink_broadcast.serializeUdevMessage(self.gpa, &state, sub, dt) catch return;
            defer self.gpa.free(msg);
            b.send(msg) catch {};
        }
    }

    /// Drain inotify watch events and re-process each affected device as a "change".
    pub fn handleWatchEvents(self: *Daemon) !void {
        const wch = self.watcher orelse return;
        const syspaths = try wch.readEvents(self.gpa);
        defer {
            for (syspaths) |s| self.gpa.free(s);
            self.gpa.free(syspaths);
        }
        var ctx = Context.init(self.gpa, self.io);
        defer ctx.deinit();
        for (syspaths) |syspath| {
            var dev = Device.fromSyspath(&ctx, syspath) catch continue;
            defer dev.deinit();
            const a = dev.arena.allocator();
            const k = a.dupe(u8, "ACTION") catch continue;
            const v = a.dupe(u8, "change") catch continue;
            dev.props.put(a, k, v) catch continue;
            self.processDevice(&dev) catch continue;
        }
    }
};

fn actionFromDevice(dev: *Device) node_actuator.Action {
    const a = dev.getProperty("ACTION") orelse "";
    if (std.mem.eql(u8, a, "add")) return .add;
    if (std.mem.eql(u8, a, "change")) return .change;
    if (std.mem.eql(u8, a, "remove")) return .remove;
    return .other;
}

fn nowUsec() ?u64 {
    var ts: std.os.linux.timespec = undefined;
    const rc = std.os.linux.clock_gettime(.REALTIME, &ts);
    if (std.os.linux.errno(rc) != .SUCCESS) return null;
    if (ts.sec < 0) return null;
    const usec = @as(u64, @intCast(ts.sec)) * 1_000_000 +
        @as(u64, @intCast(@divTrunc(ts.nsec, 1000)));
    return usec;
}

// Tests

test "processDevice add e2e" {
    const uevent = @import("../uevent.zig");
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const rp = rp_buf[0..n];

    const text = "SUBSYSTEM==\"block\", ACTION==\"add\", SYMLINK+=\"by-sub/blk\"";
    const ruleset = try rules.RuleSet.parse(gpa, text);

    const buf = "add@/devices/x/sda\x00ACTION=add\x00SUBSYSTEM=block\x00DEVNAME=sda\x00MAJOR=8\x00MINOR=0\x00";
    const parsed = try uevent.parseKernel(buf);
    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var daemon = Daemon.initWithRuleSet(gpa, io, ruleset, .{ .run_root = rp, .dev_root = rp });
    defer daemon.deinit();

    try daemon.processDevice(&dev);

    var rec = try udev_db.read(gpa, io, rp, "b8:0");
    defer rec.deinit();

    const linkpath = try std.fmt.allocPrint(gpa, "{s}/by-sub/blk", .{rp});
    defer gpa.free(linkpath);

    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const ln = try std.Io.Dir.cwd().readLink(io, linkpath, &link_buf);
    try std.testing.expectEqualStrings("../sda", link_buf[0..ln]);
}

test "processDevice remove e2e" {
    const uevent = @import("../uevent.zig");
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const rp = rp_buf[0..n];

    const text = "SUBSYSTEM==\"block\", ACTION==\"add\", SYMLINK+=\"by-sub/blk\"";
    const ruleset = try rules.RuleSet.parse(gpa, text);

    const buf_add = "add@/devices/x/sda\x00ACTION=add\x00SUBSYSTEM=block\x00DEVNAME=sda\x00MAJOR=8\x00MINOR=0\x00";
    const parsed_add = try uevent.parseKernel(buf_add);
    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();
    var dev_add = try Device.fromProps(&ctx, parsed_add.devpath.?, parsed_add.props);
    defer dev_add.deinit();

    var daemon = Daemon.initWithRuleSet(gpa, io, ruleset, .{ .run_root = rp, .dev_root = rp });
    defer daemon.deinit();

    try daemon.processDevice(&dev_add);

    const buf_remove = "remove@/devices/x/sda\x00ACTION=remove\x00SUBSYSTEM=block\x00DEVNAME=sda\x00MAJOR=8\x00MINOR=0\x00";
    const parsed_remove = try uevent.parseKernel(buf_remove);
    var dev_remove = try Device.fromProps(&ctx, parsed_remove.devpath.?, parsed_remove.props);
    defer dev_remove.deinit();

    try daemon.processDevice(&dev_remove);

    try std.testing.expectError(error.FileNotFound, udev_db.read(gpa, io, rp, "b8:0"));

    const linkpath = try std.fmt.allocPrint(gpa, "{s}/by-sub/blk", .{rp});
    defer gpa.free(linkpath);

    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().readLink(io, linkpath, &link_buf));
}

test "processDevice with broadcaster still persists" {
    const uevent = @import("../uevent.zig");
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const rp = rp_buf[0..n];

    const text = "SUBSYSTEM==\"block\", ACTION==\"add\", SYMLINK+=\"by-sub/blk\"";
    const ruleset = try rules.RuleSet.parse(gpa, text);

    const buf = "add@/devices/x/sda\x00ACTION=add\x00SUBSYSTEM=block\x00DEVNAME=sda\x00MAJOR=8\x00MINOR=0\x00";
    const parsed = try uevent.parseKernel(buf);
    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var daemon = Daemon.initWithRuleSet(gpa, io, ruleset, .{ .run_root = rp, .dev_root = rp });
    defer daemon.deinit();

    var b = netlink_broadcast.Broadcaster.init() catch |e| switch (e) {
        error.PermissionDenied => return,
        else => return e,
    };
    defer b.deinit();
    daemon.broadcaster = &b;
    try daemon.processDevice(&dev);
    var rec = try udev_db.read(gpa, io, rp, "b8:0");
    defer rec.deinit();
}

test "coldplug writes db records for enumerated block devices" {
    const testfs = @import("../testfs.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    // fake sysfs with two block devices
    var sys_tmp = std.testing.tmpDir(.{});
    defer sys_tmp.cleanup();

    try testfs.makeClassDevice(&sys_tmp, .{
        .subsystem = "block",
        .name = "sda",
        .uevent = "MAJOR=8\nMINOR=0\n",
    });
    try testfs.makeClassDevice(&sys_tmp, .{
        .subsystem = "block",
        .name = "sdb",
        .uevent = "MAJOR=8\nMINOR=16\n",
    });

    // derive sys_root realpath from sda device dir
    var sda_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sda_n = try sys_tmp.dir.realPathFile(io, "devices/sda", &sda_buf);
    const sda_abs = sda_buf[0..sda_n];
    const devices_dir = std.fs.path.dirname(sda_abs).?;
    const sys_root = std.fs.path.dirname(devices_dir).?;

    // separate run_root and dev_root so coldplug does not write into the fake sysfs
    var run_tmp = std.testing.tmpDir(.{});
    defer run_tmp.cleanup();

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const rp_n = try run_tmp.dir.realPathFile(io, ".", &rp_buf);
    const rp = rp_buf[0..rp_n];

    const text = "SUBSYSTEM==\"block\", SYMLINK+=\"by-sub/blk-%n\"";
    const ruleset = try rules.RuleSet.parse(gpa, text);

    var daemon = Daemon.initWithRuleSet(gpa, io, ruleset, .{ .run_root = rp, .dev_root = rp });
    defer daemon.deinit();

    try daemon.coldplug(sys_root);

    // assert that a db record was written for sda (deviceId "b8:0")
    var rec = try udev_db.read(gpa, io, rp, "b8:0");
    defer rec.deinit();
}

test "processDevice link_db single claimant symlink regression" {
    const uevent = @import("../uevent.zig");
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const rp = rp_buf[0..n];

    const text = "SUBSYSTEM==\"block\", ACTION==\"add\", SYMLINK+=\"by-sub/blk\"";
    const ruleset = try rules.RuleSet.parse(gpa, text);

    const buf = "add@/devices/x/sda\x00ACTION=add\x00SUBSYSTEM=block\x00DEVNAME=sda\x00MAJOR=8\x00MINOR=0\x00";
    const parsed = try uevent.parseKernel(buf);
    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var daemon = Daemon.initWithRuleSet(gpa, io, ruleset, .{ .run_root = rp, .dev_root = rp });
    defer daemon.deinit();

    try daemon.processDevice(&dev);

    const linkpath = try std.fmt.allocPrint(gpa, "{s}/by-sub/blk", .{rp});
    defer gpa.free(linkpath);

    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const ln = try std.Io.Dir.cwd().readLink(io, linkpath, &link_buf);
    // Single claimant: symlink target must end with the device devname "sda".
    try std.testing.expect(std.mem.endsWith(u8, link_buf[0..ln], "sda"));
}

test "udev_db.remove direct" {
    const uevent = @import("../uevent.zig");
    const context = @import("../context.zig");
    const runner_mod = @import("../rules/runner.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const rp = rp_buf[0..n];

    const buf = "add@/devices/x/sda\x00SUBSYSTEM=block\x00MAJOR=8\x00MINOR=0\x00DEVNAME=sda\x00";
    const parsed = try uevent.parseKernel(buf);
    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = runner_mod.EventState.init(gpa);
    defer state.deinit();

    try udev_db.write(gpa, io, rp, &dev, &state, null);

    var rec = try udev_db.read(gpa, io, rp, "b8:0");
    rec.deinit();

    try udev_db.remove(io, gpa, rp, "b8:0");

    try std.testing.expectError(error.FileNotFound, udev_db.read(gpa, io, rp, "b8:0"));
}

test "processDevice registers a watch for OPTIONS watch" {
    const uevent = @import("../uevent.zig");
    const context = @import("../context.zig");
    const watcher_mod = @import("watcher.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const rp = rp_buf[0..n];

    // Pre-create the stand-in device node file (mknod is root-gated, a regular file is enough).
    try tmp.dir.writeFile(io, .{ .sub_path = "sda", .data = "" });

    const text = "SUBSYSTEM==\"block\", ACTION==\"add\", OPTIONS+=\"watch\"";
    const ruleset = try rules.RuleSet.parse(gpa, text);

    const buf = "add@/devices/x/sda\x00ACTION=add\x00SUBSYSTEM=block\x00DEVNAME=sda\x00MAJOR=8\x00MINOR=0\x00";
    const parsed = try uevent.parseKernel(buf);
    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var daemon = Daemon.initWithRuleSet(gpa, io, ruleset, .{ .run_root = rp, .dev_root = rp });
    defer daemon.deinit();

    var w = try watcher_mod.Watcher.init();
    defer w.deinit(gpa);
    daemon.watcher = &w;

    try daemon.processDevice(&dev);

    try std.testing.expect(w.watches.count() >= 1);
}
