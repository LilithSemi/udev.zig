/// Filtered sysfs scan yielding an iterator of syspaths.
///
/// Enumerate owns one ArenaAllocator (child of ctx.gpa) for filter strings and
/// result paths. Call deinit() to release everything in one shot.
const std = @import("std");
const context = @import("context.zig");
const device_mod = @import("device.zig");

pub const Context = context.Context;
pub const Device = device_mod.Device;

const FilterKind = enum {
    match_subsystem,
    nomatch_subsystem,
    match_sysname,
    match_sysattr,
    match_property,
    match_tag,
};

const Filter = struct {
    kind: FilterKind,
    /// For subsystem/sysname/tag filters: the value to match.
    /// For sysattr/property filters: the attribute or property key.
    key: []const u8,
    /// For sysattr/property filters: the expected value. Empty slice otherwise.
    value: []const u8,
};

fn pathLessThan(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.lessThan(u8, a, b);
}

pub const Enumerate = struct {
    ctx: *Context,
    arena: std.heap.ArenaAllocator,
    filters: std.ArrayListUnmanaged(Filter),
    paths: std.ArrayListUnmanaged([]const u8),
    /// Deduplication set keyed by resolved absolute syspath. Cleared at the
    /// start of each scanDevices call; memory lives in the arena until deinit.
    seen: std.StringHashMapUnmanaged(void),
    /// Sysfs root; defaults to "/sys". Override with setSysRoot for tests.
    sys_root: []const u8,

    pub fn init(ctx: *Context) Enumerate {
        return Enumerate{
            .ctx = ctx,
            .arena = std.heap.ArenaAllocator.init(ctx.gpa),
            .filters = .empty,
            .paths = .empty,
            .seen = .empty,
            .sys_root = "/sys",
        };
    }

    pub fn deinit(self: *Enumerate) void {
        self.arena.deinit();
    }

    /// Override the sysfs root. Use in tests to point at a TmpDir.
    /// Dupes `root` into the arena so callers may free their buffer freely.
    pub fn setSysRoot(self: *Enumerate, root: []const u8) !void {
        self.sys_root = try self.arena.allocator().dupe(u8, root);
    }

    // Filter registration

    pub fn addMatchSubsystem(self: *Enumerate, sub: []const u8) !void {
        const alloc = self.arena.allocator();
        try self.filters.append(alloc, .{
            .kind = .match_subsystem,
            .key = try alloc.dupe(u8, sub),
            .value = &.{},
        });
    }

    pub fn addNomatchSubsystem(self: *Enumerate, sub: []const u8) !void {
        const alloc = self.arena.allocator();
        try self.filters.append(alloc, .{
            .kind = .nomatch_subsystem,
            .key = try alloc.dupe(u8, sub),
            .value = &.{},
        });
    }

    pub fn addMatchSysname(self: *Enumerate, name: []const u8) !void {
        const alloc = self.arena.allocator();
        try self.filters.append(alloc, .{
            .kind = .match_sysname,
            .key = try alloc.dupe(u8, name),
            .value = &.{},
        });
    }

    pub fn addMatchSysattr(self: *Enumerate, name: []const u8, value: []const u8) !void {
        const alloc = self.arena.allocator();
        try self.filters.append(alloc, .{
            .kind = .match_sysattr,
            .key = try alloc.dupe(u8, name),
            .value = try alloc.dupe(u8, value),
        });
    }

    pub fn addMatchProperty(self: *Enumerate, key: []const u8, value: []const u8) !void {
        const alloc = self.arena.allocator();
        try self.filters.append(alloc, .{
            .kind = .match_property,
            .key = try alloc.dupe(u8, key),
            .value = try alloc.dupe(u8, value),
        });
    }

    pub fn addMatchTag(self: *Enumerate, tag: []const u8) !void {
        const alloc = self.arena.allocator();
        try self.filters.append(alloc, .{
            .kind = .match_tag,
            .key = try alloc.dupe(u8, tag),
            .value = &.{},
        });
    }

    // Cheap (string-only) filter checks

    /// Returns false if ANY nomatch_subsystem filter matches, or if there are
    /// match_subsystem filters and none of them match `sub`.
    fn checkSubsystem(self: *const Enumerate, sub: []const u8) bool {
        var has_match = false;
        var any_matched = false;
        for (self.filters.items) |f| {
            switch (f.kind) {
                .match_subsystem => {
                    has_match = true;
                    if (std.mem.eql(u8, f.key, sub)) any_matched = true;
                },
                .nomatch_subsystem => {
                    if (std.mem.eql(u8, f.key, sub)) return false;
                },
                else => {},
            }
        }
        if (has_match and !any_matched) return false;
        return true;
    }

    /// Returns false if there are match_sysname filters and none match `name`.
    fn checkSysname(self: *const Enumerate, name: []const u8) bool {
        var has_filter = false;
        for (self.filters.items) |f| {
            if (f.kind == .match_sysname) {
                has_filter = true;
                if (std.mem.eql(u8, f.key, name)) return true;
            }
        }
        return !has_filter;
    }

    fn hasExpensiveFilters(self: *const Enumerate) bool {
        for (self.filters.items) |f| {
            switch (f.kind) {
                .match_sysattr, .match_property, .match_tag => return true,
                else => {},
            }
        }
        return false;
    }

    /// Check all sysattr/property/tag filters against an already-opened Device.
    /// Returns true only if ALL expensive filters pass.
    fn checkExpensive(self: *Enumerate, dev: *Device) !bool {
        for (self.filters.items) |f| {
            switch (f.kind) {
                .match_sysattr => {
                    const val = (try dev.getSysattr(f.key)) orelse return false;
                    if (!std.mem.eql(u8, val, f.value)) return false;
                },
                .match_property => {
                    const val = dev.getProperty(f.key) orelse return false;
                    if (!std.mem.eql(u8, val, f.value)) return false;
                },
                .match_tag => {
                    const tags = dev.getProperty("TAGS") orelse return false;
                    var tag_it = std.mem.splitScalar(u8, tags, ':');
                    var found = false;
                    while (tag_it.next()) |t| {
                        if (std.mem.eql(u8, t, f.key)) {
                            found = true;
                            break;
                        }
                    }
                    if (!found) return false;
                },
                else => {},
            }
        }
        return true;
    }

    // Candidate processing

    /// If no expensive filters exist, store syspath directly. Otherwise build a
    /// temp Device, test expensive filters, deinit the Device, store if matched.
    /// Deduplicates by resolved syspath: each unique path is stored at most once
    /// per scan regardless of how many scan roots resolve to it.
    fn processDevice(self: *Enumerate, syspath: []const u8) !void {
        const alloc = self.arena.allocator();

        // Skip paths already encountered from another scan root.
        if (self.seen.contains(syspath)) return;
        // Dupe once. The owned slice is used as both the seen-set key and
        // the stored path so we never allocate two copies of the same string.
        const owned = try alloc.dupe(u8, syspath);
        try self.seen.put(alloc, owned, {});

        if (!self.hasExpensiveFilters()) {
            try self.paths.append(alloc, owned);
            return;
        }
        var dev = try Device.fromSyspath(self.ctx, syspath);
        defer dev.deinit();
        if (try self.checkExpensive(&dev)) {
            try self.paths.append(alloc, owned);
        }
    }

    // Root scanning

    /// Walk <sys_root>/class: each subdir is a subsystem; its entries are device
    /// symlinks. Applies cheap filters on names, resolves symlinks for syspaths,
    /// then applies expensive filters if needed.
    fn scanClassRoot(self: *Enumerate) !void {
        var class_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const class_path = try std.fmt.bufPrint(&class_path_buf, "{s}/class", .{self.sys_root});

        var class_dir = std.Io.Dir.cwd().openDir(self.ctx.io, class_path, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => return,
            else => return err,
        };
        defer class_dir.close(self.ctx.io);

        var class_it = class_dir.iterateAssumeFirstIteration();
        while (try class_it.next(self.ctx.io)) |sub_entry| {
            const sub_name = sub_entry.name;
            if (!self.checkSubsystem(sub_name)) continue;

            var sub_path_buf: [std.fs.max_path_bytes]u8 = undefined;
            const sub_path = try std.fmt.bufPrint(&sub_path_buf, "{s}/class/{s}", .{ self.sys_root, sub_name });

            var sub_dir = std.Io.Dir.cwd().openDir(self.ctx.io, sub_path, .{ .iterate = true }) catch |err| switch (err) {
                error.FileNotFound, error.NotDir => continue,
                else => return err,
            };
            defer sub_dir.close(self.ctx.io);

            var sub_it = sub_dir.iterateAssumeFirstIteration();
            while (try sub_it.next(self.ctx.io)) |dev_entry| {
                const dev_name = dev_entry.name;
                if (!self.checkSysname(dev_name)) continue;

                var link_path_buf: [std.fs.max_path_bytes]u8 = undefined;
                const link_path = try std.fmt.bufPrint(
                    &link_path_buf,
                    "{s}/class/{s}/{s}",
                    .{ self.sys_root, sub_name, dev_name },
                );

                var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
                const rp_n = std.Io.Dir.cwd().realPathFile(self.ctx.io, link_path, &rp_buf) catch |err| switch (err) {
                    error.FileNotFound => continue,
                    else => return err,
                };
                try self.processDevice(rp_buf[0..rp_n]);
            }
        }
    }

    /// Walk <sys_root>/block: each entry is a device with subsystem "block".
    fn scanBlockRoot(self: *Enumerate) !void {
        if (!self.checkSubsystem("block")) return;

        var block_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const block_path = try std.fmt.bufPrint(&block_path_buf, "{s}/block", .{self.sys_root});

        var block_dir = std.Io.Dir.cwd().openDir(self.ctx.io, block_path, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => return,
            else => return err,
        };
        defer block_dir.close(self.ctx.io);

        var block_it = block_dir.iterateAssumeFirstIteration();
        while (try block_it.next(self.ctx.io)) |dev_entry| {
            const dev_name = dev_entry.name;
            if (!self.checkSysname(dev_name)) continue;

            var link_path_buf: [std.fs.max_path_bytes]u8 = undefined;
            const link_path = try std.fmt.bufPrint(
                &link_path_buf,
                "{s}/block/{s}",
                .{ self.sys_root, dev_name },
            );

            var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
            const rp_n = std.Io.Dir.cwd().realPathFile(self.ctx.io, link_path, &rp_buf) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => return err,
            };
            try self.processDevice(rp_buf[0..rp_n]);
        }
    }

    /// Walk <sys_root>/bus: each subdir is a bus name (subsystem); its `devices/` entries are
    /// device symlinks. Present on virtually all kernels. The subsystem name equals the bus dir
    /// name, so cheap subsystem filters apply directly before any realpath resolution.
    fn scanBusRoot(self: *Enumerate) !void {
        var bus_path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const bus_path = try std.fmt.bufPrint(&bus_path_buf, "{s}/bus", .{self.sys_root});

        var bus_dir = std.Io.Dir.cwd().openDir(self.ctx.io, bus_path, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => return,
            else => return err,
        };
        defer bus_dir.close(self.ctx.io);

        var bus_it = bus_dir.iterateAssumeFirstIteration();
        while (try bus_it.next(self.ctx.io)) |bus_entry| {
            const bus_name = bus_entry.name;
            if (!self.checkSubsystem(bus_name)) continue;

            var dev_dir_buf: [std.fs.max_path_bytes]u8 = undefined;
            const dev_dir_path = try std.fmt.bufPrint(
                &dev_dir_buf,
                "{s}/bus/{s}/devices",
                .{ self.sys_root, bus_name },
            );

            var dev_dir = std.Io.Dir.cwd().openDir(self.ctx.io, dev_dir_path, .{ .iterate = true }) catch |err| switch (err) {
                error.FileNotFound, error.NotDir => continue,
                else => return err,
            };
            defer dev_dir.close(self.ctx.io);

            var dev_it = dev_dir.iterateAssumeFirstIteration();
            while (try dev_it.next(self.ctx.io)) |dev_entry| {
                const dev_name = dev_entry.name;
                if (!self.checkSysname(dev_name)) continue;

                var link_path_buf: [std.fs.max_path_bytes]u8 = undefined;
                const link_path = try std.fmt.bufPrint(
                    &link_path_buf,
                    "{s}/bus/{s}/devices/{s}",
                    .{ self.sys_root, bus_name, dev_name },
                );

                var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
                const rp_n = std.Io.Dir.cwd().realPathFile(self.ctx.io, link_path, &rp_buf) catch |err| switch (err) {
                    error.FileNotFound => continue,
                    else => return err,
                };
                try self.processDevice(rp_buf[0..rp_n]);
            }
        }
    }

    /// Walk <sys_root>/subsystem: the modern merged view of all subsystems when present.
    /// Each subdir is a subsystem; its `devices/` subdir contains symlinks to device dirs.
    /// Preferred over the separate class+bus+block roots when this directory exists.
    /// When absent (common on many kernels), scanDevices falls back to class+bus+block.
    fn scanSubsystemRoot(self: *Enumerate) !void {
        var sub_root_buf: [std.fs.max_path_bytes]u8 = undefined;
        const sub_root_path = try std.fmt.bufPrint(&sub_root_buf, "{s}/subsystem", .{self.sys_root});

        var sub_root_dir = std.Io.Dir.cwd().openDir(self.ctx.io, sub_root_path, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => return,
            else => return err,
        };
        defer sub_root_dir.close(self.ctx.io);

        var sub_root_it = sub_root_dir.iterateAssumeFirstIteration();
        while (try sub_root_it.next(self.ctx.io)) |sub_entry| {
            const sub_name = sub_entry.name;
            if (!self.checkSubsystem(sub_name)) continue;

            var dev_dir_buf: [std.fs.max_path_bytes]u8 = undefined;
            const dev_dir_path = try std.fmt.bufPrint(
                &dev_dir_buf,
                "{s}/subsystem/{s}/devices",
                .{ self.sys_root, sub_name },
            );

            var dev_dir = std.Io.Dir.cwd().openDir(self.ctx.io, dev_dir_path, .{ .iterate = true }) catch |err| switch (err) {
                error.FileNotFound, error.NotDir => continue,
                else => return err,
            };
            defer dev_dir.close(self.ctx.io);

            var dev_it = dev_dir.iterateAssumeFirstIteration();
            while (try dev_it.next(self.ctx.io)) |dev_entry| {
                const dev_name = dev_entry.name;
                if (!self.checkSysname(dev_name)) continue;

                var link_path_buf: [std.fs.max_path_bytes]u8 = undefined;
                const link_path = try std.fmt.bufPrint(
                    &link_path_buf,
                    "{s}/subsystem/{s}/devices/{s}",
                    .{ self.sys_root, sub_name, dev_name },
                );

                var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
                const rp_n = std.Io.Dir.cwd().realPathFile(self.ctx.io, link_path, &rp_buf) catch |err| switch (err) {
                    error.FileNotFound => continue,
                    else => return err,
                };
                try self.processDevice(rp_buf[0..rp_n]);
            }
        }
    }

    // Public scan + iteration

    /// Walk sysfs roots, apply filters, and store matching absolute syspaths
    /// sorted ascending. Safe to call multiple times; the path list is cleared
    /// each call but memory from previous scans is retained in the arena until
    /// deinit (rescan does not reclaim it).
    pub fn scanDevices(self: *Enumerate) !void {
        self.paths.clearRetainingCapacity();
        self.seen.clearRetainingCapacity();

        // /sys/subsystem is the modern merged view when present (preferred).
        // When absent (common on many kernels), fall back to scanning class, bus, and block
        // roots individually. /sys/bus/<name>/devices is the primary bus-device source.
        var sub_root_buf: [std.fs.max_path_bytes]u8 = undefined;
        const sub_root_path = try std.fmt.bufPrint(&sub_root_buf, "{s}/subsystem", .{self.sys_root});
        const has_subsystem_root = blk: {
            std.Io.Dir.cwd().access(self.ctx.io, sub_root_path, .{}) catch break :blk false;
            break :blk true;
        };

        if (has_subsystem_root) {
            try self.scanSubsystemRoot();
        } else {
            try self.scanClassRoot();
            try self.scanBusRoot();
            try self.scanBlockRoot();
        }
        std.mem.sort([]const u8, self.paths.items, {}, pathLessThan);
    }

    /// Iterator over the sorted syspaths from the last scanDevices call.
    /// The iterator is invalidated by a subsequent scanDevices() (it reads the shared
    /// backing buffer).
    pub const Iterator = struct {
        items: []const []const u8,
        index: usize,

        pub fn next(self: *Iterator) ?[]const u8 {
            if (self.index >= self.items.len) return null;
            const item = self.items[self.index];
            self.index += 1;
            return item;
        }
    };

    /// Return an iterator over the syspaths collected by scanDevices. The caller
    /// may build a Device from each path via Device.fromSyspath.
    /// The iterator is invalidated by a subsequent scanDevices() (it reads the shared backing buffer).
    pub fn devices(self: *Enumerate) Iterator {
        return .{ .items = self.paths.items, .index = 0 };
    }
};

// Tests

test "Enumerate subsystem filter returns sorted matching paths" {
    const testfs = @import("testfs.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.testing.io;
    const gpa = std.testing.allocator;

    try testfs.makeClassDevice(&tmp, .{
        .subsystem = "input",
        .name = "event0",
        .uevent = "MAJOR=13\nMINOR=64\n",
    });
    try testfs.makeClassDevice(&tmp, .{
        .subsystem = "input",
        .name = "event1",
        .uevent = "MAJOR=13\nMINOR=65\n",
    });
    try testfs.makeClassDevice(&tmp, .{
        .subsystem = "drm",
        .name = "card0",
        .uevent = "MAJOR=226\nMINOR=0\n",
    });

    // Resolve expected syspaths and derive the tmp root from one of them.
    var ep0_buf: [std.fs.max_path_bytes]u8 = undefined;
    const ep0_n = try tmp.dir.realPathFile(io, "devices/event0", &ep0_buf);
    const event0_abs: []const u8 = ep0_buf[0..ep0_n];
    const devices_dir = std.fs.path.dirname(event0_abs).?;
    const tmp_abs = std.fs.path.dirname(devices_dir).?;

    var ep1_buf: [std.fs.max_path_bytes]u8 = undefined;
    const ep1_n = try tmp.dir.realPathFile(io, "devices/event1", &ep1_buf);
    const event1_abs: []const u8 = ep1_buf[0..ep1_n];

    var ctx = Context.init(gpa, io);
    defer ctx.deinit();

    var en = Enumerate.init(&ctx);
    defer en.deinit();

    try en.setSysRoot(tmp_abs);
    try en.addMatchSubsystem("input");
    try en.scanDevices();

    var it = en.devices();
    const first = it.next() orelse return error.ExpectedFirstDevice;
    const second = it.next() orelse return error.ExpectedSecondDevice;
    try std.testing.expect(it.next() == null);

    try std.testing.expectEqualStrings(event0_abs, first);
    try std.testing.expectEqualStrings(event1_abs, second);
}

test "Enumerate sysattr filter returns only matching device" {
    const testfs = @import("testfs.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.testing.io;
    const gpa = std.testing.allocator;

    try testfs.makeClassDevice(&tmp, .{
        .subsystem = "input",
        .name = "event0",
        .uevent = "MAJOR=13\nMINOR=64\n",
        .attrs = &.{.{ "name", "Keyboard" }},
    });
    try testfs.makeClassDevice(&tmp, .{
        .subsystem = "input",
        .name = "event1",
        .uevent = "MAJOR=13\nMINOR=65\n",
        .attrs = &.{.{ "name", "Mouse" }},
    });

    var ep0_buf: [std.fs.max_path_bytes]u8 = undefined;
    const ep0_n = try tmp.dir.realPathFile(io, "devices/event0", &ep0_buf);
    const event0_abs: []const u8 = ep0_buf[0..ep0_n];
    const devices_dir = std.fs.path.dirname(event0_abs).?;
    const tmp_abs = std.fs.path.dirname(devices_dir).?;

    var ctx = Context.init(gpa, io);
    defer ctx.deinit();

    var en = Enumerate.init(&ctx);
    defer en.deinit();

    try en.setSysRoot(tmp_abs);
    try en.addMatchSubsystem("input");
    try en.addMatchSysattr("name", "Keyboard");
    try en.scanDevices();

    var it = en.devices();
    const first = it.next() orelse return error.ExpectedDevice;
    try std.testing.expect(it.next() == null);
    try std.testing.expectEqualStrings(event0_abs, first);
}

test "Enumerate property filter returns only matching device" {
    const testfs = @import("testfs.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.testing.io;
    const gpa = std.testing.allocator;

    try testfs.makeClassDevice(&tmp, .{
        .subsystem = "input",
        .name = "event0",
        .uevent = "MAJOR=13\nMINOR=64\nDEVTYPE=keyboard\n",
    });
    try testfs.makeClassDevice(&tmp, .{
        .subsystem = "input",
        .name = "event1",
        .uevent = "MAJOR=13\nMINOR=65\nDEVTYPE=mouse\n",
    });

    var ep0_buf: [std.fs.max_path_bytes]u8 = undefined;
    const ep0_n = try tmp.dir.realPathFile(io, "devices/event0", &ep0_buf);
    const event0_abs: []const u8 = ep0_buf[0..ep0_n];
    const devices_dir = std.fs.path.dirname(event0_abs).?;
    const tmp_abs = std.fs.path.dirname(devices_dir).?;

    var ctx = Context.init(gpa, io);
    defer ctx.deinit();

    var en = Enumerate.init(&ctx);
    defer en.deinit();

    try en.setSysRoot(tmp_abs);
    try en.addMatchProperty("DEVTYPE", "keyboard");
    try en.scanDevices();

    var it = en.devices();
    const first = it.next() orelse return error.ExpectedDevice;
    try std.testing.expect(it.next() == null);
    try std.testing.expectEqualStrings(event0_abs, first);
}

test "Enumerate addNomatchSubsystem excludes matching subsystem" {
    const testfs = @import("testfs.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.testing.io;
    const gpa = std.testing.allocator;

    try testfs.makeClassDevice(&tmp, .{
        .subsystem = "input",
        .name = "event0",
        .uevent = "MAJOR=13\nMINOR=64\n",
    });
    try testfs.makeClassDevice(&tmp, .{
        .subsystem = "drm",
        .name = "card0",
        .uevent = "MAJOR=226\nMINOR=0\n",
    });

    var card0_buf: [std.fs.max_path_bytes]u8 = undefined;
    const card0_n = try tmp.dir.realPathFile(io, "devices/card0", &card0_buf);
    const card0_abs: []const u8 = card0_buf[0..card0_n];
    const devices_dir = std.fs.path.dirname(card0_abs).?;
    const tmp_abs = std.fs.path.dirname(devices_dir).?;

    var ctx = Context.init(gpa, io);
    defer ctx.deinit();

    var en = Enumerate.init(&ctx);
    defer en.deinit();

    try en.setSysRoot(tmp_abs);
    try en.addNomatchSubsystem("input");
    try en.scanDevices();

    var it = en.devices();
    const first = it.next() orelse return error.ExpectedDevice;
    try std.testing.expect(it.next() == null);
    try std.testing.expectEqualStrings(card0_abs, first);
}

test "Enumerate addMatchTag returns only tagged device" {
    const testfs = @import("testfs.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.testing.io;
    const gpa = std.testing.allocator;

    try testfs.makeClassDevice(&tmp, .{
        .subsystem = "input",
        .name = "event0",
        .uevent = "MAJOR=13\nMINOR=64\nTAGS=:seat:uaccess:\n",
    });
    try testfs.makeClassDevice(&tmp, .{
        .subsystem = "input",
        .name = "event1",
        .uevent = "MAJOR=13\nMINOR=65\n",
    });

    var ep0_buf: [std.fs.max_path_bytes]u8 = undefined;
    const ep0_n = try tmp.dir.realPathFile(io, "devices/event0", &ep0_buf);
    const event0_abs: []const u8 = ep0_buf[0..ep0_n];
    const devices_dir = std.fs.path.dirname(event0_abs).?;
    const tmp_abs = std.fs.path.dirname(devices_dir).?;

    var ctx = Context.init(gpa, io);
    defer ctx.deinit();

    var en = Enumerate.init(&ctx);
    defer en.deinit();

    try en.setSysRoot(tmp_abs);
    try en.addMatchTag("seat");
    try en.scanDevices();

    var it = en.devices();
    const first = it.next() orelse return error.ExpectedDevice;
    try std.testing.expect(it.next() == null);
    try std.testing.expectEqualStrings(event0_abs, first);
}

test "Enumerate prefers subsystem root and finds device via scanSubsystemRoot" {
    const testfs = @import("testfs.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.testing.io;
    const gpa = std.testing.allocator;

    try testfs.makeSubsystemDevice(&tmp, .{
        .subsystem = "input",
        .name = "event0",
        .uevent = "MAJOR=13\nMINOR=64\n",
    });

    var ep0_buf: [std.fs.max_path_bytes]u8 = undefined;
    const ep0_n = try tmp.dir.realPathFile(io, "devices/event0", &ep0_buf);
    const event0_abs: []const u8 = ep0_buf[0..ep0_n];
    const devices_dir = std.fs.path.dirname(event0_abs).?;
    const tmp_abs = std.fs.path.dirname(devices_dir).?;

    var ctx = Context.init(gpa, io);
    defer ctx.deinit();

    var en = Enumerate.init(&ctx);
    defer en.deinit();

    try en.setSysRoot(tmp_abs);
    try en.scanDevices();

    var it = en.devices();
    const first = it.next() orelse return error.ExpectedDevice;
    try std.testing.expect(it.next() == null);
    try std.testing.expectEqualStrings(event0_abs, first);
}

test "Enumerate scanBusRoot finds USB device via bus tree" {
    const testfs = @import("testfs.zig");
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const io = std.testing.io;
    const gpa = std.testing.allocator;

    try testfs.makeBusDevice(&tmp, .{
        .subsystem = "usb",
        .name = "1-1",
        .uevent = "MAJOR=189\nMINOR=1\n",
    });

    var dev_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dev_n = try tmp.dir.realPathFile(io, "devices/1-1", &dev_buf);
    const dev_abs: []const u8 = dev_buf[0..dev_n];
    const devices_dir = std.fs.path.dirname(dev_abs).?;
    const tmp_abs = std.fs.path.dirname(devices_dir).?;

    var ctx = Context.init(gpa, io);
    defer ctx.deinit();

    var en = Enumerate.init(&ctx);
    defer en.deinit();

    try en.setSysRoot(tmp_abs);
    try en.addMatchSubsystem("usb");
    try en.scanDevices();

    var it = en.devices();
    const first = it.next() orelse return error.ExpectedDevice;
    try std.testing.expect(it.next() == null);
    try std.testing.expectEqualStrings(dev_abs, first);
}
