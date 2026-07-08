const std = @import("std");
const Device = @import("device.zig").Device;
const uevent = @import("uevent.zig");
const context = @import("context.zig");
const EventState = @import("rules/runner.zig").EventState;

/// Return the udev database id for the given device.
/// Caller owns the returned slice (free with gpa.free).
pub fn deviceId(gpa: std.mem.Allocator, dev: *Device) ![]u8 {
    const maj = dev.getProperty("MAJOR");
    const min = dev.getProperty("MINOR");
    if (maj != null and min != null) {
        const sub = (try dev.subsystem()) orelse "";
        const prefix: []const u8 = if (std.mem.eql(u8, sub, "block")) "b" else "c";
        return std.fmt.allocPrint(gpa, "{s}{s}:{s}", .{ prefix, maj.?, min.? });
    } else {
        return std.fmt.allocPrint(gpa, "+{s}:{s}", .{ (try dev.subsystem()) orelse "", dev.sysname() });
    }
}

pub const KeyVal = struct { key: []const u8, val: []const u8 };

pub const Record = struct {
    arena: std.heap.ArenaAllocator,
    properties: []const KeyVal,
    symlinks: []const []const u8,
    tags: []const []const u8, // from G: (persistent)
    current_tags: []const []const u8, // from Q: (current)
    init_usec: ?u64,
    version: ?u8,

    pub fn get(self: *const Record, key: []const u8) ?[]const u8 {
        for (self.properties) |kv| {
            if (std.mem.eql(u8, kv.key, key)) return kv.val;
        }
        return null;
    }

    pub fn deinit(self: *Record) void {
        self.arena.deinit();
    }
};

/// Read a udev database record from <run_root>/data/<id>.
/// The returned Record owns all strings via its arena allocator.
/// Caller must call rec.deinit() when done.
pub fn read(gpa: std.mem.Allocator, io: std.Io, run_root: []const u8, id: []const u8) !Record {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const aa = arena.allocator();

    const path = try std.fmt.allocPrint(aa, "{s}/data/{s}", .{ run_root, id });
    const content = try std.Io.Dir.cwd().readFileAlloc(io, path, aa, .limited(4 << 20));

    var props: std.ArrayListUnmanaged(KeyVal) = .empty;
    var syms: std.ArrayListUnmanaged([]const u8) = .empty;
    var tags: std.ArrayListUnmanaged([]const u8) = .empty;
    var current_tags: std.ArrayListUnmanaged([]const u8) = .empty;
    var init_usec: ?u64 = null;
    var version: ?u8 = null;

    var lines = std.mem.tokenizeScalar(u8, content, '\n');
    while (lines.next()) |line| {
        if (line.len < 2) continue;
        const prefix = line[0..2];
        const rest = line[2..];
        if (std.mem.eql(u8, prefix, "E:")) {
            const eq = std.mem.indexOfScalar(u8, rest, '=') orelse continue;
            try props.append(aa, .{
                .key = try aa.dupe(u8, rest[0..eq]),
                .val = try aa.dupe(u8, rest[eq + 1 ..]),
            });
        } else if (std.mem.eql(u8, prefix, "S:")) {
            try syms.append(aa, try aa.dupe(u8, rest));
        } else if (std.mem.eql(u8, prefix, "G:")) {
            try tags.append(aa, try aa.dupe(u8, rest));
        } else if (std.mem.eql(u8, prefix, "Q:")) {
            try current_tags.append(aa, try aa.dupe(u8, rest));
        } else if (std.mem.eql(u8, prefix, "I:")) {
            init_usec = std.fmt.parseInt(u64, std.mem.trim(u8, rest, " \t\r"), 10) catch null;
        } else if (std.mem.eql(u8, prefix, "V:")) {
            version = std.fmt.parseInt(u8, std.mem.trim(u8, rest, " \t\r"), 10) catch null;
        }
    }

    return Record{
        .arena = arena,
        .properties = try props.toOwnedSlice(aa),
        .symlinks = try syms.toOwnedSlice(aa),
        .tags = try tags.toOwnedSlice(aa),
        .current_tags = try current_tags.toOwnedSlice(aa),
        .init_usec = init_usec,
        .version = version,
    };
}

/// Write a udev database record to <run_root>/data/<id> atomically,
/// and stamp tag marker files under <run_root>/tags/<tag>/<id>.
/// Only udev-added or udev-changed properties are written (E: lines).
/// Properties identical to what the kernel already reported via the device
/// are skipped. Caller provides gpa for scratch allocations.
pub fn write(
    gpa: std.mem.Allocator,
    io: std.Io,
    run_root: []const u8,
    dev: *Device,
    state: *const EventState,
    init_usec: ?u64,
) !void {
    const id = try deviceId(gpa, dev);
    defer gpa.free(id);

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(gpa);

    try buf.appendSlice(gpa, "V:1\n");

    if (init_usec) |u| {
        const line = try std.fmt.allocPrint(gpa, "I:{d}\n", .{u});
        defer gpa.free(line);
        try buf.appendSlice(gpa, line);
    }

    var prop_it = state.properties.iterator();
    while (prop_it.next()) |e| {
        const key = e.key_ptr.*;
        const val = e.value_ptr.*;
        const dev_val = dev.getProperty(key);
        // Emit only udev-added/changed props. Skip any key/value containing a newline: the db is a
        // line-based format and an embedded '\n' would corrupt the record (kernel/udev values never
        // contain newlines in practice).
        if (std.mem.indexOfScalar(u8, key, '\n') != null or std.mem.indexOfScalar(u8, val, '\n') != null) continue;
        if (dev_val == null or !std.mem.eql(u8, dev_val.?, val)) {
            const line = try std.fmt.allocPrint(gpa, "E:{s}={s}\n", .{ key, val });
            defer gpa.free(line);
            try buf.appendSlice(gpa, line);
        }
    }

    for (state.symlinks.items) |sym| {
        const line = try std.fmt.allocPrint(gpa, "S:{s}\n", .{sym});
        defer gpa.free(line);
        try buf.appendSlice(gpa, line);
    }

    var tag_it = state.tags.keyIterator();
    while (tag_it.next()) |tag_ptr| {
        const tag = tag_ptr.*;
        const gline = try std.fmt.allocPrint(gpa, "G:{s}\n", .{tag});
        defer gpa.free(gline);
        try buf.appendSlice(gpa, gline);
        const qline = try std.fmt.allocPrint(gpa, "Q:{s}\n", .{tag});
        defer gpa.free(qline);
        try buf.appendSlice(gpa, qline);
    }

    const data_dir = try std.fmt.allocPrint(gpa, "{s}/data", .{run_root});
    defer gpa.free(data_dir);
    std.Io.Dir.cwd().createDirPath(io, data_dir) catch {};

    const final = try std.fmt.allocPrint(gpa, "{s}/data/{s}", .{ run_root, id });
    defer gpa.free(final);
    const tmp_path = try std.fmt.allocPrint(gpa, "{s}.tmp", .{final});
    defer gpa.free(tmp_path);

    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = tmp_path, .data = buf.items });
    try std.Io.Dir.renameAbsolute(tmp_path, final, io);

    var tags_it = state.tags.keyIterator();
    while (tags_it.next()) |tag_ptr| {
        const tag = tag_ptr.*;
        const tdir = try std.fmt.allocPrint(gpa, "{s}/tags/{s}", .{ run_root, tag });
        defer gpa.free(tdir);
        std.Io.Dir.cwd().createDirPath(io, tdir) catch {};
        const tmark = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ tdir, id });
        defer gpa.free(tmark);
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = tmark, .data = "" });
    }
}

/// Remove a device's db record and clean up tag marker files under <run_root>/tags/<tag>/<id>.
pub fn remove(io: std.Io, gpa: std.mem.Allocator, run_root: []const u8, id: []const u8) !void {
    // Best-effort tag-marker cleanup: read the record to learn its tags, unlink each marker.
    if (read(gpa, io, run_root, id)) |rec_val| {
        var rec = rec_val;
        defer rec.deinit();
        var mbuf: [std.fs.max_path_bytes]u8 = undefined;
        // Delete markers for both persistent (G:) and current (Q:) tags.
        for (rec.tags) |tag| {
            const m = std.fmt.bufPrint(&mbuf, "{s}/tags/{s}/{s}", .{ run_root, tag, id }) catch continue;
            std.Io.Dir.cwd().deleteFile(io, m) catch {};
        }
        for (rec.current_tags) |tag| {
            const m = std.fmt.bufPrint(&mbuf, "{s}/tags/{s}/{s}", .{ run_root, tag, id }) catch continue;
            std.Io.Dir.cwd().deleteFile(io, m) catch {};
        }
    } else |_| {}
    const path = try std.fmt.allocPrint(gpa, "{s}/data/{s}", .{ run_root, id });
    defer gpa.free(path);
    std.Io.Dir.cwd().deleteFile(io, path) catch {};
}

// Tests

test "deviceId block device" {
    const Context = context.Context;
    var ctx = Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const buf = "add@/devices/x/sda\x00" ++
        "SUBSYSTEM=block\x00MAJOR=259\x00MINOR=0\x00DEVNAME=sda\x00";
    const parsed = try uevent.parseKernel(buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    const id = try deviceId(std.testing.allocator, &dev);
    defer std.testing.allocator.free(id);
    try std.testing.expectEqualStrings("b259:0", id);
}

test "deviceId char device" {
    const Context = context.Context;
    var ctx = Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const buf = "add@/devices/x/event0\x00" ++
        "SUBSYSTEM=input\x00MAJOR=13\x00MINOR=64\x00";
    const parsed = try uevent.parseKernel(buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    const id = try deviceId(std.testing.allocator, &dev);
    defer std.testing.allocator.free(id);
    try std.testing.expectEqualStrings("c13:64", id);
}

test "deviceId nodeless device" {
    const Context = context.Context;
    var ctx = Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const buf = "add@/devices/x/ACPI0007:00\x00" ++
        "SUBSYSTEM=acpi\x00";
    const parsed = try uevent.parseKernel(buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    const id = try deviceId(std.testing.allocator, &dev);
    defer std.testing.allocator.free(id);
    try std.testing.expectEqualStrings("+acpi:ACPI0007:00", id);
}

test "read round-trip" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.createDirPath(io, "data");
    const data = "V:1\nI:12345\nE:ID_FS_TYPE=ext4\nS:disk/by-uuid/x\nG:systemd\nQ:seat\n";
    try tmp.dir.writeFile(io, .{ .sub_path = "data/b1:2", .data = data });

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const run_root = rp_buf[0..n];

    var rec = try read(gpa, io, run_root, "b1:2");
    defer rec.deinit();

    try std.testing.expectEqual(@as(?u8, 1), rec.version);
    try std.testing.expectEqual(@as(?u64, 12345), rec.init_usec);
    try std.testing.expectEqualStrings("ext4", rec.get("ID_FS_TYPE").?);

    var found_sym = false;
    for (rec.symlinks) |s| {
        if (std.mem.eql(u8, s, "disk/by-uuid/x")) {
            found_sym = true;
            break;
        }
    }
    try std.testing.expect(found_sym);

    var found_tag = false;
    for (rec.tags) |t| {
        if (std.mem.eql(u8, t, "systemd")) {
            found_tag = true;
            break;
        }
    }
    try std.testing.expect(found_tag);

    var found_ctag = false;
    for (rec.current_tags) |t| {
        if (std.mem.eql(u8, t, "seat")) {
            found_ctag = true;
            break;
        }
    }
    try std.testing.expect(found_ctag);
}

test "write round-trip with added-only E: selection" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    const Context = context.Context;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const buf_uevent = "add@/devices/x/sda\x00" ++
        "SUBSYSTEM=block\x00MAJOR=1\x00MINOR=2\x00DEVNAME=sda\x00FOO=kernelval\x00";
    const parsed = try uevent.parseKernel(buf_uevent);

    var ctx = Context.init(gpa, io);
    defer ctx.deinit();

    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try state.setProperty("FOO", "kernelval");
    try state.setProperty("ID_FS_TYPE", "ext4");
    try state.addSymlink("disk/by-uuid/x");
    try state.addTag("systemd");

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const run_root = rp_buf[0..n];

    try write(gpa, io, run_root, &dev, &state, 999);

    var rec = try read(gpa, io, run_root, "b1:2");
    defer rec.deinit();

    try std.testing.expectEqualStrings("ext4", rec.get("ID_FS_TYPE").?);
    try std.testing.expect(rec.get("FOO") == null);

    var found_sym = false;
    for (rec.symlinks) |s| {
        if (std.mem.eql(u8, s, "disk/by-uuid/x")) {
            found_sym = true;
            break;
        }
    }
    try std.testing.expect(found_sym);

    var found_tag = false;
    for (rec.tags) |t| {
        if (std.mem.eql(u8, t, "systemd")) {
            found_tag = true;
            break;
        }
    }
    try std.testing.expect(found_tag);

    var found_ctag = false;
    for (rec.current_tags) |t| {
        if (std.mem.eql(u8, t, "systemd")) {
            found_ctag = true;
            break;
        }
    }
    try std.testing.expect(found_ctag);

    try std.testing.expectEqual(@as(?u64, 999), rec.init_usec);
    try std.testing.expectEqual(@as(?u8, 1), rec.version);

    const tag_marker = try std.fmt.allocPrint(gpa, "{s}/tags/systemd/b1:2", .{run_root});
    defer gpa.free(tag_marker);
    try std.Io.Dir.cwd().access(io, tag_marker, .{});
}

test "remove cleans tag markers" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    const Context = context.Context;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const buf_uevent = "add@/devices/x/sda\x00" ++
        "SUBSYSTEM=block\x00MAJOR=1\x00MINOR=2\x00DEVNAME=sda\x00";
    const parsed = try uevent.parseKernel(buf_uevent);

    var ctx = Context.init(gpa, io);
    defer ctx.deinit();

    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try state.addTag("systemd");

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const run_root = rp_buf[0..n];

    try write(gpa, io, run_root, &dev, &state, null);

    // Verify the marker exists before remove.
    const tag_marker = try std.fmt.allocPrint(gpa, "{s}/tags/systemd/b1:2", .{run_root});
    defer gpa.free(tag_marker);
    try std.Io.Dir.cwd().access(io, tag_marker, .{});

    // Verify the data file exists before remove.
    const data_file = try std.fmt.allocPrint(gpa, "{s}/data/b1:2", .{run_root});
    defer gpa.free(data_file);
    try std.Io.Dir.cwd().access(io, data_file, .{});

    try remove(io, gpa, run_root, "b1:2");

    // Data file must be gone.
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(io, data_file, .{}));
    // Tag marker must be gone.
    try std.testing.expectError(error.FileNotFound, std.Io.Dir.cwd().access(io, tag_marker, .{}));
}

test "read against real /run/udev/data (skippable)" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;

    std.Io.Dir.cwd().access(io, "/run/udev/data", .{}) catch return;

    var data_dir = std.Io.Dir.cwd().openDir(io, "/run/udev/data", .{ .iterate = true }) catch return;
    defer data_dir.close(io);

    var it = data_dir.iterateAssumeFirstIteration();
    var name_buf: [256]u8 = undefined;
    var name_len: usize = 0;
    while (it.next(io) catch null) |entry| {
        if (entry.name.len > 0 and (entry.name[0] == 'b' or entry.name[0] == 'c')) {
            const copy_len = @min(entry.name.len, name_buf.len);
            @memcpy(name_buf[0..copy_len], entry.name[0..copy_len]);
            name_len = copy_len;
            break;
        }
    }
    if (name_len == 0) return;

    const name = name_buf[0..name_len];
    var rec = try read(gpa, io, "/run/udev", name);
    defer rec.deinit();

    try std.testing.expect(rec.version != null);
}
