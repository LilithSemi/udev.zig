/// Builds a fake sysfs tree under a TmpDir for use in device tests.
/// Reused by the enumerate tests. This file is test-only infrastructure.
const std = @import("std");

/// A name-value pair for a sysfs attribute file.
pub const AttrPair = [2][]const u8;

/// Specification for one fake sysfs device.
pub const Spec = struct {
    /// Basename (or relative sub-path) of the device directory under <tmp>/devices/.
    name: []const u8,
    /// Subsystem name; becomes the basename of the `subsystem` symlink target.
    subsystem: []const u8,
    /// Content written verbatim to the `uevent` file (newline-separated KEY=VALUE lines).
    uevent: []const u8,
    /// Extra attribute files: each element is [name, content].
    attrs: []const AttrPair = &.{},
    /// If non-null, creates a `driver` symlink whose target basename equals this string.
    /// The full target is `../../../bus/usb/drivers/<driver>` (dangling OK).
    driver: ?[]const u8 = null,
};

/// Internal: create <tmp>/devices/<spec.name>/ with uevent, subsystem symlink, and attr files.
/// Shared by makeSysfs and makeClassDevice.
fn createDevDir(tmp: *std.testing.TmpDir, spec: Spec) !void {
    const io = std.testing.io;

    var dev_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dev_rel = try std.fmt.bufPrint(&dev_buf, "devices/{s}", .{spec.name});
    try tmp.dir.createDirPath(io, dev_rel);

    var uevent_buf: [std.fs.max_path_bytes]u8 = undefined;
    const uevent_rel = try std.fmt.bufPrint(&uevent_buf, "devices/{s}/uevent", .{spec.name});
    try tmp.dir.writeFile(io, .{ .sub_path = uevent_rel, .data = spec.uevent });

    var sym_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sym_rel = try std.fmt.bufPrint(&sym_buf, "devices/{s}/subsystem", .{spec.name});
    var tgt_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tgt = try std.fmt.bufPrint(&tgt_buf, "../../class/{s}", .{spec.subsystem});
    try tmp.dir.symLink(io, tgt, sym_rel, .{});

    for (spec.attrs) |attr| {
        var ab: [std.fs.max_path_bytes]u8 = undefined;
        const attr_rel = try std.fmt.bufPrint(&ab, "devices/{s}/{s}", .{ spec.name, attr[0] });

        // If the attr name contains '/', create intermediate directories first.
        if (std.mem.lastIndexOf(u8, attr[0], "/")) |slash| {
            var dir_ab: [std.fs.max_path_bytes]u8 = undefined;
            const dir_rel = try std.fmt.bufPrint(&dir_ab, "devices/{s}/{s}", .{ spec.name, attr[0][0..slash] });
            tmp.dir.createDirPath(io, dir_rel) catch |err| switch (err) {
                error.PathAlreadyExists => {},
                else => return err,
            };
        }

        try tmp.dir.writeFile(io, .{ .sub_path = attr_rel, .data = attr[1] });
    }

    if (spec.driver) |drv| {
        var dsym_buf: [std.fs.max_path_bytes]u8 = undefined;
        const dsym_rel = try std.fmt.bufPrint(&dsym_buf, "devices/{s}/driver", .{spec.name});
        var dtgt_buf: [std.fs.max_path_bytes]u8 = undefined;
        const dtgt = try std.fmt.bufPrint(&dtgt_buf, "../../../bus/usb/drivers/{s}", .{drv});
        try tmp.dir.symLink(io, dtgt, dsym_rel, .{});
    }
}

/// Create a fake sysfs device under `<tmp>/devices/<spec.name>/`:
///   - `uevent`   file with the given content
///   - `subsystem` symlink pointing to `../../class/<subsystem>` (dangling OK)
///   - one file per attr
///
/// Returns the **absolute** path to the device directory, allocated with
/// `std.testing.allocator`. The caller must free the returned slice.
pub fn makeSysfs(tmp: *std.testing.TmpDir, spec: Spec) ![]u8 {
    try createDevDir(tmp, spec);

    const io = std.testing.io;
    const gpa = std.testing.allocator;

    var dev_buf: [std.fs.max_path_bytes]u8 = undefined;
    const dev_rel = try std.fmt.bufPrint(&dev_buf, "devices/{s}", .{spec.name});

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const rp_n = try tmp.dir.realPathFile(io, dev_rel, &rp_buf);
    return gpa.dupe(u8, rp_buf[0..rp_n]);
}

/// Create a fake sysfs device suitable for enumerate scanning:
///   - `<tmp>/devices/<spec.name>/` with uevent, subsystem symlink, and attr files
///   - `<tmp>/class/<spec.subsystem>/` directory (created if absent)
///   - `<tmp>/class/<spec.subsystem>/<spec.name>` symlink -> `../../devices/<spec.name>`
///
/// Iterating `<tmp>/class/<spec.subsystem>` will find the device and realpath
/// will resolve to the device dir. Returns void; call setSysRoot(tmp_realpath) in
/// the test to point Enumerate at the fake tree.
pub fn makeClassDevice(tmp: *std.testing.TmpDir, spec: Spec) !void {
    try createDevDir(tmp, spec);

    const io = std.testing.io;

    // Create class/<subsystem>/ dir, ignoring PathAlreadyExists for shared subsystems.
    var class_sub_buf: [std.fs.max_path_bytes]u8 = undefined;
    const class_sub_rel = try std.fmt.bufPrint(&class_sub_buf, "class/{s}", .{spec.subsystem});
    tmp.dir.createDirPath(io, class_sub_rel) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Symlink: class/<subsystem>/<name> -> ../../devices/<name>
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link_rel = try std.fmt.bufPrint(&link_buf, "class/{s}/{s}", .{ spec.subsystem, spec.name });
    var ltgt_buf: [std.fs.max_path_bytes]u8 = undefined;
    const ltgt = try std.fmt.bufPrint(&ltgt_buf, "../../devices/{s}", .{spec.name});
    try tmp.dir.symLink(io, ltgt, link_rel, .{});
}

/// Create a fake /sys/bus/<sub>/devices/<name> tree:
///   - `<tmp>/devices/<spec.name>/` with uevent, subsystem symlink, and attr files
///   - `<tmp>/bus/<spec.subsystem>/devices/` directory (created if absent)
///   - `<tmp>/bus/<spec.subsystem>/devices/<spec.name>` symlink ->
///     `../../../devices/<spec.name>`
///
/// Scanning `<tmp>/bus/<spec.subsystem>/devices` will find the device and
/// realPathFile will resolve to the device dir. Call setSysRoot(tmp_realpath) to
/// point Enumerate at the fake tree.
pub fn makeBusDevice(tmp: *std.testing.TmpDir, spec: Spec) !void {
    try createDevDir(tmp, spec);

    const io = std.testing.io;

    // Create bus/<subsystem>/devices/ dir, ignoring PathAlreadyExists.
    var bus_dev_buf: [std.fs.max_path_bytes]u8 = undefined;
    const bus_dev_rel = try std.fmt.bufPrint(&bus_dev_buf, "bus/{s}/devices", .{spec.subsystem});
    tmp.dir.createDirPath(io, bus_dev_rel) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Symlink: bus/<subsystem>/devices/<name> -> ../../../devices/<name>
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link_rel = try std.fmt.bufPrint(&link_buf, "bus/{s}/devices/{s}", .{ spec.subsystem, spec.name });
    var ltgt_buf: [std.fs.max_path_bytes]u8 = undefined;
    const ltgt = try std.fmt.bufPrint(&ltgt_buf, "../../../devices/{s}", .{spec.name});
    try tmp.dir.symLink(io, ltgt, link_rel, .{});
}

/// Specification for one level in a multi-level sysfs device topology.
pub const Level = struct {
    /// Directory name for this level (basename only, no embedded slashes).
    name: []const u8,
    /// When non-null, creates a `subsystem` symlink whose basename equals this string.
    subsystem: ?[]const u8 = null,
    /// When non-null, written as "DEVTYPE=<devtype>\n" in the `uevent` file.
    devtype: ?[]const u8 = null,
    /// Extra attribute files: each element is .{ name, content }.
    attrs: []const struct { []const u8, []const u8 } = &.{},
};

/// Build a nested sysfs device chain under `<tmp>/devices/<name0>/<name1>/.../<nameN>`.
/// At each level this creates:
///   - a `uevent` file (empty, or "DEVTYPE=<dt>\n" when devtype is given)
///   - a `subsystem` symlink with basename == subsystem (dangling OK) when given
///   - one file per attr (nested names with '/' are supported)
/// Returns the **absolute** path to the deepest level directory, allocated with
/// `std.testing.allocator`. The caller must free the returned slice.
pub fn makeTopology(tmp: *std.testing.TmpDir, levels: []const Level) ![]u8 {
    const io = std.testing.io;
    const gpa = std.testing.allocator;

    // Accumulate the relative path across iterations.
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    var path_len: usize = 0;

    // Seed the buffer with the "devices/" prefix.
    const prefix = "devices/";
    std.mem.copyForwards(u8, path_buf[0..prefix.len], prefix);
    path_len = prefix.len;

    for (levels) |level| {
        // Extend the path with this level's name.
        std.mem.copyForwards(u8, path_buf[path_len .. path_len + level.name.len], level.name);
        path_len += level.name.len;
        const dev_rel = path_buf[0..path_len];

        try tmp.dir.createDirPath(io, dev_rel);

        // Write the uevent file.
        var uevent_pb: [std.fs.max_path_bytes]u8 = undefined;
        const uevent_rel = try std.fmt.bufPrint(&uevent_pb, "{s}/uevent", .{dev_rel});
        var ue_buf: [256]u8 = undefined;
        const uevent_data: []const u8 = if (level.devtype) |dt|
            try std.fmt.bufPrint(&ue_buf, "DEVTYPE={s}\n", .{dt})
        else
            "";
        try tmp.dir.writeFile(io, .{ .sub_path = uevent_rel, .data = uevent_data });

        // Write the subsystem symlink when requested (dangling is fine, only the basename
        // is ever used by Device.subsystem()).
        if (level.subsystem) |sub| {
            var sym_pb: [std.fs.max_path_bytes]u8 = undefined;
            const sym_rel = try std.fmt.bufPrint(&sym_pb, "{s}/subsystem", .{dev_rel});
            var tgt_buf: [std.fs.max_path_bytes]u8 = undefined;
            const tgt = try std.fmt.bufPrint(&tgt_buf, "../../../../bus/{s}", .{sub});
            try tmp.dir.symLink(io, tgt, sym_rel, .{});
        }

        // Write attr files, supporting nested names with '/' like the existing helpers.
        for (level.attrs) |attr| {
            var ab: [std.fs.max_path_bytes]u8 = undefined;
            const attr_rel = try std.fmt.bufPrint(&ab, "{s}/{s}", .{ dev_rel, attr[0] });
            if (std.mem.lastIndexOf(u8, attr[0], "/")) |slash| {
                var dir_ab: [std.fs.max_path_bytes]u8 = undefined;
                const dir_rel = try std.fmt.bufPrint(
                    &dir_ab,
                    "{s}/{s}",
                    .{ dev_rel, attr[0][0..slash] },
                );
                tmp.dir.createDirPath(io, dir_rel) catch |err| switch (err) {
                    error.PathAlreadyExists => {},
                    else => return err,
                };
            }
            try tmp.dir.writeFile(io, .{ .sub_path = attr_rel, .data = attr[1] });
        }

        // Append the separator before the next level name.
        path_buf[path_len] = '/';
        path_len += 1;
    }

    // Strip the trailing '/' added by the last iteration.
    if (path_len > 0 and path_buf[path_len - 1] == '/') {
        path_len -= 1;
    }

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const rp_n = try tmp.dir.realPathFile(io, path_buf[0..path_len], &rp_buf);
    return gpa.dupe(u8, rp_buf[0..rp_n]);
}

/// Create a fake /sys/subsystem/<sub>/devices/<name> tree:
///   - `<tmp>/devices/<spec.name>/` with uevent, subsystem symlink, and attr files
///   - `<tmp>/subsystem/<spec.subsystem>/devices/` directory (created if absent)
///   - `<tmp>/subsystem/<spec.subsystem>/devices/<spec.name>` symlink ->
///     `../../../../devices/<spec.name>`
///
/// Scanning `<tmp>/subsystem/<spec.subsystem>/devices` will find the device and
/// realPathFile will resolve to the device dir. Call setSysRoot(tmp_realpath) to
/// point Enumerate at the fake tree.
pub fn makeSubsystemDevice(tmp: *std.testing.TmpDir, spec: Spec) !void {
    try createDevDir(tmp, spec);

    const io = std.testing.io;

    // Create subsystem/<subsystem>/devices/ dir, ignoring PathAlreadyExists.
    var sub_dev_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sub_dev_rel = try std.fmt.bufPrint(&sub_dev_buf, "subsystem/{s}/devices", .{spec.subsystem});
    tmp.dir.createDirPath(io, sub_dev_rel) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // Symlink: subsystem/<subsystem>/devices/<name> -> ../../../../devices/<name>
    var link_buf: [std.fs.max_path_bytes]u8 = undefined;
    const link_rel = try std.fmt.bufPrint(&link_buf, "subsystem/{s}/devices/{s}", .{ spec.subsystem, spec.name });
    var ltgt_buf: [std.fs.max_path_bytes]u8 = undefined;
    const ltgt = try std.fmt.bufPrint(&ltgt_buf, "../../../devices/{s}", .{spec.name});
    try tmp.dir.symLink(io, ltgt, link_rel, .{});
}

test "testfs: nested attr path (capabilities/ev) round-trips via getSysattr" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const syspath = try makeSysfs(&tmp, .{
        .name = "input0",
        .subsystem = "input",
        .uevent = "DEVTYPE=input\n",
        .attrs = &.{
            .{ "capabilities/ev", "1f\n" },
        },
    });
    defer gpa.free(syspath);

    var ctx = @import("context.zig").Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try @import("device.zig").Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    const val = try dev.getSysattr("capabilities/ev");
    try std.testing.expect(val != null);
    try std.testing.expectEqualStrings("1f", val.?);
}

test "testfs: makeTopology 3-level chain - parent of leaf is middle level" {
    const io = std.testing.io;
    const gpa = std.testing.allocator;
    const Device = @import("device.zig").Device;
    const ctx_mod = @import("context.zig");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const syspath = try makeTopology(&tmp, &.{
        .{ .name = "root0", .subsystem = "pci" },
        .{ .name = "mid0", .subsystem = "scsi" },
        .{ .name = "leaf0", .subsystem = "input" },
    });
    defer gpa.free(syspath);

    var ctx = ctx_mod.Context.init(gpa, io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    const maybe_parent = try dev.parent();
    try std.testing.expect(maybe_parent != null);
    var par = maybe_parent.?;
    defer par.deinit();

    try std.testing.expectEqualStrings("mid0", par.sysname());
}
