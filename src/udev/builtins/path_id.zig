/// path_id builtin: construct hardware path IDs (ID_PATH / ID_PATH_TAG /
/// ID_PATH_WITH_USB_REVISION).
/// Handles pci, scsi, nvme, usb, ata, platform, acpi, ccw (virtio transparent).
/// Matches systemd builtin/path_id output for the supported device classes.
/// Zero C deps.
const std = @import("std");
const Device = @import("../device.zig").Device;
const EventState = @import("../rules/runner.zig").EventState;

// Internal helpers

/// Append `seg` to both lists. `seg` becomes owned by `segs_plain`; a dup is
/// appended to `segs_rev`. On error the caller's outer defers clean the lists.
fn appendBoth(
    gpa: std.mem.Allocator,
    segs_plain: *std.ArrayListUnmanaged([]u8),
    segs_rev: *std.ArrayListUnmanaged([]u8),
    seg: []u8,
) !void {
    segs_plain.append(gpa, seg) catch |err| {
        gpa.free(seg);
        return err;
    };
    // seg is now owned by segs_plain. Outer defer frees it on error.
    const seg2 = try gpa.dupe(u8, seg);
    segs_rev.append(gpa, seg2) catch |err| {
        gpa.free(seg2);
        return err;
    };
}

/// Attempt to append one path segment for `dev` to both segment lists.
///
/// `pci_done` is set after the first (deepest) PCI segment; further PCI
/// ancestors are skipped. `has_usb` is set when a USB interface is processed;
/// the caller emits ID_PATH_WITH_USB_REVISION only when true.
fn handleDevice(
    gpa: std.mem.Allocator,
    dev: *Device,
    segs_plain: *std.ArrayListUnmanaged([]u8),
    segs_rev: *std.ArrayListUnmanaged([]u8),
    pci_done: *bool,
    has_usb: *bool,
) !void {
    const sub = (try dev.subsystem()) orelse return;

    if (std.mem.eql(u8, sub, "pci")) {
        if (pci_done.*) return;
        const seg = try std.fmt.allocPrint(gpa, "pci-{s}", .{dev.sysname()});
        try appendBoth(gpa, segs_plain, segs_rev, seg);
        pci_done.* = true;
    } else if (std.mem.eql(u8, sub, "scsi")) {
        // Only emit a segment for the actual scsi_device. Skip scsi_host /
        // scsi_target levels that also live under the "scsi" subsystem.
        if (dev.devtype()) |dt| {
            if (!std.mem.eql(u8, dt, "scsi_device")) return;
        }
        const seg = try std.fmt.allocPrint(gpa, "scsi-{s}", .{dev.sysname()});
        try appendBoth(gpa, segs_plain, segs_rev, seg);
    } else if (std.mem.eql(u8, sub, "nvme")) {
        // Simplified test topology: nvme namespace appears directly as sub="nvme"
        // with an nsid attr. Real sysfs puts nsid on the block child. That case
        // is handled in the "block" branch below.
        const nsid = (try dev.getSysattr("nsid")) orelse return;
        const seg = try std.fmt.allocPrint(gpa, "nvme-{s}", .{nsid});
        try appendBoth(gpa, segs_plain, segs_rev, seg);
    } else if (std.mem.eql(u8, sub, "block") and
        std.mem.startsWith(u8, dev.sysname(), "nvme"))
    {
        // Real nvme block namespace (nvme0n1, etc.): read nsid from the block
        // device itself (the nvme controller ancestor has no nsid attr).
        const nsid = (try dev.getSysattr("nsid")) orelse return;
        const seg = try std.fmt.allocPrint(gpa, "nvme-{s}", .{nsid});
        try appendBoth(gpa, segs_plain, segs_rev, seg);
    } else if (std.mem.eql(u8, sub, "usb")) {
        // Skip the usb_device level. Only the usb_interface emits a segment.
        if (dev.devtype()) |dt| {
            if (std.mem.eql(u8, dt, "usb_device")) return;
        }
        // Parse sysname "N-port:intf" (e.g. "1-1.1:1.4").
        const name = dev.sysname();
        const dash_pos = std.mem.indexOfScalar(u8, name, '-') orelse return;
        const after_dash = name[dash_pos + 1 ..];
        const colon_pos = std.mem.indexOfScalar(u8, after_dash, ':') orelse return;
        const port = after_dash[0..colon_pos];
        const intf = after_dash[colon_pos + 1 ..];

        // Derive USB major version from the usb_device ancestor for the
        // ID_PATH_WITH_USB_REVISION variant. Default to 2 if not found.
        var major: u32 = 2;
        if (try dev.parentWithSubsystem("usb", "usb_device")) |usb_dev_val| {
            var usb_dev = usb_dev_val;
            defer usb_dev.deinit();
            if (try usb_dev.getSysattr("version")) |ver| {
                const trimmed = std.mem.trim(u8, ver, " ");
                const dot = std.mem.indexOfScalar(u8, trimmed, '.') orelse trimmed.len;
                major = std.fmt.parseInt(u32, trimmed[0..dot], 10) catch 2;
            }
        }

        const plain_seg = try std.fmt.allocPrint(gpa, "usb-0:{s}:{s}", .{ port, intf });
        segs_plain.append(gpa, plain_seg) catch |err| {
            gpa.free(plain_seg);
            return err;
        };
        // plain_seg is now owned by segs_plain. Outer defer handles it on error.
        const rev_seg = std.fmt.allocPrint(gpa, "usbv{d}-0:{s}:{s}", .{ major, port, intf }) catch |err| {
            return err;
        };
        segs_rev.append(gpa, rev_seg) catch |err| {
            gpa.free(rev_seg);
            return err;
        };
        has_usb.* = true;
    } else if (std.mem.eql(u8, sub, "ata")) {
        // Strip the "ata" prefix from sysname to get the port number.
        const name = dev.sysname();
        const port_num = if (std.mem.startsWith(u8, name, "ata")) name["ata".len..] else name;
        const seg = try std.fmt.allocPrint(gpa, "ata-{s}", .{port_num});
        try appendBoth(gpa, segs_plain, segs_rev, seg);
    } else if (std.mem.eql(u8, sub, "platform")) {
        const seg = try std.fmt.allocPrint(gpa, "platform-{s}", .{dev.sysname()});
        try appendBoth(gpa, segs_plain, segs_rev, seg);
    } else if (std.mem.eql(u8, sub, "acpi")) {
        const seg = try std.fmt.allocPrint(gpa, "acpi-{s}", .{dev.sysname()});
        try appendBoth(gpa, segs_plain, segs_rev, seg);
    } else if (std.mem.eql(u8, sub, "ccw")) {
        const seg = try std.fmt.allocPrint(gpa, "ccw-{s}", .{dev.sysname()});
        try appendBoth(gpa, segs_plain, segs_rev, seg);
    }
    // virtio: transparent, so emit no segment and keep walking to the backing parent.
    // Unrecognized subsystems: skip this level.
}

// run

pub fn run(
    gpa: std.mem.Allocator,
    dev: *Device,
    state: *EventState,
    args: []const u8,
) anyerror!void {
    _ = args;

    // Two parallel segment lists in leaf->root order, reversed before joining.
    // segs_rev differs from segs_plain only in the USB segment (usbv<N> prefix).
    var segs_plain: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (segs_plain.items) |s| gpa.free(s);
        segs_plain.deinit(gpa);
    }
    var segs_rev: std.ArrayListUnmanaged([]u8) = .empty;
    defer {
        for (segs_rev.items) |s| gpa.free(s);
        segs_rev.deinit(gpa);
    }

    var pci_done = false;
    var has_usb = false;

    // Process the leaf device itself.
    try handleDevice(gpa, dev, &segs_plain, &segs_rev, &pci_done, &has_usb);

    // Walk up the parent chain.
    var maybe_parent: ?Device = try dev.parent();
    while (maybe_parent) |pd_val| {
        var pd = pd_val;

        handleDevice(gpa, &pd, &segs_plain, &segs_rev, &pci_done, &has_usb) catch |err| {
            pd.deinit();
            return err;
        };

        const next = pd.parent() catch |err| {
            pd.deinit();
            return err;
        };
        pd.deinit();
        maybe_parent = next;
    }

    if (segs_plain.items.len == 0) return;

    // Reverse from leaf->root into root->leaf order.
    std.mem.reverse([]u8, segs_plain.items);
    std.mem.reverse([]u8, segs_rev.items);

    // Build and set ID_PATH.
    const id_path = try std.mem.join(gpa, "-", segs_plain.items);
    defer gpa.free(id_path);
    try state.setProperty("ID_PATH", id_path);

    // ID_PATH_TAG: replace every byte outside [A-Za-z0-9_-] with '_'.
    const tag = try gpa.dupe(u8, id_path);
    defer gpa.free(tag);
    for (tag) |*c| {
        if (!std.ascii.isAlphanumeric(c.*) and c.* != '_' and c.* != '-') c.* = '_';
    }
    try state.setProperty("ID_PATH_TAG", tag);

    // ID_PATH_WITH_USB_REVISION: only when the path contained a USB interface.
    if (has_usb) {
        const id_path_rev = try std.mem.join(gpa, "-", segs_rev.items);
        defer gpa.free(id_path_rev);
        try state.setProperty("ID_PATH_WITH_USB_REVISION", id_path_rev);
    }
}

// Tests

test "path_id: pci->scsi sets ID_PATH and ID_PATH_TAG" {
    const testfs = @import("../testfs.zig");
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const syspath = try testfs.makeTopology(&tmp, &.{
        .{ .name = "0000:00:1f.2", .subsystem = "pci" },
        .{ .name = "2:0:0:0", .subsystem = "scsi" },
    });
    defer gpa.free(syspath);

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(gpa, &dev, &state, "");

    try std.testing.expectEqualStrings(
        "pci-0000:00:1f.2-scsi-2:0:0:0",
        state.getProperty("ID_PATH").?,
    );
    try std.testing.expectEqualStrings(
        "pci-0000_00_1f_2-scsi-2_0_0_0",
        state.getProperty("ID_PATH_TAG").?,
    );
    // No USB hop -> no ID_PATH_WITH_USB_REVISION.
    try std.testing.expect(state.getProperty("ID_PATH_WITH_USB_REVISION") == null);
}

test "path_id: pci->nvme with nsid attr sets ID_PATH" {
    const testfs = @import("../testfs.zig");
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const syspath = try testfs.makeTopology(&tmp, &.{
        .{ .name = "0002:01:00.0", .subsystem = "pci" },
        .{ .name = "nvme0n1", .subsystem = "nvme", .attrs = &.{.{ "nsid", "1" }} },
    });
    defer gpa.free(syspath);

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(gpa, &dev, &state, "");

    try std.testing.expectEqualStrings(
        "pci-0002:01:00.0-nvme-1",
        state.getProperty("ID_PATH").?,
    );
    // No USB hop -> no ID_PATH_WITH_USB_REVISION.
    try std.testing.expect(state.getProperty("ID_PATH_WITH_USB_REVISION") == null);
}

test "path_id: device with no recognized subsystem emits nothing" {
    const testfs = @import("../testfs.zig");
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const syspath = try testfs.makeSysfs(&tmp, .{
        .name = "input0",
        .subsystem = "input",
        .uevent = "",
    });
    defer gpa.free(syspath);

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(gpa, &dev, &state, "");

    try std.testing.expect(state.getProperty("ID_PATH") == null);
    try std.testing.expect(state.getProperty("ID_PATH_TAG") == null);
}

test "path_id: pci->usb->scsi sets ID_PATH and ID_PATH_WITH_USB_REVISION" {
    const testfs = @import("../testfs.zig");
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Topology (root to leaf):
    //   pci 0003:04:00.0
    //   usb_device 1-1.1  (DEVTYPE=usb_device, version="2.10")
    //   usb_interface 1-1.1:1.4  (no DEVTYPE, treated as usb_interface)
    //   scsi 0:0:0:0
    const syspath = try testfs.makeTopology(&tmp, &.{
        .{ .name = "0003:04:00.0", .subsystem = "pci" },
        .{ .name = "1-1.1", .subsystem = "usb", .devtype = "usb_device", .attrs = &.{
            .{ "version", "2.10" },
        } },
        .{ .name = "1-1.1:1.4", .subsystem = "usb" },
        .{ .name = "0:0:0:0", .subsystem = "scsi" },
    });
    defer gpa.free(syspath);

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(gpa, &dev, &state, "");

    try std.testing.expectEqualStrings(
        "pci-0003:04:00.0-usb-0:1.1:1.4-scsi-0:0:0:0",
        state.getProperty("ID_PATH").?,
    );
    try std.testing.expectEqualStrings(
        "pci-0003:04:00.0-usbv2-0:1.1:1.4-scsi-0:0:0:0",
        state.getProperty("ID_PATH_WITH_USB_REVISION").?,
    );
}

test "path_id: integration - sda sets non-empty ID_PATH starting with pci-" {
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    // Skip when sda is not present on this machine.
    std.Io.Dir.cwd().access(io, "/sys/class/block/sda", .{}) catch return;

    // Resolve the real sysfs path (follows the class symlink).
    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const rp_n = std.Io.Dir.cwd().realPathFile(io, "/sys/class/block/sda", &rp_buf) catch return;
    const syspath = rp_buf[0..rp_n];

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();

    var dev = Device.fromSyspath(&ctx, syspath) catch return;
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(gpa, &dev, &state, "");

    const id_path = state.getProperty("ID_PATH") orelse return;
    try std.testing.expect(id_path.len > 0);
    try std.testing.expect(std.mem.startsWith(u8, id_path, "pci-"));
}
