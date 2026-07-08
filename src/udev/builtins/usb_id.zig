/// usb_id builtin: identify USB devices and set ID_USB_* properties.
/// Matches systemd v260+ usb_id output (ID_USB_* prefix; no ID_BUS/ID_TYPE).
const std = @import("std");
const Device = @import("../device.zig").Device;
const EventState = @import("../rules/runner.zig").EventState;
const encode = @import("encode.zig");

// run

pub fn run(
    gpa: std.mem.Allocator,
    dev: *Device,
    state: *EventState,
    args: []const u8,
) anyerror!void {
    _ = args;

    // Find the usb_device. If dev itself is a usb_device use it directly;
    // otherwise walk up to the nearest usb_device ancestor.
    var usb_dev_owned: ?Device = null;
    defer if (usb_dev_owned) |*d| d.deinit();

    const usb_dev: *Device = blk: {
        const self_sub = (try dev.subsystem()) orelse "";
        const self_dt = dev.devtype() orelse "";
        if (std.mem.eql(u8, self_sub, "usb") and std.mem.eql(u8, self_dt, "usb_device")) {
            break :blk dev;
        }
        usb_dev_owned = (try dev.parentWithSubsystem("usb", "usb_device")) orelse return;
        break :blk &usb_dev_owned.?;
    };

    // Read attrs from the usb_device node.
    const id_vendor = (try usb_dev.getSysattr("idVendor")) orelse "";
    const id_product = (try usb_dev.getSysattr("idProduct")) orelse "";
    const manufacturer = (try usb_dev.getSysattr("manufacturer")) orelse "";
    const product_str = (try usb_dev.getSysattr("product")) orelse "";
    const serial = (try usb_dev.getSysattr("serial")) orelse "";
    const bcd_device = (try usb_dev.getSysattr("bcdDevice")) orelse "";

    if (id_vendor.len > 0) try state.setProperty("ID_USB_VENDOR_ID", id_vendor);
    if (id_product.len > 0) try state.setProperty("ID_USB_MODEL_ID", id_product);
    if (bcd_device.len > 0) try state.setProperty("ID_USB_REVISION", bcd_device);

    // systemd falls back to the numeric idVendor/idProduct when the manufacturer/product STRING
    // descriptors are absent (common on cheap hubs/HID/flash devices): e.g. a device with no
    // manufacturer string yields ID_USB_VENDOR=0a12, ID_USB_SERIAL=0a12_0001.
    const vendor_src = if (manufacturer.len > 0) manufacturer else id_vendor;
    const model_src = if (product_str.len > 0) product_str else id_product;

    // ID_USB_VENDOR / ID_USB_VENDOR_ENC
    if (vendor_src.len > 0) {
        const ws = try encode.replaceWhitespace(gpa, vendor_src);
        defer gpa.free(ws);
        const plain = try encode.replaceChars(gpa, ws);
        defer gpa.free(plain);
        try state.setProperty("ID_USB_VENDOR", plain);
        const enc = try encode.encodeString(gpa, vendor_src);
        defer gpa.free(enc);
        try state.setProperty("ID_USB_VENDOR_ENC", enc);
    }

    // ID_USB_MODEL / ID_USB_MODEL_ENC
    if (model_src.len > 0) {
        const ws = try encode.replaceWhitespace(gpa, model_src);
        defer gpa.free(ws);
        const plain = try encode.replaceChars(gpa, ws);
        defer gpa.free(plain);
        try state.setProperty("ID_USB_MODEL", plain);
        const enc = try encode.encodeString(gpa, model_src);
        defer gpa.free(enc);
        try state.setProperty("ID_USB_MODEL_ENC", enc);
    }

    // ID_USB_SERIAL_SHORT (only if the serial attr exists and is non-empty)
    if (serial.len > 0) try state.setProperty("ID_USB_SERIAL_SHORT", serial);

    // ID_USB_SERIAL = vendor_plain ['_' model_plain] ['_' serial]  (using the fallback sources)
    {
        var sbuf: std.ArrayListUnmanaged(u8) = .empty;
        defer sbuf.deinit(gpa);

        if (vendor_src.len > 0) {
            const ws = try encode.replaceWhitespace(gpa, vendor_src);
            defer gpa.free(ws);
            const plain = try encode.replaceChars(gpa, ws);
            defer gpa.free(plain);
            try sbuf.appendSlice(gpa, plain);
        }

        if (model_src.len > 0) {
            const ws = try encode.replaceWhitespace(gpa, model_src);
            defer gpa.free(ws);
            const plain = try encode.replaceChars(gpa, ws);
            defer gpa.free(plain);
            if (sbuf.items.len > 0) try sbuf.append(gpa, '_');
            try sbuf.appendSlice(gpa, plain);
        }

        if (serial.len > 0) {
            if (sbuf.items.len > 0) try sbuf.append(gpa, '_');
            try sbuf.appendSlice(gpa, serial);
        }

        if (sbuf.items.len > 0) {
            try state.setProperty("ID_USB_SERIAL", sbuf.items);
        }
    }

    // ID_USB_INTERFACES: enumerate child interface directories of usb_device.
    // Interface dirs are named "<usb_sysname>:<config>.<interface>" (e.g. "1-1.1:1.0").
    {
        const usb_sysname = usb_dev.sysname();
        const usb_syspath_str = usb_dev.syspath();

        // Collect and sort interface dir names.
        var iface_names: std.ArrayListUnmanaged([]u8) = .empty;
        defer {
            for (iface_names.items) |n| gpa.free(n);
            iface_names.deinit(gpa);
        }

        var usb_dir = try std.Io.Dir.cwd().openDir(dev.ctx.io, usb_syspath_str, .{ .iterate = true });
        defer usb_dir.close(dev.ctx.io);

        var dir_it = usb_dir.iterateAssumeFirstIteration();
        while (try dir_it.next(dev.ctx.io)) |entry| {
            // Match entries named "<usb_sysname>:..."
            if (entry.name.len <= usb_sysname.len) continue;
            if (!std.mem.startsWith(u8, entry.name, usb_sysname)) continue;
            if (entry.name[usb_sysname.len] != ':') continue;
            const owned = try gpa.dupe(u8, entry.name);
            errdefer gpa.free(owned);
            try iface_names.append(gpa, owned);
        }

        std.mem.sort([]u8, iface_names.items, {}, struct {
            fn lessThan(_: void, a: []u8, b: []u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lessThan);

        // Build ":CCSSPP:CCSSPP:..." deduplicating identical entries.
        var ibuf: std.ArrayListUnmanaged(u8) = .empty;
        defer ibuf.deinit(gpa);
        try ibuf.append(gpa, ':');

        for (iface_names.items) |iname| {
            var iface_path_buf: [std.fs.max_path_bytes]u8 = undefined;
            const iface_path = try std.fmt.bufPrint(&iface_path_buf, "{s}/{s}", .{ usb_syspath_str, iname });

            var iface_dev = try Device.fromSyspath(dev.ctx, iface_path);
            defer iface_dev.deinit();

            const class = (try iface_dev.getSysattr("bInterfaceClass")) orelse "00";
            const subclass = (try iface_dev.getSysattr("bInterfaceSubClass")) orelse "00";
            const proto = (try iface_dev.getSysattr("bInterfaceProtocol")) orelse "00";

            // Each field is normally 2 hex chars ("CCSSPP:"); size the buffer generously so a
            // malformed/oversized sysfs attr degrades instead of erroring the whole builtin.
            var entry_buf: [32]u8 = undefined;
            const entry_str = std.fmt.bufPrint(&entry_buf, "{s}{s}{s}:", .{ class, subclass, proto }) catch continue;

            // Skip duplicate entries (same class+subclass+protocol already appended).
            if (std.mem.indexOf(u8, ibuf.items, entry_str) != null) continue;
            try ibuf.appendSlice(gpa, entry_str);
        }

        // Only set if at least one interface was found (ibuf has more than just ':').
        if (ibuf.items.len > 1) {
            try state.setProperty("ID_USB_INTERFACES", ibuf.items);
        }
    }
}

// Tests

// (Encoding helpers are tested in encode.zig. usb_id's own tests below cover the ID_USB_* logic.)

test "usb_id: HID USB device sets expected ID_USB_* properties" {
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create usb_device node: devices/usb1/
    // Interface dirs must be named "<sysname>:..." so "usb1:1.0".
    try tmp.dir.createDirPath(io, "devices/usb1");
    try tmp.dir.writeFile(io, .{
        .sub_path = "devices/usb1/uevent",
        .data = "DEVTYPE=usb_device\n",
    });
    try tmp.dir.symLink(io, "../../class/usb", "devices/usb1/subsystem", .{});
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/usb1/idVendor", .data = "046d\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/usb1/idProduct", .data = "c52b\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/usb1/manufacturer", .data = "Logitech\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/usb1/product", .data = "USB Receiver\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/usb1/serial", .data = "0123\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/usb1/bcdDevice", .data = "1200\n" });

    // Create usb_interface dir: devices/usb1/usb1:1.0/ (child of usb1, named <sysname>:1.0)
    try tmp.dir.createDirPath(io, "devices/usb1/usb1:1.0");
    try tmp.dir.writeFile(io, .{
        .sub_path = "devices/usb1/usb1:1.0/uevent",
        .data = "DEVTYPE=usb_interface\n",
    });
    try tmp.dir.symLink(io, "../../../class/usb", "devices/usb1/usb1:1.0/subsystem", .{});
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/usb1/usb1:1.0/bInterfaceClass", .data = "03\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/usb1/usb1:1.0/bInterfaceSubClass", .data = "01\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/usb1/usb1:1.0/bInterfaceProtocol", .data = "00\n" });

    // Create leaf device: devices/usb1/usb1:1.0/leaf/ (child of the interface)
    try tmp.dir.createDirPath(io, "devices/usb1/usb1:1.0/leaf");
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/usb1/usb1:1.0/leaf/uevent", .data = "" });

    // Resolve absolute path for the leaf
    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const rp_n = try tmp.dir.realPathFile(io, "devices/usb1/usb1:1.0/leaf", &rp_buf);
    const leaf_path = try gpa.dupe(u8, rp_buf[0..rp_n]);
    defer gpa.free(leaf_path);

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, leaf_path);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(gpa, &dev, &state, "");

    try std.testing.expectEqualStrings("046d", state.getProperty("ID_USB_VENDOR_ID").?);
    try std.testing.expectEqualStrings("c52b", state.getProperty("ID_USB_MODEL_ID").?);
    try std.testing.expectEqualStrings("1200", state.getProperty("ID_USB_REVISION").?);
    try std.testing.expectEqualStrings("Logitech", state.getProperty("ID_USB_VENDOR").?);
    try std.testing.expectEqualStrings("Logitech", state.getProperty("ID_USB_VENDOR_ENC").?);
    try std.testing.expectEqualStrings("USB_Receiver", state.getProperty("ID_USB_MODEL").?);
    try std.testing.expectEqualStrings("USB\\x20Receiver", state.getProperty("ID_USB_MODEL_ENC").?);
    try std.testing.expectEqualStrings("0123", state.getProperty("ID_USB_SERIAL_SHORT").?);
    try std.testing.expectEqualStrings("Logitech_USB_Receiver_0123", state.getProperty("ID_USB_SERIAL").?);
    try std.testing.expectEqualStrings(":030100:", state.getProperty("ID_USB_INTERFACES").?);
    // Old classic properties must NOT be set.
    try std.testing.expect(state.getProperty("ID_BUS") == null);
    try std.testing.expect(state.getProperty("ID_VENDOR") == null);
    try std.testing.expect(state.getProperty("ID_MODEL") == null);
    try std.testing.expect(state.getProperty("ID_TYPE") == null);
}

test "usb_id: non-USB device (no usb_device parent) returns without setting any properties" {
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

    try std.testing.expect(state.getProperty("ID_USB_VENDOR_ID") == null);
    try std.testing.expect(state.getProperty("ID_BUS") == null);
}

test "usb_id: integration (skipped when no USB device in /sys)" {
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    // Skip if no USB device is present.
    std.Io.Dir.cwd().access(io, "/sys/bus/usb/devices/usb1", .{}) catch return;

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = std.Io.Dir.cwd().realPathFile(io, "/sys/bus/usb/devices/usb1", &rp_buf) catch return;
    const syspath = rp_buf[0..n];

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    // usb1 is itself a usb_device, so run() uses it directly and ID_USB_VENDOR_ID is set.
    try run(gpa, &dev, &state, "");
    try std.testing.expect(state.getProperty("ID_USB_VENDOR_ID") != null);
}
