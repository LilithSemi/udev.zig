/// net_id builtin: construct stable network interface names.
/// Produces ID_NET_NAMING_SCHEME, ID_NET_NAME_MAC, ID_NET_NAME_PATH,
/// ID_NET_NAME_ONBOARD, ID_NET_LABEL_ONBOARD, ID_NET_NAME_SLOT.
/// PATH includes names_pci plus an optional USB suffix when the netdev
/// hangs off a USB interface between the netdev and the PCI controller.
/// SLOT uses the PCI hotplug slot number from /sys/bus/pci/slots or
/// firmware_node/sun, with the same USB suffix as PATH.
/// Zero C deps.
const std = @import("std");
const Device = @import("../device.zig").Device;
const EventState = @import("../rules/runner.zig").EventState;

/// Parse a PCI sysname of the form "DOMAIN:BUS:DEV.FUNC" (all fields hex).
/// Returns null if the format is not recognized.
fn parsePciSysname(sysname: []const u8) ?struct { domain: u32, bus: u32, dev: u32, func: u32 } {
    const colon1 = std.mem.indexOfScalar(u8, sysname, ':') orelse return null;
    const rest1 = sysname[colon1 + 1 ..];
    const colon2 = std.mem.indexOfScalar(u8, rest1, ':') orelse return null;
    const domain_str = sysname[0..colon1];
    const bus_str = rest1[0..colon2];
    const devfunc_str = rest1[colon2 + 1 ..];
    const dot_pos = std.mem.indexOfScalar(u8, devfunc_str, '.') orelse return null;
    const dev_str = devfunc_str[0..dot_pos];
    const func_str = devfunc_str[dot_pos + 1 ..];

    const domain = std.fmt.parseInt(u32, domain_str, 16) catch return null;
    const bus = std.fmt.parseInt(u32, bus_str, 16) catch return null;
    const dev_num = std.fmt.parseInt(u32, dev_str, 16) catch return null;
    const func = std.fmt.parseInt(u32, func_str, 16) catch return null;

    return .{ .domain = domain, .bus = bus, .dev = dev_num, .func = func };
}

/// Build the USB suffix from a usb_interface sysname like "1-2.3.1:2.0".
/// PORT = between first '-' and ':' (e.g. "2.3.1"), split on '.', gives "u2u3u1".
/// CONFIG = after ':' up to '.' -> "c2".
/// INTERFACE = after that '.' -> append "i{n}" only when n > 0.
/// Result is a gpa-owned slice. Caller must free.
fn buildUsbSuffix(gpa: std.mem.Allocator, sysname: []const u8) ![]u8 {
    const dash = std.mem.indexOfScalar(u8, sysname, '-') orelse return gpa.dupe(u8, "");
    const colon = std.mem.indexOfScalar(u8, sysname, ':') orelse return gpa.dupe(u8, "");
    if (colon <= dash) return gpa.dupe(u8, "");

    const port_str = sysname[dash + 1 .. colon];
    const config_intf_str = sysname[colon + 1 ..];

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(gpa);

    var port_it = std.mem.splitScalar(u8, port_str, '.');
    while (port_it.next()) |component| {
        if (component.len == 0) continue; // skip a degenerate empty port component
        try buf.appendSlice(gpa, "u");
        try buf.appendSlice(gpa, component);
    }

    const dot = std.mem.indexOfScalar(u8, config_intf_str, '.') orelse {
        try buf.appendSlice(gpa, "c");
        try buf.appendSlice(gpa, config_intf_str);
        return buf.toOwnedSlice(gpa);
    };

    const config_str = config_intf_str[0..dot];
    const intf_str = config_intf_str[dot + 1 ..];

    try buf.appendSlice(gpa, "c");
    try buf.appendSlice(gpa, config_str);

    const intf_num = std.fmt.parseInt(u32, intf_str, 10) catch 0;
    if (intf_num > 0) {
        var intf_buf: [16]u8 = undefined;
        const intf_part = try std.fmt.bufPrint(&intf_buf, "i{d}", .{intf_num});
        try buf.appendSlice(gpa, intf_part);
    }

    return buf.toOwnedSlice(gpa);
}

/// Determine whether the PCI function at pci_syspath is part of a multifunction
/// device.  Looks at the parent directory of pci_syspath and counts peer entries
/// that share the same domain:bus:device prefix (differ only in the function
/// number).  Returns true when more than one such entry exists.  Returns false on
/// any error (single-function assumption).
fn isMultifunction(io: std.Io, pci_syspath: []const u8, domain: u32, bus: u32, dev_num: u32) bool {
    const parent_path = std.fs.path.dirname(pci_syspath) orelse return false;
    if (parent_path.len == 0) return false;

    // Build the prefix "DDDD:BB:DD." to match sibling function sysnames.
    var prefix_buf: [16]u8 = undefined;
    const prefix_str = std.fmt.bufPrint(
        &prefix_buf,
        "{x:0>4}:{x:0>2}:{x:0>2}.",
        .{ domain, bus, dev_num },
    ) catch return false;

    var dir = std.Io.Dir.cwd().openDir(io, parent_path, .{ .iterate = true }) catch return false;
    defer dir.close(io);

    var count: usize = 0;
    var it = dir.iterate();
    while (it.next(io) catch return false) |entry| {
        if (std.mem.startsWith(u8, entry.name, prefix_str)) {
            count += 1;
        }
    }

    return count > 1;
}

/// Resolve the PCI hotplug slot number for the function at (domain, bus, dev_num).
/// Returns a gpa-owned string (caller frees) or null when no slot number is found.
/// PRIMARY: iterate /sys/bus/pci/slots; for each entry <N>, read <N>/address; match
/// the trimmed "DDDD:BB:DD" string against the function's own address. Return <N>.
/// FALLBACK: read <pci_syspath>/firmware_node/sun; if non-empty, return that string.
fn pciSlotNumber(
    io: std.Io,
    gpa: std.mem.Allocator,
    domain: u32,
    bus: u32,
    dev_num: u32,
    pci_syspath: []const u8,
) !?[]u8 {
    var addr_buf: [16]u8 = undefined;
    const want_addr = try std.fmt.bufPrint(
        &addr_buf,
        "{x:0>4}:{x:0>2}:{x:0>2}",
        .{ domain, bus, dev_num },
    );

    // PRIMARY: /sys/bus/pci/slots/<N>/address
    slots: {
        var slots_dir = std.Io.Dir.cwd().openDir(
            io,
            "/sys/bus/pci/slots",
            .{ .iterate = true },
        ) catch break :slots;
        defer slots_dir.close(io);

        var it = slots_dir.iterate();
        while (it.next(io) catch break :slots) |entry| {
            var ap_buf: [std.fs.max_path_bytes]u8 = undefined;
            const addr_path = std.fmt.bufPrint(
                &ap_buf,
                "/sys/bus/pci/slots/{s}/address",
                .{entry.name},
            ) catch continue;

            const raw = std.Io.Dir.cwd().readFileAlloc(io, addr_path, gpa, .limited(64)) catch continue;
            defer gpa.free(raw);

            const trimmed = std.mem.trim(u8, raw, " \t\n\r");
            if (std.mem.eql(u8, trimmed, want_addr)) {
                return @as(?[]u8, try gpa.dupe(u8, entry.name));
            }
        }
    }

    // FALLBACK: firmware_node/sun sysattr of the PCI device.
    var sp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const sun_path = std.fmt.bufPrint(
        &sp_buf,
        "{s}/firmware_node/sun",
        .{pci_syspath},
    ) catch return null;

    const sun_raw = std.Io.Dir.cwd().readFileAlloc(io, sun_path, gpa, .limited(64)) catch return null;
    defer gpa.free(sun_raw);

    const sun_str = std.mem.trim(u8, sun_raw, " \t\n\r");
    if (sun_str.len > 0) {
        return @as(?[]u8, try gpa.dupe(u8, sun_str));
    }

    return null;
}

pub fn run(
    gpa: std.mem.Allocator,
    dev: *Device,
    state: *EventState,
    args: []const u8,
) anyerror!void {
    _ = args;

    // Always emit the naming scheme version.
    try state.setProperty("ID_NET_NAMING_SCHEME", "v260");

    // Determine prefix from interface type sysattr.
    const prefix: []const u8 = blk: {
        if (try dev.getSysattr("type")) |type_str| {
            const t = std.fmt.parseInt(u32, std.mem.trim(u8, type_str, " \t\n"), 10) catch 0;
            if (t == 1) break :blk "en";
            if (t == 32) break :blk "ib";
        }
        if (dev.getProperty("DEVTYPE")) |dt| {
            if (std.mem.eql(u8, dt, "wlan")) break :blk "wl";
            if (std.mem.eql(u8, dt, "wwan")) break :blk "ww";
        }
        break :blk "en";
    };

    // ID_NET_NAME_MAC: permanent, globally-administered MAC address.
    mac: {
        const addr_str = (try dev.getSysattr("address")) orelse break :mac;
        const assign_str = (try dev.getSysattr("addr_assign_type")) orelse break :mac;

        // Only emit for permanent assignment (addr_assign_type == "0").
        if (!std.mem.eql(u8, std.mem.trim(u8, assign_str, " \t\n"), "0")) break :mac;

        // Parse "xx:xx:xx:xx:xx:xx" into 6 bytes.
        var bytes: [6]u8 = undefined;
        var count: usize = 0;
        var it = std.mem.splitScalar(u8, std.mem.trim(u8, addr_str, " \t\n"), ':');
        while (it.next()) |part| {
            if (count >= 6) break :mac;
            bytes[count] = std.fmt.parseInt(u8, part, 16) catch break :mac;
            count += 1;
        }
        if (count != 6) break :mac;

        // Skip all-zero address.
        const all_zero = for (bytes) |b| {
            if (b != 0) break false;
        } else true;
        if (all_zero) break :mac;

        // Format as prefix ++ "x" ++ 12 lowercase hex digits.
        const hex_chars = "0123456789abcdef";
        var hex_buf: [12]u8 = undefined;
        for (bytes, 0..) |b, i| {
            hex_buf[i * 2] = hex_chars[b >> 4];
            hex_buf[i * 2 + 1] = hex_chars[b & 0x0f];
        }

        const mac_name = try std.fmt.allocPrint(gpa, "{s}x{s}", .{ prefix, hex_buf[0..] });
        defer gpa.free(mac_name);
        try state.setProperty("ID_NET_NAME_MAC", mac_name);
    }

    // ID_NET_NAME_PATH, ID_NET_NAME_ONBOARD, ID_NET_LABEL_ONBOARD:
    // Walk parent chain to find the PCI function ancestor. Along the way,
    // record the first usb_interface (subsystem "usb", sysname contains ':')
    // so we can append its suffix to PATH.
    var usb_sysname: ?[]u8 = null;
    defer if (usb_sysname) |s| gpa.free(s);

    path: {
        var maybe_parent: ?Device = try dev.parent();
        while (maybe_parent) |pd_val| {
            var pd = pd_val;

            const sub = pd.subsystem() catch |err| {
                pd.deinit();
                return err;
            };

            if (sub != null and std.mem.eql(u8, sub.?, "pci")) {
                // Extract sysname data (slice into pd's arena) before any deinit.
                const parsed = parsePciSysname(pd.sysname());

                if (parsed) |p| {
                    // Read sysattrs from the PCI function BEFORE deinit, they live
                    // in pd's arena and become invalid after pd.deinit().
                    const acpi_index_attr = pd.getSysattr("acpi_index") catch |err| {
                        pd.deinit();
                        return err;
                    };
                    const index_attr = pd.getSysattr("index") catch |err| {
                        pd.deinit();
                        return err;
                    };
                    const label_attr = pd.getSysattr("label") catch |err| {
                        pd.deinit();
                        return err;
                    };

                    // Compute the onboard index: prefer acpi_index, fall back to index.
                    const index_val: ?u32 = index_blk: {
                        const raw: ?[]const u8 = raw_blk: {
                            if (acpi_index_attr) |ai| {
                                const t = std.mem.trim(u8, ai, " \t\n");
                                if (t.len > 0) break :raw_blk t;
                            }
                            if (index_attr) |idx| {
                                const t = std.mem.trim(u8, idx, " \t\n");
                                if (t.len > 0) break :raw_blk t;
                            }
                            break :raw_blk null;
                        };
                        if (raw) |r| {
                            const v = std.fmt.parseInt(i64, r, 10) catch break :index_blk null;
                            // v260 has NAMING_16BIT_INDEX: the rubbish-index sanity cap is 0xffff.
                            if (v > 0 and v <= 65535) break :index_blk @as(u32, @intCast(v));
                        }
                        break :index_blk null;
                    };

                    // Dupe label into gpa so it survives pd.deinit().
                    const label_owned: ?[]u8 = label_blk: {
                        if (label_attr) |lv| {
                            if (lv.len > 0) {
                                const duped = gpa.dupe(u8, lv) catch |err| {
                                    pd.deinit();
                                    return err;
                                };
                                break :label_blk duped;
                            }
                        }
                        break :label_blk null;
                    };
                    defer if (label_owned) |lo| gpa.free(lo);

                    // Save syspath before pd.deinit() so pciSlotNumber can read it later.
                    const pci_syspath_owned = gpa.dupe(u8, pd.syspath()) catch |err| {
                        pd.deinit();
                        return err;
                    };

                    // Detect multifunction while pd (and its syspath) is still alive.
                    const multifunction = isMultifunction(
                        dev.ctx.io,
                        pd.syspath(),
                        p.domain,
                        p.bus,
                        p.dev,
                    );

                    pd.deinit(); // Done with the PCI Device.
                    defer gpa.free(pci_syspath_owned);

                    // Per-port suffix on a multi-port-per-PCI-function NIC, read from the NETDEV:
                    // "n{phys_port_name}" (preferred) else "d{dev_port}" (when >0), else empty. This
                    // distinguishes the ports of e.g. a dual-port card that share one PCI function,
                    // and is appended to ONBOARD, PATH, and SLOT (systemd names_pci/dev_pci_onboard).
                    const port_suffix: []const u8 = ps_blk: {
                        if (try dev.getSysattr("phys_port_name")) |ppn| {
                            const t = std.mem.trim(u8, ppn, " \t\n");
                            if (t.len > 0) break :ps_blk try std.fmt.allocPrint(gpa, "n{s}", .{t});
                        }
                        if (try dev.getSysattr("dev_port")) |dp| {
                            const t = std.mem.trim(u8, dp, " \t\n");
                            const n = std.fmt.parseInt(u32, t, 10) catch 0;
                            if (n > 0) break :ps_blk try std.fmt.allocPrint(gpa, "d{d}", .{n});
                        }
                        break :ps_blk try gpa.dupe(u8, "");
                    };
                    defer gpa.free(port_suffix);

                    // Build the PCI component of PATH (names_pci).
                    // Append "f{n}" when func > 0 OR this is a multifunction device
                    // (so that func-0 on a multifunction card gets "f0").
                    const pci_str = if (p.domain > 0 and (p.func > 0 or multifunction))
                        try std.fmt.allocPrint(gpa, "P{d}p{d}s{d}f{d}", .{ p.domain, p.bus, p.dev, p.func })
                    else if (p.domain > 0)
                        try std.fmt.allocPrint(gpa, "P{d}p{d}s{d}", .{ p.domain, p.bus, p.dev })
                    else if (p.func > 0 or multifunction)
                        try std.fmt.allocPrint(gpa, "p{d}s{d}f{d}", .{ p.bus, p.dev, p.func })
                    else
                        try std.fmt.allocPrint(gpa, "p{d}s{d}", .{ p.bus, p.dev });
                    defer gpa.free(pci_str);

                    const usb_suffix = if (usb_sysname) |usn|
                        try buildUsbSuffix(gpa, usn)
                    else
                        try gpa.dupe(u8, "");
                    defer gpa.free(usb_suffix);

                    const full = try std.fmt.allocPrint(gpa, "{s}{s}{s}{s}", .{ prefix, pci_str, port_suffix, usb_suffix });
                    defer gpa.free(full);
                    try state.setProperty("ID_NET_NAME_PATH", full);

                    // ID_NET_NAME_ONBOARD: prefix ++ "o" ++ index ++ port_suffix (n.../d...).
                    if (index_val) |idx| {
                        const onboard_name = try std.fmt.allocPrint(gpa, "{s}o{d}{s}", .{ prefix, idx, port_suffix });
                        defer gpa.free(onboard_name);
                        try state.setProperty("ID_NET_NAME_ONBOARD", onboard_name);
                    }

                    // ID_NET_LABEL_ONBOARD: verbatim label string from the PCI function.
                    if (label_owned) |lv| {
                        try state.setProperty("ID_NET_LABEL_ONBOARD", lv);
                    }

                    // ID_NET_NAME_SLOT: hotplug slot name built from the PCI slot number.
                    // Slot number comes from /sys/bus/pci/slots (PRIMARY) or firmware_node/sun (FALLBACK).
                    // Format: prefix ++ ["P{domain}" if domain>0] ++ "s" ++ slot
                    //         ++ ["f{func}" if func>0 or multifunction] ++ usb_suffix.
                    slot_blk: {
                        const slot = (try pciSlotNumber(
                            dev.ctx.io,
                            gpa,
                            p.domain,
                            p.bus,
                            p.dev,
                            pci_syspath_owned,
                        )) orelse break :slot_blk;
                        defer gpa.free(slot);

                        var sn: std.ArrayListUnmanaged(u8) = .empty;
                        defer sn.deinit(gpa);

                        try sn.appendSlice(gpa, prefix);
                        if (p.domain > 0) {
                            var db: [16]u8 = undefined;
                            const dp = try std.fmt.bufPrint(&db, "P{d}", .{p.domain});
                            try sn.appendSlice(gpa, dp);
                        }
                        try sn.appendSlice(gpa, "s");
                        try sn.appendSlice(gpa, slot);
                        if (p.func > 0 or multifunction) {
                            var fb: [16]u8 = undefined;
                            const fp = try std.fmt.bufPrint(&fb, "f{d}", .{p.func});
                            try sn.appendSlice(gpa, fp);
                        }
                        try sn.appendSlice(gpa, port_suffix);
                        try sn.appendSlice(gpa, usb_suffix);

                        const slot_name = try sn.toOwnedSlice(gpa);
                        defer gpa.free(slot_name);
                        try state.setProperty("ID_NET_NAME_SLOT", slot_name);
                    }
                } else {
                    pd.deinit();
                }
                break :path;
            }

            // Record the first usb_interface (subsystem "usb", sysname contains ':').
            if (usb_sysname == null and
                sub != null and std.mem.eql(u8, sub.?, "usb") and
                std.mem.indexOfScalar(u8, pd.sysname(), ':') != null)
            {
                // Dupe before pd is deinit'd. On OOM, deinit pd first (it is owned here).
                usb_sysname = gpa.dupe(u8, pd.sysname()) catch |err| {
                    pd.deinit();
                    return err;
                };
            }

            const next = pd.parent() catch |err| {
                pd.deinit();
                return err;
            };
            pd.deinit();
            maybe_parent = next;
        }
    }
}

// Tests

test "net_id: pci->net sets MAC, PATH, and SCHEME" {
    const testfs = @import("../testfs.zig");
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const syspath = try testfs.makeTopology(&tmp, &.{
        .{ .name = "0003:05:00.0", .subsystem = "pci" },
        .{ .name = "eno2", .subsystem = "net", .attrs = &.{
            .{ "type", "1" },
            .{ "address", "9c:6b:00:4b:11:91" },
            .{ "addr_assign_type", "0" },
        } },
    });
    defer gpa.free(syspath);

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(gpa, &dev, &state, "");

    try std.testing.expectEqualStrings("v260", state.getProperty("ID_NET_NAMING_SCHEME").?);
    try std.testing.expectEqualStrings("enx9c6b004b1191", state.getProperty("ID_NET_NAME_MAC").?);
    try std.testing.expectEqualStrings("enP3p5s0", state.getProperty("ID_NET_NAME_PATH").?);
}

test "net_id: func>0 appends f suffix in PATH" {
    const testfs = @import("../testfs.zig");
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const syspath = try testfs.makeTopology(&tmp, &.{
        .{ .name = "0003:03:00.1", .subsystem = "pci" },
        .{ .name = "eno2", .subsystem = "net", .attrs = &.{
            .{ "type", "1" },
            .{ "address", "9c:6b:00:4b:11:91" },
            .{ "addr_assign_type", "0" },
        } },
    });
    defer gpa.free(syspath);

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(gpa, &dev, &state, "");

    try std.testing.expectEqualStrings("enP3p3s0f1", state.getProperty("ID_NET_NAME_PATH").?);
    try std.testing.expectEqualStrings("v260", state.getProperty("ID_NET_NAMING_SCHEME").?);
}

test "net_id: random-assigned MAC (addr_assign_type=1) is not emitted; SCHEME and PATH still set" {
    const testfs = @import("../testfs.zig");
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const syspath = try testfs.makeTopology(&tmp, &.{
        .{ .name = "0003:05:00.0", .subsystem = "pci" },
        .{ .name = "eno2", .subsystem = "net", .attrs = &.{
            .{ "type", "1" },
            .{ "address", "9c:6b:00:4b:11:91" },
            .{ "addr_assign_type", "1" },
        } },
    });
    defer gpa.free(syspath);

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(gpa, &dev, &state, "");

    try std.testing.expect(state.getProperty("ID_NET_NAME_MAC") == null);
    try std.testing.expectEqualStrings("v260", state.getProperty("ID_NET_NAMING_SCHEME").?);
    try std.testing.expectEqualStrings("enP3p5s0", state.getProperty("ID_NET_NAME_PATH").?);
}

test "net_id: pci->usb_interface->net PATH has USB suffix" {
    const testfs = @import("../testfs.zig");
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Topology: pci "0003:04:00.0" -> usb_interface "1-2.3.1:2.0" -> net leaf.
    // Expected PATH: "en" ++ "P3p4s0" ++ "u2u3u1c2" = "enP3p4s0u2u3u1c2".
    const syspath = try testfs.makeTopology(&tmp, &.{
        .{ .name = "0003:04:00.0", .subsystem = "pci" },
        .{ .name = "1-2.3.1:2.0", .subsystem = "usb" },
        .{ .name = "eth0", .subsystem = "net", .attrs = &.{
            .{ "type", "1" },
            .{ "address", "9c:6b:00:4b:11:aa" },
            .{ "addr_assign_type", "0" },
        } },
    });
    defer gpa.free(syspath);

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(gpa, &dev, &state, "");

    try std.testing.expectEqualStrings("v260", state.getProperty("ID_NET_NAMING_SCHEME").?);
    try std.testing.expectEqualStrings("enP3p4s0u2u3u1c2", state.getProperty("ID_NET_NAME_PATH").?);
    try std.testing.expectEqualStrings("enx9c6b004b11aa", state.getProperty("ID_NET_NAME_MAC").?);
}

test "net_id: virtual device (no pci ancestor) sets only SCHEME" {
    const testfs = @import("../testfs.zig");
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Single-level net device with no PCI/USB ancestor: virtual device.
    const syspath = try testfs.makeTopology(&tmp, &.{
        .{ .name = "docker0", .subsystem = "net", .attrs = &.{
            .{ "type", "1" },
        } },
    });
    defer gpa.free(syspath);

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(gpa, &dev, &state, "");

    try std.testing.expectEqualStrings("v260", state.getProperty("ID_NET_NAMING_SCHEME").?);
    try std.testing.expect(state.getProperty("ID_NET_NAME_MAC") == null);
    try std.testing.expect(state.getProperty("ID_NET_NAME_PATH") == null);
}

test "net_id: onboard index and label set ONBOARD and LABEL_ONBOARD" {
    const testfs = @import("../testfs.zig");
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // PCI function with acpi index=2 and label, single-function so PATH has no f suffix.
    const syspath = try testfs.makeTopology(&tmp, &.{
        .{ .name = "0003:05:00.0", .subsystem = "pci", .attrs = &.{
            .{ "index", "2" },
            .{ "label", "1G LAN" },
        } },
        .{ .name = "eno2", .subsystem = "net", .attrs = &.{
            .{ "type", "1" },
            .{ "address", "9c:6b:00:4b:11:91" },
            .{ "addr_assign_type", "0" },
        } },
    });
    defer gpa.free(syspath);

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(gpa, &dev, &state, "");

    try std.testing.expectEqualStrings("v260", state.getProperty("ID_NET_NAMING_SCHEME").?);
    // Single-function: PATH must NOT have f suffix.
    try std.testing.expectEqualStrings("enP3p5s0", state.getProperty("ID_NET_NAME_PATH").?);
    // ONBOARD: prefix "en" + "o" + "2" = "eno2".
    try std.testing.expectEqualStrings("eno2", state.getProperty("ID_NET_NAME_ONBOARD").?);
    // LABEL passes through verbatim.
    try std.testing.expectEqualStrings("1G LAN", state.getProperty("ID_NET_LABEL_ONBOARD").?);
}

test "net_id: multifunction pci device gets f0 suffix in PATH" {
    const testfs = @import("../testfs.zig");
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // PCI function 0 of a multifunction device. The sibling "0003:03:00.1" is
    // created manually so isMultifunction counts 2 entries and returns true.
    const syspath = try testfs.makeTopology(&tmp, &.{
        .{ .name = "0003:03:00.0", .subsystem = "pci" },
        .{ .name = "eth_mf", .subsystem = "net", .attrs = &.{
            .{ "type", "1" },
            .{ "address", "9c:6b:00:4b:11:92" },
            .{ "addr_assign_type", "0" },
        } },
    });
    defer gpa.free(syspath);

    // Create a sibling directory at the same level as "0003:03:00.0" so that
    // isMultifunction sees 2 entries with prefix "0003:03:00." and returns true.
    try tmp.dir.createDirPath(io, "devices/0003:03:00.1");

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(gpa, &dev, &state, "");

    try std.testing.expectEqualStrings("v260", state.getProperty("ID_NET_NAMING_SCHEME").?);
    // Multifunction func-0: PATH must include f0.
    try std.testing.expectEqualStrings("enP3p3s0f0", state.getProperty("ID_NET_NAME_PATH").?);
}

test "net_id: firmware_node/sun sets ID_NET_NAME_SLOT" {
    const testfs = @import("../testfs.zig");
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // PCI "0003:05:00.0" with firmware_node/sun="4" -> net leaf (type 1, global addr).
    // Expected SLOT: "en" ++ "P3" ++ "s4" = "enP3s4".
    const syspath = try testfs.makeTopology(&tmp, &.{
        .{ .name = "0003:05:00.0", .subsystem = "pci", .attrs = &.{
            .{ "firmware_node/sun", "4" },
        } },
        .{ .name = "eno2", .subsystem = "net", .attrs = &.{
            .{ "type", "1" },
            .{ "address", "9c:6b:00:4b:11:91" },
            .{ "addr_assign_type", "0" },
        } },
    });
    defer gpa.free(syspath);

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(gpa, &dev, &state, "");

    try std.testing.expectEqualStrings("v260", state.getProperty("ID_NET_NAMING_SCHEME").?);
    try std.testing.expectEqualStrings("enP3p5s0", state.getProperty("ID_NET_NAME_PATH").?);
    try std.testing.expectEqualStrings("enP3s4", state.getProperty("ID_NET_NAME_SLOT").?);
}

test "net_id: multifunction + firmware_node/sun sets SLOT with f suffix" {
    const testfs = @import("../testfs.zig");
    const context = @import("../context.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // PCI "0003:03:00.0" func-0, multifunction, firmware_node/sun="2".
    // Sibling "0003:03:00.1" makes isMultifunction return true.
    // Expected SLOT: "en" ++ "P3" ++ "s2" ++ "f0" = "enP3s2f0".
    const syspath = try testfs.makeTopology(&tmp, &.{
        .{ .name = "0003:03:00.0", .subsystem = "pci", .attrs = &.{
            .{ "firmware_node/sun", "2" },
        } },
        .{ .name = "eth_mf", .subsystem = "net", .attrs = &.{
            .{ "type", "1" },
            .{ "address", "9c:6b:00:4b:11:92" },
            .{ "addr_assign_type", "0" },
        } },
    });
    defer gpa.free(syspath);

    // Create the sibling dir so isMultifunction counts 2 peers and returns true.
    try tmp.dir.createDirPath(io, "devices/0003:03:00.1");

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(gpa, &dev, &state, "");

    try std.testing.expectEqualStrings("v260", state.getProperty("ID_NET_NAMING_SCHEME").?);
    // Multifunction func-0: PATH must have f0.
    try std.testing.expectEqualStrings("enP3p3s0f0", state.getProperty("ID_NET_NAME_PATH").?);
    // SLOT: same multifunction flag applies.
    try std.testing.expectEqualStrings("enP3s2f0", state.getProperty("ID_NET_NAME_SLOT").?);
}

test "net_id: integration eno2 (skipped when absent)" {
    const context = @import("../context.zig");
    const io = std.testing.io;
    const gpa = std.testing.allocator;

    // Skip if eno2 is not present on this machine.
    std.Io.Dir.cwd().access(io, "/sys/class/net/eno2", .{}) catch return;

    // Resolve the class symlink to the actual device directory.
    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = std.Io.Dir.cwd().realPathFile(io, "/sys/class/net/eno2", &rp_buf) catch return;
    const syspath = rp_buf[0..n];

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    try run(gpa, &dev, &state, "");

    try std.testing.expectEqualStrings("v260", state.getProperty("ID_NET_NAMING_SCHEME").?);
    // eno2 has a PCI ancestor so PATH must be set and must start with "enP".
    const path = state.getProperty("ID_NET_NAME_PATH") orelse return error.MissingPath;
    try std.testing.expect(std.mem.startsWith(u8, path, "enP"));
    // When ONBOARD is set (confirmed firmware name present), also assert SLOT.
    if (state.getProperty("ID_NET_NAME_ONBOARD")) |onboard| {
        try std.testing.expectEqualStrings("eno2", onboard);
        const slot = state.getProperty("ID_NET_NAME_SLOT") orelse return error.MissingSlot;
        try std.testing.expectEqualStrings("enP3s4", slot);
    }
}
