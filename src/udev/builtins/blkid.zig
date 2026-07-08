/// blkid builtin: identify filesystem superblocks and set ID_FS_* properties.
/// Thin adapter over the external blkid.zig package (zero C deps).
const std = @import("std");
const blkid = @import("blkid");
const encode = @import("encode.zig");
const Device = @import("../device.zig").Device;
const EventState = @import("../rules/runner.zig").EventState;

/// Map the values from a completed probe into ID_FS_* properties on `state`.
/// The probe must have already run safeprobe() or fullprobe() successfully.
pub fn mapSuperblock(
    gpa: std.mem.Allocator,
    probe: *const blkid.Probe,
    state: *EventState,
) !void {
    // Map plain tag names -> property names.
    for (probe.values()) |v| {
        const prop: []const u8 = if (std.mem.eql(u8, v.name, "TYPE"))
            "ID_FS_TYPE"
        else if (std.mem.eql(u8, v.name, "USAGE"))
            "ID_FS_USAGE"
        else if (std.mem.eql(u8, v.name, "VERSION"))
            "ID_FS_VERSION"
        else if (std.mem.eql(u8, v.name, "SEC_TYPE"))
            "ID_FS_SEC_TYPE"
        else if (std.mem.eql(u8, v.name, "UUID"))
            "ID_FS_UUID"
        else if (std.mem.eql(u8, v.name, "UUID_SUB"))
            "ID_FS_UUID_SUB"
        else if (std.mem.eql(u8, v.name, "LABEL"))
            "ID_FS_LABEL"
        else
            // Skip _RAW tags and any unrecognised name.
            continue;

        try state.setProperty(prop, v.data);
    }

    // _ENC variants: encode the raw (or plain) value for LABEL, UUID, UUID_SUB.
    if (probe.lookup("LABEL") != null) {
        const src = probe.lookup("LABEL_RAW") orelse probe.lookup("LABEL").?;
        const enc = try encode.encodeString(gpa, src);
        defer gpa.free(enc);
        try state.setProperty("ID_FS_LABEL_ENC", enc);
    }

    if (probe.lookup("UUID") != null) {
        const src = probe.lookup("UUID_RAW") orelse probe.lookup("UUID").?;
        const enc = try encode.encodeString(gpa, src);
        defer gpa.free(enc);
        try state.setProperty("ID_FS_UUID_ENC", enc);
    }

    if (probe.lookup("UUID_SUB") != null) {
        const src = probe.lookup("UUID_SUB_RAW") orelse probe.lookup("UUID_SUB").?;
        const enc = try encode.encodeString(gpa, src);
        defer gpa.free(enc);
        try state.setProperty("ID_FS_UUID_SUB_ENC", enc);
    }
}

/// Map PTTYPE/PTUUID from a completed partition probe into ID_PART_TABLE_* properties on `state`.
/// The probe must have already run safeprobe() or fullprobe() successfully.
/// Per-partition ID_PART_ENTRY_* is emitted by mapPartitionEntry (see below).
pub fn mapPartitionTable(
    _: std.mem.Allocator,
    probe: *const blkid.Probe,
    state: *EventState,
) !void {
    if (probe.lookup("PTTYPE")) |v| {
        try state.setProperty("ID_PART_TABLE_TYPE", v);
    }
    if (probe.lookup("PTUUID")) |v| {
        try state.setProperty("ID_PART_TABLE_UUID", v);
    }
}

/// Emit ID_PART_ENTRY_* for the partition numbered `number`, found in `parts` (the parent disk's
/// partition table). `scheme` is the parent's PTTYPE (gpt/dos), `disk_devnum` is "maj:min" of the parent.
pub fn mapPartitionEntry(
    gpa: std.mem.Allocator,
    state: *EventState,
    number: u32,
    parts: []const blkid.Partition,
    scheme: ?[]const u8,
    disk_devnum: ?[]const u8,
) !void {
    for (parts) |p| {
        if (p.number != number) continue;
        if (scheme) |s| try state.setProperty("ID_PART_ENTRY_SCHEME", s);
        const num_str = try std.fmt.allocPrint(gpa, "{d}", .{p.number});
        defer gpa.free(num_str);
        try state.setProperty("ID_PART_ENTRY_NUMBER", num_str);
        const off_str = try std.fmt.allocPrint(gpa, "{d}", .{p.start});
        defer gpa.free(off_str);
        try state.setProperty("ID_PART_ENTRY_OFFSET", off_str);
        const size_str = try std.fmt.allocPrint(gpa, "{d}", .{p.size});
        defer gpa.free(size_str);
        try state.setProperty("ID_PART_ENTRY_SIZE", size_str);
        try state.setProperty("ID_PART_ENTRY_TYPE", p.type_str);
        if (p.uuid) |u| try state.setProperty("ID_PART_ENTRY_UUID", u);
        if (p.name) |n| try state.setProperty("ID_PART_ENTRY_NAME", n);
        if (disk_devnum) |d| try state.setProperty("ID_PART_ENTRY_DISK", d);
        return;
    }
}

/// Builtin entry point called by the builtins registry.
pub fn run(
    gpa: std.mem.Allocator,
    dev: *Device,
    state: *EventState,
    args: []const u8,
) anyerror!void {
    _ = args;

    const node = dev.devnode() orelse return;
    const io = dev.ctx.io;

    // Superblock probe via seekable FileSource (no whole-device read into RAM).
    {
        var file = std.Io.Dir.cwd().openFile(io, node, .{}) catch return;
        defer file.close(io);
        var rbuf: [8192]u8 = undefined;
        var reader = file.reader(io, &rbuf);
        var fs = blkid.FileSource.init(&reader);
        const src = fs.source() catch return;
        var probe = blkid.newProbe(gpa, src) catch return;
        defer probe.deinit();
        probe.safeprobe() catch |e| switch (e) {
            error.NotFound => {}, // nothing recognized; leave FS props unset
            // error.Ambiguous (and any other): keep whatever values were stored and proceed,
            // matching systemd's tolerant behavior.
            else => {},
        };
        try mapSuperblock(gpa, &probe, state);
    }

    // Partition table probe via a fresh seekable FileSource.
    pt: {
        var file2 = std.Io.Dir.cwd().openFile(io, node, .{}) catch break :pt;
        defer file2.close(io);
        var rbuf2: [8192]u8 = undefined;
        var reader2 = file2.reader(io, &rbuf2);
        var fs2 = blkid.FileSource.init(&reader2);
        const src2 = fs2.source() catch break :pt;
        var pprobe = blkid.newPartitionProbe(gpa, src2) catch break :pt;
        defer pprobe.deinit();
        pprobe.fullprobe() catch break :pt;
        try mapPartitionTable(gpa, &pprobe, state);
    }

    // Partition entry: if this device is a partition, probe the PARENT disk's table and match our number.
    pe: {
        const part_attr = (dev.getSysattr("partition") catch break :pe) orelse break :pe; // not a partition
        const number = std.fmt.parseInt(u32, std.mem.trim(u8, part_attr, " \t\r\n"), 10) catch break :pe;
        var parent = (dev.parent() catch break :pe) orelse break :pe;
        defer parent.deinit();
        const disk_node = parent.devnode() orelse break :pe;

        var file3 = std.Io.Dir.cwd().openFile(io, disk_node, .{}) catch break :pe;
        defer file3.close(io);
        var rbuf3: [8192]u8 = undefined;
        var reader3 = file3.reader(io, &rbuf3);
        var fs3 = blkid.FileSource.init(&reader3);
        const src3 = fs3.source() catch break :pe;
        var pprobe3 = blkid.newPartitionProbe(gpa, src3) catch break :pe;
        defer pprobe3.deinit();
        pprobe3.fullprobe() catch break :pe;

        const scheme = pprobe3.lookup("PTTYPE");
        var dbuf: [64]u8 = undefined;
        const disk_devnum: ?[]const u8 = blk: {
            const maj = parent.getProperty("MAJOR") orelse break :blk null;
            const min = parent.getProperty("MINOR") orelse break :blk null;
            break :blk std.fmt.bufPrint(&dbuf, "{s}:{s}", .{ maj, min }) catch null;
        };
        try mapPartitionEntry(gpa, state, number, pprobe3.partitionList(), scheme, disk_devnum);
    }
}

// Tests

test "blkid: mapSuperblock ext4 fixture sets ID_FS_TYPE, ID_FS_LABEL, ID_FS_UUID, ID_FS_UUID_ENC" {
    const gpa = std.testing.allocator;

    // Build a minimal ext4 superblock in a 2048-byte buffer.
    // Magic at offset 1080-1081, incompat flags at 1120-1124, UUID at 1128-1144, label at 1144.
    var buf = [_]u8{0} ** 2048;
    buf[1080] = 0x53;
    buf[1081] = 0xEF;
    std.mem.writeInt(u32, buf[1120..1124], 0x40, .little); // EXTENTS -> ext4
    const uuid = [16]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 };
    @memcpy(buf[1128..1144], &uuid);
    @memcpy(buf[1144 .. 1144 + 4], "ROOT");

    var bs = blkid.BufferSource.init(&buf);
    var probe = try blkid.newProbe(gpa, bs.source());
    defer probe.deinit();
    try probe.safeprobe();

    var state = EventState.init(gpa);
    defer state.deinit();

    try mapSuperblock(gpa, &probe, &state);

    try std.testing.expectEqualStrings("ext4", state.getProperty("ID_FS_TYPE").?);
    try std.testing.expectEqualStrings("ROOT", state.getProperty("ID_FS_LABEL").?);
    try std.testing.expect(state.getProperty("ID_FS_UUID") != null);
    try std.testing.expect(state.getProperty("ID_FS_UUID_ENC") != null);
}

test "blkid: mapPartitionEntry match sets all ID_PART_ENTRY_* properties" {
    const gpa = std.testing.allocator;

    var state = EventState.init(gpa);
    defer state.deinit();

    const parts = [_]blkid.Partition{
        .{ .number = 1, .start = 2048, .size = 40960, .type_str = "0x83" },
        .{ .number = 2, .start = 43008, .size = 40960, .type_str = "0x83", .name = "boot", .uuid = "abc" },
    };
    try mapPartitionEntry(gpa, &state, 2, &parts, "gpt", "8:0");
    try std.testing.expectEqualStrings("2", state.getProperty("ID_PART_ENTRY_NUMBER").?);
    try std.testing.expectEqualStrings("43008", state.getProperty("ID_PART_ENTRY_OFFSET").?);
    try std.testing.expectEqualStrings("40960", state.getProperty("ID_PART_ENTRY_SIZE").?);
    try std.testing.expectEqualStrings("0x83", state.getProperty("ID_PART_ENTRY_TYPE").?);
    try std.testing.expectEqualStrings("boot", state.getProperty("ID_PART_ENTRY_NAME").?);
    try std.testing.expectEqualStrings("abc", state.getProperty("ID_PART_ENTRY_UUID").?);
    try std.testing.expectEqualStrings("gpt", state.getProperty("ID_PART_ENTRY_SCHEME").?);
    try std.testing.expectEqualStrings("8:0", state.getProperty("ID_PART_ENTRY_DISK").?);
}

test "blkid: mapPartitionEntry no match sets no properties" {
    const gpa = std.testing.allocator;

    var state = EventState.init(gpa);
    defer state.deinit();

    const parts = [_]blkid.Partition{
        .{ .number = 1, .start = 2048, .size = 40960, .type_str = "0x83" },
        .{ .number = 2, .start = 43008, .size = 40960, .type_str = "0x83", .name = "boot", .uuid = "abc" },
    };
    try mapPartitionEntry(gpa, &state, 99, &parts, "gpt", "8:0");
    try std.testing.expect(state.getProperty("ID_PART_ENTRY_NUMBER") == null);
    try std.testing.expect(state.getProperty("ID_PART_ENTRY_OFFSET") == null);
    try std.testing.expect(state.getProperty("ID_PART_ENTRY_SIZE") == null);
    try std.testing.expect(state.getProperty("ID_PART_ENTRY_TYPE") == null);
    try std.testing.expect(state.getProperty("ID_PART_ENTRY_UUID") == null);
    try std.testing.expect(state.getProperty("ID_PART_ENTRY_NAME") == null);
    try std.testing.expect(state.getProperty("ID_PART_ENTRY_SCHEME") == null);
    try std.testing.expect(state.getProperty("ID_PART_ENTRY_DISK") == null);
}

test "blkid: mapPartitionEntry minimal entry sets NUMBER/OFFSET/SIZE/TYPE/SCHEME/DISK but not UUID/NAME" {
    const gpa = std.testing.allocator;

    var state = EventState.init(gpa);
    defer state.deinit();

    const parts = [_]blkid.Partition{
        .{ .number = 1, .start = 2048, .size = 40960, .type_str = "0x83" },
        .{ .number = 2, .start = 43008, .size = 40960, .type_str = "0x83", .name = "boot", .uuid = "abc" },
    };
    try mapPartitionEntry(gpa, &state, 1, &parts, "dos", "8:0");
    try std.testing.expectEqualStrings("1", state.getProperty("ID_PART_ENTRY_NUMBER").?);
    try std.testing.expectEqualStrings("2048", state.getProperty("ID_PART_ENTRY_OFFSET").?);
    try std.testing.expectEqualStrings("40960", state.getProperty("ID_PART_ENTRY_SIZE").?);
    try std.testing.expectEqualStrings("0x83", state.getProperty("ID_PART_ENTRY_TYPE").?);
    try std.testing.expectEqualStrings("dos", state.getProperty("ID_PART_ENTRY_SCHEME").?);
    try std.testing.expectEqualStrings("8:0", state.getProperty("ID_PART_ENTRY_DISK").?);
    try std.testing.expect(state.getProperty("ID_PART_ENTRY_UUID") == null);
    try std.testing.expect(state.getProperty("ID_PART_ENTRY_NAME") == null);
}

test "blkid: mapPartitionTable DOS fixture sets ID_PART_TABLE_TYPE and ID_PART_TABLE_UUID" {
    const gpa = std.testing.allocator;

    // DOS partition table fixture. Copied from blkid.zig's partitions/integration_test.zig.
    var buf = [_]u8{0} ** 512;
    std.mem.writeInt(u32, buf[440..444], 0xdeadbeef, .little); // disk signature -> PTUUID="deadbeef"
    buf[446 + 4] = 0x83; // partition type: Linux
    std.mem.writeInt(u32, buf[454..458], 2048, .little); // LBA start
    std.mem.writeInt(u32, buf[458..462], 20480, .little); // LBA size
    buf[510] = 0x55;
    buf[511] = 0xAA; // MBR magic

    var bs = blkid.BufferSource.init(&buf);
    var pprobe = try blkid.newPartitionProbe(gpa, bs.source());
    defer pprobe.deinit();
    try pprobe.fullprobe();

    var state = EventState.init(gpa);
    defer state.deinit();

    try mapPartitionTable(gpa, &pprobe, &state);

    try std.testing.expectEqualStrings("dos", state.getProperty("ID_PART_TABLE_TYPE").?);
    try std.testing.expectEqualStrings("deadbeef", state.getProperty("ID_PART_TABLE_UUID").?);
}
