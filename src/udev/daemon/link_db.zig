//! link_db.zig - /run/udev/links symlink priority arbitration.
//! When multiple devices claim the same symlink the device with the highest
//! link_priority wins.  Stamp files under
//! <run_root>/links/<escaped_symlink>/<devid> record each active claim.
const std = @import("std");

/// Escape a symlink relative path into a single filename (reversible enough
/// for our own read/write): replace every '/' with the 4-char sequence "\x2f";
/// other bytes pass through.  gpa-owned; caller frees.
pub fn escapeLinkName(gpa: std.mem.Allocator, symlink: []const u8) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(gpa);
    for (symlink) |c| {
        if (c == '/') try out.appendSlice(gpa, "\\x2f") else try out.append(gpa, c);
    }
    return out.toOwnedSlice(gpa);
}

/// Record that `devid` (with `priority`) claims `symlink`, whose target node
/// basename is `target`.
/// Writes <run_root>/links/<escaped>/<devid> = "<priority>\n<target>\n".
pub fn claim(
    io: std.Io,
    gpa: std.mem.Allocator,
    run_root: []const u8,
    symlink: []const u8,
    devid: []const u8,
    priority: i32,
    target: []const u8,
) !void {
    const escaped = try escapeLinkName(gpa, symlink);
    defer gpa.free(escaped);

    const dir_path = try std.fmt.allocPrint(gpa, "{s}/links/{s}", .{ run_root, escaped });
    defer gpa.free(dir_path);

    try std.Io.Dir.cwd().createDirPath(io, dir_path);

    const stamp_path = try std.fmt.allocPrint(gpa, "{s}/{s}", .{ dir_path, devid });
    defer gpa.free(stamp_path);

    const tmp_path = try std.fmt.allocPrint(gpa, "{s}.tmp", .{stamp_path});
    defer gpa.free(tmp_path);

    const content = try std.fmt.allocPrint(gpa, "{d}\n{s}\n", .{ priority, target });
    defer gpa.free(content);

    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = tmp_path, .data = content });
    try std.Io.Dir.renameAbsolute(tmp_path, stamp_path, io);
}

/// Remove `devid`'s claim on `symlink` (best-effort; does not return errors).
pub fn release(
    io: std.Io,
    gpa: std.mem.Allocator,
    run_root: []const u8,
    symlink: []const u8,
    devid: []const u8,
) void {
    const escaped = escapeLinkName(gpa, symlink) catch return;
    defer gpa.free(escaped);

    const stamp_path = std.fmt.allocPrint(
        gpa,
        "{s}/links/{s}/{s}",
        .{ run_root, escaped, devid },
    ) catch return;
    defer gpa.free(stamp_path);

    std.Io.Dir.cwd().deleteFile(io, stamp_path) catch {};
}

/// Return the target node basename of the highest-priority current claimant
/// of `symlink`, or null if there are no claimants.
/// The returned slice is gpa-owned; caller must free it.
/// Ties: any max-priority claimant is acceptable.
pub fn resolveOwner(
    gpa: std.mem.Allocator,
    io: std.Io,
    run_root: []const u8,
    symlink: []const u8,
) !?[]u8 {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const aa = arena.allocator();

    const escaped = try escapeLinkName(aa, symlink);
    const dir_path = try std.fmt.allocPrint(aa, "{s}/links/{s}", .{ run_root, escaped });

    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch return null;
    defer dir.close(io);

    var it = dir.iterate();

    var best_priority: i32 = 0;
    var best_target: ?[]const u8 = null;
    var found_any = false;

    while (it.next(io) catch null) |entry| {
        if (entry.name.len == 0 or entry.name[0] == '.') continue;
        // Skip a leftover ".tmp" stamp from a failed rename so it never participates in arbitration.
        if (std.mem.endsWith(u8, entry.name, ".tmp")) continue;

        const stamp_path = try std.fmt.allocPrint(aa, "{s}/{s}", .{ dir_path, entry.name });
        const content = std.Io.Dir.cwd().readFileAlloc(
            io,
            stamp_path,
            aa,
            .limited(4096),
        ) catch continue;

        var lines = std.mem.tokenizeScalar(u8, content, '\n');
        const prio_str = lines.next() orelse continue;
        const target_str = lines.next() orelse continue;

        const prio = std.fmt.parseInt(i32, prio_str, 10) catch continue;

        if (!found_any or prio > best_priority) {
            best_priority = prio;
            best_target = target_str;
            found_any = true;
        }
    }

    if (best_target) |t| {
        return try gpa.dupe(u8, t);
    }
    return null;
}

// Tests

test "escapeLinkName replaces slashes" {
    const gpa = std.testing.allocator;
    const result = try escapeLinkName(gpa, "disk/by-id/x");
    defer gpa.free(result);
    try std.testing.expectEqualStrings("disk\\x2fby-id\\x2fx", result);
}

test "escapeLinkName no slashes" {
    const gpa = std.testing.allocator;
    const result = try escapeLinkName(gpa, "cdrom");
    defer gpa.free(result);
    try std.testing.expectEqualStrings("cdrom", result);
}

test "claim resolveOwner release priority" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const rp = rp_buf[0..n];

    // Two devices claim "cdrom": b11:0 at priority 10, b11:1 at priority 20.
    try claim(io, gpa, rp, "cdrom", "b11:0", 10, "sr0");
    try claim(io, gpa, rp, "cdrom", "b11:1", 20, "sr1");

    // Priority 20 wins.
    const winner1 = (try resolveOwner(gpa, io, rp, "cdrom")).?;
    defer gpa.free(winner1);
    try std.testing.expectEqualStrings("sr1", winner1);

    // Release the winner. Priority 10 now holds.
    release(io, gpa, rp, "cdrom", "b11:1");

    const winner2 = (try resolveOwner(gpa, io, rp, "cdrom")).?;
    defer gpa.free(winner2);
    try std.testing.expectEqualStrings("sr0", winner2);

    // Release all. No claimants remain.
    release(io, gpa, rp, "cdrom", "b11:0");

    const winner3 = try resolveOwner(gpa, io, rp, "cdrom");
    try std.testing.expect(winner3 == null);
}

test "resolveOwner missing dir returns null" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, ".", &rp_buf);
    const rp = rp_buf[0..n];

    const result = try resolveOwner(gpa, io, rp, "nonexistent/link");
    try std.testing.expect(result == null);
}
