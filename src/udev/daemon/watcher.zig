//! watcher.zig - inotify-based device-node watcher.
//! Tracks OPTIONS+="watch" nodes and fires a re-trigger (change event) when
//! the node is closed after a write (IN_CLOSE_WRITE). inotify is unprivileged
//! so this module is fully testable without root.
const std = @import("std");
const linux = std.os.linux;

pub const Watcher = struct {
    fd_: i32,
    /// wd -> syspath (gpa-owned dup). Watches are added via addWatch; the fd
    /// being closed on deinit implicitly removes all kernel watches.
    watches: std.AutoHashMapUnmanaged(i32, []const u8) = .empty,

    /// Open an inotify fd (NONBLOCK | CLOEXEC). Returns error.PermissionDenied
    /// if the kernel denies the syscall (should not happen in practice).
    pub fn init() !Watcher {
        const rc = linux.inotify_init1(linux.IN.NONBLOCK | linux.IN.CLOEXEC);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .ACCES, .PERM => return error.PermissionDenied,
            else => |e| return std.posix.unexpectedErrno(e),
        }
        return .{ .fd_ = @intCast(rc) };
    }

    /// Watch `devnode_path` for IN_CLOSE_WRITE; remember `syspath` for re-triggering.
    /// Best-effort: if the node does not exist or cannot be watched, return error.WatchFailed
    /// so the caller can ignore it with `catch {}`.
    pub fn addWatch(
        self: *Watcher,
        gpa: std.mem.Allocator,
        devnode_path: []const u8,
        syspath: []const u8,
    ) !void {
        const pathZ = try std.fmt.allocPrintSentinel(gpa, "{s}", .{devnode_path}, 0);
        defer gpa.free(pathZ);
        const rc = linux.inotify_add_watch(self.fd_, pathZ.ptr, linux.IN.CLOSE_WRITE);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            else => return error.WatchFailed,
        }
        const wd: i32 = @intCast(rc);
        // Re-watching the same inode returns the same wd, so free the old mapping first.
        if (self.watches.fetchRemove(wd)) |old| gpa.free(old.value);
        const duped = try gpa.dupe(u8, syspath);
        errdefer gpa.free(duped);
        try self.watches.put(gpa, wd, duped);
    }

    /// Drain pending inotify events and return the syspaths whose nodes were
    /// closed-after-write. Returns a gpa-owned slice; caller frees the slice AND
    /// each element string inside it.
    pub fn readEvents(self: *Watcher, gpa: std.mem.Allocator) ![][]const u8 {
        var result: std.ArrayListUnmanaged([]const u8) = .empty;
        errdefer {
            for (result.items) |s| gpa.free(s);
            result.deinit(gpa);
        }
        var buf: [4096]u8 align(@alignOf(linux.inotify_event)) = undefined;
        while (true) {
            const rc = linux.read(self.fd_, &buf, buf.len);
            switch (linux.errno(rc)) {
                .SUCCESS => {},
                .AGAIN => break, // no more events
                .INTR => continue,
                else => break,
            }
            const n: usize = @intCast(rc);
            if (n == 0) break;
            var off: usize = 0;
            while (off + @sizeOf(linux.inotify_event) <= n) {
                const ev: *const linux.inotify_event = @ptrCast(@alignCast(&buf[off]));
                off += @sizeOf(linux.inotify_event) + ev.len;
                // Only re-trigger on a genuine close-after-write. The kernel also delivers IN_IGNORED
                // (watch auto-removed on node deletion) regardless of the requested mask, so skip those.
                if (ev.mask & linux.IN.CLOSE_WRITE == 0) continue;
                if (self.watches.get(ev.wd)) |syspath| {
                    const duped = try gpa.dupe(u8, syspath);
                    errdefer gpa.free(duped);
                    try result.append(gpa, duped);
                }
            }
            if (n < buf.len) break; // likely fully drained
        }
        return result.toOwnedSlice(gpa);
    }

    /// Remove the watch (if any) registered for `syspath`: rm the kernel watch and free the map entry.
    pub fn removeBySyspath(self: *Watcher, gpa: std.mem.Allocator, syspath: []const u8) void {
        var target_wd: ?i32 = null;
        var it = self.watches.iterator();
        while (it.next()) |e| {
            if (std.mem.eql(u8, e.value_ptr.*, syspath)) {
                target_wd = e.key_ptr.*;
                break;
            }
        }
        if (target_wd) |wd| {
            _ = linux.inotify_rm_watch(self.fd_, wd);
            if (self.watches.fetchRemove(wd)) |old| gpa.free(old.value);
        }
    }

    /// Raw fd for poll integration.
    pub fn fd(self: *const Watcher) i32 {
        return self.fd_;
    }

    pub fn deinit(self: *Watcher, gpa: std.mem.Allocator) void {
        var it = self.watches.valueIterator();
        while (it.next()) |v| gpa.free(v.*);
        self.watches.deinit(gpa);
        if (self.fd_ >= 0) _ = linux.close(@intCast(self.fd_));
    }
};

// Tests

test "Watcher end-to-end: IN_CLOSE_WRITE fires after write+close" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var w = try Watcher.init();
    defer w.deinit(gpa);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Create the stand-in node file.
    try tmp.dir.writeFile(io, .{ .sub_path = "node", .data = "x" });

    // Get the absolute path of the file.
    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, "node", &rp_buf);
    const abs = rp_buf[0..n];

    // Register the watch.
    try w.addWatch(gpa, abs, "/sys/devices/fake/sda");

    // Write-then-close to trigger IN_CLOSE_WRITE.
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = abs, .data = "y" });

    // Drain events.
    const evs = try w.readEvents(gpa);
    defer {
        for (evs) |s| gpa.free(s);
        gpa.free(evs);
    }

    try std.testing.expect(evs.len >= 1);
    try std.testing.expectEqualStrings("/sys/devices/fake/sda", evs[0]);
}

test "addWatch on missing path returns WatchFailed" {
    const gpa = std.testing.allocator;

    var w = try Watcher.init();
    defer w.deinit(gpa);

    try std.testing.expectError(
        error.WatchFailed,
        w.addWatch(gpa, "/definitely/not/here/xyz", "/sys/x"),
    );
}

test "removeBySyspath: removes watch and frees map entry" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var w = try Watcher.init();
    defer w.deinit(gpa);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "node", .data = "x" });

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, "node", &rp_buf);
    const abs = rp_buf[0..n];

    try w.addWatch(gpa, abs, "/sys/x");
    try std.testing.expectEqual(@as(u32, 1), w.watches.count());

    w.removeBySyspath(gpa, "/sys/x");
    try std.testing.expectEqual(@as(u32, 0), w.watches.count());
}
