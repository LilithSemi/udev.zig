//! Runner interface, EventState, and FakeRunner for the udev rules engine.
//! No evaluation logic lives here, only types and the test double.
const std = @import("std");
const Device = @import("../device.zig").Device;

// Error set

pub const RunError = error{ ExecFailed, ImportFailed, OutOfMemory };

// RunEntry is one deferred action queued during rule evaluation.

pub const RunEntry = struct {
    kind: enum { program, builtin },
    command: []const u8,
};

// Options holds the per-device rule options accumulated during evaluation.

pub const Options = struct {
    link_priority: i32 = 0,
    watch: ?bool = null,
    db_persist: bool = false,
    string_escape: enum { none, replace } = .none,
    static_node: ?[]const u8 = null,
};

// PropEntry is a named key/value pair used by FakeRunner.

pub const PropEntry = struct { key: []const u8, val: []const u8 };

// EventState is the mutable state the evaluator builds up for one uevent.

pub const EventState = struct {
    arena: std.heap.ArenaAllocator,
    properties: std.StringHashMapUnmanaged([]const u8),
    name: ?[]const u8,
    symlinks: std.ArrayListUnmanaged([]const u8),
    owner: ?[]const u8,
    group: ?[]const u8,
    mode: ?u32,
    tags: std.StringHashMapUnmanaged(void),
    run_list: std.ArrayListUnmanaged(RunEntry),
    options: Options,
    last_result: ?[]const u8,
    locked: std.StringHashMapUnmanaged(void),

    pub fn init(gpa: std.mem.Allocator) EventState {
        return .{
            .arena = std.heap.ArenaAllocator.init(gpa),
            .properties = .empty,
            .name = null,
            .symlinks = .empty,
            .owner = null,
            .group = null,
            .mode = null,
            .tags = .empty,
            .run_list = .empty,
            .options = .{},
            .last_result = null,
            .locked = .empty,
        };
    }

    pub fn deinit(self: *EventState) void {
        self.arena.deinit();
    }

    /// Returns the arena allocator. Always call it fresh and never store the result.
    pub fn alloc(self: *EventState) std.mem.Allocator {
        return self.arena.allocator();
    }

    pub fn setProperty(self: *EventState, key: []const u8, val: []const u8) !void {
        const a = self.arena.allocator();
        const k = try a.dupe(u8, key);
        const v = try a.dupe(u8, val);
        try self.properties.put(a, k, v);
    }

    pub fn getProperty(self: *const EventState, key: []const u8) ?[]const u8 {
        return self.properties.get(key);
    }

    pub fn addSymlink(self: *EventState, s: []const u8) !void {
        for (self.symlinks.items) |existing| {
            if (std.mem.eql(u8, existing, s)) return;
        }
        const a = self.arena.allocator();
        const owned = try a.dupe(u8, s);
        try self.symlinks.append(a, owned);
    }

    pub fn removeSymlink(self: *EventState, s: []const u8) void {
        var i: usize = 0;
        while (i < self.symlinks.items.len) {
            if (std.mem.eql(u8, self.symlinks.items[i], s)) {
                _ = self.symlinks.orderedRemove(i);
            } else {
                i += 1;
            }
        }
    }

    pub fn addTag(self: *EventState, t: []const u8) !void {
        const a = self.arena.allocator();
        const owned = try a.dupe(u8, t);
        try self.tags.put(a, owned, {});
    }

    pub fn removeTag(self: *EventState, t: []const u8) void {
        _ = self.tags.remove(t);
    }

    pub fn lock(self: *EventState, key: []const u8) !void {
        const a = self.arena.allocator();
        const owned = try a.dupe(u8, key);
        try self.locked.put(a, owned, {});
    }

    pub fn isLocked(self: *const EventState, key: []const u8) bool {
        return self.locked.contains(key);
    }
};

// Runner is the injected interface for exec, path tests, and builtins.

pub const Runner = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        runProgram: *const fn (
            *anyopaque,
            argv: []const []const u8,
            out: *std.ArrayListUnmanaged(u8),
            gpa: std.mem.Allocator,
        ) RunError!u8,
        testPath: *const fn (*anyopaque, path: []const u8, mode: ?u32) bool,
        importBuiltin: *const fn (
            *anyopaque,
            name: []const u8,
            dev: *Device,
            state: *EventState,
        ) RunError!void,
        importFile: *const fn (
            *anyopaque,
            path: []const u8,
            state: *EventState,
        ) RunError!void,
    };

    pub fn runProgram(
        self: Runner,
        argv: []const []const u8,
        out: *std.ArrayListUnmanaged(u8),
        gpa: std.mem.Allocator,
    ) RunError!u8 {
        return self.vtable.runProgram(self.ptr, argv, out, gpa);
    }

    pub fn testPath(self: Runner, path: []const u8, mode: ?u32) bool {
        return self.vtable.testPath(self.ptr, path, mode);
    }

    pub fn importBuiltin(
        self: Runner,
        name: []const u8,
        dev: *Device,
        state: *EventState,
    ) RunError!void {
        return self.vtable.importBuiltin(self.ptr, name, dev, state);
    }

    pub fn importFile(self: Runner, path: []const u8, state: *EventState) RunError!void {
        return self.vtable.importFile(self.ptr, path, state);
    }
};

// FakeRunner is a canned test double.

pub const FakeRunner = struct {
    program_exit: u8 = 0,
    program_output: []const u8 = "",
    test_result: bool = false,
    import_props: []const PropEntry = &.{},

    pub fn runner(self: *FakeRunner) Runner {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    const vtable: Runner.VTable = .{
        .runProgram = fakeRunProgram,
        .testPath = fakeTestPath,
        .importBuiltin = fakeImportBuiltin,
        .importFile = fakeImportFile,
    };

    fn fakeRunProgram(
        ptr: *anyopaque,
        argv: []const []const u8,
        out: *std.ArrayListUnmanaged(u8),
        gpa: std.mem.Allocator,
    ) RunError!u8 {
        _ = argv;
        const self: *FakeRunner = @ptrCast(@alignCast(ptr));
        try out.appendSlice(gpa, self.program_output);
        return self.program_exit;
    }

    fn fakeTestPath(ptr: *anyopaque, path: []const u8, mode: ?u32) bool {
        _ = path;
        _ = mode;
        const self: *FakeRunner = @ptrCast(@alignCast(ptr));
        return self.test_result;
    }

    fn fakeImportBuiltin(
        ptr: *anyopaque,
        name: []const u8,
        dev: *Device,
        state: *EventState,
    ) RunError!void {
        _ = name;
        _ = dev;
        const self: *FakeRunner = @ptrCast(@alignCast(ptr));
        for (self.import_props) |prop| {
            try state.setProperty(prop.key, prop.val);
        }
    }

    fn fakeImportFile(
        ptr: *anyopaque,
        path: []const u8,
        state: *EventState,
    ) RunError!void {
        _ = path;
        const self: *FakeRunner = @ptrCast(@alignCast(ptr));
        for (self.import_props) |prop| {
            try state.setProperty(prop.key, prop.val);
        }
    }
};

// Tests

test "EventState.init/deinit: no leaks" {
    var state = EventState.init(std.testing.allocator);
    defer state.deinit();
    _ = state.alloc();
}

test "EventState.setProperty/getProperty" {
    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    try state.setProperty("SUBSYSTEM", "net");
    try std.testing.expectEqualStrings("net", state.getProperty("SUBSYSTEM").?);
    try std.testing.expect(state.getProperty("MISSING") == null);

    // overwrite existing key
    try state.setProperty("SUBSYSTEM", "usb");
    try std.testing.expectEqualStrings("usb", state.getProperty("SUBSYSTEM").?);
}

test "EventState.addSymlink/removeSymlink" {
    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    try state.addSymlink("/dev/disk/by-id/foo");
    try state.addSymlink("/dev/disk/by-id/bar");
    // duplicate should be silently ignored
    try state.addSymlink("/dev/disk/by-id/foo");
    try std.testing.expectEqual(@as(usize, 2), state.symlinks.items.len);

    state.removeSymlink("/dev/disk/by-id/foo");
    try std.testing.expectEqual(@as(usize, 1), state.symlinks.items.len);
    try std.testing.expectEqualStrings("/dev/disk/by-id/bar", state.symlinks.items[0]);
}

test "EventState.addTag/removeTag" {
    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    try state.addTag("seat");
    try state.addTag("uaccess");
    try std.testing.expect(state.tags.contains("seat"));
    try std.testing.expect(state.tags.contains("uaccess"));

    state.removeTag("seat");
    try std.testing.expect(!state.tags.contains("seat"));
    try std.testing.expect(state.tags.contains("uaccess"));
}

test "EventState.lock/isLocked" {
    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    try std.testing.expect(!state.isLocked("NAME"));
    try state.lock("NAME");
    try std.testing.expect(state.isLocked("NAME"));
    try std.testing.expect(!state.isLocked("SUBSYSTEM"));
}

test "FakeRunner.runProgram: exit and output" {
    var fake: FakeRunner = .{ .program_exit = 42, .program_output = "hello\n" };
    const r = fake.runner();

    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(std.testing.allocator);

    const argv: []const []const u8 = &.{"/usr/bin/echo"};
    const exit = try r.runProgram(argv, &out, std.testing.allocator);
    try std.testing.expectEqual(@as(u8, 42), exit);
    try std.testing.expectEqualStrings("hello\n", out.items);
}

test "FakeRunner.testPath" {
    var fake: FakeRunner = .{ .test_result = true };
    const r = fake.runner();
    try std.testing.expect(r.testPath("/dev/sda", null));
}

test "FakeRunner.importBuiltin injects props into EventState" {
    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    const props = [_]PropEntry{
        .{ .key = "ID_VENDOR", .val = "Acme" },
        .{ .key = "ID_MODEL", .val = "Widget" },
    };
    var fake: FakeRunner = .{ .import_props = &props };
    const r = fake.runner();

    // importBuiltin needs a *Device, but the fake ignores dev entirely.
    try r.importBuiltin("path_id", undefined, &state);
    try std.testing.expectEqualStrings("Acme", state.getProperty("ID_VENDOR").?);
    try std.testing.expectEqualStrings("Widget", state.getProperty("ID_MODEL").?);
}

test "FakeRunner.importFile injects props into EventState" {
    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    const props = [_]PropEntry{
        .{ .key = "COLOR", .val = "red" },
    };
    var fake: FakeRunner = .{ .import_props = &props };
    const r = fake.runner();

    try r.importFile("/etc/udev/hwdb.d/foo.hwdb", &state);
    try std.testing.expectEqualStrings("red", state.getProperty("COLOR").?);
}
