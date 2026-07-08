//! Real Runner implementation for udevd.
//! Handles runProgram (fork+exec via std.process), testPath (access+stat),
//! importFile (parse key=val env file), and importBuiltin (builtin + hwdb dispatch).
const std = @import("std");
const runner_mod = @import("../rules/runner.zig");
const hwdb_mod = @import("../hwdb.zig");
const builtins_mod = @import("../builtins.zig");
const Device = @import("../device.zig").Device;
const EventState = runner_mod.EventState;
const RunError = runner_mod.RunError;

pub const ExecRunner = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    hwdb: ?*hwdb_mod.Hwdb = null,
    helper_dirs: []const []const u8 = &.{ "/usr/lib/udev", "/lib/udev" },
    /// Milliseconds before a PROGRAM= helper is killed; 0 = no limit.
    program_timeout_ms: u32 = 0,

    pub fn runner(self: *ExecRunner) runner_mod.Runner {
        return .{ .ptr = self, .vtable = &vtable };
    }
};

const vtable = runner_mod.Runner.VTable{
    .runProgram = runProgramImpl,
    .testPath = testPathImpl,
    .importBuiltin = importBuiltinImpl,
    .importFile = importFileImpl,
};

fn runProgramImpl(
    ptr: *anyopaque,
    argv: []const []const u8,
    out: *std.ArrayListUnmanaged(u8),
    gpa: std.mem.Allocator,
) RunError!u8 {
    const self: *ExecRunner = @ptrCast(@alignCast(ptr));
    if (argv.len == 0) return error.ExecFailed;

    // Resolve argv[0]: use as-is if absolute, else search helper_dirs.
    var resolved_alloc: ?[]u8 = null;
    defer if (resolved_alloc) |b| gpa.free(b);

    const arg0 = argv[0];
    if (arg0.len > 0 and arg0[0] != '/') {
        for (self.helper_dirs) |dir| {
            const joined = std.fmt.allocPrint(gpa, "{s}/{s}", .{ dir, arg0 }) catch return error.ExecFailed;
            std.Io.Dir.cwd().access(self.io, joined, .{}) catch {
                gpa.free(joined);
                continue;
            };
            resolved_alloc = joined;
            break;
        }
    }
    const resolved: []const u8 = if (resolved_alloc) |b| b else arg0;

    // Build a new argv slice with the resolved argv[0].
    const new_argv = gpa.alloc([]const u8, argv.len) catch return error.ExecFailed;
    defer gpa.free(new_argv);
    new_argv[0] = resolved;
    @memcpy(new_argv[1..], argv[1..]);

    // Spawn, capture stdout, wait.
    const timeout: std.Io.Timeout = if (self.program_timeout_ms == 0)
        .none
    else
        .{ .duration = .{
            .raw = std.Io.Duration.fromMilliseconds(@as(i64, self.program_timeout_ms)),
            .clock = .awake,
        } };
    const result = std.process.run(gpa, self.io, .{
        .argv = new_argv,
        .stdout_limit = .unlimited,
        .stderr_limit = .unlimited,
        .timeout = timeout,
    }) catch return error.ExecFailed;
    defer gpa.free(result.stderr);
    defer gpa.free(result.stdout);

    out.appendSlice(gpa, result.stdout) catch return error.OutOfMemory;

    return switch (result.term) {
        .exited => |code| code,
        .signal => |sig| @as(u8, @truncate(128 + @as(u32, @intFromEnum(sig)))),
        .stopped => |sig| @as(u8, @truncate(128 + @as(u32, @intFromEnum(sig)))),
        .unknown => 255,
    };
}

fn testPathImpl(ptr: *anyopaque, path: []const u8, mode: ?u32) bool {
    const self: *ExecRunner = @ptrCast(@alignCast(ptr));
    std.Io.Dir.cwd().access(self.io, path, .{}) catch return false;
    const m = mode orelse return true;
    const st = std.Io.Dir.cwd().statFile(self.io, path, .{}) catch return false;
    return (st.permissions.toMode() & m) == m;
}

fn importFileImpl(
    ptr: *anyopaque,
    path: []const u8,
    state: *EventState,
) RunError!void {
    const self: *ExecRunner = @ptrCast(@alignCast(ptr));
    const buf = std.Io.Dir.cwd().readFileAlloc(
        self.io,
        path,
        self.gpa,
        .limited(1 << 20),
    ) catch return error.ImportFailed;
    defer self.gpa.free(buf);

    var iter = std.mem.tokenizeScalar(u8, buf, '\n');
    while (iter.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        const eq = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        state.setProperty(line[0..eq], line[eq + 1 ..]) catch return error.OutOfMemory;
    }
}

fn importBuiltinImpl(
    ptr: *anyopaque,
    name: []const u8,
    dev: *Device,
    state: *EventState,
) RunError!void {
    const self: *ExecRunner = @ptrCast(@alignCast(ptr));

    // Split name into the first whitespace-delimited token (builtin name) and the remainder (args).
    const first_ws = std.mem.indexOfAny(u8, name, " \t") orelse name.len;
    const name_token = name[0..first_ws];
    const args = std.mem.trim(u8, name[first_ws..], " \t");

    if (std.mem.eql(u8, name_token, "hwdb")) {
        if (self.hwdb) |hw| {
            hwdb_mod.builtin.run(hw, self.gpa, args, dev, state) catch return error.ImportFailed;
        }
        return;
    }

    const handled = builtins_mod.dispatch(name_token, self.gpa, dev, state, args) catch return error.ImportFailed;
    if (!handled) return;
}

// Tests

test "ExecRunner.runProgram captures stdout" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var er = ExecRunner{ .gpa = gpa, .io = io };
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);

    const argv: []const []const u8 = &.{ "/bin/sh", "-c", "printf hello" };
    const code = try er.runner().runProgram(argv, &out, gpa);
    try std.testing.expectEqual(@as(u8, 0), code);
    try std.testing.expectEqualStrings("hello", out.items);
}

test "ExecRunner.runProgram non-zero exit code" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var er = ExecRunner{ .gpa = gpa, .io = io };
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);

    const argv: []const []const u8 = &.{ "/bin/sh", "-c", "exit 3" };
    const code = try er.runner().runProgram(argv, &out, gpa);
    try std.testing.expectEqual(@as(u8, 3), code);
    try std.testing.expectEqual(@as(usize, 0), out.items.len);
}

test "ExecRunner.testPath existing and missing" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "f", .data = "x" });

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, "f", &rp_buf);
    const abs_path = rp_buf[0..n];

    var er = ExecRunner{ .gpa = gpa, .io = io };
    const r = er.runner();

    try std.testing.expect(r.testPath(abs_path, null));
    try std.testing.expect(!r.testPath("/nonexistent/path/does/not/exist", null));
}

test "ExecRunner.importFile parses key=val lines" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{
        .sub_path = "props.env",
        .data = "FOO=1\n# comment\nBAR=baz\n",
    });

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try tmp.dir.realPathFile(io, "props.env", &rp_buf);
    const abs_path = rp_buf[0..n];

    var er = ExecRunner{ .gpa = gpa, .io = io };
    var state = EventState.init(gpa);
    defer state.deinit();

    try er.runner().importFile(abs_path, &state);

    try std.testing.expectEqualStrings("1", state.getProperty("FOO").?);
    try std.testing.expectEqualStrings("baz", state.getProperty("BAR").?);
    try std.testing.expect(state.getProperty("# comment") == null);
}

test "ExecRunner.importBuiltin dispatches input_id builtin" {
    const testfs = @import("../testfs.zig");
    const context = @import("../context.zig");
    const input_id_mod = @import("../builtins/input_id.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Minimal keyboard: EV_KEY set, key bits 1..32 set (standard keys).
    const ev_str = try input_id_mod.fmtBitmapWords(gpa, &.{1}); // EV_KEY = 1
    defer gpa.free(ev_str);

    var kbd_bits: [32]usize = undefined;
    for (0..32) |i| kbd_bits[i] = i + 1; // bits 1..32
    const key_str = try input_id_mod.fmtBitmapWords(gpa, &kbd_bits);
    defer gpa.free(key_str);

    const syspath = try testfs.makeSysfs(&tmp, .{
        .name = "kbd_runner",
        .subsystem = "input",
        .uevent = "",
        .attrs = &.{
            .{ "capabilities/ev", ev_str },
            .{ "capabilities/key", key_str },
        },
    });
    defer gpa.free(syspath);

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    var er = ExecRunner{ .gpa = gpa, .io = io };
    try er.runner().importBuiltin("input_id", &dev, &state);

    try std.testing.expectEqualStrings("1", state.getProperty("ID_INPUT").?);
}

test "ExecRunner end-to-end: PROGRAM rule executes and matches RESULT" {
    const uevent_mod = @import("../uevent.zig");
    const context_mod = @import("../context.zig");
    const rules_mod = @import("../rules.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    // Write a non-executable shell script to a tmp dir, then run it via /bin/sh.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "hi.sh", .data = "printf hi\n" });

    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const rp_n = try tmp.dir.realPathFile(io, "hi.sh", &rp_buf);
    const script_abs = rp_buf[0..rp_n];

    // Build rules text: PROGRAM splits on space -> {"/bin/sh", script_abs}.
    var rule_buf: [1024]u8 = undefined;
    const rules_text = try std.fmt.bufPrint(
        &rule_buf,
        "PROGRAM==\"/bin/sh {s}\", RESULT==\"hi\", ENV{{GOT}}=\"1\"\n",
        .{script_abs},
    );

    var rs = try rules_mod.RuleSet.parse(gpa, rules_text);
    defer rs.deinit();

    // Minimal device built from props (no sysfs needed for this rule).
    const ev_buf = "add@/devices/x\x00ACTION=add\x00DEVPATH=/devices/x\x00";
    const parsed = try uevent_mod.parseKernel(ev_buf);
    var ctx = context_mod.Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var er = ExecRunner{ .gpa = gpa, .io = io };
    var st = try rs.apply(gpa, &dev, er.runner());
    defer st.deinit();

    try std.testing.expectEqualStrings("1", st.getProperty("GOT").?);
}

test "ExecRunner.runProgram timeout plumbing: fast program with timeout set still works" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var er = ExecRunner{ .gpa = gpa, .io = io, .program_timeout_ms = 10_000 };
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);

    const argv: []const []const u8 = &.{ "/bin/sh", "-c", "printf hi" };
    const code = try er.runner().runProgram(argv, &out, gpa);
    try std.testing.expectEqual(@as(u8, 0), code);
    try std.testing.expectEqualStrings("hi", out.items);
}

test "ExecRunner.runProgram timeout fires: slow program returns error.ExecFailed" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var er = ExecRunner{ .gpa = gpa, .io = io, .program_timeout_ms = 300 };
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);

    const argv: []const []const u8 = &.{ "/bin/sh", "-c", "sleep 3" };
    try std.testing.expectError(error.ExecFailed, er.runner().runProgram(argv, &out, gpa));
}

test "ExecRunner end-to-end: IMPORT{builtin}=\"input_id\" sets ID_INPUT" {
    const testfs = @import("../testfs.zig");
    const context = @import("../context.zig");
    const input_id_mod = @import("../builtins/input_id.zig");
    const rules_mod = @import("../rules.zig");
    const gpa = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const ev_str = try input_id_mod.fmtBitmapWords(gpa, &.{1});
    defer gpa.free(ev_str);

    var kbd_bits: [32]usize = undefined;
    for (0..32) |i| kbd_bits[i] = i + 1;
    const key_str = try input_id_mod.fmtBitmapWords(gpa, &kbd_bits);
    defer gpa.free(key_str);

    const syspath = try testfs.makeSysfs(&tmp, .{
        .name = "kbd_e2e",
        .subsystem = "input",
        .uevent = "",
        .attrs = &.{
            .{ "capabilities/ev", ev_str },
            .{ "capabilities/key", key_str },
        },
    });
    defer gpa.free(syspath);

    var ctx = context.Context.init(gpa, io);
    defer ctx.deinit();
    var dev = try Device.fromSyspath(&ctx, syspath);
    defer dev.deinit();

    const rules_text = "IMPORT{builtin}=\"input_id\"\n";
    var rs = try rules_mod.RuleSet.parse(gpa, rules_text);
    defer rs.deinit();

    var er = ExecRunner{ .gpa = gpa, .io = io };
    var st = try rs.apply(gpa, &dev, er.runner());
    defer st.deinit();

    try std.testing.expectEqualStrings("1", st.getProperty("ID_INPUT").?);
}
