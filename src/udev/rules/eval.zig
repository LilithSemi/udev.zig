//! Rule evaluator.
//! Covers core match and assign over a sequential walk, GOTO/LABEL navigation, the
//! plural match keys (KERNELS/SUBSYSTEMS/DRIVERS/ATTRS), TEST, PROGRAM, RESULT, IMPORT,
//! RUN, OPTIONS, and the parse-accepted no-op SYSCTL/SECLABEL entries.
const std = @import("std");
const parser = @import("parser.zig");
const glob = @import("glob.zig");
const subst_mod = @import("subst.zig");
const runner_mod = @import("runner.zig");
const Device = @import("../device.zig").Device;

const EventState = runner_mod.EventState;
const Runner = runner_mod.Runner;

/// Walk `rules` in order. For each rule: evaluate its match entries in order;
/// the first failing match skips the entire rule. If all match, apply
/// assignment entries in order. Values are substituted before use.
/// GOTO jumps to the rule whose LABEL= value matches; unknown labels are ignored.
pub fn evaluate(
    rules: []const parser.Rule,
    dev: *Device,
    runner: Runner,
    state: *EventState,
) !void {
    const alloc = state.alloc();

    // Build label -> rule-index map by scanning every rule for LABEL assign entries.
    var label_map: std.StringHashMapUnmanaged(usize) = .empty;
    for (rules, 0..) |rule, i| {
        for (rule.entries) |entry| {
            if (entry.key == .label and !isMatchOp(entry.op)) {
                try label_map.put(alloc, entry.value, i);
            }
        }
    }

    var rule_idx: usize = 0;
    while (rule_idx < rules.len) {
        const rule = rules[rule_idx];
        var next_idx = rule_idx + 1;
        var rule_matched = true;

        // Single pass in source order: match entries gate, assign entries apply.
        // This mirrors real udev: IMPORT (assignment) on a line runs before a later match
        // entry on the same line sees state, enabling patterns like
        // IMPORT{program}="...", ENV{KEY}=="val", NAME="ok".
        for (rule.entries) |entry| {
            if (isMatchOp(entry.op)) {
                var buf: std.ArrayListUnmanaged(u8) = .empty;
                try subst_mod.substitute(&buf, alloc, entry.value, dev, state);
                const sub = buf.items;

                const passes = try evalMatchEntry(entry, sub, dev, state, runner, alloc);
                if (!passes) {
                    rule_matched = false;
                    break;
                }
            } else {
                if (entry.key == .label) continue; // LABEL is a no-op marker

                var buf: std.ArrayListUnmanaged(u8) = .empty;
                try subst_mod.substitute(&buf, alloc, entry.value, dev, state);
                const sub = buf.items;

                // GOTO: jump to labelled rule. Always stop processing the current rule's entries.
                if (entry.key == .goto_op) {
                    if (label_map.get(sub)) |target| {
                        // udev GOTO is forward-only. Ignoring backward/self jumps prevents an
                        // infinite loop on a malformed ruleset that labels an earlier rule.
                        if (target > rule_idx) next_idx = target;
                    }
                    // Unknown label: silently ignore, break regardless.
                    break;
                }

                try applyAssign(entry, sub, state, alloc, runner, dev);
            }
        }

        rule_idx = if (rule_matched) next_idx else rule_idx + 1;
    }
}

// Internal helpers

fn isMatchOp(op: parser.Op) bool {
    return op == .match or op == .nomatch;
}

/// Evaluate one match entry (op is == or !=). Returns true if the entry passes.
fn evalMatchEntry(
    entry: parser.Entry,
    sub: []const u8,
    dev: *Device,
    state: *EventState,
    runner: Runner,
    alloc: std.mem.Allocator,
) !bool {
    switch (entry.key) {
        .tag => {
            const in_set = state.tags.contains(sub);
            return if (entry.op == .match) in_set else !in_set;
        },
        .kernels, .subsystems, .drivers, .attrs => {
            return try evalPluralMatch(entry, sub, dev);
        },
        .tags => {
            // TAGS (plural): no-op match for now, always passes.
            return true;
        },
        .test_op => {
            const mode: ?u32 = if (entry.arg) |a| std.fmt.parseInt(u32, a, 8) catch null else null;
            const result = runner.testPath(sub, mode);
            return if (entry.op == .match) result else !result;
        },
        .program => {
            var argv_list: std.ArrayListUnmanaged([]const u8) = .empty;
            {
                var it = std.mem.tokenizeScalar(u8, sub, ' ');
                while (it.next()) |part| try argv_list.append(alloc, part);
            }
            var out: std.ArrayListUnmanaged(u8) = .empty;
            const exit_code: u8 = runner.runProgram(argv_list.items, &out, alloc) catch 1;
            const trimmed = std.mem.trimEnd(u8, out.items, " \t\n\r");
            state.last_result = try alloc.dupe(u8, trimmed);
            const matched = exit_code == 0;
            return if (entry.op == .match) matched else !matched;
        },
        .result => {
            const last = state.last_result orelse "";
            const matched = glob.match(sub, last);
            return if (entry.op == .match) matched else !matched;
        },
        else => {
            // action, devpath, kernel, subsystem, driver, env, attr, constant, ...
            const field = try getField(entry, dev, state);
            const matched = glob.match(sub, field);
            return if (entry.op == .match) matched else !matched;
        },
    }
}

/// Walk dev then its parent chain; return whether `sub` glob-matches the plural field
/// at any level. For `==`: true if any matches. For `!=`: true if none match.
fn evalPluralMatch(entry: parser.Entry, sub: []const u8, dev: *Device) !bool {
    // Check dev itself (never owned here, do NOT deinit).
    {
        const field = try getPluralField(entry, dev);
        if (glob.match(sub, field)) return entry.op == .match;
    }

    // Walk parent chain. Each parent is independently owned and must be deinited.
    var maybe_owned: ?Device = try dev.parent();
    while (maybe_owned) |owned| {
        var cur = owned;
        defer cur.deinit();
        const field = try getPluralField(entry, &cur);
        if (glob.match(sub, field)) return entry.op == .match;
        maybe_owned = try cur.parent();
    }

    // No level matched.
    return entry.op == .nomatch;
}

/// Get the plural-match field value at a single device level.
fn getPluralField(entry: parser.Entry, d: *Device) ![]const u8 {
    return switch (entry.key) {
        .kernels => d.sysname(),
        .subsystems => (try d.subsystem()) orelse "",
        .drivers => (try d.driver()) orelse "",
        .attrs => blk: {
            const arg = entry.arg orelse "";
            break :blk (try d.getSysattr(arg)) orelse "";
        },
        else => "",
    };
}

/// Retrieve the device or state field value for a given single-device match key.
fn getField(
    entry: parser.Entry,
    dev: *Device,
    state: *const EventState,
) ![]const u8 {
    return switch (entry.key) {
        .action => state.getProperty("ACTION") orelse dev.getProperty("ACTION") orelse "",
        .devpath => state.getProperty("DEVPATH") orelse
            dev.getProperty("DEVPATH") orelse "",
        .kernel => dev.sysname(),
        .subsystem => (try dev.subsystem()) orelse "",
        .driver => (try dev.driver()) orelse dev.getProperty("DRIVER") orelse "",
        .env, .constant => blk: {
            const arg = entry.arg orelse "";
            break :blk state.getProperty(arg) orelse
                dev.getProperty(arg) orelse "";
        },
        .attr => blk: {
            const arg = entry.arg orelse "";
            break :blk (try dev.getSysattr(arg)) orelse "";
        },
        // .tag is handled in evalMatchEntry.
        // plural keys and runner-backed keys handled in evalMatchEntry.
        else => "",
    };
}

/// Apply one assignment entry to state. Respects locks set by :=.
fn applyAssign(
    entry: parser.Entry,
    sub: []const u8,
    state: *EventState,
    alloc: std.mem.Allocator,
    runner: Runner,
    dev: *Device,
) !void {
    switch (entry.key) {
        .name => {
            if (state.isLocked("NAME")) return;
            state.name = try alloc.dupe(u8, sub);
            if (entry.op == .assign_final) try state.lock("NAME");
        },
        .symlink => {
            if (state.isLocked("SYMLINK")) return;
            switch (entry.op) {
                .add => try state.addSymlink(sub),
                .remove => state.removeSymlink(sub),
                .assign, .assign_final => {
                    state.symlinks.clearRetainingCapacity();
                    var it = std.mem.splitScalar(u8, sub, ' ');
                    while (it.next()) |part| {
                        const p = std.mem.trim(u8, part, " \t");
                        if (p.len > 0) try state.addSymlink(p);
                    }
                    if (entry.op == .assign_final) try state.lock("SYMLINK");
                },
                else => {},
            }
        },
        .owner => {
            if (state.isLocked("OWNER")) return;
            state.owner = try alloc.dupe(u8, sub);
            if (entry.op == .assign_final) try state.lock("OWNER");
        },
        .group => {
            if (state.isLocked("GROUP")) return;
            state.group = try alloc.dupe(u8, sub);
            if (entry.op == .assign_final) try state.lock("GROUP");
        },
        .mode => {
            if (state.isLocked("MODE")) return;
            const m = std.fmt.parseInt(u32, sub, 8) catch return;
            state.mode = m;
            if (entry.op == .assign_final) try state.lock("MODE");
        },
        .env => {
            const arg = entry.arg orelse return;
            const lock_key = try std.fmt.allocPrint(alloc, "ENV:{s}", .{arg});
            if (state.isLocked(lock_key)) return;
            try state.setProperty(arg, sub);
            if (entry.op == .assign_final) try state.lock(lock_key);
        },
        .constant => {
            // CONST{k} is read-only in real udev, no assignment action.
        },
        .tag => switch (entry.op) {
            .add, .assign => try state.addTag(sub),
            .remove => state.removeTag(sub),
            else => {},
        },
        .label => {}, // no-op marker; GOTO/LABEL handled in evaluate
        .run => switch (entry.op) {
            .add, .assign, .assign_final => {
                // udev RUN= (assign) REPLACES the deferred run list. RUN+= appends.
                if (entry.op != .add) state.run_list.clearRetainingCapacity();
                const is_builtin = std.mem.eql(u8, entry.arg orelse "", "builtin");
                try state.run_list.append(alloc, runner_mod.RunEntry{
                    .kind = if (is_builtin) .builtin else .program,
                    .command = try alloc.dupe(u8, sub),
                });
            },
            .remove => {}, // no-op
            else => {},
        },
        .import_op => {
            const import_type = entry.arg orelse "";
            if (std.mem.eql(u8, import_type, "program")) {
                var argv_list: std.ArrayListUnmanaged([]const u8) = .empty;
                {
                    var it = std.mem.tokenizeScalar(u8, sub, ' ');
                    while (it.next()) |part| try argv_list.append(alloc, part);
                }
                var out: std.ArrayListUnmanaged(u8) = .empty;
                const exit_code = runner.runProgram(argv_list.items, &out, alloc) catch return;
                if (exit_code != 0) return;
                // Parse "KEY=VALUE" lines from stdout into state properties.
                var line_it = std.mem.tokenizeScalar(u8, out.items, '\n');
                while (line_it.next()) |line| {
                    const tl = std.mem.trim(u8, line, " \t\r");
                    if (tl.len == 0) continue;
                    const eq = std.mem.indexOfScalar(u8, tl, '=') orelse continue;
                    if (eq == 0) continue; // empty key ("=value") is junk; skip
                    try state.setProperty(tl[0..eq], tl[eq + 1 ..]);
                }
            } else if (std.mem.eql(u8, import_type, "file")) {
                runner.importFile(sub, state) catch |e| if (e == error.OutOfMemory) return e;
            } else if (std.mem.eql(u8, import_type, "builtin")) {
                runner.importBuiltin(sub, dev, state) catch |e| if (e == error.OutOfMemory) return e;
            } else if (std.mem.eql(u8, import_type, "parent")) {
                var maybe_par = dev.parent() catch null;
                if (maybe_par) |*par| {
                    defer par.deinit();
                    var prop_it = par.props.iterator();
                    while (prop_it.next()) |kv| {
                        if (state.getProperty(kv.key_ptr.*) == null) {
                            if (sub.len == 0 or glob.match(sub, kv.key_ptr.*)) {
                                try state.setProperty(kv.key_ptr.*, kv.value_ptr.*);
                            }
                        }
                    }
                }
            }
            // Other import types: no-op.
        },
        .options => {
            // Parse comma-separated option tokens. Unknown tokens are ignored.
            var it = std.mem.tokenizeScalar(u8, sub, ',');
            while (it.next()) |token| {
                const t = std.mem.trim(u8, token, " \t");
                if (std.mem.startsWith(u8, t, "link_priority=")) {
                    const n = std.fmt.parseInt(i32, t["link_priority=".len..], 10) catch continue;
                    state.options.link_priority = n;
                } else if (std.mem.eql(u8, t, "watch")) {
                    state.options.watch = true;
                } else if (std.mem.eql(u8, t, "nowatch")) {
                    state.options.watch = false;
                } else if (std.mem.eql(u8, t, "db_persist")) {
                    state.options.db_persist = true;
                } else if (std.mem.eql(u8, t, "string_escape=none")) {
                    state.options.string_escape = .none;
                } else if (std.mem.eql(u8, t, "string_escape=replace")) {
                    state.options.string_escape = .replace;
                } else if (std.mem.startsWith(u8, t, "static_node=")) {
                    state.options.static_node = try alloc.dupe(u8, t["static_node=".len..]);
                }
            }
        },
        .sysctl => {}, // parse-accepted but not applied
        .seclabel => {}, // parse-accepted but not applied
        .tags => {}, // no-op in assign position
        else => {},
    }
}

// Tests, part 1

test "evaluate: full match+assign happy path" {
    const uevent_mod = @import("../uevent.zig");
    const context_mod = @import("../context.zig");

    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const ev_buf = "add@/devices/x/event0\x00" ++
        "SUBSYSTEM=input\x00DEVPATH=/devices/x/event0\x00ID_INPUT=1\x00";
    const parsed = try uevent_mod.parseKernel(ev_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    const rules_text =
        \\SUBSYSTEM=="input", KERNEL=="event*", ENV{ID_INPUT}=="1", NAME="input/%k", MODE="0640", GROUP="input", SYMLINK+="by-id/kbd", TAG+="seat"
        \\SUBSYSTEM=="block", NAME="should-not-apply"
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags: std.ArrayListUnmanaged(parser.Diagnostic) = .empty;
    const rules = try parser.parse(arena.allocator(), rules_text, &diags);

    var fake: runner_mod.FakeRunner = .{};
    try evaluate(rules, &dev, fake.runner(), &state);

    try std.testing.expectEqualStrings("input/event0", state.name.?);
    try std.testing.expectEqual(@as(u32, 0o640), state.mode.?);
    try std.testing.expectEqualStrings("input", state.group.?);
    try std.testing.expectEqual(@as(usize, 1), state.symlinks.items.len);
    try std.testing.expectEqualStrings("by-id/kbd", state.symlinks.items[0]);
    try std.testing.expect(state.tags.contains("seat"));
    try std.testing.expectEqualStrings("input/event0", state.name.?);
}

test "evaluate: non-matching rule is skipped" {
    const uevent_mod = @import("../uevent.zig");
    const context_mod = @import("../context.zig");

    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const ev_buf = "add@/devices/x/event0\x00" ++
        "SUBSYSTEM=input\x00DEVPATH=/devices/x/event0\x00";
    const parsed = try uevent_mod.parseKernel(ev_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    const rules_text =
        \\SUBSYSTEM=="block", NAME="should-not-apply"
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags: std.ArrayListUnmanaged(parser.Diagnostic) = .empty;
    const rules = try parser.parse(arena.allocator(), rules_text, &diags);

    var fake: runner_mod.FakeRunner = .{};
    try evaluate(rules, &dev, fake.runner(), &state);

    try std.testing.expect(state.name == null);
}

test "evaluate: != (nomatch) skips rule" {
    const uevent_mod = @import("../uevent.zig");
    const context_mod = @import("../context.zig");

    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const ev_buf = "add@/devices/x/event0\x00" ++
        "SUBSYSTEM=input\x00DEVPATH=/devices/x/event0\x00";
    const parsed = try uevent_mod.parseKernel(ev_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    const rules_text =
        \\SUBSYSTEM!="input", NAME="should-not-set"
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags: std.ArrayListUnmanaged(parser.Diagnostic) = .empty;
    const rules = try parser.parse(arena.allocator(), rules_text, &diags);

    var fake: runner_mod.FakeRunner = .{};
    try evaluate(rules, &dev, fake.runner(), &state);

    try std.testing.expect(state.name == null);
}

test "evaluate: -= removes a symlink" {
    const uevent_mod = @import("../uevent.zig");
    const context_mod = @import("../context.zig");

    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const ev_buf = "add@/devices/x/sda\x00" ++
        "SUBSYSTEM=block\x00DEVPATH=/devices/x/sda\x00";
    const parsed = try uevent_mod.parseKernel(ev_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();
    try state.addSymlink("old-link");

    const rules_text =
        \\SUBSYSTEM=="block", SYMLINK-="old-link"
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags: std.ArrayListUnmanaged(parser.Diagnostic) = .empty;
    const rules = try parser.parse(arena.allocator(), rules_text, &diags);

    var fake: runner_mod.FakeRunner = .{};
    try evaluate(rules, &dev, fake.runner(), &state);

    try std.testing.expectEqual(@as(usize, 0), state.symlinks.items.len);
}

test "evaluate: := locks NAME, later = does not override" {
    const uevent_mod = @import("../uevent.zig");
    const context_mod = @import("../context.zig");

    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const ev_buf = "add@/devices/x/sda\x00" ++
        "SUBSYSTEM=block\x00DEVPATH=/devices/x/sda\x00";
    const parsed = try uevent_mod.parseKernel(ev_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    const rules_text =
        \\SUBSYSTEM=="block", NAME:="locked-name"
        \\SUBSYSTEM=="block", NAME="override-attempt"
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags: std.ArrayListUnmanaged(parser.Diagnostic) = .empty;
    const rules = try parser.parse(arena.allocator(), rules_text, &diags);

    var fake: runner_mod.FakeRunner = .{};
    try evaluate(rules, &dev, fake.runner(), &state);

    try std.testing.expectEqualStrings("locked-name", state.name.?);
}

// Tests, part 2

test "evaluate: GOTO jumps over intervening rule" {
    const uevent_mod = @import("../uevent.zig");
    const context_mod = @import("../context.zig");

    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const ev_buf = "add@/devices/x/foo\x00DEVPATH=/devices/x/foo\x00";
    const parsed = try uevent_mod.parseKernel(ev_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    // Rule 0: GOTO="end"           (no match conditions; always fires; jumps to LABEL="end")
    // Rule 1: NAME="should-skip"   (skipped by GOTO)
    // Rule 2: LABEL="end"          (target; LABEL is a no-op; NAME stays unset)
    const rules_text =
        \\GOTO="end"
        \\NAME="should-skip"
        \\LABEL="end"
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags: std.ArrayListUnmanaged(parser.Diagnostic) = .empty;
    const rules = try parser.parse(arena.allocator(), rules_text, &diags);

    var fake: runner_mod.FakeRunner = .{};
    try evaluate(rules, &dev, fake.runner(), &state);

    try std.testing.expect(state.name == null);
}

test "evaluate: backward GOTO is ignored (no infinite loop)" {
    const uevent_mod = @import("../uevent.zig");
    const context_mod = @import("../context.zig");

    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const ev_buf = "add@/devices/x/foo\x00DEVPATH=/devices/x/foo\x00";
    const parsed = try uevent_mod.parseKernel(ev_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    // Rule 0 is LABEL "top", rule 1 is NAME "set", rule 2 is GOTO "top" (a backward jump that must be ignored,
    // otherwise this would loop forever). Evaluation must terminate and NAME must be set once.
    const rules_text =
        \\LABEL="top"
        \\NAME="set"
        \\GOTO="top"
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags: std.ArrayListUnmanaged(parser.Diagnostic) = .empty;
    const rules = try parser.parse(arena.allocator(), rules_text, &diags);

    var fake: runner_mod.FakeRunner = .{};
    try evaluate(rules, &dev, fake.runner(), &state);

    try std.testing.expectEqualStrings("set", state.name.?);
}

test "evaluate: SUBSYSTEMS matches ancestor subsystem via parent walk" {
    const context_mod = @import("../context.zig");

    const io = std.testing.io;
    const gpa = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Parent device: devices/usbdev0/ with subsystem symlink -> ../../class/usb
    try tmp.dir.createDirPath(io, "devices/usbdev0");
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/usbdev0/uevent", .data = "" });
    try tmp.dir.symLink(io, "../../class/usb", "devices/usbdev0/subsystem", .{});

    // Child device: devices/usbdev0/input0/ with its own subsystem symlink
    try tmp.dir.createDirPath(io, "devices/usbdev0/input0");
    try tmp.dir.writeFile(io, .{ .sub_path = "devices/usbdev0/input0/uevent", .data = "" });
    try tmp.dir.symLink(io, "../../../class/input", "devices/usbdev0/input0/subsystem", .{});

    // Resolve absolute path for the child device.
    var rp_buf: [std.fs.max_path_bytes]u8 = undefined;
    const rp_n = try tmp.dir.realPathFile(io, "devices/usbdev0/input0", &rp_buf);
    const child_path = try gpa.dupe(u8, rp_buf[0..rp_n]);
    defer gpa.free(child_path);

    var ctx = context_mod.Context.init(gpa, io);
    defer ctx.deinit();

    var dev = try Device.fromSyspath(&ctx, child_path);
    defer dev.deinit();

    var state = EventState.init(gpa);
    defer state.deinit();

    // SUBSYSTEMS=="usb" should match the parent level.
    const rules_text =
        \\SUBSYSTEMS=="usb", NAME="got-it"
    ;
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    var diags: std.ArrayListUnmanaged(parser.Diagnostic) = .empty;
    const rules = try parser.parse(arena.allocator(), rules_text, &diags);

    var fake: runner_mod.FakeRunner = .{};
    try evaluate(rules, &dev, fake.runner(), &state);

    try std.testing.expectEqualStrings("got-it", state.name.?);
}

test "evaluate: PROGRAM+RESULT set last_result and match ENV" {
    const uevent_mod = @import("../uevent.zig");
    const context_mod = @import("../context.zig");

    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const ev_buf = "add@/devices/x/foo\x00DEVPATH=/devices/x/foo\x00";
    const parsed = try uevent_mod.parseKernel(ev_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    // FakeRunner: exit 0, stdout "KEY=v\n"
    var fake: runner_mod.FakeRunner = .{ .program_exit = 0, .program_output = "KEY=v\n" };

    // PROGRAM match sets last_result, RESULT matches it, then ENV{GOT}="1" fires.
    const rules_text =
        \\PROGRAM=="/bin/foo", RESULT=="KEY=v", ENV{GOT}="1"
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags: std.ArrayListUnmanaged(parser.Diagnostic) = .empty;
    const rules = try parser.parse(arena.allocator(), rules_text, &diags);

    try evaluate(rules, &dev, fake.runner(), &state);

    try std.testing.expectEqualStrings("KEY=v", state.last_result.?);
    try std.testing.expectEqualStrings("1", state.getProperty("GOT").?);
}

test "evaluate: IMPORT{program} injects KEY=VAL lines into properties" {
    const uevent_mod = @import("../uevent.zig");
    const context_mod = @import("../context.zig");

    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const ev_buf = "add@/devices/x/foo\x00DEVPATH=/devices/x/foo\x00";
    const parsed = try uevent_mod.parseKernel(ev_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    // FakeRunner: exit 0, stdout "ID_X=42\n"
    var fake: runner_mod.FakeRunner = .{ .program_exit = 0, .program_output = "ID_X=42\n" };

    const rules_text =
        \\IMPORT{program}="/bin/bar"
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags: std.ArrayListUnmanaged(parser.Diagnostic) = .empty;
    const rules = try parser.parse(arena.allocator(), rules_text, &diags);

    try evaluate(rules, &dev, fake.runner(), &state);

    try std.testing.expectEqualStrings("42", state.getProperty("ID_X").?);
}

test "evaluate: RUN+= appends program entry to run_list" {
    const uevent_mod = @import("../uevent.zig");
    const context_mod = @import("../context.zig");

    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const ev_buf = "add@/devices/x/foo\x00DEVPATH=/devices/x/foo\x00";
    const parsed = try uevent_mod.parseKernel(ev_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    const rules_text =
        \\RUN+="/bin/notify"
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags: std.ArrayListUnmanaged(parser.Diagnostic) = .empty;
    const rules = try parser.parse(arena.allocator(), rules_text, &diags);

    var fake: runner_mod.FakeRunner = .{};
    try evaluate(rules, &dev, fake.runner(), &state);

    try std.testing.expectEqual(@as(usize, 1), state.run_list.items.len);
    try std.testing.expect(state.run_list.items[0].kind == .program);
    try std.testing.expectEqualStrings("/bin/notify", state.run_list.items[0].command);
}

test "evaluate: OPTIONS sets link_priority" {
    const uevent_mod = @import("../uevent.zig");
    const context_mod = @import("../context.zig");

    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const ev_buf = "add@/devices/x/foo\x00DEVPATH=/devices/x/foo\x00";
    const parsed = try uevent_mod.parseKernel(ev_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    const rules_text =
        \\OPTIONS+="link_priority=10"
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags: std.ArrayListUnmanaged(parser.Diagnostic) = .empty;
    const rules = try parser.parse(arena.allocator(), rules_text, &diags);

    var fake: runner_mod.FakeRunner = .{};
    try evaluate(rules, &dev, fake.runner(), &state);

    try std.testing.expectEqual(@as(i32, 10), state.options.link_priority);
}

// Regression tests for single-pass evaluation

test "evaluate: single-pass IMPORT{program} runs before later ENV match on same line" {
    // Verifies that the single left-to-right pass lets an assignment entry (IMPORT)
    // execute before a subsequent match entry (ENV) on the same rule line sees state.
    // A two-phase evaluator would fail this: ENV would be checked in phase-1 before
    // IMPORT ran in phase-2, so ID_BUS would be absent and the rule would not fire.
    const uevent_mod = @import("../uevent.zig");
    const context_mod = @import("../context.zig");

    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const ev_buf = "add@/devices/x/foo\x00DEVPATH=/devices/x/foo\x00";
    const parsed = try uevent_mod.parseKernel(ev_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    // FakeRunner: exit 0, stdout "ID_BUS=usb"
    var fake: runner_mod.FakeRunner = .{ .program_exit = 0, .program_output = "ID_BUS=usb\n" };

    const rules_text =
        \\IMPORT{program}="/bin/x", ENV{ID_BUS}=="usb", NAME="ok"
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags: std.ArrayListUnmanaged(parser.Diagnostic) = .empty;
    const rules = try parser.parse(arena.allocator(), rules_text, &diags);

    try evaluate(rules, &dev, fake.runner(), &state);

    try std.testing.expectEqualStrings("ok", state.name.?);
}

test "evaluate: DRIVER match falls back to uevent DRIVER property for fromProps device" {
    // A Device built with fromProps (monitor source, no live sysfs) has no driver
    // symlink to read. The DRIVER match key must fall back to the uevent DRIVER
    // property so rules still fire correctly.
    const uevent_mod = @import("../uevent.zig");
    const context_mod = @import("../context.zig");

    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const ev_buf = "add@/devices/x/foo\x00" ++
        "DEVPATH=/devices/x/foo\x00DRIVER=usbhid\x00";
    const parsed = try uevent_mod.parseKernel(ev_buf);
    var dev = try Device.fromProps(&ctx, parsed.devpath.?, parsed.props);
    defer dev.deinit();

    var state = EventState.init(std.testing.allocator);
    defer state.deinit();

    const rules_text =
        \\DRIVER=="usbhid", NAME="matched"
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags: std.ArrayListUnmanaged(parser.Diagnostic) = .empty;
    const rules = try parser.parse(arena.allocator(), rules_text, &diags);

    var fake: runner_mod.FakeRunner = .{};
    try evaluate(rules, &dev, fake.runner(), &state);

    try std.testing.expectEqualStrings("matched", state.name.?);
}
