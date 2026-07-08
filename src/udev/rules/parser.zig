//! udev rules parser: typed AST produced from rules file text.
//! Resilient: malformed entries and unknown keys emit diagnostics and are
//! skipped. A line with zero valid entries also emits a diagnostic but the
//! parse never fails wholesale because of bad input.

const std = @import("std");
const lexer = @import("lexer.zig");

// Public types
/// Comparison / assignment operator from a rules entry.
pub const Op = enum {
    match, // ==
    nomatch, // !=
    assign, // =
    add, // +=
    remove, // -=
    assign_final, // :=
};

/// The key part of a rules entry (uppercase token before the operator).
pub const Key = enum {
    action,
    devpath,
    kernel,
    kernels,
    subsystem,
    subsystems,
    driver,
    drivers,
    attr,
    attrs,
    env,
    constant, // CONST in rules files
    tag,
    tags,
    test_op, // TEST in rules files
    program,
    result,
    import_op, // IMPORT in rules files
    name,
    symlink,
    owner,
    group,
    mode,
    seclabel,
    run,
    label,
    goto_op, // GOTO in rules files
    options,
    sysctl,
};

/// One parsed entry from a rules line.
pub const Entry = struct {
    key: Key,
    arg: ?[]const u8, // content of {arg}, or null
    op: Op,
    value: []const u8, // inner text of the double-quoted value
    line: u32,
};

/// One rules line (may contain multiple comma-separated entries).
pub const Rule = struct {
    entries: []const Entry,
    line: u32,
};

/// A parse-time problem. Non-fatal; the surrounding entries/rule are still
/// returned where possible.
pub const Diagnostic = struct {
    line: u32,
    message: []const u8,
};

// Internal mapping helpers
fn mapKey(k: []const u8) ?Key {
    if (std.mem.eql(u8, k, "ACTION")) return .action;
    if (std.mem.eql(u8, k, "DEVPATH")) return .devpath;
    if (std.mem.eql(u8, k, "KERNEL")) return .kernel;
    if (std.mem.eql(u8, k, "KERNELS")) return .kernels;
    if (std.mem.eql(u8, k, "SUBSYSTEM")) return .subsystem;
    if (std.mem.eql(u8, k, "SUBSYSTEMS")) return .subsystems;
    if (std.mem.eql(u8, k, "DRIVER")) return .driver;
    if (std.mem.eql(u8, k, "DRIVERS")) return .drivers;
    if (std.mem.eql(u8, k, "ATTR")) return .attr;
    if (std.mem.eql(u8, k, "ATTRS")) return .attrs;
    if (std.mem.eql(u8, k, "ENV")) return .env;
    if (std.mem.eql(u8, k, "CONST")) return .constant;
    if (std.mem.eql(u8, k, "TAG")) return .tag;
    if (std.mem.eql(u8, k, "TAGS")) return .tags;
    if (std.mem.eql(u8, k, "TEST")) return .test_op;
    if (std.mem.eql(u8, k, "PROGRAM")) return .program;
    if (std.mem.eql(u8, k, "RESULT")) return .result;
    if (std.mem.eql(u8, k, "IMPORT")) return .import_op;
    if (std.mem.eql(u8, k, "NAME")) return .name;
    if (std.mem.eql(u8, k, "SYMLINK")) return .symlink;
    if (std.mem.eql(u8, k, "OWNER")) return .owner;
    if (std.mem.eql(u8, k, "GROUP")) return .group;
    if (std.mem.eql(u8, k, "MODE")) return .mode;
    if (std.mem.eql(u8, k, "SECLABEL")) return .seclabel;
    if (std.mem.eql(u8, k, "RUN")) return .run;
    if (std.mem.eql(u8, k, "LABEL")) return .label;
    if (std.mem.eql(u8, k, "GOTO")) return .goto_op;
    if (std.mem.eql(u8, k, "OPTIONS")) return .options;
    if (std.mem.eql(u8, k, "SYSCTL")) return .sysctl;
    return null;
}

fn mapOp(op: []const u8) ?Op {
    if (std.mem.eql(u8, op, "==")) return .match;
    if (std.mem.eql(u8, op, "!=")) return .nomatch;
    if (std.mem.eql(u8, op, "=")) return .assign;
    if (std.mem.eql(u8, op, "+=")) return .add;
    if (std.mem.eql(u8, op, "-=")) return .remove;
    if (std.mem.eql(u8, op, ":=")) return .assign_final;
    return null;
}

// Public API
/// Parse `text` (the full content of a rules file) into a slice of Rules.
/// All returned strings are duplicated into `arena`.
/// On a bad entry the function appends a Diagnostic and skips that entry.
/// On a non-empty, non-comment line with zero valid entries it appends a
/// Diagnostic and emits no Rule. The parse never returns an error for bad
/// input, only on allocator failure.
pub fn parse(
    arena: std.mem.Allocator,
    text: []const u8,
    diags: *std.ArrayListUnmanaged(Diagnostic),
) ![]const Rule {
    var rules: std.ArrayListUnmanaged(Rule) = .empty;

    var line_iter = std.mem.splitScalar(u8, text, '\n');
    var line_num: u32 = 0;

    while (line_iter.next()) |first_raw| {
        line_num += 1;
        const start_line = line_num;

        // Join backslash-newline continuations into one logical line: a physical line whose last
        // non-whitespace char is '\' continues on the next line (a standard udev rules feature).
        // Like udev, this is a plain "ends with backslash" test. Real rule values never end a line
        // with a literal backslash, so no `\\`-escape special-casing is needed.
        var logical: []const u8 = std.mem.trimEnd(u8, first_raw, " \t\r");
        var cont_buf: std.ArrayListUnmanaged(u8) = .empty;
        if (logical.len > 0 and logical[logical.len - 1] == '\\') {
            try cont_buf.appendSlice(arena, logical[0 .. logical.len - 1]);
            while (line_iter.next()) |cont_raw| {
                line_num += 1;
                const seg = std.mem.trimEnd(u8, cont_raw, " \t\r");
                if (seg.len > 0 and seg[seg.len - 1] == '\\') {
                    try cont_buf.appendSlice(arena, seg[0 .. seg.len - 1]);
                } else {
                    try cont_buf.appendSlice(arena, seg);
                    break;
                }
            }
            logical = cont_buf.items;
        }
        const line = std.mem.trim(u8, logical, " \t\r");

        // Blank lines and comment lines are silently ignored.
        if (line.len == 0 or line[0] == '#') continue;

        const entry_strs = try lexer.splitEntries(arena, line);
        var entries: std.ArrayListUnmanaged(Entry) = .empty;
        const diags_before = diags.items.len;

        for (entry_strs) |es| {
            // Tokenize raw text -> key string, optional arg string, op string, value string.
            const raw = lexer.tokenizeEntry(es) orelse {
                const msg = try std.fmt.allocPrint(arena, "malformed entry: '{s}'", .{es});
                try diags.append(arena, .{ .line = start_line, .message = msg });
                continue;
            };

            // Map key string to Key enum.
            const key = mapKey(raw.key) orelse {
                const msg = try std.fmt.allocPrint(arena, "unknown key: '{s}'", .{raw.key});
                try diags.append(arena, .{ .line = start_line, .message = msg });
                continue;
            };

            // Map operator string to Op enum.
            const op = mapOp(raw.op) orelse {
                const msg = try std.fmt.allocPrint(arena, "unknown op: '{s}'", .{raw.op});
                try diags.append(arena, .{ .line = start_line, .message = msg });
                continue;
            };

            // Dupe arg and value strings into arena so they survive the caller's lifetime.
            const duped_arg = if (raw.arg) |a| try arena.dupe(u8, a) else null;
            const duped_val = try arena.dupe(u8, raw.value);

            try entries.append(arena, .{
                .key = key,
                .arg = duped_arg,
                .op = op,
                .value = duped_val,
                .line = start_line,
            });
        }

        if (entries.items.len == 0) {
            // Non-empty, non-comment line produced nothing usable. Only emit a line-level
            // diagnostic if no per-entry diagnostic already fired for this line (avoids N+1
            // diagnostics for a line whose every entry was individually reported).
            if (diags.items.len == diags_before) {
                const msg = try std.fmt.allocPrint(
                    arena,
                    "line {d}: no valid entries",
                    .{start_line},
                );
                try diags.append(arena, .{ .line = start_line, .message = msg });
            }
            continue;
        }

        try rules.append(arena, .{
            .entries = try entries.toOwnedSlice(arena),
            .line = start_line,
        });
    }

    return rules.toOwnedSlice(arena);
}

// Tests
test "parse a rule with match and assign entries" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags: std.ArrayListUnmanaged(Diagnostic) = .empty;
    const text =
        \\# a comment
        \\SUBSYSTEM=="block", KERNEL=="sd*", SYMLINK+="disk/by-foo/%k"
        \\
    ;
    const rules = try parse(arena.allocator(), text, &diags);
    try std.testing.expectEqual(@as(usize, 1), rules.len);
    const e = rules[0].entries;
    try std.testing.expectEqual(@as(usize, 3), e.len);
    try std.testing.expectEqual(Key.subsystem, e[0].key);
    try std.testing.expectEqual(Op.match, e[0].op);
    try std.testing.expectEqualStrings("block", e[0].value);
    try std.testing.expectEqual(Key.symlink, e[2].key);
    try std.testing.expectEqual(Op.add, e[2].op);
    try std.testing.expectEqualStrings("disk/by-foo/%k", e[2].value);
    try std.testing.expectEqual(@as(usize, 0), diags.items.len);
}

test "parse extracts ATTR/ENV arg and records diagnostics for junk" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags: std.ArrayListUnmanaged(Diagnostic) = .empty;
    const text =
        \\ENV{ID_FS_TYPE}=="ext4", ATTR{size}=="1024"
        \\this is not a valid rule line @@@
        \\ACTION=="add"
    ;
    const rules = try parse(arena.allocator(), text, &diags);
    try std.testing.expectEqual(@as(usize, 2), rules.len); // junk line skipped, others kept
    try std.testing.expect(diags.items.len >= 1);
    try std.testing.expectEqualStrings("ID_FS_TYPE", rules[0].entries[0].arg.?);
}

test "assign_final op and no-arg key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags: std.ArrayListUnmanaged(Diagnostic) = .empty;
    const text =
        \\NAME:="fixed-name"
    ;
    const rules = try parse(arena.allocator(), text, &diags);
    try std.testing.expectEqual(@as(usize, 1), rules.len);
    try std.testing.expectEqual(Key.name, rules[0].entries[0].key);
    try std.testing.expectEqual(Op.assign_final, rules[0].entries[0].op);
    try std.testing.expectEqualStrings("fixed-name", rules[0].entries[0].value);
    try std.testing.expectEqual(@as(usize, 0), diags.items.len);
}

test "backslash-newline line continuation joins into one rule" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags: std.ArrayListUnmanaged(Diagnostic) = .empty;
    const text =
        "SUBSYSTEM==\"block\", \\\n" ++
        "    KERNEL==\"sd*\", \\\n" ++
        "    SYMLINK+=\"disk/x\"\n";
    const rules = try parse(arena.allocator(), text, &diags);
    try std.testing.expectEqual(@as(usize, 1), rules.len);
    try std.testing.expectEqual(@as(usize, 3), rules[0].entries.len);
    try std.testing.expectEqual(Key.subsystem, rules[0].entries[0].key);
    try std.testing.expectEqual(Key.symlink, rules[0].entries[2].key);
    try std.testing.expectEqual(@as(usize, 0), diags.items.len);
    try std.testing.expectEqual(@as(u32, 1), rules[0].line); // reports the rule's START line
}

test "whitespace around operators is tolerated" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags: std.ArrayListUnmanaged(Diagnostic) = .empty;
    const text =
        \\KERNEL == "sd*", ENV{FOO} != "bar", SYMLINK += "x"
    ;
    const rules = try parse(arena.allocator(), text, &diags);
    try std.testing.expectEqual(@as(usize, 1), rules.len);
    const e = rules[0].entries;
    try std.testing.expectEqual(@as(usize, 3), e.len);
    try std.testing.expectEqual(Op.match, e[0].op);
    try std.testing.expectEqualStrings("sd*", e[0].value);
    try std.testing.expectEqual(Op.nomatch, e[1].op);
    try std.testing.expectEqualStrings("FOO", e[1].arg.?);
    try std.testing.expectEqual(Op.add, e[2].op);
    try std.testing.expectEqual(@as(usize, 0), diags.items.len);
}

test "an all-bad line emits per-entry diagnostics but not an extra line diagnostic" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags: std.ArrayListUnmanaged(Diagnostic) = .empty;
    const text =
        \\BOGUS=="x", ALSOBAD=="y"
    ;
    const rules = try parse(arena.allocator(), text, &diags);
    try std.testing.expectEqual(@as(usize, 0), rules.len);
    // Two unknown-key diagnostics, and NOT a third "no valid entries".
    try std.testing.expectEqual(@as(usize, 2), diags.items.len);
}

test "multi-entry line and comment are both handled" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var diags: std.ArrayListUnmanaged(Diagnostic) = .empty;
    const text =
        \\# comment skipped
        \\ACTION=="add", ENV{DEVTYPE}=="disk", OWNER:="root"
    ;
    const rules = try parse(arena.allocator(), text, &diags);
    try std.testing.expectEqual(@as(usize, 1), rules.len);
    const e = rules[0].entries;
    try std.testing.expectEqual(@as(usize, 3), e.len);
    try std.testing.expectEqual(Key.action, e[0].key);
    try std.testing.expectEqual(Op.match, e[0].op);
    try std.testing.expectEqual(Key.env, e[1].key);
    try std.testing.expectEqualStrings("DEVTYPE", e[1].arg.?);
    try std.testing.expectEqual(Key.owner, e[2].key);
    try std.testing.expectEqual(Op.assign_final, e[2].op);
    try std.testing.expectEqual(@as(usize, 0), diags.items.len);
}
