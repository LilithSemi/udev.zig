//! udev rules engine (parser, evaluator, substitutions). Builtins and real process
//! execution arrive through the injected Runner interface.
const std = @import("std");
pub const glob = @import("rules/glob.zig");
pub const lexer = @import("rules/lexer.zig");
pub const parser = @import("rules/parser.zig");
pub const runner = @import("rules/runner.zig");
pub const subst = @import("rules/subst.zig");
pub const eval = @import("rules/eval.zig");

const Device = @import("device.zig").Device;

pub const RuleSet = struct {
    arena: std.heap.ArenaAllocator,
    rules: []const parser.Rule,
    diagnostics: []const parser.Diagnostic,

    pub fn parse(gpa: std.mem.Allocator, text: []const u8) !RuleSet {
        var arena = std.heap.ArenaAllocator.init(gpa);
        errdefer arena.deinit();
        const a = arena.allocator();

        var diags: std.ArrayListUnmanaged(parser.Diagnostic) = .empty;
        const rules_slice = try parser.parse(a, text, &diags);
        const diags_slice = try diags.toOwnedSlice(a);

        return RuleSet{
            .arena = arena,
            .rules = rules_slice,
            .diagnostics = diags_slice,
        };
    }

    pub fn deinit(self: *RuleSet) void {
        self.arena.deinit();
    }

    /// Apply rules to `dev` and return an EventState with all assignments resolved.
    /// Note: for a Device built via `fromProps` (monitor source, no live sysfs),
    /// the sysfs-backed match keys ATTR/ATTRS and the driver/subsystem symlink
    /// reads degrade to empty unless the value is present as a uevent property.
    /// DRIVER and SUBSYSTEM are carried in the uevent and remain matchable;
    /// sysattr values (ATTR/ATTRS) are not and will always compare as empty.
    pub fn apply(
        self: *const RuleSet,
        gpa: std.mem.Allocator,
        dev: *Device,
        r: runner.Runner,
    ) !runner.EventState {
        var state = runner.EventState.init(gpa);
        errdefer state.deinit();

        var prop_it = dev.props.iterator();
        while (prop_it.next()) |kv| {
            try state.setProperty(kv.key_ptr.*, kv.value_ptr.*);
        }

        try eval.evaluate(self.rules, dev, r, &state);
        return state;
    }
};

test "RuleSet: end-to-end parse, apply, diagnostics surface" {
    const uevent_mod = @import("uevent.zig");
    const context_mod = @import("context.zig");

    var ctx = context_mod.Context.init(std.testing.allocator, std.testing.io);
    defer ctx.deinit();

    const ev_buf = "add@/devices/x/sda\x00" ++
        "ACTION=add\x00SUBSYSTEM=block\x00DEVPATH=/devices/x/sda\x00";
    const parsed_ev = try uevent_mod.parseKernel(ev_buf);
    var dev = try Device.fromProps(&ctx, parsed_ev.devpath.?, parsed_ev.props);
    defer dev.deinit();

    const rules_text =
        \\ACTION=="add", SUBSYSTEM=="block", NAME="storage/%k"
        \\this is complete junk @@@
        \\SUBSYSTEM=="block", SYMLINK+="by-sub/block"
    ;

    var ruleset = try RuleSet.parse(std.testing.allocator, rules_text);
    defer ruleset.deinit();

    try std.testing.expect(ruleset.diagnostics.len >= 1);
    try std.testing.expectEqual(@as(usize, 2), ruleset.rules.len);

    var fake: runner.FakeRunner = .{};
    var state = try ruleset.apply(std.testing.allocator, &dev, fake.runner());
    defer state.deinit();

    try std.testing.expectEqualStrings("storage/sda", state.name.?);
    try std.testing.expectEqual(@as(usize, 1), state.symlinks.items.len);
    try std.testing.expectEqualStrings("by-sub/block", state.symlinks.items[0]);
}

test {
    std.testing.refAllDecls(@This());
}
