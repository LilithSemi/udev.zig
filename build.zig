const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const udev_mod = b.addModule("udev", .{
        .root_source_file = b.path("src/udev.zig"),
        .target = target,
        .optimize = optimize,
    });

    const blkid_dep = b.dependency("blkid", .{ .target = target, .optimize = optimize });
    udev_mod.addImport("blkid", blkid_dep.module("blkid"));

    const udevd_exe = b.addExecutable(.{
        .name = "udevd",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/udevd.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    udevd_exe.root_module.addImport("udev", udev_mod);
    b.installArtifact(udevd_exe);

    const udevadm_exe = b.addExecutable(.{
        .name = "udevadm",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/udevadm.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    udevadm_exe.root_module.addImport("udev", udev_mod);
    b.installArtifact(udevadm_exe);

    const test_step = b.step("test", "Run tests");
    const udev_tests = b.addTest(.{ .root_module = udev_mod });
    test_step.dependOn(&b.addRunArtifact(udev_tests).step);
}
