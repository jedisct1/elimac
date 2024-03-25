const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseFast });

    const lib = b.addStaticLibrary(.{
        .name = "elimac",
        .target = target,
        .optimize = optimize,
        .strip = true,
    });

    lib.linkLibC();

    lib.addIncludePath(.{ .path = "src/include" });

    const source_files = &.{
        "src/elimac.c",
    };

    lib.addCSourceFiles(.{ .files = source_files });

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(lib);

    b.installDirectory(.{
        .install_dir = .header,
        .install_subdir = "",
        .source_dir = .{ .path = "src/include" },
    });
}
