const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseFast });

    const lib_mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .strip = true,
        .link_libc = true,
    });

    const lib = b.addLibrary(.{
        .name = "elimac",
        .root_module = lib_mod,
        .linkage = .static,
    });

    const lib_options = b.addOptions();

    const with_benchmark: bool = b.option(bool, "with-benchmark", "Compile benchmark") orelse false;
    lib_options.addOption(bool, "benchmark", with_benchmark);

    lib_mod.addIncludePath(b.path("src/include"));

    const source_files = &.{
        "src/elimac.c",
    };

    lib_mod.addCSourceFiles(.{ .files = source_files });

    b.installArtifact(lib);

    b.installDirectory(.{
        .install_dir = .header,
        .install_subdir = "",
        .source_dir = b.path("src/include"),
    });

    if (with_benchmark) {
        const translate_c = b.addTranslateC(.{
            .root_source_file = b.path("src/include/elimac.h"),
            .target = target,
            .optimize = optimize,
        });
        translate_c.addIncludePath(b.path("src/include"));

        const benchmark = b.addExecutable(.{
            .name = "benchmark",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/test/benchmark.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "elimac", .module = translate_c.createModule() },
                },
            }),
        });
        benchmark.root_module.addIncludePath(b.path("src/include"));
        benchmark.root_module.linkLibrary(lib);
        b.installArtifact(benchmark);
    }
}
