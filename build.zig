const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // module

    const stdx = b.createModule(.{
        .root_source_file = b.path("src/stdx.zig"),
        .target = target,
        .optimize = optimize,
    });

    const generator_chain = b.addExecutable(.{
        .name = "generator_chain",
        .root_module = b.createModule(.{
            .target = b.graph.host,
            // Overall it takes less time to compile in debug mode than the perf gain from a release mode at runtime
            .optimize = .Debug,
            .root_source_file = b.path("src/range_proofs/bulletproofs/generator_chain.zig"),
        }),
    });
    const run_generator_chain = b.addRunArtifact(generator_chain);
    const generator_chain_output = run_generator_chain.captureStdOut();
    run_generator_chain.captured_stdout.?.basename = "table.zig";

    const test_filters = b.option(
        []const []const u8,
        "test-filter",
        "Filters for which tests to run",
    ) orelse &.{};

    const use_llvm = b.option(bool, "use-llvm", "Use LLVM to compile") orelse true;

    const zk_mod = b.addModule("zk", .{
        .root_source_file = b.path("src/zk.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "stdx", .module = stdx },
        },
    });
    zk_mod.addAnonymousImport(
        "bullet_table",
        .{ .root_source_file = generator_chain_output },
    );

    // tests

    const test_step = b.step("test", "Run tests");

    {
        const test_zk_exe = b.addTest(.{
            .root_module = zk_mod,
            .filters = test_filters,
            .use_llvm = use_llvm,
        });
        b.installArtifact(test_zk_exe);

        const test_zk_step = b.step("test-zk", "Run zk module tests");
        test_zk_step.dependOn(&b.addRunArtifact(test_zk_exe).step);
        test_step.dependOn(test_zk_step);
    }
    {
        const test_stdx_exe = b.addTest(.{
            .root_module = stdx,
            .filters = test_filters,
            .use_llvm = use_llvm,
        });
        b.installArtifact(test_stdx_exe);

        const test_stdx_step = b.step("test-stdx", "Run stdx module tests");
        test_stdx_step.dependOn(&b.addRunArtifact(test_stdx_exe).step);
        test_step.dependOn(test_stdx_step);
    }

    // docs
    const docs_step = b.step("docs", "Generate documentation for the library");
    const docs_obj = b.addObject(.{
        .name = "zk",
        .root_module = zk_mod,
    });
    const install_dir = b.addInstallDirectory(.{
        .source_dir = docs_obj.getEmittedDocs(),
        .install_dir = .prefix,
        .install_subdir = "docs",
    });
    docs_step.dependOn(&install_dir.step);

    // benchmark
    const benchmark_exe = b.addExecutable(.{
        .name = "benchmark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zk", .module = zk_mod },
                .{ .name = "stdx", .module = stdx },
            },
        }),
        .use_llvm = use_llvm,
    });
    b.installArtifact(benchmark_exe);
    const benchmark_step = b.step("benchmark", "Runs the benchmarks");
    const run_benchmark = b.addRunArtifact(benchmark_exe);
    if (b.args) |args| run_benchmark.addArgs(args);
    benchmark_step.dependOn(&run_benchmark.step);

    // fuzzing
    // const libfuzz = b.dependency("fuzz", .{
    //     .target = target,
    //     .optimize = optimize,
    // });
    // const fuzz_obj = b.addObject(.{
    //     .name = "zigfuzz",
    //     .root_module = b.createModule(.{
    //         .root_source_file = b.path("src/fuzz.zig"),
    //         .target = target,
    //         .optimize = optimize,
    //         .fuzz = true,
    //     }),
    // });
    // fuzz_obj.root_module.fuzz = true;

    // const fuzz_exe = b.addExecutable(.{
    //     .name = "fuzz",
    //     .root_module = b.createModule(.{
    //         .target = target,
    //         .optimize = optimize,
    //     }),
    // });
    // fuzz_exe.addCSourceFile(.{ .file = libfuzz.path("src/FuzzerMain.cpp") });
    // fuzz_exe.linkLibrary(libfuzz.artifact("fuzzer"));
    // fuzz_exe.addObject(fuzz_obj);

    // const run_fuzz = b.step("fuzz", "Run the fuzzing");
    // run_fuzz.dependOn(&b.addRunArtifact(fuzz_exe).step);
    // b.installArtifact(fuzz_exe);
}
