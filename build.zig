const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const stdx = b.createModule(.{
        .root_source_file = b.path("src/stdx.zig"),
        .target = target,
        .optimize = optimize,
    });

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

    const result = target.result;
    const has_avx512 = result.cpu.arch == .x86_64 and
        result.cpu.has(.x86, .avx512ifma) and
        result.cpu.has(.x86, .avx512vl);
    const use_avx512 = has_avx512 and use_llvm;

    const options = b.addOptions();
    options.addOption(bool, "use_avx512", use_avx512);
    zk_mod.addOptions("build_options", options);

    // Add the precomputed tables

    const generator_chain = addTable(
        b,
        options,
        "generator_chain",
        "src/range_proofs/bulletproofs/generator_chain.zig",
        .zig,
    );
    zk_mod.addAnonymousImport("bullet_table", .{ .root_source_file = generator_chain });
    const ed25519_base_table = addTable(
        b,
        options,
        "ed25519_base_table",
        "src/curves/ed25519/gen_base_table.zig",
        .zon,
    );
    zk_mod.addAnonymousImport("ed25519_base_table", .{ .root_source_file = ed25519_base_table });

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

fn addTable(
    b: *std.Build,
    options: *std.Build.Step.Options,
    name: []const u8,
    path: []const u8,
    ty: enum { zon, zig },
) std.Build.LazyPath {
    const mod = b.createModule(.{
        .target = b.graph.host,
        .optimize = .Debug,
        .root_source_file = b.path(path),
    });
    mod.addOptions("build_options", options);

    const generator = b.addExecutable(.{ .name = name, .root_module = mod });
    const run_generator = b.addRunArtifact(generator);
    const output = run_generator.captureStdOut();
    // TODO: Working around Zig 0.15 bug here, update when it's fixed.
    run_generator.captured_stdout.?.basename = switch (ty) {
        .zon => "table.zon",
        .zig => "table.zig",
    };

    return output;
}
