//! The nitro-crypto engine: one static library with a C ABI (`include/nitro_crypto.h`), its tests, and a
//! WebAssembly build of the same code for hosts without a device (the TypeScript tests).
//!
//!   zig build                     the static library for the host, into zig-out/
//!   zig build test                every Zig unit test, the published vectors, and the C ABI harness in C
//!   zig build wasm                zig-out/bin/nitro_crypto.wasm (wasm32-wasi reactor)
//!   zig build bench               primitive timings, ReleaseFast
//!   zig build test-exe, bench-exe the same binaries into zig-out/bin, for a device (with -Dtarget, then adb)
//!
//! iOS and Android artifacts are cross-compiled by scripts/build-native, which calls this file per target.

const std = @import("std");
const zon = @import("build.zig.zon");

/// libsecp256k1's verification table: 2^(w-2) points of 64 bytes, twice. Upstream's default, 15, is 1 MiB of
/// tables in every slice of every app; 8 is 8 KiB, for verification about 7% slower (27 µs against 29 µs on
/// Apple Silicon). Measurements and the decision: docs/adr/0002-secp256k1-from-libsecp256k1.md.
const default_ecmult_window: u8 = 8;

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const ecmult_window = b.option(u8, "ecmult-window", "libsecp256k1 ECMULT_WINDOW_SIZE, 2 to 15") orelse
        default_ecmult_window;
    const pic = b.option(bool, "pic", "Position-independent code (Android links the archive into a .so)");
    // Release artifacts are stripped: DWARF carries the build machine's paths (and a randomized cache path),
    // which would make two builds of the same source differ and leak into every app.
    const strip = b.option(bool, "strip", "Omit debug information (the shipped artifacts)");

    const secp256k1 = b.dependency("secp256k1", .{});
    const config: Config = .{ .secp256k1 = secp256k1, .ecmult_window = ecmult_window, .pic = pic, .strip = strip };

    const lib = b.addLibrary(.{
        .name = "nitro_crypto",
        .linkage = .static,
        .root_module = engineModule(b, config, "src/root.zig", target, optimize),
    });
    lib.bundle_compiler_rt = false;
    lib.installHeader(b.path("include/nitro_crypto.h"), "nitro_crypto.h");
    b.installArtifact(lib);

    addTests(b, config, target, optimize, lib);
    addWasm(b, config);
    addBench(b, config, target);
}

const Config = struct {
    secp256k1: *std.Build.Dependency,
    ecmult_window: u8,
    pic: ?bool,
    strip: ?bool,
};

/// libsecp256k1's release, from the tag in build.zig.zon's URL (".../tags/v0.8.0.tar.gz" is "0.8.0").
fn secp256k1Version() []const u8 {
    return comptime version: {
        const url = zon.dependencies.secp256k1.url;
        const start = (std.mem.indexOf(u8, url, "/tags/v") orelse @compileError("pin libsecp256k1 to a release tag")) + "/tags/v".len;
        const end = std.mem.indexOfPos(u8, url, start, ".tar.gz") orelse @compileError("expected a .tar.gz release");
        break :version url[start..end];
    };
}

/// A module of the engine rooted at `root`, with libsecp256k1 compiled into it and `build_options` imported.
fn engineModule(
    b: *std.Build,
    config: Config,
    root: []const u8,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const options = b.addOptions();
    options.addOption([]const u8, "version", zon.version);
    options.addOption([]const u8, "secp256k1_version", secp256k1Version());
    options.addOption(u8, "ecmult_window", config.ecmult_window);

    const module = b.createModule(.{
        .root_source_file = b.path(root),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = config.pic,
        .strip = config.strip,
        .imports = &.{
            .{ .name = "build_options", .module = options.createModule() },
            .{ .name = "secp256k1_c", .module = secp256k1Bindings(b, config, target, optimize) },
        },
    });
    addSecp256k1Sources(b, module, config);
    return module;
}

/// libsecp256k1 with only the recovery module, upstream's signing table (COMB 11/6), our own default callbacks,
/// and every public symbol renamed `nc_secp256k1_*` by `src/curves/secp256k1_prefix.h`: an app that links another copy
/// of the library links both without a clash.
fn addSecp256k1Sources(b: *std.Build, module: *std.Build.Module, config: Config) void {
    module.addCMacro("ENABLE_MODULE_RECOVERY", "1");
    module.addCMacro("ECMULT_WINDOW_SIZE", b.fmt("{d}", .{config.ecmult_window}));
    module.addCMacro("COMB_BLOCKS", "11");
    module.addCMacro("COMB_TEETH", "6");
    module.addCMacro("USE_EXTERNAL_DEFAULT_CALLBACKS", "1");
    module.addCMacro("SECP256K1_NO_API_VISIBILITY_ATTRIBUTES", "1");
    module.addIncludePath(config.secp256k1.path("include"));
    module.addIncludePath(config.secp256k1.path("src"));
    module.addCSourceFiles(.{
        .root = config.secp256k1.path("src"),
        .files = &.{ "secp256k1.c", "precomputed_ecmult.c", "precomputed_ecmult_gen.c" },
        .flags = &.{
            "-std=c89",
            "-include",
            b.pathFromRoot("src/curves/secp256k1_prefix.h"),
            "-fvisibility=hidden",
            "-Wno-unused-function",
        },
    });
}

fn secp256k1Bindings(
    b: *std.Build,
    config: Config,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *std.Build.Module {
    const translate = b.addTranslateC(.{
        .root_source_file = b.path("src/curves/secp256k1.h"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    translate.addIncludePath(config.secp256k1.path("include"));
    translate.addIncludePath(b.path("src/curves"));
    return translate.createModule();
}

fn addTests(
    b: *std.Build,
    config: Config,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    lib: *std.Build.Step.Compile,
) void {
    const step = b.step("test", "Unit tests, published vectors, and the C ABI harness");

    const engine = engineModule(b, config, "src/root.zig", target, optimize);
    // LLVM even in Debug: Zig's own x86-64 backend cannot encode the SHA extensions, and the tests run what ships.
    const unit = b.addTest(.{ .root_module = engine, .use_llvm = true });
    step.dependOn(&b.addRunArtifact(unit).step);

    // The published vectors, in a root of their own so the JSON files sit beside it.
    const vectors = b.addTest(.{ .root_module = b.createModule(.{
        .root_source_file = b.path("test/vectors.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{.{ .name = "engine", .module = engine }},
    }) });
    step.dependOn(&b.addRunArtifact(vectors).step);

    // The ABI as a C program sees it: the installed header and the static library, nothing from Zig.
    const harness = b.addExecutable(.{
        .name = "c_abi_test",
        .root_module = b.createModule(.{ .target = target, .optimize = optimize, .link_libc = true }),
    });
    harness.root_module.addCSourceFile(.{ .file = b.path("test/c_abi_test.c"), .flags = &.{ "-std=c11", "-Wall", "-Wextra", "-Werror", "-pthread" } });
    harness.root_module.addIncludePath(b.path("include"));
    harness.root_module.linkLibrary(lib);
    step.dependOn(&b.addRunArtifact(harness).step);

    // The same three, built for a device and run there: `-Dtarget=aarch64-linux-musl -Dcpu=baseline`, then adb.
    const device = b.step("test-exe", "Build the tests into zig-out/bin, to run on another machine");
    device.dependOn(&b.addInstallArtifact(unit, .{ .dest_sub_path = "engine_test" }).step);
    device.dependOn(&b.addInstallArtifact(vectors, .{ .dest_sub_path = "vectors_test" }).step);
    device.dependOn(&b.addInstallArtifact(harness, .{}).step);
}

fn addWasm(b: *std.Build, base: Config) void {
    // Stripped like the native artifacts: it ships (inside @hzblj/nitro-crypto/testing) and must not carry paths.
    var config = base;
    config.strip = true;
    const target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .wasi });
    const wasm = b.addExecutable(.{
        .name = "nitro_crypto",
        .root_module = engineModule(b, config, "src/wasm.zig", target, .ReleaseSmall),
    });
    wasm.entry = .disabled;
    wasm.rdynamic = true;
    wasm.wasi_exec_model = .reactor;
    const install = b.addInstallArtifact(wasm, .{});
    b.step("wasm", "The engine as a wasm32-wasi reactor, for the TypeScript tests").dependOn(&install.step);
}

fn addBench(b: *std.Build, config: Config, target: std.Build.ResolvedTarget) void {
    const bench = b.addExecutable(.{
        .name = "nitro_crypto_bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("bench/main.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .imports = &.{.{ .name = "engine", .module = engineModule(b, config, "src/root.zig", target, .ReleaseFast) }},
        }),
    });
    const run = b.addRunArtifact(bench);
    b.step("bench", "Time the primitives (ReleaseFast)").dependOn(&run.step);
    const install = b.addInstallArtifact(bench, .{});
    b.step("bench-exe", "Build the benchmark into zig-out/bin, to run on another machine").dependOn(&install.step);
}
