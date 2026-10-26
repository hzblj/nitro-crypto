const std = @import("std");
/// Zig version. When writing code that supports multiple versions of Zig, prefer
/// feature detection (i.e. with `@hasDecl` or `@hasField`) over version checks.
pub const zig_version = std.SemanticVersion.parse(zig_version_string) catch unreachable;
pub const zig_version_string = "0.16.0";
pub const zig_backend = std.builtin.CompilerBackend.stage2_llvm;

pub const output_mode: std.builtin.OutputMode = .Lib;
pub const link_mode: std.builtin.LinkMode = .static;
pub const unwind_tables: std.builtin.UnwindTables = .async;
pub const is_test = false;
pub const single_threaded = false;
pub const abi: std.Target.Abi = .simulator;
pub const cpu: std.Target.Cpu = .{
    .arch = .aarch64,
    .model = &std.Target.aarch64.cpu.apple_a7,
    .features = std.Target.aarch64.featureSet(&.{
        .aes,
        .alternate_sextload_cvt_f32_pattern,
        .arith_bcc_fusion,
        .arith_cbz_fusion,
        .disable_latency_sched_heuristic,
        .el2vmsa,
        .el3,
        .fp_armv8,
        .fuse_aes,
        .fuse_crypto_eor,
        .neon,
        .perfmon,
        .sha2,
        .store_pair_suppress,
        .v8a,
        .zcm_fpr64,
        .zcm_gpr64,
        .zcz,
        .zcz_fp_workaround,
        .zcz_gp,
    }),
};
pub const os: std.Target.Os = .{
    .tag = .ios,
    .version_range = .{ .semver = .{
        .min = .{
            .major = 15,
            .minor = 1,
            .patch = 0,
        },
        .max = .{
            .major = 18,
            .minor = 6,
            .patch = 0,
        },
    }},
};
pub const target: std.Target = .{
    .cpu = cpu,
    .os = os,
    .abi = abi,
    .ofmt = object_format,
    .dynamic_linker = .init("/usr/lib/dyld"),
};
pub const object_format: std.Target.ObjectFormat = .macho;
pub const mode: std.builtin.OptimizeMode = .ReleaseFast;
pub const link_libc = true;
pub const link_libcpp = false;
pub const have_error_return_tracing = false;
pub const valgrind_support = false;
pub const sanitize_thread = false;
pub const fuzz = false;
pub const position_independent_code = true;
pub const position_independent_executable = false;
pub const strip_debug_info = true;
pub const code_model: std.builtin.CodeModel = .default;
pub const omit_frame_pointer = false;
