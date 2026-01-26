const std = @import("std");
const use_avx512 = @import("build_options").use_avx512;

const ed25519 = @import("generic.zig");
const avx512 = @import("avx512.zig");
const Edwards25519 = std.crypto.ecc.Edwards25519;
const ExtendedPoint = ed25519.ExtendedPoint;
const CachedPoint = ed25519.CachedPoint;

// Number of elements to make in our LUT.
const N = 64;

pub fn main() !void {
    var buffer: [4096]u8 = undefined;
    var stderr_writer = std.fs.File.stdout().writer(&buffer);
    const writer = &stderr_writer.interface;

    try writer.writeAll(".{ .table = .{\n");

    const A: ExtendedPoint = .fromPoint(.basePoint);
    var Ai: [N]CachedPoint = @splat(.fromExtended(A));
    const A2 = A.dbl();
    for (0..N - 1) |i| Ai[i + 1] = .fromExtended(A2.addCached(Ai[i]));

    for (Ai) |point| {
        try writer.writeAll("    .{ ");

        if (use_avx512) {
            const edwards = point.element.toPoint();
            const converted: avx512.CachedPoint = .fromExtended(.fromPoint(edwards));
            try writer.writeAll(".limbs = .{");
            for (converted.limbs) |limb| {
                try writer.print(".{d},\n", .{limb});
            }
            try writer.writeAll("} ");
        } else {
            try writer.writeAll(".element = .{ .limbs = .{ ");
            for (point.element.limbs) |limb| {
                try writer.print(".{d},\n", .{limb});
            }
            try writer.writeAll("} } ");
        }

        try writer.writeAll("},\n");
    }

    try writer.writeAll("} }");
    try writer.flush();
}
