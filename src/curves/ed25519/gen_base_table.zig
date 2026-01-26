const std = @import("std");
const use_avx512 = @import("build_options").use_avx512;

const generic = @import("generic.zig");
const avx512 = @import("avx512.zig");
const Edwards25519 = std.crypto.ecc.Edwards25519;

// Number of elements to make in our LUT.
const N = 64;

pub fn main() !void {
    var buffer: [4096]u8 = undefined;
    var stderr_writer = std.fs.File.stdout().writer(&buffer);
    const writer = &stderr_writer.interface;

    try writer.writeAll(".{ .table = .{\n");

    const A: generic.ExtendedPoint = .fromPoint(.basePoint);
    var Ai: [N]generic.CachedPoint = @splat(.fromExtended(A));
    const A2 = A.dbl();
    for (0..N - 1) |i| Ai[i + 1] = .fromExtended(A2.addCached(Ai[i]));

    for (Ai) |point| {
        try writer.writeAll("    .{ ");

        if (use_avx512) {
            const base = point.element.toPoint();
            const converted: avx512.CachedPoint = .fromExtended(.fromPoint(base));
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
