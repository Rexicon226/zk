const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");

pub const pippenger = @import("ed25519/pippenger.zig");
pub const straus = @import("ed25519/straus.zig");

pub const mul = straus.mul;
pub const mulManyWithSameScalar = straus.mulManyWithSameScalar;
pub const mulMulti = straus.mulMulti;

const convention: std.builtin.CallingConvention = switch (builtin.mode) {
    .ReleaseFast => .@"inline",
    else => .auto,
};

const generic = @import("ed25519/generic.zig");
const avx512 = @import("ed25519/avx512.zig");

pub const use_avx512 = build_options.use_avx512;

// avx512 implementation relies on llvm specific tricks
const namespace = if (use_avx512) avx512 else generic;
pub const ExtendedPoint = namespace.ExtendedPoint;
pub const CachedPoint = namespace.CachedPoint;

const Edwards25519 = std.crypto.ecc.Edwards25519;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const CompressedScalar = [32]u8;

pub fn ReturnType(encoded: bool, ristretto: bool) type {
    const Base = if (ristretto) Ristretto255 else Edwards25519;
    return if (encoded) (error{NonCanonical} || std.crypto.errors.EncodingError)!Base else Base;
}

pub fn PointType(encoded: bool, ristretto: bool) type {
    if (encoded) return [32]u8;
    return if (ristretto) Ristretto255 else Edwards25519;
}

/// MSM in variable time with a runtime known (but comptime bounded) number
/// of points. useful for things such as bulletproofs where we are generic over
/// the bitsize and it can change between being more optimal to use straus or pippenger.
///
/// Generally speaking, `mulMulti` will be more useful as in most cases the number of points
/// and scalars is known ahead of time.
pub fn mulMultiRuntime(
    comptime max_elements: comptime_int,
    /// Set to true if the input is in wire-format. This lets us usually save
    /// an extra stack copy and loop when buffering the decoding process,
    /// instead just doing it once here straight into the extended point form.
    ///
    /// Changes the return type of the function to an error union, in case
    /// the encoded points decode into a non-canonical form.
    comptime encoded: bool,
    /// (Option only applies if we're decoding from a wire format).
    ///
    /// Set to true if the wire format we're decoding from is Ristretto instead
    /// of Edwards25519. The actual MSM itself still happens on the underlying
    /// Edwards25519 element, since there's no difference between the operation
    /// on Ristretto and Edwards25519, but the decoding is different.
    comptime ristretto: bool,
    ed_points: []const PointType(encoded, ristretto),
    compressed_scalars: []const CompressedScalar,
) ReturnType(encoded, ristretto) {
    // through impirical benchmarking, we see that pippenger's MSM becomes faster around
    // the 190 element mark.
    // TODO: maybe consider checking the `max_elements < 190` here instead
    // in order to avoid generating both versions? probably would be slower, not sure about the
    // code size impact.

    if (ed_points.len < 190) {
        return straus.mulMultiRuntime(
            max_elements,
            encoded,
            ristretto,
            ed_points,
            compressed_scalars,
        );
    } else {
        return pippenger.mulMultiRuntime(
            max_elements,
            encoded,
            ristretto,
            ed_points,
            compressed_scalars,
        );
    }
}

/// Stores a lookup table of multiplications of a point over radix-16 scalars, which is the most
/// common usecase for straus' method. table contains 1P, 2P, 3P, 4P, 5P, 6P, 7P, 8P, and
/// our window for the scalar indexes into it. Since we want radix-16 (i.e one nibble per byte),
/// we need 16 points, however we can optimize further by centering the radix at 0 (-8..8) and
/// negating the cached point if the radix is below zero. Thus our initialization for the table
/// is twice as keep while retaining the same effect.
pub const LookupTable = struct {
    table: [8]CachedPoint,

    pub fn init(point: Edwards25519) callconv(convention) LookupTable {
        const e: ExtendedPoint = .fromPoint(point);
        var points: [8]CachedPoint = @splat(.fromExtended(e));
        for (0..7) |i| points[i + 1] = .fromExtended(e.addCached(points[i]));
        return .{ .table = points };
    }

    /// NOTE: variable time!
    pub fn select(self: LookupTable, index: i8) callconv(convention) CachedPoint {
        // ensure we're in radix
        std.debug.assert(index >= -8);
        std.debug.assert(index <= 8);

        const abs = @abs(index);

        // t == |x| * P
        var t: CachedPoint = if (abs == 0) .identityElement else self.table[abs - 1];
        // if index was negative, negate the point
        if (index < 0) t = t.neg();

        return t;
    }
};

fn NafLookupTable(N: comptime_int) type {
    return struct {
        table: [N]CachedPoint,

        const Self = @This();

        fn init(point: Edwards25519) callconv(convention) Self {
            const A: ExtendedPoint = .fromPoint(point);
            var Ai: [N]CachedPoint = @splat(.fromExtended(A));
            const A2 = A.dbl();
            for (0..N - 1) |i| Ai[i + 1] = .fromExtended(A2.addCached(Ai[i]));
            return .{ .table = Ai };
        }

        fn select(self: Self, index: u64) CachedPoint {
            std.debug.assert(index & 1 == 1); // make sur ethe index is odd
            std.debug.assert(index < N * 2);
            return self.table[index / 2];
        }
    };
}

/// Compute `(aA + bB)`, in variable time, where `B` is the Ed25519 basepoint.
pub fn doubleBaseMul(a: CompressedScalar, A: Edwards25519, b: CompressedScalar) Edwards25519 {
    const a_naf = asNaf(a, 5);
    const b_naf = asNaf(b, 8);

    // Search through our NAFs to find the first index that will actually affect the outcome.
    // Otherwise the prepending 0s added by `asNaf` will just keep doubling the identityElement.
    var i: u64 = std.math.maxInt(u8);
    for (0..256) |rev| {
        i = 256 - rev - 1;
        if (a_naf[i] != 0 or b_naf[i] != 0) break;
    }

    const table_A: NafLookupTable(8) = .init(A);
    const table_B: NafLookupTable(64) = @import("ed25519_base_table");

    var Q: ExtendedPoint = .identityElement;
    while (true) {
        Q = Q.dbl();

        switch (std.math.order(a_naf[i], 0)) {
            .gt => Q = Q.addCached(table_A.select(@intCast(a_naf[i]))),
            .lt => Q = Q.subCached(table_A.select(@intCast(-a_naf[i]))),
            .eq => {},
        }

        switch (std.math.order(b_naf[i], 0)) {
            .gt => Q = Q.addCached(table_B.select(@intCast(b_naf[i]))),
            .lt => Q = Q.subCached(table_B.select(@intCast(-b_naf[i]))),
            .eq => {},
        }

        if (i == 0) break;
        i -= 1;
    }

    return Q.toPoint();
}

/// Ported from: https://github.com/dalek-cryptography/curve25519-dalek/blob/c3a82a8a38a58aee500a20bde1664012fcfa83ba/curve25519-dalek/src/scalar.rs#L958
fn asNaf(a: CompressedScalar, w: comptime_int) [256]i8 {
    std.debug.assert(w >= 2);
    std.debug.assert(w <= 8);

    var naf: [256]i8 = @splat(0);

    var x: [5]u64 = @splat(0);
    @memcpy(std.mem.asBytes(x[0..4]), &a);

    const width = 1 << w;
    const window_mask = width - 1;

    var pos: u64 = 0;
    var carry: u64 = 0;
    while (pos < 256) {
        const idx = pos / 64;
        const bit_idx: std.math.Log2Int(u64) = @intCast(pos % 64);

        const bit_buf: u64 = switch (bit_idx) {
            0...63 - w => x[idx] >> bit_idx,
            else => x[idx] >> bit_idx | x[1 + idx] << @intCast(64 - @as(u7, bit_idx)),
        };

        const window = carry + (bit_buf & window_mask);

        if (window & 1 == 0) {
            pos += 1;
            continue;
        }

        if (window < width / 2) {
            carry = 0;
            naf[pos] = @intCast(window);
        } else {
            carry = 1;
            const signed: i64 = @bitCast(window);
            naf[pos] = @as(i8, @truncate(signed)) -% @as(i8, @truncate(width));
        }

        pos += w;
    }

    return naf;
}

test asNaf {
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/c3a82a8a38a58aee500a20bde1664012fcfa83ba/curve25519-dalek/src/scalar.rs#L1495-L1513
    const A_SCALAR: [32]u8 = .{
        0x1a, 0x0e, 0x97, 0x8a, 0x90, 0xf6, 0x62, 0x2d, 0x37, 0x47, 0x02, 0x3f, 0x8a, 0xd8,
        0x26, 0x4d, 0xa7, 0x58, 0xaa, 0x1b, 0x88, 0xe0, 0x40, 0xd1, 0x58, 0x9e, 0x7b, 0x7f,
        0x23, 0x76, 0xef, 0x09,
    };
    const A_NAF: [256]i8 = .{
        0,  13, 0, 0,  0,  0, 0, 0, 0, 7,   0,  0,   0,  0, 0,  0,  -9, 0,  0, 0,  0,  -11,
        0,  0,  0, 0,  3,  0, 0, 0, 0, 1,   0,  0,   0,  0, 9,  0,  0,  0,  0, -5, 0,  0,
        0,  0,  0, 0,  3,  0, 0, 0, 0, 11,  0,  0,   0,  0, 11, 0,  0,  0,  0, 0,  -9, 0,
        0,  0,  0, 0,  -3, 0, 0, 0, 0, 9,   0,  0,   0,  0, 0,  1,  0,  0,  0, 0,  0,  0,
        -1, 0,  0, 0,  0,  0, 9, 0, 0, 0,   0,  -15, 0,  0, 0,  0,  -7, 0,  0, 0,  0,  -9,
        0,  0,  0, 0,  0,  5, 0, 0, 0, 0,   13, 0,   0,  0, 0,  0,  -3, 0,  0, 0,  0,  -11,
        0,  0,  0, 0,  -7, 0, 0, 0, 0, -13, 0,  0,   0,  0, 11, 0,  0,  0,  0, -9, 0,  0,
        0,  0,  0, 1,  0,  0, 0, 0, 0, -15, 0,  0,   0,  0, 1,  0,  0,  0,  0, 7,  0,  0,
        0,  0,  0, 0,  0,  0, 5, 0, 0, 0,   0,  0,   13, 0, 0,  0,  0,  0,  0, 11, 0,  0,
        0,  0,  0, 15, 0,  0, 0, 0, 0, -9,  0,  0,   0,  0, 0,  0,  0,  -1, 0, 0,  0,  0,
        0,  0,  0, 7,  0,  0, 0, 0, 0, -15, 0,  0,   0,  0, 0,  15, 0,  0,  0, 0,  15, 0,
        0,  0,  0, 15, 0,  0, 0, 0, 0, 1,   0,  0,   0,  0,
    };

    const result = asNaf(A_SCALAR, 5);
    try std.testing.expectEqualSlices(i8, &A_NAF, &result);
}

test "wnaf reconstruction" {
    const Scalar = Edwards25519.scalar.Scalar;
    for (0..1000) |_| {
        const scalar: Scalar = .random();
        inline for (.{ 5, 6, 7, 8 }) |w| {
            const naf = asNaf(scalar.toBytes(), w);
            var y: Scalar = .fromBytes(@splat(0));
            for (0..256) |rev| {
                const i = 256 - rev - 1;
                y = y.add(y);

                const n = @abs(naf[i]);
                var limbs: [32]u8 = @splat(0);
                std.mem.writeInt(u64, limbs[0..8], n, .little);

                const digit: Scalar = .fromBytes(if (naf[i] < 0)
                    Edwards25519.scalar.neg(limbs)
                else
                    limbs);

                y = y.add(digit);
            }

            try std.testing.expectEqual(y, scalar);
        }
    }
}

test doubleBaseMul {
    // https://github.com/dalek-cryptography/curve25519-dalek/blob/c3a82a8a38a58aee500a20bde1664012fcfa83ba/curve25519-dalek/src/edwards.rs#L1812-L1835
    const A_TIMES_BASEPOINT: [32]u8 = .{
        0xea, 0x27, 0xe2, 0x60, 0x53, 0xdf, 0x1b, 0x59, 0x56, 0xf1, 0x4d, 0x5d, 0xec, 0x3c, 0x34,
        0xc3, 0x84, 0xa2, 0x69, 0xb7, 0x4c, 0xc3, 0x80, 0x3e, 0xa8, 0xe2, 0xe7, 0xc9, 0x42, 0x5e,
        0x40, 0xa5,
    };
    const A_SCALAR: [32]u8 = .{
        0x1a, 0x0e, 0x97, 0x8a, 0x90, 0xf6, 0x62, 0x2d, 0x37, 0x47, 0x02, 0x3f, 0x8a, 0xd8,
        0x26, 0x4d, 0xa7, 0x58, 0xaa, 0x1b, 0x88, 0xe0, 0x40, 0xd1, 0x58, 0x9e, 0x7b, 0x7f,
        0x23, 0x76, 0xef, 0x09,
    };
    const B_SCALAR: [32]u8 = .{
        0x91, 0x26, 0x7a, 0xcf, 0x25, 0xc2, 0x09, 0x1b, 0xa2, 0x17, 0x74, 0x7b, 0x66, 0xf0,
        0xb3, 0x2e, 0x9d, 0xf2, 0xa5, 0x67, 0x41, 0xcf, 0xda, 0xc4, 0x56, 0xa7, 0xd4, 0xaa,
        0xb8, 0x60, 0x8a, 0x05,
    };
    const DOUBLE_BASE_MUL_RESULT: [32]u8 = .{
        0x7d, 0xfd, 0x6c, 0x45, 0xaf, 0x6d, 0x6e, 0x0e, 0xba, 0x20, 0x37, 0x1a, 0x23, 0x64, 0x59,
        0xc4, 0xc0, 0x46, 0x83, 0x43, 0xde, 0x70, 0x4b, 0x85, 0x09, 0x6f, 0xfe, 0x35, 0x4f, 0x13,
        0x2b, 0x42,
    };

    const A: Edwards25519 = try .fromBytes(A_TIMES_BASEPOINT);
    const result = doubleBaseMul(A_SCALAR, A, B_SCALAR);

    try std.testing.expectEqualSlices(u8, &result.toBytes(), &DOUBLE_BASE_MUL_RESULT);
}
