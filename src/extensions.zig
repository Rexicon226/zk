//! Generic field extensions
const std = @import("std");

pub fn Quadratic(
    BaseField: type,
    comptime params: struct {
        /// Null when we don't want to allow (de)serialization.
        serialized_size: ?usize = null,
        non_residue: BaseField,
    },
    extra: anytype,
) type {
    return struct {
        c0: BaseField,
        c1: BaseField,

        const Self = @This();
        pub const zero: Self = .{
            .c0 = .zero,
            .c1 = .zero,
        };
        pub const one: Self = .{
            .c0 = .one,
            .c1 = .zero,
        };
        pub const extension_degree = BaseField.extension_degree * 2;
        pub const serialized_size = params.serialized_size orelse @compileError("cannot deserialize");
        pub const non_residue = params.non_residue;
        pub const frob = if (@hasDecl(extra, "frob")) extra.frob;
        pub const frob2 = if (@hasDecl(extra, "frob2")) extra.frob2;
        pub const powX = if (@hasDecl(extra, "powX")) extra.powX;
        pub const sqFast = if (@hasDecl(extra, "sqFast")) extra.sqFast;
        pub const mulByNonResidue = if (@hasDecl(extra, "mulByNonResidue")) extra.mulByNonResidue else struct {
            fn mulByNonResidue(base: BaseField) BaseField {
                return base.mul(params.non_residue);
            }
        }.mulByNonResidue;

        pub fn fromBytes(input: *const [serialized_size]u8, maybe_flags: ?*BaseField.Flags) !Self {
            return .{
                .c0 = try .fromBytes(input[BaseField.serialized_size..][0..BaseField.serialized_size], null),
                .c1 = try .fromBytes(input[0..BaseField.serialized_size], maybe_flags),
            };
        }

        pub fn isZero(f: Self) bool {
            return f.c0.isZero() and f.c1.isZero();
        }

        pub fn isOne(f: Self) bool {
            return f.c0.isOne() and f.c1.isZero();
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.c0.eql(b.c0) and a.c1.eql(b.c1);
        }

        pub fn add(a: Self, b: Self) Self {
            return .{
                .c0 = a.c0.add(b.c0),
                .c1 = a.c1.add(b.c1),
            };
        }

        /// Returns `2 * a`
        pub fn dbl(a: Self) Self {
            return add(a, a);
        }

        /// Returns `3 * a`
        pub fn triple(a: Self) Self {
            return add(a, add(a, a));
        }

        pub fn sub(a: Self, b: Self) Self {
            return .{
                .c0 = a.c0.sub(b.c0),
                .c1 = a.c1.sub(b.c1),
            };
        }

        pub fn mul(a: Self, b: Self) Self {
            if (extension_degree == 2) {
                // c0: (a0 * b0) + (ApplyNonResidue(a1) * b1)
                // c1: (a0 * b1) + (a1 * b0)
                // TODO: this can be optimized for bn254 and in general. too many muls!

                const a0b0 = a.c0.mul(b.c0);
                const a0b1 = a.c0.mul(b.c1);
                const a1b0 = a.c1.mul(b.c0);
                const a1b1 = mulByNonResidue(a.c1).mul(b.c1);

                return .{
                    .c0 = a0b0.add(a1b1),
                    .c1 = a0b1.add(a1b0),
                };
            } else {
                // https://eprint.iacr.org/2010/354, Alg. 20
                const a0 = a.c0;
                const a1 = a.c1;
                const b0 = b.c0;
                const b1 = b.c1;

                // t0 ← a0 · b0;
                const t0 = a0.mul(b0);
                // t1 ← a1 · b1;
                const t1 = a1.mul(b1);

                return .{
                    // c0 ← t0 + t1 · γ;
                    .c0 = t0.add(mulByNonResidue(t1)),
                    // c1 ← (a0 + a1) · (b0 + b1) − t0 − t1;
                    .c1 = a0.add(a1).mul(b0.add(b1)).sub(t0).sub(t1),
                };
            }
        }

        pub fn mulBase(a: Self, b: BaseField) Self {
            return .{
                .c0 = a.c0.mul(b),
                .c1 = a.c1.mul(b),
            };
        }

        /// https://eprint.iacr.org/2010/354, Alg. 22
        pub fn sq(a: Self) Self {
            // TODO: fp2 for bn254 can do
            // const p = a.c0.add(a.c1);
            // const m = a.c0.sub(a.c1);
            // return .{
            //     // r0 = (c0-c1)*(c0+c1)
            //     .c0 = p.mul(m),
            //     // r1 = 2 c0*c1
            //     .c1 = a.c0.mul(a.c1).dbl(),
            // };

            const c3 = a.c0.sub(mulByNonResidue(a.c1));
            const c2 = a.c0.mul(a.c1);
            const c0 = a.c0.sub(a.c1).mul(c3).add(c2);

            return .{
                .c0 = mulByNonResidue(c2).add(c0),
                .c1 = c2.dbl(),
            };
        }

        /// https://eprint.iacr.org/2010/354.pdf, Alg. 8
        pub fn inverse(a: Self) Self {
            // t0 ← a0^2
            var t0 = a.c0.sq();
            // t1 ← a1^2
            var t1 = a.c1.sq();

            // t0 ← t0 − β · t1;
            t0 = t0.sub(mulByNonResidue(t1));
            // t1 ← t0^-1
            t1 = t0.inverse();

            // c0 ← a0 · t1;
            const c0 = a.c0.mul(t1);
            // c1 ← −1 · a1 · t1;
            const c1 = a.c1.mul(t1).negate();

            return .{
                .c0 = c0,
                .c1 = c1,
            };
        }

        /// Computes the conjugate of the field extension.
        pub fn conjugate(a: Self) Self {
            return .{
                .c0 = a.c0,
                .c1 = a.c1.negate(),
            };
        }

        pub fn negate(a: Self) Self {
            return .{
                .c0 = a.c0.negate(),
                .c1 = a.c1.negate(),
            };
        }

        /// Returns `a / 2`
        pub fn halve(a: Self) Self {
            return .{
                .c0 = a.c0.halve(),
                .c1 = a.c1.halve(),
            };
        }

        pub fn format(f: Self, writer: *std.Io.Writer) !void {
            try writer.print("({f}, {f})", .{ f.c0, f.c1 });
        }
    };
}

pub fn Cubic(
    BaseField: type,
    comptime params: struct {
        non_residue: BaseField,
    },
) type {
    return struct {
        c0: BaseField,
        c1: BaseField,
        c2: BaseField,

        const Self = @This();

        pub const zero: Self = .{
            .c0 = .zero,
            .c1 = .zero,
            .c2 = .zero,
        };
        pub const one: Self = .{
            .c0 = .one,
            .c1 = .zero,
            .c2 = .zero,
        };
        pub const extension_degree = BaseField.extension_degree * 3;
        pub const non_residue = params.non_residue;

        fn isZero(f: Self) bool {
            return f.c0.isZero() and
                f.c1.isZero() and
                f.c2.isZero();
        }

        pub fn isOne(f: Self) bool {
            return f.c0.isOne() and
                f.c1.isZero() and
                f.c2.isZero();
        }

        fn add(a: Self, b: Self) Self {
            return .{
                .c0 = a.c0.add(b.c0),
                .c1 = a.c1.add(b.c1),
                .c2 = a.c2.add(b.c2),
            };
        }

        /// Returns `2 * a`
        pub fn dbl(a: Self) Self {
            return a.add(a);
        }

        /// Returns `3 * a`
        pub fn triple(a: Self) Self {
            return add(a, add(a, a));
        }

        fn sub(a: Self, b: Self) Self {
            return .{
                .c0 = a.c0.sub(b.c0),
                .c1 = a.c1.sub(b.c1),
                .c2 = a.c2.sub(b.c2),
            };
        }

        pub fn mulByNonResidue(base: BaseField) BaseField {
            return base.mul(params.non_residue);
        }

        /// https://eprint.iacr.org/2010/354, Alg. 13
        fn mul(a: Self, b: Self) Self {
            const a0 = a.c0;
            const a1 = a.c1;
            const a2 = a.c2;
            const b0 = b.c0;
            const b1 = b.c1;
            const b2 = b.c2;

            const t0 = a0.mul(b0);
            const t1 = a1.mul(b1);
            const t2 = a2.mul(b2);

            return .{
                // c0 ← [(a1 + a2) · (b1 + b2) − t1 − t2] · ξ + t0;
                .c0 = mulByNonResidue(a1.add(a2).mul(b1.add(b2)).sub(t1).sub(t2)).add(t0),
                // c1 ← (a0 + a1) · (b0 + b1) − t0 − t1 + ξ · t2;
                .c1 = a0.add(a1).mul(b0.add(b1)).sub(t0).sub(t1).add(mulByNonResidue(t2)),
                // c2 ← (a0 + a2) · (b0 + b2) − t0 − t2 + t1;
                .c2 = a0.add(a2).mul(b0.add(b2)).sub(t0).sub(t2).add(t1),
            };
        }

        pub fn negate(a: Self) Self {
            return .{
                .c0 = a.c0.negate(),
                .c1 = a.c1.negate(),
                .c2 = a.c2.negate(),
            };
        }

        /// https://eprint.iacr.org/2010/354, Alg. 16
        pub fn sq(a: Self) Self {
            const a0 = a.c0;
            const a1 = a.c1;
            const a2 = a.c2;

            // c4 ← 2(a0 · a1);
            var c4 = a0.mul(a1).dbl();
            // c5 ← a2^2
            var c5 = a2.sq();
            // c1 ← c5 · ξ + c4;
            const c1 = mulByNonResidue(c5).add(c4);
            // c2 ← c4 − c5;
            var c2 = c4.sub(c5);
            // c3 ← a0^2
            const c3 = a0.sq();
            // c4 ← a0 − a1 + a2;
            c4 = a0.sub(a1).add(a2);
            // c5 ← 2(a1 · a2);
            c5 = a1.mul(a2).dbl();
            // c4 ← c4^2
            c4 = c4.sq();
            // c0 ← c5 · ξ + c3;
            const c0 = mulByNonResidue(c5).add(c3);

            return .{
                .c0 = c0,
                .c1 = c1,
                // c2 ← c2 + c4 + c5 − c3;
                .c2 = c2.add(c4).add(c5).sub(c3),
            };
        }

        /// https://eprint.iacr.org/2010/354, Alg. 17
        pub fn inverse(a: Self) Self {
            const t0 = a.c0.sq();
            const t1 = a.c1.sq();
            const t2 = a.c2.sq();
            const t3 = a.c0.mul(a.c1);
            const t4 = a.c0.mul(a.c2);
            const t5 = a.c1.mul(a.c2);

            // c0 ← t0 − ξ · t5;
            const c0 = t0.sub(mulByNonResidue(t5));
            // c1 ← ξ · t2 − t3;
            const c1 = mulByNonResidue(t2).sub(t3);
            // c2 ← t1 − t4; NOTE: paper says t1 · t4, but that's a misprint
            const c2 = t1.sub(t4);
            // t6 ← a0 · c0;
            var t6 = a.c0.mul(c0);
            // t6 ← t6 + ξ · a2 · c1;
            t6 = t6.add(mulByNonResidue(a.c2).mul(c1));
            // t6 ← t6 + ξ · a1 · c2;
            t6 = t6.add(mulByNonResidue(a.c1).mul(c2));
            // t6 ← t6^-1;
            t6 = t6.inverse();

            return .{
                .c0 = c0.mul(t6),
                .c1 = c1.mul(t6),
                .c2 = c2.mul(t6),
            };
        }

        pub fn format(f: Self, writer: *std.Io.Writer) !void {
            try writer.print("[{f}, {f}, {f}]", .{ f.c0, f.c1, f.c2 });
        }
    };
}
