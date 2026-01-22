//! Bulletproofs range-proof implementation over Curve25519 Ristretto points.
//!
//! Specifically implements non-interactive range proof aggregation
//! that is described in the original Bulletproofs
//! [paper](https://eprint.iacr.org/2017/1066) (Section 4.3).

// NOTE: Implementation copied (and lightly modified) from:
// https://github.com/Syndica/sig/blob/783453edb250342116f7dffe3c0a2bb564825109/src/zksdk/range_proof/bulletproofs.zig
// I implemented the original copy for Syndica under Apache 2, and since this library is GPLv3 it only requires a link.
// This note includes `bulletproofs/ipp.zig` as well.

const std = @import("std");
const stdx = @import("stdx");
const builtin = @import("builtin");
const table = @import("bullet_table");
const pedersen = @import("../pedersen.zig");
const merlin = @import("../merlin.zig");
const ed25519 = @import("../curves/ed25519.zig");

const Edwards25519 = std.crypto.ecc.Edwards25519;
const Ristretto255 = std.crypto.ecc.Ristretto255;
const Scalar = std.crypto.ecc.Edwards25519.scalar.Scalar;

pub const Transcript = merlin.Transcript(Domain);
pub const InnerProductProof = @import("bulletproofs/ipp.zig").Proof;
pub const ZERO = Scalar.fromBytes(Edwards25519.scalar.zero);
pub const ONE = Scalar.fromBytes(.{1} ++ .{0} ** 31);
pub const TWO = Scalar.fromBytes(.{2} ++ .{0} ** 31);

const Domain = enum {
    @"range-proof",
    @"inner-product",
};

pub fn Proof(bit_size: comptime_int) type {
    std.debug.assert(std.math.isPowerOfTwo(bit_size));
    const logn: u64 = std.math.log2_int(u64, bit_size);
    const max = (2 * bit_size) + (2 * logn) + 8 + 5;

    const AmountInt = std.meta.Int(.unsigned, bit_size);
    const BitInt = std.math.IntFittingRange(0, bit_size);

    const contract: Transcript.Contract = &[_]Transcript.Input{
        .{ .label = "A", .type = .validate_point },
        .{ .label = "S", .type = .validate_point },
        .{ .label = "y", .type = .challenge },
        .{ .label = "z", .type = .challenge },

        .{ .label = "T_1", .type = .validate_point },
        .{ .label = "T_2", .type = .validate_point },
        .{ .label = "x", .type = .challenge },

        .{ .label = "t_x", .type = .scalar },
        .{ .label = "t_x_blinding", .type = .scalar },
        .{ .label = "e_blinding", .type = .scalar },
        .{ .label = "w", .type = .challenge },

        .{ .label = "c", .type = .challenge },

        //  InnerProductProof(bit_size).contract runs here

        .{ .label = "ipp_a", .type = .scalar },
        .{ .label = "ipp_b", .type = .scalar },
        .{ .label = "d", .type = .challenge },
    };

    return struct {
        A: Ristretto255,
        S: Ristretto255,
        T_1: Ristretto255,
        T_2: Ristretto255,
        t_x: Scalar,
        t_x_blinding: Scalar,
        e_blinding: Scalar,
        ipp: InnerProductProof(bit_size),

        const Self = @This();

        /// degree-1 vector polynomial
        const VecPoly1 = struct {
            a: [bit_size]Scalar,
            b: [bit_size]Scalar,

            const zero: VecPoly1 = .{
                .a = @splat(ZERO),
                .b = @splat(ZERO),
            };

            fn ip(l: VecPoly1, r: VecPoly1) Poly2 {
                const t0 = innerProduct(&l.a, &r.a);
                const t2 = innerProduct(&l.b, &r.b);

                const la_plus_lb = addVec(&l.a, &l.b);
                const ra_plus_rb = addVec(&r.a, &r.b);

                // p - t0 - t2
                const p = innerProduct(&la_plus_lb, &ra_plus_rb);
                const t1 = Edwards25519.scalar.sub(p.toBytes(), t0.toBytes());

                return .{
                    .a = t0,
                    .b = .fromBytes(Edwards25519.scalar.sub(t1, t2.toBytes())),
                    .c = t2,
                };
            }

            fn eval(l: VecPoly1, x: Scalar) [bit_size]Scalar {
                var out: [bit_size]Scalar = undefined;
                for (&out, l.a, l.b) |*o, a, b| {
                    o.* = b.mul(x).add(a);
                }
                return out;
            }

            fn addVec(a: *const [bit_size]Scalar, b: *const [bit_size]Scalar) [bit_size]Scalar {
                var out: [bit_size]Scalar = undefined;
                for (&out, a, b) |*o, j, k| {
                    o.* = j.add(k);
                }
                return out;
            }
        };

        /// degree-2 scalar vector polynomial
        const Poly2 = struct {
            a: Scalar,
            b: Scalar,
            c: Scalar,

            fn evaluate(self: Poly2, x: Scalar) Scalar {
                const t0 = x.mul(self.c);
                const t1 = self.b.add(t0);
                const t2 = x.mul(t1);
                return t2.add(self.a);
            }
        };

        pub fn init(
            amounts: []const AmountInt,
            bit_lengths: []const BitInt,
            openings: []const pedersen.Opening,
            transcript: *Transcript,
        ) !Self {
            // Assert the inputs are well-formed.
            {
                std.debug.assert(amounts.len == bit_lengths.len and amounts.len == openings.len);
                var nm: u64 = 0;
                for (bit_lengths) |len| {
                    std.debug.assert(len != 0 and len <= bit_size);
                    nm += len;
                }
                std.debug.assert(nm == bit_size);
            }

            transcript.appendRangeProof(.range, bit_size);

            // bit-decompose values and generate their Pedersen vector commitment
            const a_blinding: Scalar = .random();
            var A = pedersen.H.mul(a_blinding.toBytes()) catch unreachable;

            var bit: u64 = 0;
            for (amounts, bit_lengths) |amount, n| {
                for (0..n) |j| {
                    // init functions aren't exposed, so doesn't need to be constant time.
                    const v = (amount >> @intCast(j)) & 0b1 != 0;
                    const point: Ristretto255 = if (v)
                        table.G[bit]
                    else
                        // TODO: use ristretto neg() alias when added to stdlib
                        .{ .p = table.H[bit].p.neg() };
                    A = A.add(point);
                    bit += 1;
                }
            }

            var s_L: [bit_size][32]u8 = undefined;
            var s_R: [bit_size][32]u8 = undefined;
            for (&s_L, &s_R) |*l, *r| {
                l.* = Scalar.random().toBytes();
                r.* = Scalar.random().toBytes();
            }
            const s_blinding = Scalar.random();

            const S = ed25519.mulMulti(
                1 + bit_size * 2,
                .{pedersen.H} ++ table.G[0..bit_size] ++ table.H[0..bit_size],
                .{s_blinding.toBytes()} ++ &s_L ++ &s_R,
            );

            comptime var session = Transcript.getSession(contract);
            defer session.finish();

            transcript.appendNoValidate(&session, "A", A);
            transcript.appendNoValidate(&session, "S", S);

            // y and z are used to merge multiple inner product relations into one inner product
            const y = transcript.challengeScalar(&session, "y");
            const z = transcript.challengeScalar(&session, "z");

            var l_poly: VecPoly1 = .zero;
            var r_poly: VecPoly1 = .zero;

            var i: usize = 0;
            var exp_z = z.mul(z);
            var exp_y = ONE;

            for (amounts, bit_lengths) |amount, n| {
                var exp_2 = ONE;

                for (0..n) |j| {
                    const predicate: u8 = @intCast(amount >> @intCast(j) & 0b1);
                    const a_L: [32]u8 = .{predicate} ++ .{0} ** 31;
                    const a_R = Edwards25519.scalar.sub(a_L, ONE.toBytes());

                    l_poly.a[i] = .fromBytes(Edwards25519.scalar.sub(a_L, z.toBytes()));
                    l_poly.b[i] = .fromBytes(s_L[i]);
                    // exp_y * (a_R + z) + exp_z * exp_2
                    r_poly.a[i] = exp_y.mul(Scalar.fromBytes(a_R).add(z)).add(exp_z.mul(exp_2));
                    r_poly.b[i] = exp_y.mul(Scalar.fromBytes(s_R[i]));

                    exp_y = exp_y.mul(y);
                    exp_2 = exp_2.add(exp_2);

                    i += 1;
                }
                exp_z = exp_z.mul(z);
            }

            const t_poly = l_poly.ip(r_poly);

            const T_1, const t_1_blinding = pedersen.initScalar(t_poly.b);
            const T_2, const t_2_blinding = pedersen.initScalar(t_poly.c);

            transcript.appendNoValidate(&session, "T_1", T_1.point);
            transcript.appendNoValidate(&session, "T_2", T_2.point);

            // evaluate t(x) on challenge x and homomorphically compute the openings for
            // z^2 * V_1 + z^3 * V_2 + ... + z^{m+1} * V_m + delta(y, z)*G + x*T_1 + x^2*T_2
            const x = transcript.challengeScalar(&session, "x");

            var agg_opening = ZERO;
            var agg_scalar = z;
            for (openings) |opening| {
                agg_scalar = agg_scalar.mul(z);
                agg_opening = agg_opening.add(agg_scalar.mul(opening.mu));
            }

            const t_binding_poly: Poly2 = .{
                .a = agg_opening,
                .b = t_1_blinding.mu,
                .c = t_2_blinding.mu,
            };

            const t_x = t_poly.evaluate(x);
            const t_x_blinding = t_binding_poly.evaluate(x);

            transcript.append(&session, .scalar, "t_x", t_x);
            transcript.append(&session, .scalar, "t_x_blinding", t_x_blinding);

            // homomorphically compuate the openings for A + x*S
            const e_blinding = s_blinding.mul(x).add(a_blinding);
            transcript.append(&session, .scalar, "e_blinding", e_blinding);

            // compute the inner product argument on the commitment:
            // P = <l(x), G> + <r(x), H'> + <l(x), r(x)>*Q
            const w = transcript.challengeScalar(&session, "w");
            const Q = ed25519.straus.mulByKnown(pedersen.G, w.toBytes());

            const G_factors: [bit_size]Scalar = @splat(ONE);
            const H_factors = genPowers(bit_size, y.invert());

            _ = transcript.challengeScalar(&session, "c");

            var l_vec = l_poly.eval(x);
            var r_vec = r_poly.eval(x);
            const ipp_proof = InnerProductProof(bit_size).init(
                Q,
                &G_factors,
                &H_factors,
                &l_vec,
                &r_vec,
                transcript,
            );

            if (builtin.mode == .Debug) {
                transcript.append(&session, .scalar, "ipp_a", ipp_proof.a);
                transcript.append(&session, .scalar, "ipp_b", ipp_proof.b);
                _ = transcript.challengeScalar(&session, "d");
            }

            return .{
                .A = A,
                .S = S,
                .T_1 = T_1.point,
                .T_2 = T_2.point,
                .t_x = t_x,
                .t_x_blinding = t_x_blinding,
                .e_blinding = e_blinding,
                .ipp = ipp_proof,
            };
        }

        /// Verifies the range proof using the optimized verification described in
        /// section 6.2 of the [Bulletproofs](https://eprint.iacr.org/2017/1066.pdf) paper.
        pub fn verify(
            self: Self,
            commitments: []const pedersen.Commitment,
            bit_lengths: []const BitInt,
            transcript: *Transcript,
        ) !void {
            std.debug.assert(commitments.len == bit_lengths.len);

            transcript.appendRangeProof(.range, bit_size);

            comptime var session = Transcript.getSession(contract);
            defer session.finish();

            try transcript.append(&session, .validate_point, "A", self.A);
            try transcript.append(&session, .validate_point, "S", self.S);

            const y = transcript.challengeScalar(&session, "y");
            const z = transcript.challengeScalar(&session, "z");

            try transcript.append(&session, .validate_point, "T_1", self.T_1);
            try transcript.append(&session, .validate_point, "T_2", self.T_2);

            const x = transcript.challengeScalar(&session, "x");

            transcript.append(&session, .scalar, "t_x", self.t_x);
            transcript.append(&session, .scalar, "t_x_blinding", self.t_x_blinding);
            transcript.append(&session, .scalar, "e_blinding", self.e_blinding);

            const w = transcript.challengeScalar(&session, "w");
            // only left for legacy reasons, use `d` instead
            _ = transcript.challengeScalar(&session, "c");

            const x_sq, //
            const x_inv_sq, //
            const s //
            = try self.ipp.verificationScalars(transcript);

            const a = self.ipp.a;
            const b = self.ipp.b;

            transcript.append(&session, .scalar, "ipp_a", a);
            transcript.append(&session, .scalar, "ipp_b", b);

            const d = transcript.challengeScalar(&session, "d");

            // (numbers use u128 as the example)
            //        points                scalars
            //   0    H                     -(e_blinding + d * t_x_blinding)
            //   1    S                     x
            //   2    T_1                   d * x
            //   3    T_2                   d * x * x
            //   4    commitments[ 0 ]      c z^2
            //        ...                   ...
            //   9    commitments[ 3 ]      c z^6
            //   8    L_vec[ 0 ]            x_sq[ 0 ]
            //        ...                   ...
            //  14    L_vec[ 6 ]            x_sq[ 6 ]
            //  15    R_vec[ 0 ]            x_sq_inv[ 0 ]
            //        ...                   ...
            //  21    R_vec[ 6 ]            x_sq_inv[ 6 ]
            //  22    generators_H[ 0 ]     TODO
            //        ...                   ...
            // 149    generators_H[ 127 ]   TODO
            // 150    generators_G[ 0 ]     (-a * s_0) + (-z)
            //        ...                   ...
            // 277    generators_G[ 127 ]   (-a * s_127) + (-z)
            // 278    G                     basepoint_scalar
            // ------------------------------------------------------ MSM
            //       -A
            //
            // basepoint_scalar depends on a bunch of values computed beforehand so it's added last

            var points: stdx.BoundedArray(Ristretto255, max) = .{};
            var scalars: stdx.BoundedArray([32]u8, max) = .{};

            points.appendSliceAssumeCapacity(&.{
                pedersen.H,
                self.S,
                self.T_1,
                self.T_2,
            });

            for (commitments) |commitment| points.appendAssumeCapacity(commitment.point);
            for (self.ipp.L_vec) |l| points.appendAssumeCapacity(l);
            for (self.ipp.R_vec) |r| points.appendAssumeCapacity(r);

            points.appendSliceAssumeCapacity(table.H[0..bit_size]);
            points.appendSliceAssumeCapacity(table.G[0..bit_size]);

            const d_txb = d.mul(self.t_x_blinding);
            const H = Edwards25519.scalar.neg(d_txb.add(self.e_blinding).toBytes());
            const d_x = d.mul(x);

            // G's scalar is inserted last, see below.
            scalars.appendSliceAssumeCapacity(&.{
                H, // H
                x.toBytes(), // S
                d_x.toBytes(), // T_1
                d_x.mul(x).toBytes(), // T_2
            });

            // commitments: c z^2, c z^3 ...
            const zz = z.mul(z);
            scalars.appendAssumeCapacity(zz.mul(d).toBytes());
            for (1..commitments.len) |_| {
                const z_d = Scalar.fromBytes(scalars.constSlice()[scalars.len - 1]);
                scalars.appendAssumeCapacity(z_d.mul(z).toBytes());
            }

            // L_vec: u0^2, u1^2...
            // R_vec: 1/u0^2, 1/u1^2...
            for (x_sq) |sq| scalars.appendAssumeCapacity(sq.toBytes());
            for (x_inv_sq) |inv_sq| scalars.appendAssumeCapacity(inv_sq.toBytes());

            // generators_H: l_j^(-x^2_j) * r_j^(-x^{-2}_j)
            const minus_b = Scalar.fromBytes(Edwards25519.scalar.neg(b.toBytes()));
            var exp_z = zz;
            var z_and_2 = exp_z;
            var exp_y_inv = y;
            var j: u64 = 0;
            var m: u64 = 0;
            const y_inv = y.invert();
            for (0..bit_size) |i| {
                defer j += 1;
                if (j == bit_lengths[m]) {
                    j = 0;
                    m += 1;
                    exp_z = exp_z.mul(z);
                    z_and_2 = exp_z;
                }
                if (j != 0) z_and_2 = z_and_2.add(z_and_2);
                exp_y_inv = exp_y_inv.mul(y_inv);
                const result = s[bit_size - 1 - i].mul(minus_b).add(z_and_2);
                scalars.appendAssumeCapacity(result.mul(exp_y_inv).add(z).toBytes());
            }

            // generators_G: (-a * s_i) + (-z)
            const z_negated = Scalar.fromBytes(Edwards25519.scalar.neg(z.toBytes()));
            const a_negated = Scalar.fromBytes(Edwards25519.scalar.neg(a.toBytes()));
            for (s) |s_i| {
                const result = a_negated.mul(s_i).add(z_negated);
                scalars.appendAssumeCapacity(result.toBytes());
            }

            const delta_tx = Scalar.fromBytes(Edwards25519.scalar.sub(
                delta(bit_lengths, y, z).toBytes(),
                self.t_x.toBytes(),
            )).mul(d);
            const abw_tx = a_negated.mul(b).add(self.t_x).mul(w);
            const basepoint_scalar = delta_tx.add(abw_tx);
            scalars.appendAssumeCapacity(basepoint_scalar.toBytes()); // G
            points.appendAssumeCapacity(pedersen.G);

            const check: Ristretto255 = ed25519.mulMultiRuntime(
                max,
                false,
                true,
                points.constSlice(),
                scalars.constSlice(),
            );

            if (!check.equivalent(.{ .p = self.A.p.neg() })) {
                return error.AlgebraicRelation;
            }
        }

        /// $$\delta(y,z) = (z - z^{2}) \langle \mathbf{1}, {\mathbf{y}}^{n \cdot m} \rangle - \sum_{j=0}^{m-1} z^{j+3} \cdot \langle \mathbf{1}, {\mathbf{2}}^{n \cdot m} \rangle$$
        fn delta(bit_lengths: []const BitInt, y: Scalar, z: Scalar) Scalar {
            const sum_y = sumOfPowers(bit_size, y);
            const zz = z.mul(z);
            const negative_z = Scalar.fromBytes(Edwards25519.scalar.sub(
                z.toBytes(),
                zz.toBytes(),
            ));
            var agg_delta = negative_z.mul(sum_y);
            var exp_z = zz.mul(z);
            for (bit_lengths) |n_i| {
                const sum_2 = sumOfPowers(n_i, TWO);
                agg_delta = Scalar.fromBytes(Edwards25519.scalar.sub(
                    agg_delta.toBytes(),
                    exp_z.mul(sum_2).toBytes(),
                ));
                exp_z = exp_z.mul(z);
            }
            return agg_delta;
        }

        fn sumOfPowers(n: BitInt, x: Scalar) Scalar {
            // TODO: use O(2log(n)) algorithm instead when `n` is a power of two
            var acc = ZERO;
            var next_exp = ONE;
            for (0..n) |_| {
                const exp_x = next_exp;
                next_exp = next_exp.mul(x);
                acc = acc.add(exp_x);
            }
            return acc;
        }
    };
}

/// Computes the inner product between two vectors.
///
/// Asserts the length is the same.
pub fn innerProduct(a: []const Scalar, b: []const Scalar) Scalar {
    std.debug.assert(a.len == b.len);
    var out = Scalar.fromBytes(Edwards25519.scalar.zero);
    for (a, b) |c, d| out = out.add(c.mul(d));
    return out;
}

/// Generates a list of the powers of `x`.
pub fn genPowers(comptime n: usize, x: Scalar) [n]Scalar {
    var next_exp = ONE;
    var out: [n]Scalar = undefined;
    for (&out) |*o| {
        const exp_x = next_exp;
        next_exp = next_exp.mul(x);
        o.* = exp_x;
    }
    return out;
}

test "single rangeproof" {
    const commitment, const opening = pedersen.initValue(u64, 55);

    var creation_transcript = Transcript.initTest("Test");
    var verification_transcript = Transcript.initTest("Test");

    const proof = try Proof(32).init(
        &.{55},
        &.{32},
        &.{opening},
        &creation_transcript,
    );

    try proof.verify(
        &.{commitment},
        &.{32},
        &verification_transcript,
    );
}

test "aggregated rangeproof" {
    const comm1, const opening1 = pedersen.initValue(u64, 55);
    const comm2, const opening2 = pedersen.initValue(u64, 77);
    const comm3, const opening3 = pedersen.initValue(u64, 99);

    var creation_transcript = Transcript.initTest("Test");
    var verification_transcript = Transcript.initTest("Test");

    const proof = try Proof(128).init(
        &.{ 55, 77, 99 },
        &.{ 64, 32, 32 },
        &.{ opening1, opening2, opening3 },
        &creation_transcript,
    );

    try proof.verify(
        &.{ comm1, comm2, comm3 },
        &.{ 64, 32, 32 },
        &verification_transcript,
    );
}

test "general case" {
    var prng: std.Random.DefaultPrng = .init(std.testing.random_seed);
    const random = prng.random();

    inline for (.{ true, false }) |expect_error| {
        inline for (.{ 32, 64, 128, 256 }) |bits| {
            const Int = @Type(.{ .int = .{ .signedness = .unsigned, .bits = bits / 8 } });
            const amount_1: u256 = std.math.maxInt(Int) + @as(u256, @intFromBool(expect_error));
            const amount_2 = random.int(Int);
            const amount_3 = random.int(Int);
            const amount_4 = random.int(Int);
            const amount_5 = random.int(Int);
            const amount_6 = random.int(Int);
            const amount_7 = random.int(Int);
            const amount_8 = random.int(Int);

            const commitment_1, const opening_1 = pedersen.initValue(u256, amount_1);
            const commitment_2, const opening_2 = pedersen.initValue(u256, amount_2);
            const commitment_3, const opening_3 = pedersen.initValue(u256, amount_3);
            const commitment_4, const opening_4 = pedersen.initValue(u256, amount_4);
            const commitment_5, const opening_5 = pedersen.initValue(u256, amount_5);
            const commitment_6, const opening_6 = pedersen.initValue(u256, amount_6);
            const commitment_7, const opening_7 = pedersen.initValue(u256, amount_7);
            const commitment_8, const opening_8 = pedersen.initValue(u256, amount_8);

            const bit_lengths: [8]std.math.IntFittingRange(0, bits) = @splat(bits / 8);

            var proof_script = Transcript.initTest(":3");
            const proof = try Proof(bits).init(
                &.{
                    amount_1, amount_2, amount_3, amount_4,
                    amount_5, amount_6, amount_7, amount_8,
                },
                &bit_lengths,
                &.{
                    opening_1, opening_2, opening_3, opening_4,
                    opening_5, opening_6, opening_7, opening_8,
                },
                &proof_script,
            );

            var verify_script = Transcript.initTest(":3");
            const result = proof.verify(
                &.{
                    commitment_1, commitment_2, commitment_3, commitment_4,
                    commitment_5, commitment_6, commitment_7, commitment_8,
                },
                &bit_lengths,
                &verify_script,
            );

            if (expect_error) {
                try std.testing.expect(std.meta.isError(result));
            } else {
                try result;
            }
        }
    }
}

test {
    _ = @import("bulletproofs/ipp.zig");
}
