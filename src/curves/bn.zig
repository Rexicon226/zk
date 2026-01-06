const std = @import("std");
const stdx = @import("stdx");
const sw = @import("sw.zig");
const ff = @import("../ff.zig");
const extensions = @import("extensions.zig");

const Quadratic = extensions.Quadratic;
const Cubic = extensions.Cubic;
const ShortWeierstrass = sw.ShortWeierstrass;
const Field = ff.Fp;

pub const Bn254 = struct {
    // Frobenius coefficients for $\mathbb{F}_{p^{12}}$ arithmetic.
    const gamma1: [5]Fp2 = .{
        .{ .c0 = .int(0x1284b71c2865a7dfe8b99fdd76e68b605c521e08292f2176d60b35dadcc9e470), .c1 = .int(0x246996f3b4fae7e6a6327cfe12150b8e747992778eeec7e5ca5cf05f80f362ac) },
        .{ .c0 = .int(0x2fb347984f7911f74c0bec3cf559b143b78cc310c2c3330c99e39557176f553d), .c1 = .int(0x16c9e55061ebae204ba4cc8bd75a079432ae2a1d0b7c9dce1665d51c640fcba2) },
        .{ .c0 = .int(0x063cf305489af5dcdc5ec698b6e2f9b9dbaae0eda9c95998dc54014671a0135a), .c1 = .int(0x07c03cbcac41049a0704b5a7ec796f2b21807dc98fa25bd282d37f632623b0e3) },
        .{ .c0 = .int(0x05b54f5e64eea80180f3c0b75a181e84d33365f7be94ec72848a1f55921ea762), .c1 = .int(0x2c145edbe7fd8aee9f3a80b03b0b1c923685d2ea1bdec763c13b4711cd2b8126) },
        .{ .c0 = .int(0x0183c1e74f798649e93a3661a4353ff4425c459b55aa1bd32ea2c810eab7692f), .c1 = .int(0x12acf2ca76fd0675a27fb246c7729f7db080cb99678e2ac024c6b8ee6e0c2c4b) },
    };
    // Additional Frobenius multipliers used for $\phi_p^2$ (frob^2) operations.
    const gamma2: [5]Fp = .{
        .int(0x30644e72e131a0295e6dd9e7e0acccb0c28f069fbb966e3de4bd44e5607cfd49),
        .int(0x30644e72e131a0295e6dd9e7e0acccb0c28f069fbb966e3de4bd44e5607cfd48),
        .int(Fp.order - 1),
        .int(0x000000000000000059e26bcea0d48bacd4f263f1acdb5c4f5763473177fffffe),
        .int(0x000000000000000059e26bcea0d48bacd4f263f1acdb5c4f5763473177ffffff),
    };

    /// Seed of the bn254 curve
    pub const x = 0x44e992b44a6909f1;

    /// Base field.
    pub const Fp = Field(.{
        .order = 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47,
        .serialized_size = 32,
        .flags = .sw,
    });

    /// 2nd degree field extension $\mathbb{F}_{p^2} = \mathbb{F}_p[i]/(i^2+1)$.
    pub const Fp2 = Quadratic(Fp, .{
        .serialized_size = 64,
        .non_residue = .negative_one,
    }, struct {});

    /// 6th degree field extension $\mathbb{F}_{p^6} = \mathbb{F}_{p^2}[w]/(w^3 - \xi)$.
    pub const Fp6 = Cubic(
        Fp2,
        .{ .non_residue = .{ .c0 = .int(9), .c1 = .int(1) } },
    );

    /// 12th degree field extension $\mathbb{F}_{p^{12}} = \mathbb{F}_{p^6}[v]/(v^2 - \eta)$.
    pub const Fp12 = Quadratic(
        Fp6,
        .{ .non_residue = .{ .c0 = .zero, .c1 = .one, .c2 = .zero } },
        struct {
            pub fn mulByNonResidue(a: Fp6) Fp6 {
                return .{
                    .c0 = Fp6.mulByNonResidue(a.c2),
                    .c1 = a.c0,
                    .c2 = a.c1,
                };
            }

            /// https://eprint.iacr.org/2010/354, Alg. 28
            pub fn frob(a: Fp12) Fp12 {
                return .{
                    .c0 = .{
                        .c0 = a.c0.c0.conjugate(),
                        .c1 = a.c0.c1.conjugate().mul(gamma1[1]),
                        .c2 = a.c0.c2.conjugate().mul(gamma1[3]),
                    },
                    .c1 = .{
                        .c0 = a.c1.c0.conjugate().mul(gamma1[0]),
                        .c1 = a.c1.c1.conjugate().mul(gamma1[2]),
                        .c2 = a.c1.c2.conjugate().mul(gamma1[4]),
                    },
                };
            }

            /// https://eprint.iacr.org/2010/354, Alg. 29
            pub fn frob2(a: Fp12) Fp12 {
                return .{
                    .c0 = .{
                        .c0 = a.c0.c0,
                        .c1 = .{
                            // g1 * gamma_2,2 */
                            .c0 = a.c0.c1.c0.mul(gamma2[1]),
                            .c1 = a.c0.c1.c1.mul(gamma2[1]),
                        },
                        .c2 = .{
                            // g2 * gamma_2,4 */
                            .c0 = a.c0.c2.c0.mul(gamma2[3]),
                            .c1 = a.c0.c2.c1.mul(gamma2[3]),
                        },
                    },
                    .c1 = .{
                        .c0 = .{
                            // h0 * gamma_2,1 */
                            .c0 = a.c1.c0.c0.mul(gamma2[0]),
                            .c1 = a.c1.c0.c1.mul(gamma2[0]),
                        },
                        .c1 = .{
                            // h1 * gamma_2,3 */
                            .c0 = a.c1.c1.c0.mul(gamma2[2]),
                            .c1 = a.c1.c1.c1.mul(gamma2[2]),
                        },
                        .c2 = .{
                            // h2 * gamma_2,5 */
                            .c0 = a.c1.c2.c0.mul(gamma2[4]),
                            .c1 = a.c1.c2.c1.mul(gamma2[4]),
                        },
                    },
                };
            }

            /// Cyclotomic squaring optimized for $\mathbb{F}_{p^{12}}$ elements
            /// restricted to the cyclotomic subgroup
            ///
            /// https://eprint.iacr.org/2009/565, Sec. 3.2
            pub fn sqFast(a: Fp12) Fp12 {
                const t0 = a.c1.c1.sq();
                const t1 = a.c0.c0.sq();
                const t6 = a.c1.c1.add(a.c0.c0).sq().sub(t0).sub(t1);

                const t2 = a.c0.c2.sq();
                const t3 = a.c1.c0.sq();
                const t7 = a.c0.c2.add(a.c1.c0).sq().sub(t2).sub(t3);

                const t4 = a.c1.c2.sq();
                const t5 = a.c0.c1.sq();
                const t8 = Fp6.mulByNonResidue(a.c1.c2.add(a.c0.c1).sq().sub(t4).sub(t5));

                const r0 = Fp6.mulByNonResidue(t0).add(t1);
                const r2 = Fp6.mulByNonResidue(t2).add(t3);
                const r4 = Fp6.mulByNonResidue(t4).add(t5);

                return .{
                    .c0 = .{
                        .c0 = r0.sub(a.c0.c0).dbl().add(r0),
                        .c1 = r2.sub(a.c0.c1).dbl().add(r2),
                        .c2 = r4.sub(a.c0.c2).dbl().add(r4),
                    },
                    .c1 = .{
                        .c0 = t8.add(a.c1.c0).dbl().add(t8),
                        .c1 = t6.add(a.c1.c1).dbl().add(t6),
                        .c2 = t7.add(a.c1.c2).dbl().add(t7),
                    },
                };
            }

            /// Raise `a` to `x^t mod q^12` where t is the generator of the curve.
            ///
            /// https://github.com/Consensys/gnark-crypto/blob/v0.12.1/ecc/bn254/internal/fptower/e12_pairing.go#L16
            pub fn powX(a: Fp12) Fp12 {
                // t3 = x^0x2
                var t3 = a.sqFast();
                // t5 = x^0x4
                var t5 = t3.sqFast();
                // result = x^0x8
                const result = t5.sqFast();
                // t0 = x^0x10
                var t0 = result.sqFast();
                // t2 = x^0x11
                var t2 = a.mul(t0);
                // t0 = x^0x13
                t0 = t3.mul(t2);
                // t1 = x^0x14
                var t1 = a.mul(t0);
                // t4 = x^0x19
                var t4 = result.mul(t2);
                // t6 = x^0x22
                var t6 = t2.sqFast();
                // t1 = x^0x27
                t1 = t0.mul(t1);
                // t0 = x^0x29
                t0 = t3.mul(t1);
                // t6 = x^0x880
                for (0..6) |_| t6 = t6.sqFast();
                // t5 = x^0x884
                t5 = t5.mul(t6);
                // t5 = x^0x89d
                t5 = t5.mul(t4);
                // t5 = x^0x44e80
                for (0..7) |_| t5 = t5.sqFast();
                // t4 = x^0x44e99
                t4 = t4.mul(t5);
                // t4 = x^0x44e9900
                for (0..8) |_| t4 = t4.sqFast();
                // t4 = x^0x44e9929
                t4 = t4.mul(t0);
                // t3 = x^0x44e992b
                t3 = t3.mul(t4);
                // t3 = x^0x113a64ac0
                for (0..6) |_| t3 = t3.sqFast();
                // t2 = x^0x113a64ad1
                t2 = t2.mul(t3);
                // t2 = x^0x113a64ad100
                for (0..8) |_| t2 = t2.sqFast();
                // t2 = x^0x113a64ad129
                t2 = t2.mul(t0);
                // t2 = x^0x44e992b44a40
                for (0..6) |_| t2 = t2.sqFast();
                // t2 = x^0x44e992b44a69
                t2 = t2.mul(t0);
                // t2 = x^0x113a64ad129a400
                for (0..10) |_| t2 = t2.sqFast();
                // t1 = x^0x113a64ad129a427
                t1 = t1.mul(t2);
                // t1 = x^0x44e992b44a6909c0
                for (0..6) |_| t1 = t1.sqFast();
                // t0 = x^0x44e992b44a6909e9
                t0 = t0.mul(t1);
                // result = x^0x44e992b44a6909f1
                return result.mul(t0);
            }
        },
    );

    pub const G1 = ShortWeierstrass(
        Fp,
        .{
            .a = .zero,
            .b = .int(3),
        },
        struct {},
    );

    pub const G2 = ShortWeierstrass(
        Fp2,
        .{
            .a = .zero,
            .b = b: { // b = 3/(i + 9)
                @setEvalBranchQuota(1_600);
                break :b Fp6.non_residue.inverse().mulBase(.int(3));
            },
        },
        struct {
            pub fn frob(p: G2) G2 {
                return .{
                    .x = p.x.conjugate().mul(gamma1[1]),
                    .y = p.y.conjugate().mul(gamma1[2]),
                    .z = p.z.conjugate(),
                };
            }

            pub fn frob2(p: G2) G2 {
                return .{
                    .x = .{
                        .c0 = p.x.c0.mul(gamma2[1]),
                        .c1 = p.x.c1.mul(gamma2[1]),
                    },
                    .y = .{
                        .c0 = p.y.c0.mul(gamma2[2]),
                        .c1 = p.y.c1.mul(gamma2[2]),
                    },
                    .z = p.z,
                };
            }

            /// Subgroup check for G2 using endomorpishm. Since the full group
            /// over the twist is not of prime order, an extra subgroup check is required.
            ///
            /// We can express that relationship as:
            /// $$[r]P = 0 \iff [x+1]P + \psi([x]P) + \psi^2([x]P) = \psi^3([2x]P)$$
            pub fn checkSubgroup(p: G2.Affine) !void {
                const xp: G2 = p.mulScalar(u64, x);
                const psi = xp.frob();
                const psi2 = xp.frob2();
                const psi3 = psi2.frob();
                const rhs = xp.addAffine(p).add(psi).add(psi2);
                const lhs = psi3.dbl();

                if (!lhs.eql(rhs)) return error.WrongSubgroup;
            }
        },
    );

    const P = Pairing(G1, G2, Fp12);
    pub const compute = P.compute;
    pub const millerLoop = P.millerLoop;
    pub const finalExp = P.finalExp;
};

/// Computes a product pairing:
///
/// $\prod_{i=0}^{n-1} e(P_i, Q_i) \in \mathbb{F}_{p^{12}}$
///
/// using batched Miller loops followed by a single final exponentiation.
///
/// ## Notes
///
/// - Pairs where either input is the point at infinity are skipped:
/// $e(\mathcal{O}, Q) = e(P, \mathcal{O}) = 1$
///
pub fn Pairing(G1: type, G2: type, FT: type) type {
    return struct {
        const BATCH_SIZE = 16;

        pub fn compute(x: []const G1.Affine, y: []const G2.Affine) FT {
            var p: stdx.BoundedArray(G1, BATCH_SIZE) = .{};
            var q: stdx.BoundedArray(G2, BATCH_SIZE) = .{};

            var r: FT = .one;
            for (x, y, 0..) |a, b, i| {
                // Skip any pair where either A or B are points at infinity.
                if (a.isZero() or b.isZero()) continue;

                p.appendAssumeCapacity(a.toProjective());
                q.appendAssumeCapacity(b.toProjective());

                // Trigger batch when we're either on the last element or we're at the max batch size.
                if (p.len == BATCH_SIZE or i == x.len - 1) {
                    const tmp = millerLoop(p.constSlice(), q.constSlice());

                    r = r.mul(tmp);
                    p.clear();
                    q.clear();
                }
            }

            return finalExp(r);
        }

        pub fn millerLoop(a: []const G1, b: []const G2) FT {
            std.debug.assert(a.len == b.len);
            std.debug.assert(a.len <= BATCH_SIZE);
            const size = a.len;

            var t: [BATCH_SIZE]G2 = undefined;
            var l: FT = undefined;

            var f: FT = .one;
            for (0..size) |i| t[i] = b[i];

            for (0..size) |i| {
                projDbl(&l, &t[i], a[i]);
                f = f.mul(l);
            }
            f = f.sq();

            for (0..size) |i| {
                projAddSub(&l, &t[i], a[i], b[i], false, false);
                f = f.mul(l);

                projAddSub(&l, &t[i], a[i], b[i], true, true);
                f = f.mul(l);
            }

            // zig fmt: off
            const s = [_]i2{
                0,  0,  0,  1,  0,  1,  0, -1,
                0,  0, -1,  0,  0,  0,  1,  0,
                0, -1,  0, -1,  0,  0,  0,  1,
                0, -1,  0,  0,  0,  0, -1,  0,
                0,  1,  0, -1,  0,  0,  1,  0,
                0,  0,  0,  0, -1,  0,  0, -1,
                0,  1,  0, -1,  0,  0,  0, -1,
                0, -1,  0,  0,  0,  1,  0, -1,
            };
            // zig fmt: on

            for (0..63) |fwd| {
                const i = 63 - fwd - 1;
                f = f.sq();

                for (0..size) |j| {
                    projDbl(&l, &t[j], a[j]);
                    f = f.mul(l);
                }

                if (s[i] != 0) for (0..size) |j| {
                    projAddSub(&l, &t[j], a[j], b[j], s[i] > 0, true);
                    f = f.mul(l);
                };
            }

            var frob: G2 = undefined;
            for (0..size) |i| {
                frob = b[i].frob(); // frob(b)
                projAddSub(&l, &t[i], a[i], frob, true, true);
                f = f.mul(l);

                frob = b[i].frob2(); // -frob^2(q)
                frob = frob.negate();
                projAddSub(&l, &t[i], a[i], frob, true, false);
                f = f.mul(l);
            }

            return f;
        }

        /// Doubles a point in homogenous projective coordinates and evaluates the line in the Miller loop.
        /// https://eprint.iacr.org/2013/722.pdf (Section 4.3)
        fn projDbl(r: *FT, t: *G2, p: G1) void {
            // A = X1*Y1/2
            const a = t.x.mul(t.y).halve();
            // B = Y1^2
            const b = t.y.sq();
            // C = Z1^2
            const c = t.z.sq();
            // D = 3C
            const d = c.triple();
            // E = b' * D
            const e = d.mul(G2.B);
            // F = 3E
            const f = e.triple();
            // G = (B+F)/2
            const g = b.add(f).halve();
            // H = (Y1+Z1)^2 − (B+C)
            const h = t.y.add(t.z).sq().sub(b.add(c));

            // g(P) = (H * -y) + (X^2 * 3 * x)w + (E−B)w^3
            r.* = .{
                .c0 = .{
                    // el[0][0] = -(H * y)
                    .c0 = h.negate().mulBase(p.y),
                    // el[0][1] = 0
                    .c1 = .zero,
                    // el[0][2] = 0
                    .c2 = .zero,
                },
                .c1 = .{
                    // el[1][0] = (3 * X^2 * x)
                    .c0 = t.x.sq().mulBase(p.x.triple()),
                    // el[1][0] = (E−B)
                    .c1 = e.sub(b),
                    // el[1][2] = 0
                    .c2 = .zero,
                },
            };

            // update `t`
            t.* = .{
                // A * (B−F)
                .x = b.sub(f).mul(a),
                // Y3 = G^2 − 3*E^2
                .y = g.sq().sub(e.sq().triple()),
                // Z3 = B*H
                .z = b.mul(h),
            };
        }

        /// https://eprint.iacr.org/2012/408, Sec 4.2.
        fn projAddSub(r: *FT, t: *G2, p: G1, q: G2, is_add: bool, add_point: bool) void {
            const y = p.y;
            const x = p.x;
            const X2 = q.x;

            const Y2 = if (is_add) q.y else q.y.negate();

            const a = Y2.mul(t.z);
            const b = X2.mul(t.z);
            const o = t.y.sub(a);
            const l = t.x.sub(b);

            const j = o.mul(X2);
            const k = l.mul(Y2);

            r.* = .{
                .c0 = .{
                    // el[0][0] = (l * y)
                    .c0 = l.mulBase(y),
                    // el[0][1] = 0
                    .c1 = .zero,
                    // el[0][2] = 0
                    .c2 = .zero,
                },
                .c1 = .{
                    // el[1][0] = -(o * x), term in w
                    .c0 = o.mulBase(x).negate(),
                    // el[1][1] = j-k
                    .c1 = j.sub(k),
                    // el[1][2] = 0
                    .c2 = .zero,
                },
            };

            if (add_point) {
                const c = o.sq();
                const d = l.sq();
                const e = d.mul(l);
                const f = t.z.mul(c);
                const g = t.x.mul(d);
                const h = e.add(f).sub(g).sub(g);
                const i = t.y.mul(e);

                t.* = .{
                    .x = l.mul(h),
                    .y = g.sub(h).mul(o).sub(i),
                    .z = t.z.mul(e),
                };
            }
        }

        pub fn finalExp(x: FT) FT {
            var t1 = x.inverse();
            var t0 = x.conjugate().mul(t1);
            var t2 = t0.frob2();
            var s = t0.mul(t2);

            t0 = s.powX().conjugate().sqFast();
            t1 = t0.sqFast().mul(t0);

            t2 = t1.powX().conjugate();
            t1 = t1.conjugate().mul(t2);

            var t3 = t2.sqFast();
            var t4 = t3.powX().mul(t1);
            t3 = t4.mul(t0);
            t0 = t4.mul(t2).mul(s);

            t2 = t3.frob();
            t0 = t0.mul(t2);
            t2 = t4.frob2();
            t0 = t0.mul(t2);

            // frob3 => frob2 \dot frob
            t2 = s.conjugate().mul(t3).frob2().frob();

            return t0.mul(t2);
        }
    };
}

const Case = struct {
    input: []const u8,
    expected: []const u8,
};

test "add" {
    // [agave] https://github.com/anza-xyz/agave/blob/v1.18.6/sdk/program/src/alt_bn254/mod.rs#L401
    const cases: []const Case = &.{
        .{
            .input = "18b18acfb4c2c30276db5411368e7185b311dd124691610c5d3b74034e093dc9063c909c4720840cb5134cb9f59fa749755796819658d32efc0d288198f3726607c2b7f58a84bd6145f00c9c2bc0bb1a187f20ff2c92963a88019e7c6a014eed06614e20c147e940f2d70da3f74c9a17df361706a4485c742bd6788478fa17d7",
            .expected = "2243525c5efd4b9c3d3c45ac0ca3fe4dd85e830a4ce6b65fa1eeaee202839703301d1d33be6da8e509df21cc35964723180eed7532537db9ae5e7d48f195c915",
        },
        .{
            .input = "2243525c5efd4b9c3d3c45ac0ca3fe4dd85e830a4ce6b65fa1eeaee202839703301d1d33be6da8e509df21cc35964723180eed7532537db9ae5e7d48f195c91518b18acfb4c2c30276db5411368e7185b311dd124691610c5d3b74034e093dc9063c909c4720840cb5134cb9f59fa749755796819658d32efc0d288198f37266",
            .expected = "2bd3e6d0f3b142924f5ca7b49ce5b9d54c4703d7ae5648e61d02268b1a0a9fb721611ce0a6af85915e2f1d70300909ce2e49dfad4a4619c8390cae66cefdb204",
        },
        .{
            .input = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            .expected = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        },
        .{
            .input = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            .expected = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        },
        .{
            .input = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            .expected = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        },
        .{
            .input = "",
            .expected = "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        },
        .{
            .input = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002",
            .expected = "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002",
        },
        .{
            .input = "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002",
            .expected = "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002",
        },
        .{
            .input = "0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            .expected = "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002",
        },
        .{
            .input = "0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002",
            .expected = "030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd315ed738c0e0a7c92e7845f96b2ae9c0a68a6a449e3538fc7ff3ebf7a5a18a2c4",
        },
        .{
            .input = "17c139df0efee0f766bc0204762b774362e4ded88953a39ce849a8a7fa163fa901e0559bacb160664764a357af8a9fe70baa9258e0b959273ffc5718c6d4cc7c039730ea8dff1254c0fee9c0ea777d29a9c710b7e616683f194f18c43b43b869073a5ffcc6fc7a28c30723d6e58ce577356982d65b833a5a5c15bf9024b43d98",
            .expected = "15bf2bb17880144b5d1cd2b1f46eff9d617bffd1ca57c37fb5a49bd84e53cf66049c797f9ce0d17083deb32b5e36f2ea2a212ee036598dd7624c168993d1355f",
        },
    };

    for (cases) |case| {
        var buffer: [128]u8 = @splat(0);
        _ = try std.fmt.hexToBytes(&buffer, case.input);

        var out: [64]u8 = undefined;
        {
            const G1 = Bn254.G1;
            const x: G1.Affine = try .fromBytes(buffer[0..64]);
            const y: G1.Affine = try .fromBytes(buffer[64..128]);
            const result = x.add(y);
            result.toBytes(&out);
        }

        var expected_buffer: [64]u8 = undefined;
        try std.testing.expectEqualSlices(
            u8,
            try std.fmt.hexToBytes(&expected_buffer, case.expected),
            &out,
        );
    }
}

test "mul" {
    // [agave] https://github.com/anza-xyz/agave/blob/v1.18.6/sdk/program/src/alt_bn254/mod.rs#L495
    const cases: []const Case = &.{
        .{
            .input = "2bd3e6d0f3b142924f5ca7b49ce5b9d54c4703d7ae5648e61d02268b1a0a9fb721611ce0a6af85915e2f1d70300909ce2e49dfad4a4619c8390cae66cefdb20400000000000000000000000000000000000000000000000011138ce750fa15c2",
            .expected = "070a8d6a982153cae4be29d434e8faef8a47b274a053f5a4ee2a6c9c13c31e5c031b8ce914eba3a9ffb989f9cdd5b0f01943074bf4f0f315690ec3cec6981afc",
        },
        .{
            .input = "070a8d6a982153cae4be29d434e8faef8a47b274a053f5a4ee2a6c9c13c31e5c031b8ce914eba3a9ffb989f9cdd5b0f01943074bf4f0f315690ec3cec6981afc30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd46",
            .expected = "025a6f4181d2b4ea8b724290ffb40156eb0adb514c688556eb79cdea0752c2bb2eff3f31dea215f1eb86023a133a996eb6300b44da664d64251d05381bb8a02e",
        },
        .{
            .input = "025a6f4181d2b4ea8b724290ffb40156eb0adb514c688556eb79cdea0752c2bb2eff3f31dea215f1eb86023a133a996eb6300b44da664d64251d05381bb8a02e183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3",
            .expected = "14789d0d4a730b354403b5fac948113739e276c23e0258d8596ee72f9cd9d3230af18a63153e0ec25ff9f2951dd3fa90ed0197bfef6e2a1a62b5095b9d2b4a27",
        },
        .{
            .input = "1a87b0584ce92f4593d161480614f2989035225609f08058ccfa3d0f940febe31a2f3c951f6dadcc7ee9007dff81504b0fcd6d7cf59996efdc33d92bf7f9f8f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            .expected = "2cde5879ba6f13c0b5aa4ef627f159a3347df9722efce88a9afbb20b763b4c411aa7e43076f6aee272755a7f9b84832e71559ba0d2e0b17d5f9f01755e5b0d11",
        },
        .{
            .input = "1a87b0584ce92f4593d161480614f2989035225609f08058ccfa3d0f940febe31a2f3c951f6dadcc7ee9007dff81504b0fcd6d7cf59996efdc33d92bf7f9f8f630644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
            .expected = "1a87b0584ce92f4593d161480614f2989035225609f08058ccfa3d0f940febe3163511ddc1c3f25d396745388200081287b3fd1472d8339d5fecb2eae0830451",
        },
        .{
            .input = "1a87b0584ce92f4593d161480614f2989035225609f08058ccfa3d0f940febe31a2f3c951f6dadcc7ee9007dff81504b0fcd6d7cf59996efdc33d92bf7f9f8f60000000000000000000000000000000100000000000000000000000000000000",
            .expected = "1051acb0700ec6d42a88215852d582efbaef31529b6fcbc3277b5c1b300f5cf0135b2394bb45ab04b8bd7611bd2dfe1de6a4e6e2ccea1ea1955f577cd66af85b",
        },
        .{
            .input = "1a87b0584ce92f4593d161480614f2989035225609f08058ccfa3d0f940febe31a2f3c951f6dadcc7ee9007dff81504b0fcd6d7cf59996efdc33d92bf7f9f8f60000000000000000000000000000000000000000000000000000000000000009",
            .expected = "1dbad7d39dbc56379f78fac1bca147dc8e66de1b9d183c7b167351bfe0aeab742cd757d51289cd8dbd0acf9e673ad67d0f0a89f912af47ed1be53664f5692575",
        },
        .{
            .input = "1a87b0584ce92f4593d161480614f2989035225609f08058ccfa3d0f940febe31a2f3c951f6dadcc7ee9007dff81504b0fcd6d7cf59996efdc33d92bf7f9f8f60000000000000000000000000000000000000000000000000000000000000001",
            .expected = "1a87b0584ce92f4593d161480614f2989035225609f08058ccfa3d0f940febe31a2f3c951f6dadcc7ee9007dff81504b0fcd6d7cf59996efdc33d92bf7f9f8f6",
        },
        .{
            .input = "17c139df0efee0f766bc0204762b774362e4ded88953a39ce849a8a7fa163fa901e0559bacb160664764a357af8a9fe70baa9258e0b959273ffc5718c6d4cc7cffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            .expected = "29e587aadd7c06722aabba753017c093f70ba7eb1f1c0104ec0564e7e3e21f6022b1143f6a41008e7755c71c3d00b6b915d386de21783ef590486d8afa8453b1",
        },
        .{
            .input = "17c139df0efee0f766bc0204762b774362e4ded88953a39ce849a8a7fa163fa901e0559bacb160664764a357af8a9fe70baa9258e0b959273ffc5718c6d4cc7c30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
            .expected = "17c139df0efee0f766bc0204762b774362e4ded88953a39ce849a8a7fa163fa92e83f8d734803fc370eba25ed1f6b8768bd6d83887b87165fc2434fe11a830cb",
        },
        .{
            .input = "17c139df0efee0f766bc0204762b774362e4ded88953a39ce849a8a7fa163fa901e0559bacb160664764a357af8a9fe70baa9258e0b959273ffc5718c6d4cc7c0000000000000000000000000000000100000000000000000000000000000000",
            .expected = "221a3577763877920d0d14a91cd59b9479f83b87a653bb41f82a3f6f120cea7c2752c7f64cdd7f0e494bff7b60419f242210f2026ed2ec70f89f78a4c56a1f15",
        },
        .{
            .input = "17c139df0efee0f766bc0204762b774362e4ded88953a39ce849a8a7fa163fa901e0559bacb160664764a357af8a9fe70baa9258e0b959273ffc5718c6d4cc7c0000000000000000000000000000000000000000000000000000000000000009",
            .expected = "228e687a379ba154554040f8821f4e41ee2be287c201aa9c3bc02c9dd12f1e691e0fd6ee672d04cfd924ed8fdc7ba5f2d06c53c1edc30f65f2af5a5b97f0a76a",
        },
        .{
            .input = "17c139df0efee0f766bc0204762b774362e4ded88953a39ce849a8a7fa163fa901e0559bacb160664764a357af8a9fe70baa9258e0b959273ffc5718c6d4cc7c0000000000000000000000000000000000000000000000000000000000000001",
            .expected = "17c139df0efee0f766bc0204762b774362e4ded88953a39ce849a8a7fa163fa901e0559bacb160664764a357af8a9fe70baa9258e0b959273ffc5718c6d4cc7c",
        },
        .{
            .input = "039730ea8dff1254c0fee9c0ea777d29a9c710b7e616683f194f18c43b43b869073a5ffcc6fc7a28c30723d6e58ce577356982d65b833a5a5c15bf9024b43d98ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            .expected = "00a1a234d08efaa2616607e31eca1980128b00b415c845ff25bba3afcb81dc00242077290ed33906aeb8e42fd98c41bcb9057ba03421af3f2d08cfc441186024",
        },
        .{
            .input = "039730ea8dff1254c0fee9c0ea777d29a9c710b7e616683f194f18c43b43b869073a5ffcc6fc7a28c30723d6e58ce577356982d65b833a5a5c15bf9024b43d9830644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000",
            .expected = "039730ea8dff1254c0fee9c0ea777d29a9c710b7e616683f194f18c43b43b8692929ee761a352600f54921df9bf472e66217e7bb0cee9032e00acc86b3c8bfaf",
        },
        .{
            .input = "039730ea8dff1254c0fee9c0ea777d29a9c710b7e616683f194f18c43b43b869073a5ffcc6fc7a28c30723d6e58ce577356982d65b833a5a5c15bf9024b43d980000000000000000000000000000000100000000000000000000000000000000",
            .expected = "1071b63011e8c222c5a771dfa03c2e11aac9666dd097f2c620852c3951a4376a2f46fe2f73e1cf310a168d56baa5575a8319389d7bfa6b29ee2d908305791434",
        },
        .{
            .input = "039730ea8dff1254c0fee9c0ea777d29a9c710b7e616683f194f18c43b43b869073a5ffcc6fc7a28c30723d6e58ce577356982d65b833a5a5c15bf9024b43d980000000000000000000000000000000000000000000000000000000000000009",
            .expected = "19f75b9dd68c080a688774a6213f131e3052bd353a304a189d7a2ee367e3c2582612f545fb9fc89fde80fd81c68fc7dcb27fea5fc124eeda69433cf5c46d2d7f",
        },
        .{
            .input = "039730ea8dff1254c0fee9c0ea777d29a9c710b7e616683f194f18c43b43b869073a5ffcc6fc7a28c30723d6e58ce577356982d65b833a5a5c15bf9024b43d980000000000000000000000000000000000000000000000000000000000000001",
            .expected = "039730ea8dff1254c0fee9c0ea777d29a9c710b7e616683f194f18c43b43b869073a5ffcc6fc7a28c30723d6e58ce577356982d65b833a5a5c15bf9024b43d98",
        },
    };

    for (cases) |case| {
        var buffer: [96]u8 = @splat(0);
        _ = try std.fmt.hexToBytes(&buffer, case.input);

        const G1 = Bn254.G1;

        var out: [64]u8 = undefined;
        {
            const a: G1.Affine = try .fromBytes(buffer[0..64]);
            const b: u256 = @bitCast(buffer[64..][0..32].*);
            const result = a.mulScalar(u256, @byteSwap(b));
            result.toAffine().toBytes(&out);
        }

        var expected_buffer: [64]u8 = undefined;
        try std.testing.expectEqualSlices(
            u8,
            try std.fmt.hexToBytes(&expected_buffer, case.expected),
            &out,
        );
    }
}

test "g2 subgroup check works" {
    // bad case
    var bad_point: [128]u8 = .{
        0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  0,   0,   0,   0,   0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  0,   1,   0,   0,   0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   0,   0,   0,   0,  0,   0,   0,   0,   0,   0,   0,   0,
        0,   0,   0,   0,   0,   0,   0,   40,  167, 168, 28, 107, 242, 167, 93,  201, 240, 18,  91,
        181, 129, 116, 126, 158, 107, 51,  252, 59,  39,  16, 162, 48,  156, 239, 151, 163, 22,  60,
        101, 35,  113, 33,  54,  151, 142, 212, 159, 175, 33, 32,  202, 79,  127, 113, 207, 212, 231,
        180, 111, 250, 14,  168, 158, 219, 201, 77,  220, 89, 35,  142, 159,
    };
    try std.testing.expectError(
        error.WrongSubgroup,
        Bn254.G2.Affine.fromBytes(&bad_point),
    );

    // good case
    const good_point: [128]u8 = .{
        26,  44,  48,  19,  210, 234, 146, 225, 60,  128, 12,  222, 104, 239, 86,
        162, 148, 184, 131, 246, 172, 53,  210, 95,  88,  124, 9,   177, 179, 198,
        53,  247, 41,  1,   88,  168, 12,  211, 214, 101, 48,  247, 77,  201, 76,
        148, 173, 184, 143, 92,  219, 72,  26,  204, 169, 151, 182, 230, 0,   113,
        240, 138, 17,  95,  47,  153, 127, 61,  189, 102, 167, 175, 224, 127, 231,
        134, 44,  226, 57,  237, 186, 158, 5,   197, 175, 255, 127, 138, 18,  89,
        201, 115, 59,  45,  251, 185, 41,  209, 105, 21,  48,  202, 112, 27,  74,
        16,  96,  84,  104, 135, 40,  201, 151, 44,  133, 18,  233, 120, 158, 149,
        103, 170, 226, 62,  48,  44,  205, 117,
    };
    _ = try Bn254.G2.Affine.fromBytes(&good_point);
}

test "final exp" {
    const fp: [12][]const u8 = .{
        "dfc6a6f009e7c251800a3639442c69ed2636c17406cc33f31cf382eb8b8e1e2d",
        "a5c3b5f42e2f85134c951132c07ed65e270571e63e56410d4a1ac97233f3a61b",
        "33918b27cbc1eb9f92e284050236b65bc98f894b54d4fda21130ff4e27f4411e",
        "376f78f99b29ba623e8041e0b015d95175245cbde91c0501b0bdc414effa3a22",
        "d843aea85fbdec8097a16e488b7aa2fd0002877a97f282ca5cc3dffa6e0f9709",
        "50cdcb309b43d1fb438848e151dce5ede94206ad68a3ab11b8a44c38c6e34419",
        "83edf31a8ff400bb750a5f4b0d145be36c207a2d84db90e6ee889a29d6884912",
        "4aa2bfeb329e848fcd59f68a270bfd24a2140087c31e538128a6c919713b322a",
        "6ac6f0c2bd00ec6e25a8318d3ad8418cf7b157e5f31b844e2f11f81aa41e9014",
        "d735c568da6b14c7ca5dd36bbd44bd2c7eb925dba4711539ada26038a097131a",
        "3f0de4616aaf9276c9108e1ed7ac3b84dfb635cf64b881666d2b3a2d079f9a1d",
        "860a8f5982edeb4a1c6fcfcf9acee44bbe568f0de2d53ef1a07c6033c650db1e",
    };

    const Fp = Bn254.Fp;
    const Fp12 = Bn254.Fp12;

    const S = struct {
        fn fromBytes(input: []const u8) !Fp {
            var bytes: [32]u8 = undefined;
            _ = try std.fmt.hexToBytes(&bytes, input);
            return .{ .base = @intCast(@as(Fp.Single, @bitCast(bytes))) };
        }
    };

    const fp12: Fp12 = .{ .c0 = .{
        .c0 = .{ .c0 = try S.fromBytes(fp[0]), .c1 = try S.fromBytes(fp[1]) },
        .c1 = .{ .c0 = try S.fromBytes(fp[2]), .c1 = try S.fromBytes(fp[3]) },
        .c2 = .{ .c0 = try S.fromBytes(fp[4]), .c1 = try S.fromBytes(fp[5]) },
    }, .c1 = .{
        .c0 = .{ .c0 = try S.fromBytes(fp[6]), .c1 = try S.fromBytes(fp[7]) },
        .c1 = .{ .c0 = try S.fromBytes(fp[8]), .c1 = try S.fromBytes(fp[9]) },
        .c2 = .{ .c0 = try S.fromBytes(fp[10]), .c1 = try S.fromBytes(fp[11]) },
    } };

    try std.testing.expect(Bn254.finalExp(fp12).isOne());
}

test "pairing" {
    const cases: []const struct { input: []const u8, expected: bool } = &.{
        .{
            .input = "1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
            .expected = true,
        },
        .{
            .input = "2eca0c7238bf16e83e7a1e6c5d49540685ff51380f309842a98561558019fc0203d3260361bb8451de5ff5ecd17f010ff22f5c31cdf184e9020b06fa5997db841213d2149b006137fcfb23036606f848d638d576a120ca981b5b1a5f9300b3ee2276cf730cf493cd95d64677bbb75fc42db72513a4c1e387b476d056f80aa75f21ee6226d31426322afcda621464d0611d226783262e21bb3bc86b537e986237096df1f82dff337dd5972e32a8ad43e28a78a96a823ef1cd4debe12b6552ea5f06967a1237ebfeca9aaae0d6d0bab8e28c198c5a339ef8a2407e31cdac516db922160fa257a5fd5b280642ff47b65eca77e626cb685c84fa6d3b6882a283ddd1198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
            .expected = true,
        },
        .{
            .input = "0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9bbdfec6c36c7d515536431b3a865468acbba2e89718ad33c8bed92e210e81d1853435399a271913a6520736a4729cf0d51eb01a9e2ffa2e92599b68e44de5bcf354fa2642bd4f26b259daa6f7ce3ed57aeb314a9a87b789a58af499b314e13c3d65bede56c07ea2d418d6874857b70763713178fb49a2d6cd347dc58973ff49613a20757d0fcc22079f9abd10c3baee245901b9e027bd5cfc2cb5db82d4dc9677ac795ec500ecd47deee3b5da006d6d049b811d7511c78158de484232fc68daf8a45cf217d1c2fae693ff5871e8752d73b21198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
            .expected = true,
        },
        .{
            .input = "2f2ea0b3da1e8ef11914acf8b2e1b32d99df51f5f4f206fc6b947eae860eddb6068134ddb33dc888ef446b648d72338684d678d2eb2371c61a50734d78da4b7225f83c8b6ab9de74e7da488ef02645c5a16a6652c3c71a15dc37fe3a5dcb7cb122acdedd6308e3bb230d226d16a105295f523a8a02bfc5e8bd2da135ac4c245d065bbad92e7c4e31bf3757f1fe7362a63fbfee50e7dc68da116e67d600d9bf6806d302580dc0661002994e7cd3a7f224e7ddc27802777486bf80f40e4ca3cfdb186bac5188a98c45e6016873d107f5cd131f3a3e339d0375e58bd6219347b008122ae2b09e539e152ec5364e7e2204b03d11d3caa038bfc7cd499f8176aacbee1f39e4e4afc4bc74790a4a028aff2c3d2538731fb755edefd8cb48d6ea589b5e283f150794b6736f670d6a1033f9b46c6f5204f50813eb85c8dc4b59db1c5d39140d97ee4d2b36d99bc49974d18ecca3e7ad51011956051b464d9e27d46cc25e0764bb98575bd466d32db7b15f582b2d5c452b36aa394b789366e5e3ca5aabd415794ab061441e51d01e94640b7e3084a07e02c78cf3103c542bc5b298669f211b88da1679b0b64a63b7e0e7bfe52aae524f73a55be7fe70c7e9bfc94b4cf0da1213d2149b006137fcfb23036606f848d638d576a120ca981b5b1a5f9300b3ee2276cf730cf493cd95d64677bbb75fc42db72513a4c1e387b476d056f80aa75f21ee6226d31426322afcda621464d0611d226783262e21bb3bc86b537e986237096df1f82dff337dd5972e32a8ad43e28a78a96a823ef1cd4debe12b6552ea5f",
            .expected = true,
        },
        .{
            .input = "20a754d2071d4d53903e3b31a7e98ad6882d58aec240ef981fdf0a9d22c5926a29c853fcea789887315916bbeb89ca37edb355b4f980c9a12a94f30deeed30211213d2149b006137fcfb23036606f848d638d576a120ca981b5b1a5f9300b3ee2276cf730cf493cd95d64677bbb75fc42db72513a4c1e387b476d056f80aa75f21ee6226d31426322afcda621464d0611d226783262e21bb3bc86b537e986237096df1f82dff337dd5972e32a8ad43e28a78a96a823ef1cd4debe12b6552ea5f1abb4a25eb9379ae96c84fff9f0540abcfc0a0d11aeda02d4f37e4baf74cb0c11073b3ff2cdbb38755f8691ea59e9606696b3ff278acfc098fa8226470d03869217cee0a9ad79a4493b5253e2e4e3a39fc2df38419f230d341f60cb064a0ac290a3d76f140db8418ba512272381446eb73958670f00cf46f1d9e64cba057b53c26f64a8ec70387a13e41430ed3ee4a7db2059cc5fc13c067194bcc0cb49a98552fd72bd9edb657346127da132e5b82ab908f5816c826acb499e22f2412d1a2d70f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd2198a1f162a73261f112401aa2db79c7dab1533c9935c77290a6ce3b191f2318d198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
            .expected = true,
        },
        .{
            .input = "1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c103188585e2364128fe25c70558f1560f4f9350baf3959e603cc91486e110936198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
            .expected = false,
        },
        .{
            .input = "",
            .expected = true,
        },
        .{
            .input = "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
            .expected = false,
        },
        .{
            .input = "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed275dc4a288d1afb3cbb1ac09187524c7db36395df7be3b99e673b13a075a65ec1d9befcd05a5323e6da4d435f3b617cdb3af83285c2df711ef39c01571827f9d",
            .expected = true,
        },
        .{
            .input = "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002203e205db4f19b37b60121b83a7333706db86431c6d835849957ed8c3928ad7927dc7234fd11d3e8c36c59277c3e6f149d5cd3cfa9a62aee49f8130962b4b3b9195e8aa5b7827463722b8c153931579d3505566b4edf48d498e185f0509de15204bb53b8977e5f92a0bc372742c4830944a59b4fe6b1c0466e2a6dad122b5d2e030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd31a76dae6d3272396d0cbe61fced2bc532edac647851e3ac53ce1cc9c7e645a83198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
            .expected = true,
        },
        .{
            .input = "105456a333e6d636854f987ea7bb713dfd0ae8371a72aea313ae0c32c0bf10160cf031d41b41557f3e7e3ba0c51bebe5da8e6ecd855ec50fc87efcdeac168bcc0476be093a6d2b4bbf907172049874af11e1b6267606e00804d3ff0037ec57fd3010c68cb50161b7d1d96bb71edfec9880171954e56871abf3d93cc94d745fa114c059d74e5b6c4ec14ae5864ebe23a71781d86c29fb8fb6cce94f70d3de7a2101b33461f39d9e887dbb100f170a2345dde3c07e256d1dfa2b657ba5cd030427000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000021a2c3013d2ea92e13c800cde68ef56a294b883f6ac35d25f587c09b1b3c635f7290158a80cd3d66530f74dc94c94adb88f5cdb481acca997b6e60071f08a115f2f997f3dbd66a7afe07fe7862ce239edba9e05c5afff7f8a1259c9733b2dfbb929d1691530ca701b4a106054688728c9972c8512e9789e9567aae23e302ccd75",
            .expected = true,
        },
        .{
            .input = "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed275dc4a288d1afb3cbb1ac09187524c7db36395df7be3b99e673b13a075a65ec1d9befcd05a5323e6da4d435f3b617cdb3af83285c2df711ef39c01571827f9d00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed275dc4a288d1afb3cbb1ac09187524c7db36395df7be3b99e673b13a075a65ec1d9befcd05a5323e6da4d435f3b617cdb3af83285c2df711ef39c01571827f9d00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed275dc4a288d1afb3cbb1ac09187524c7db36395df7be3b99e673b13a075a65ec1d9befcd05a5323e6da4d435f3b617cdb3af83285c2df711ef39c01571827f9d00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed275dc4a288d1afb3cbb1ac09187524c7db36395df7be3b99e673b13a075a65ec1d9befcd05a5323e6da4d435f3b617cdb3af83285c2df711ef39c01571827f9d00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed275dc4a288d1afb3cbb1ac09187524c7db36395df7be3b99e673b13a075a65ec1d9befcd05a5323e6da4d435f3b617cdb3af83285c2df711ef39c01571827f9d",
            .expected = true,
        },
        .{
            .input = "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002203e205db4f19b37b60121b83a7333706db86431c6d835849957ed8c3928ad7927dc7234fd11d3e8c36c59277c3e6f149d5cd3cfa9a62aee49f8130962b4b3b9195e8aa5b7827463722b8c153931579d3505566b4edf48d498e185f0509de15204bb53b8977e5f92a0bc372742c4830944a59b4fe6b1c0466e2a6dad122b5d2e030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd31a76dae6d3272396d0cbe61fced2bc532edac647851e3ac53ce1cc9c7e645a83198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002203e205db4f19b37b60121b83a7333706db86431c6d835849957ed8c3928ad7927dc7234fd11d3e8c36c59277c3e6f149d5cd3cfa9a62aee49f8130962b4b3b9195e8aa5b7827463722b8c153931579d3505566b4edf48d498e185f0509de15204bb53b8977e5f92a0bc372742c4830944a59b4fe6b1c0466e2a6dad122b5d2e030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd31a76dae6d3272396d0cbe61fced2bc532edac647851e3ac53ce1cc9c7e645a83198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002203e205db4f19b37b60121b83a7333706db86431c6d835849957ed8c3928ad7927dc7234fd11d3e8c36c59277c3e6f149d5cd3cfa9a62aee49f8130962b4b3b9195e8aa5b7827463722b8c153931579d3505566b4edf48d498e185f0509de15204bb53b8977e5f92a0bc372742c4830944a59b4fe6b1c0466e2a6dad122b5d2e030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd31a76dae6d3272396d0cbe61fced2bc532edac647851e3ac53ce1cc9c7e645a83198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002203e205db4f19b37b60121b83a7333706db86431c6d835849957ed8c3928ad7927dc7234fd11d3e8c36c59277c3e6f149d5cd3cfa9a62aee49f8130962b4b3b9195e8aa5b7827463722b8c153931579d3505566b4edf48d498e185f0509de15204bb53b8977e5f92a0bc372742c4830944a59b4fe6b1c0466e2a6dad122b5d2e030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd31a76dae6d3272396d0cbe61fced2bc532edac647851e3ac53ce1cc9c7e645a83198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002203e205db4f19b37b60121b83a7333706db86431c6d835849957ed8c3928ad7927dc7234fd11d3e8c36c59277c3e6f149d5cd3cfa9a62aee49f8130962b4b3b9195e8aa5b7827463722b8c153931579d3505566b4edf48d498e185f0509de15204bb53b8977e5f92a0bc372742c4830944a59b4fe6b1c0466e2a6dad122b5d2e030644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd31a76dae6d3272396d0cbe61fced2bc532edac647851e3ac53ce1cc9c7e645a83198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa",
            .expected = true,
        },
        .{
            .input = "105456a333e6d636854f987ea7bb713dfd0ae8371a72aea313ae0c32c0bf10160cf031d41b41557f3e7e3ba0c51bebe5da8e6ecd855ec50fc87efcdeac168bcc0476be093a6d2b4bbf907172049874af11e1b6267606e00804d3ff0037ec57fd3010c68cb50161b7d1d96bb71edfec9880171954e56871abf3d93cc94d745fa114c059d74e5b6c4ec14ae5864ebe23a71781d86c29fb8fb6cce94f70d3de7a2101b33461f39d9e887dbb100f170a2345dde3c07e256d1dfa2b657ba5cd030427000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000021a2c3013d2ea92e13c800cde68ef56a294b883f6ac35d25f587c09b1b3c635f7290158a80cd3d66530f74dc94c94adb88f5cdb481acca997b6e60071f08a115f2f997f3dbd66a7afe07fe7862ce239edba9e05c5afff7f8a1259c9733b2dfbb929d1691530ca701b4a106054688728c9972c8512e9789e9567aae23e302ccd75",
            .expected = true,
        },
    };
    for (cases) |case| {
        const N = 192 * 10;
        var buffer: [N]u8 = .{0} ** N;
        const input = try std.fmt.hexToBytes(&buffer, case.input);

        const G1 = Bn254.G1;
        const G2 = Bn254.G2;

        var p: stdx.BoundedArray(G1.Affine, 10) = .{};
        var q: stdx.BoundedArray(G2.Affine, 10) = .{};
        std.debug.assert(input.len % 192 == 0);

        for (0..input.len / 192) |i| {
            try p.append(try .fromBytes(input[i * 192 ..][0..64]));
            try q.append(try .fromBytes(input[i * 192 ..][64..][0..128]));
        }

        const computed = Bn254.compute(p.constSlice(), q.constSlice());
        try std.testing.expectEqual(case.expected, computed.isOne());
    }
}
