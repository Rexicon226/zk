const std = @import("std");
const stdx = @import("stdx");
const ff = @import("../ff.zig");

pub const Flags = packed struct(u8) {
    _padding: u6,
    negative: bool,
    infinity: bool,

    pub const mask: u8 = 0b11000000;
};

/// Here we work with elliptic curves given by the short Weierstrass equation:
/// $$E : y^2 = x^3 + a x + b$$
///
/// over a field $\mathbb{F}$. \
/// The nonsingularity condition
/// $$4a^3 + 27b^2 \neq 0$$
/// ensures that $E$ is a smooth algebraic curve.
///
/// The set $E(\mathbb{F}) \cup \{\mathcal{O}\}$ forms an abelian group.
///
/// - Point addition is defined by line intersection
/// - Doubling uses tangent line
/// - The point at infinity $\( \mathcal{O} \)$ acts as the identity.
///
/// ## Why we use Jacobian coordinates
///
/// Affine formulas require field inversion:
/// $$\lambda = \frac{y_2 - y_1}{x_2 - x_1}$$
/// which is significantly more expensive than multiplication.
///
/// To avoid inversions, points are represented in Jacobian form:
/// $$(X : Y : Z) \longleftrightarrow \left( \frac{X}{Z^2}, \frac{Y}{Z^3} \right)$$
/// with $Z = 0$ representing $\mathcal{O}$.
///
/// All group operations can then be expressed using only multiplications and
/// squaring in $\mathbb{F}$.
///
/// ## Jacobian group formula
///
/// Point doubling and addition in Jacobian coordinates implement the same
/// geometric group law, but operate on homogeneous coordinates.\
/// The formulas are derived by clearing denominators in the affine expressions
/// and re-normalizing the result.
///
/// We can define that $(X_3 : Y_3 : Z_3)$ represents the same affine point
/// as the intersection-defined sum.
///
/// - Each Jacobian point represents a uninque affine point (up to scaling)
/// - The curve equation holds after de-homogenization
/// - No inversions are required until the final affine conversion
pub fn ShortWeierstrass(
    BaseField: type,
    comptime params: struct {
        a: BaseField,
        b: BaseField,
    },
    extra: anytype,
) type {
    return struct {
        x: BaseField,
        y: BaseField,
        /// Zero, if and only if, at the point at infinity.
        z: BaseField,

        const Self = @This();

        pub const zero: Self = .{
            .x = .one,
            .y = .one,
            .z = .zero,
        };
        pub const A = params.a;
        const A_is_zero = A.isZero();
        pub const B = params.b;
        pub const frob = if (@hasDecl(extra, "frob")) extra.frob;
        pub const frob2 = if (@hasDecl(extra, "frob2")) extra.frob2;

        pub const Affine = struct {
            /// `x / z^2`
            x: BaseField,
            /// `y / z^3`
            y: BaseField,
            infinity: bool,

            const serialized_size = BaseField.serialized_size * 2;

            pub const zero: Affine = .{
                .x = .zero,
                .y = .zero,
                .infinity = true,
            };

            pub fn isZero(a: Affine) bool {
                return a.infinity;
            }

            /// When this returns, the fields are *not* in montgomery form.
            fn fromBytesInternal(input: *const [serialized_size]u8) !Affine {
                if (std.mem.allEqual(u8, input, 0)) return .zero;

                var flags: Flags = undefined;
                return .{
                    .x = try .fromBytes(input[0..BaseField.serialized_size], null),
                    .y = try .fromBytes(input[BaseField.serialized_size..][0..BaseField.serialized_size], &flags),
                    .infinity = flags.infinity,
                };
            }

            pub fn isWellFormed(g: Affine) !void {
                try g.onCurve();
                if (@hasDecl(extra, "checkSubgroup")) try extra.checkSubgroup(g);
            }

            fn DecodeSet() type {
                var x = error{ TooLarge, BothFlags, NotOnCurve };
                if (@hasDecl(extra, "checkSubgroup")) x = x || error{WrongSubgroup};
                return x;
            }

            pub fn fromBytes(input: *const [serialized_size]u8) DecodeSet()!Affine {
                const g = try fromBytesInternal(input);
                if (g.isZero()) return g;
                try g.isWellFormed();
                return g;
            }

            pub fn toBytes(p: Affine, out: *[serialized_size]u8) void {
                if (p.isZero()) { // no flags
                    @memset(out, 0);
                    return;
                }

                p.x.toBytes(out[0..BaseField.serialized_size]);
                p.y.toBytes(out[BaseField.serialized_size..][0..BaseField.serialized_size]);
            }

            /// Checks whether the point is on the curve.
            pub fn onCurve(a: Affine) error{NotOnCurve}!void {
                // zero-point always well formed, no matter what X and Y are
                if (a.infinity) return;

                // Check that y^2 = x^3 + ax + b
                const y2 = a.y.sq();
                const x3b = a.x.sq().mul(a.x).add(B);
                // We can skip the `a` coeff if it's zero.
                if (!A_is_zero) {
                    @compileError("TODO");
                }
                if (!y2.eql(x3b)) return error.NotOnCurve;
            }

            pub fn toProjective(a: Affine) Self {
                return .{
                    .x = a.x,
                    .y = a.y,
                    .z = if (a.infinity) .zero else .one,
                };
            }

            /// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-mmadd-2007-bl
            pub fn add(a: Affine, b: Affine) Affine {
                // if a == 0, return b
                if (a.isZero()) return b;
                // if b == 0, return a
                if (b.isZero()) return a;

                const lambda: BaseField = if (a.x.eql(b.x)) r: {
                    if (a.y.eql(b.y)) {
                        // a == b => point double: lambda = 3 * x1^2 / (2 * y1)
                        const x = a.x.sq().triple();
                        const y = a.y.dbl(); // y = 2 * y1
                        break :r y.inverse().mul(x);
                    } else {
                        // a == -b => 0
                        return .zero;
                    }
                } else r: {
                    // point add: lambda = (y1 - y2) / (x1 - x2)
                    const x = a.x.sub(b.x);
                    const y = a.y.sub(b.y);
                    break :r x.inverse().mul(y);
                };

                // x3 = lambda^2 - x1 - x2
                const x = lambda.sq().sub(a.x).sub(b.x);
                // y3 = lambda * (x1 - x3) - y1
                const y = a.x.sub(x).mul(lambda).sub(a.y);

                return .{ .x = x, .y = y, .infinity = false };
            }

            /// https://encrypt.a41.io/primitives/abstract-algebra/elliptic-curve/scalar-multiplication/double-and-add
            /// https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Double-and-add
            pub fn mulScalar(base: Affine, T: type, v: T) Self {
                if (v == 0) return .zero;

                // TODO: glv and wnaf
                var r: Self = .zero;
                var iterator = stdx.BitIterator(T, .big, true).init(v);
                while (iterator.next()) |set| {
                    r = r.dbl();
                    if (set) r = base.addProjective(r);
                }
                return r;
            }

            /// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-madd-2007-bl
            ///
            /// NOTE: the argument are "reversed", `(X1, Y1, Z1)` is `b` and `(X2, Y2, Z2)` is `a`.
            pub fn addProjective(a: Affine, b: Self) Self {
                // b==0, return a
                if (b.isZero()) return a.toProjective();
                // a==0, return b
                if (a.isZero()) return b;

                // Z1Z1 = Z1^2
                const z1z1 = b.z.sq();
                // U2 = X2*Z1Z1
                const @"u2" = a.x.mul(z1z1);
                // S2 = Y2*Z1*Z1Z1
                const s2 = a.y.mul(b.z).mul(z1z1);

                // if (a==b): return b * 2
                if (@"u2".eql(b.x)) {
                    // points are equal, double it
                    if (s2.eql(b.y)) return b.dbl();
                    // a + (-a) = 0
                    return .zero;
                }

                // H = U2-X1
                const h = @"u2".sub(b.x);
                // HH = H^2
                const hh = h.sq();
                // I = 4*HH
                const i = hh.dbl().dbl();
                // J = H*I
                const j = h.mul(i);
                // r = 2*(S2-Y1)
                const r = s2.sub(b.y).dbl();
                // V = X1*I
                const v = b.x.mul(i);
                // X3 = r^2 - J - 2*V
                const x3 = r.sq().sub(j).sub(v).sub(v);
                // Y3 = r*(V - V3) - 2*Y1*J
                const y3 = v.sub(x3).mul(r).sub(b.y.mul(j).dbl());
                // Z3 = (Z1 + H)^2 - Z1Z1 - HH
                const z3 = b.z.add(h).sq().sub(z1z1).sub(hh);

                return .{
                    .x = x3,
                    .y = y3,
                    .z = z3,
                };
            }
        };

        pub fn isZero(a: Self) bool {
            return a.z.eql(.zero);
        }

        pub fn toAffine(p: Self) Affine {
            // nothing to do
            if (p.z.isZero() or p.z.isOne()) return .{
                .x = p.x,
                .y = p.y,
                .infinity = p.z.isZero(),
            };

            // x / z^2, y / z^3
            const iz = p.z.inverse();
            const iz2 = iz.sq();
            return .{
                .x = p.x.mul(iz2),
                .y = p.y.mul(iz2).mul(iz),
                .infinity = false,
            };
        }

        /// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#addition-add-2007-bl
        pub fn add(a: Self, b: Self) Self {
            // if a==0, return b
            if (a.isZero()) return b;
            // if b==0, return a
            if (b.isZero()) return a;

            // Z1Z1 = Z1^2
            const z1z1 = a.z.sq();
            // Z2Z2 = Z2^2
            const z2z2 = b.z.sq();
            // U1 = X1*Z2Z2
            const @"u1" = a.x.mul(z2z2);
            // U2 = X2*Z1Z1
            const @"u2" = b.x.mul(z1z1);
            // S1 = Y1*Z2*Z2Z2
            const s1 = a.y.mul(b.z).mul(z2z2);
            // S2 = Y2*Z1*Z1Z1
            const s2 = b.y.mul(a.z).mul(z1z1);

            if (@"u2".eql(a.x)) {
                // points are equal, we can double (a * 2)
                if (s2.eql(a.y)) return a.dbl();
                // a + (-a) is zero
                return .zero;
            }

            // H = U2-U1
            const h = @"u2".sub(@"u1");
            // I = (2*H)^2
            const i = h.dbl().sq();
            // J = H*I
            const j = h.mul(i);
            // r = 2*(S2-S1)
            const r = s2.sub(s1).dbl();
            // V = U1*I
            const v = @"u1".mul(i);

            // X3 = r^2-J-2*V
            const x3 = r.sq().sub(j).sub(v.dbl());
            // Y3 = r*(V-X3)-2*S1*J
            const y3 = v.sub(x3).mul(r).sub(s1.mul(j).dbl());
            // Z3 = ((Z1+Z2)^2-Z1Z1-Z2Z2)*H
            const z3 = a.z.add(b.z).sq().sub(z1z1).sub(z2z2).mul(h);

            return .{
                .x = x3,
                .y = y3,
                .z = z3,
            };
        }

        /// Returns `2 * p`.
        ///
        /// Jacobian coordinates cannot be doubled by simply `p + p`, we need
        /// to account for the "slope" of the curve to ensure the result lies on the curve.
        pub fn dbl(p: Self) Self {
            // Doubling zero just gives us zero. Return the point - if we return `.zero`, it might
            // perform an extra copy after inlining, and we want to avoid that.
            if (p.isZero()) return p;

            if (A_is_zero) {
                // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#doubling-dbl-2009-l

                // A = X1^2
                const a = p.x.sq();
                // B = Y1^2
                const b = p.y.sq();
                // C = B^2
                const c = b.sq();

                // D = 2*((X1+B)^2-A-C)
                const d = switch (BaseField.extension_degree) {
                    // (X1+B)^2 = X1^2 + 2*X1*B + B^2
                    // D = 2*(X1^2 + 2*X1*B + B^2 - A    - C)
                    // D = 2*(X1^2 + 2*X1*B + B^2 - X1^2 - B^2)
                    //        ^               ^     ^      ^
                    //        |---------------|-----|      |
                    //                        |------------|
                    // These terms cancel each other out, and we're left with:
                    // D = 2*(2*X1*B) */
                    1, 2 => p.x.mul(b).dbl().dbl(),
                    // Just uses the regular algorithm. The `sq()` ends up being
                    // faster then the `mul()` with the larger extensions.
                    else => p.x.add(b).sq().sub(a).sub(c).dbl(),
                };

                // E = 3*A
                const e = a.triple();
                // F = E^2
                const f = e.sq();

                // X3 = F-2*D
                const x3 = f.sub(d.dbl());
                // Y3 = E*(D-X3)-8*C
                const y3 = e.mul(d.sub(x3)).sub(c.dbl().dbl().dbl());
                // Z3 = 2*Y1*Z1
                const z3 = p.y.mul(p.z).dbl();

                return .{
                    .x = x3,
                    .y = y3,
                    .z = z3,
                };
            } else {
                // https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian.html#doubling-dbl-2007-bl

                // XX = X1^2
                const xx = p.x.sq();
                // YY = Y1^2
                const yy = p.y.sq();
                // ZZ = Z1^2
                const zz = p.z.sq();
                // YYYY = YY^2
                const y4 = yy.sq();
                // S = 2*((X1+YY)^2-XX-YYYY)
                const s = p.x.add(yy).sq().sub(xx).sub(y4).dbl();
                // M = 3*XX + a*ZZ^2
                const m = xx.triple().add(zz.sq().mul(A));

                // T = M^2-2*S
                const t = m.sq().sub(s).sub(s);
                // Y3 = M*(S-T)-8*YYYY
                const y3 = s.sub(t).mul(m).sub(y4.dbl().dbl().dbl());
                // Z3 = (Y1+Z1)^2-YY-ZZ
                const z3 = p.y.add(p.z).sq().sub(yy).sub(zz);

                return .{
                    .x = t,
                    .y = y3,
                    .z = z3,
                };
            }
        }

        pub fn eql(a: Self, b: Self) bool {
            if (a.isZero()) return b.isZero();
            if (b.isZero()) return false;

            const l = a.z.sq();
            const r = b.z.sq();

            const lx = l.mul(b.x);
            const rx = r.mul(a.x);
            if (!lx.eql(rx)) return false;

            const r2 = r.mul(a.y).mul(b.z);
            const l2 = l.mul(b.y).mul(a.z);
            return l2.eql(r2);
        }

        pub fn negate(a: Self) Self {
            return .{
                .x = a.x,
                .y = a.y.negate(),
                .z = a.z,
            };
        }

        pub fn mulScalar(base: Self, T: type, v: T) Self {
            // TODO: glv and wnaf
            var r: Self = .zero;
            var iterator = stdx.BitIterator(T, .big, true).init(v);
            while (iterator.next()) |set| {
                r = r.dbl();
                if (set) r = base.add(r);
            }
            return r;
        }

        pub fn format(g: Self, writer: *std.Io.Writer) !void {
            try writer.print("(x: {f}, y: {f}, z: {f})", .{ g.x, g.y, g.z });
        }
    };
}
