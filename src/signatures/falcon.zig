const std = @import("std");
const sampler = @import("falcon/samplerz.zig");

const Shake256 = std.crypto.hash.sha3.Shake256;

pub const Falcon512 = Falcon(512);

fn Falcon(N: u32) type {
    return struct {
        const logn = std.math.log2(N);

        /// The integer modulus used in Falcon.
        const Q = 12 * 1024 + 1;
        const V = @Vector(4, i16);
        const QV: V = @splat(Q);

        comptime {
            switch (N) {
                512, 1024 => {},
                else => @compileError("unsupported falcon signature bit size"),
            }

            // Show that Q is NTT-friendly
            std.debug.assert(Q % (2 * N) == 1);
        }

        const precompute = struct {
            const T = u64;

            // Takes 18ms to compute powers at comptime, in Zig 0.15.
            const positive = precompute.powers(psi);
            const negative = precompute.powers(inv(psi));

            /// A primative 2N-th root of unity in $\mathbb{Z}_q$.
            const psi = psi: {
                const exp = (Q - 1) / (2 * N);
                for (1..Q) |i| {
                    const g = powmod(i, exp);
                    const g2 = powmod(g, N);
                    if (g2 != 1) break :psi g;
                }
                @compileError("no primative 2N-th root of unity!");
            };

            fn reverse(x: T) T {
                return @bitReverse(x) >> (@as(u7, 64) - logn);
            }

            /// Returns the bitreversed powers of `x`, from 0 to N - 1.
            fn powers(x: T) [N]Fq {
                @setEvalBranchQuota(10_000);
                var pows: [N]T = @splat(1);
                var fqs: [N]Fq = @splat(.init(1));
                for (1..N) |i| {
                    const pow = (pows[i - 1] * x) % Q;
                    pows[i] = pow;
                    fqs[reverse(i)] = .init(pow);
                }
                return fqs;
            }

            /// Returns x^k mod Q
            fn powmod(a: T, b: T) T {
                var res = 1;
                var x = a;
                var k = b;
                while (k > 0) {
                    if (k % 2 == 1) res = (res * x) % Q;
                    x = (x * x) % Q;
                    k /= 2;
                }
                return res;
            }

            /// Returns x^-1 mod Q
            fn inv(x: T) T {
                var t: i64 = 0;
                var new_t: i64 = 1;
                var r: i64 = Q;
                var new_r: i64 = x;

                while (new_r != 0) {
                    const quo = r / new_r;
                    const a = t - (quo * new_t);
                    const b = r - (quo * new_r);
                    t = new_t;
                    r = new_r;
                    new_t = a;
                    new_r = b;
                }
                if (r > 1) @compileError("could not find inverse");
                if (t < 0) t += Q;
                return t;
            }
        };

        pub const PublicKey = struct {
            h: Polynomial(N, Fq),

            const BITS_PER_VALUE = 14;
            const SIZE = 1 + (14 * N / 8);

            pub fn fromBytes(bytes: *const [SIZE]u8) !PublicKey {
                // first byte is the header, encoded as
                // 0 0 0 0 n n n n
                // where the leftmost 4 bits are 0
                // and nnnn encodes logn
                if (bytes[0] != logn) return error.InvalidHeader;

                // The rest of the bytes are the public key polynomial.
                // Each value, in [0, Q), is encoded as a 14-bit integer. The encoded
                // values are compressed into a bit sequence of 14 * N bits, or 14N/8 bytes.
                const h = bytes[1..];
                var coeff: [N]Fq = undefined;
                inline for (0..512 / 4) |i| {
                    // Given that each element is 14 bits, 7 bytes hold 4 elements (56 / 14 = 4).
                    // We represent the elements as u32 for efficient arithmetics.
                    const in = h[i * 7 ..][0..7];
                    const out: *[4]u32 = @ptrCast(coeff[i * 4 ..][0..4]);
                    const mask: @Vector(4, u32) = @splat((1 << 14) - 1);

                    // We perform 2 movs to load words at `in` and `in + 3`.
                    // The vector now contains 4 compressed elements (end-exclusive ranges):
                    // 1. 00..14 (bytes 0, 1)
                    // 2. 14..28 (bytes 1, 2, 3)
                    // 3. 28..42 (bytes 3, 4, 5)
                    // 4. 42..56 (bytes 5, 6)
                    const compressed: @Vector(4, u32) = .{
                        @bitCast(in[0..4].*),
                        @bitCast(in[0..4].*),
                        @bitCast(in[3..7].*),
                        @bitCast(in[3..7].*),
                    };
                    const shifted = @byteSwap(compressed) >> .{ 18, 4, 14, 0 };
                    // After the mask, each element fits into 14-bits, so it'll always fit into signed 16 bits.
                    const masked: V = @intCast(shifted & mask);
                    // We perform the modulus check in parallel, checking each element and returning
                    // an error if any of the elements are greater than greater than or equal to the modulus.
                    if (@reduce(.Or, masked >= QV)) return error.InvalidCoeff;
                    out.* = Fq.initVector(masked);
                }

                return .{ .h = .{ .coeff = coeff } };
            }
        };

        pub const Signature = struct {
            nonce: [40]u8,
            s2: Polynomial(N, i16),

            const Header = packed struct(u8) {
                logn: u4,
                one: u1 = 1,
                cc: enum(u2) {
                    compressed = 0b01,
                    uncompressed = 0b10,
                    _,
                },
                zero: u1 = 0,
            };

            /// NOTE: As signatures use compress/decompress, their length is variable.
            pub fn fromBytes(bytes: []const u8) !Signature {
                if (bytes.len > 666) return error.TooManyBytes;
                // We need at least 41 bytes to read the header/salt.
                if (bytes.len < 41) return error.TooLittleBytes;

                // The first byte is a header with the following format:
                // 0 c c 1 n n n n
                const header: Header = @bitCast(bytes[0]);
                if (header.logn != logn or
                    header.one != 1 or
                    header.zero != 0 or
                    // NOTE: we *require* that signatures are in compressed form. Perhaps later
                    // we'll allow uncompressed as well, however this is what I need right now
                    // for Solana precompiles.
                    header.cc != .compressed) return error.InvalidHeader;

                return .{
                    .nonce = bytes[1..][0..40].*,
                    .s2 = try decompress(bytes[41..]),
                };
            }
        };

        pub const Fq = struct {
            data: u32,

            pub fn init(value: i16) Fq {
                const sign: i16 = if (value < 0) -1 else 1;
                const reduced = sign * @mod(sign * value, Q);
                return .{ .data = @intCast(reduced + Q * @as(i16, @intFromBool(value < 0))) };
            }

            /// Given @Vector(4, i16), returns [init(v0), init(v1), init(v2), init(v3)].
            fn initVector(value: V) @Vector(4, u32) {
                const one: V = @splat(1);
                const predicate = value < (one - one);
                const sign = @select(i16, predicate, -one, one);
                const reduced = sign * @mod(sign * value, QV);
                return @intCast(reduced + QV * @intFromBool(predicate));
            }

            fn vector(L: u32) type {
                return struct {
                    const Fv = @Vector(L, u32);
                    const Ql: Fv = @splat(Q);

                    inline fn add(a: Fv, b: Fv) Fv {
                        const s = a +% b;
                        const d, const n: Fv = @subWithOverflow(s, Ql);
                        const r = d +% (Ql * n);
                        return r;
                    }
                    inline fn sub(a: Fv, b: Fv) Fv {
                        return @This().add(a, @This().neg(b));
                    }
                    inline fn neg(a: Fv) Fv {
                        const r = Ql - a;
                        return r * @intFromBool(a != @as(Fv, @splat(0)));
                    }
                    inline fn mul(a: Fv, b: Fv) Fv {
                        return (a * b) % Ql;
                    }
                };
            }

            inline fn add(a: Fq, b: Fq) Fq {
                const s = a.data +% b.data;
                const d, const n: u32 = @subWithOverflow(s, Q);
                const r = d +% (Q * n);
                return .{ .data = r };
            }
            inline fn sub(a: Fq, b: Fq) Fq {
                return a.add(b.neg());
            }
            inline fn neg(a: Fq) Fq {
                const r = Q - a.data;
                return .{ .data = r * @intFromBool(a.data != 0) };
            }
            inline fn mul(a: Fq, b: Fq) Fq {
                return .{ .data = (a.data * b.data) % Q };
            }

            inline fn balanced(a: Fq) i16 {
                const value: i16 = @intCast(a.data);
                const g: i16 = @intFromBool(value > Q / 2);
                return value - Q * g;
            }
        };

        fn Polynomial(length: comptime_int, T: type) type {
            return struct {
                coeff: [length]T,

                const Self = @This();
                comptime {
                    std.debug.assert(length < 4096);
                }

                /// Generate a polynomial of degree at most (N - 1), with coefficients
                /// following a discrete Gaussian distribution $D_{Z, 0, sigma}$ with
                /// sigma = 1.17 * sqrt(Q / (2 * N)).
                // pub fn generate() Self {
                //     comptime std.debug.assert(T == i16);

                //     const rng = std.crypto.random;
                //     const mu = 0.0;
                //     const sigma_star = 1.17 * @sqrt(12289.0 / 8192.0);
                //     var f0: [4096]i16 = undefined;
                //     for (&f0) |*o| o.* = sampler.samplerz(
                //         mu,
                //         sigma_star,
                //         sigma_star - 0.001,
                //         rng,
                //     );
                //     var f: [length]i16 = @splat(0);
                //     const k = 4096 / length;
                //     for (0..length) |i| {
                //         var sum: i16 = 0;
                //         for (0..k) |j| sum += f0[i * k + j];
                //         f[i] = sum;
                //     }
                //     return .{ .coeff = f };
                // }

                fn toField(a: Self) Polynomial(length, Fq) {
                    comptime std.debug.assert(T == i16);
                    var coeff: [length]Fq = undefined;
                    for (a.coeff, &coeff) |b, *c| c.* = .init(b);
                    return .{ .coeff = coeff };
                }

                fn add(a: Self, b: Self) Self {
                    var out: [length]T = a.coeff;
                    for (&out, b.coeff) |*o, x| o.* = o.add(x);
                    return .{ .coeff = out };
                }
                fn sub(a: Self, b: Self) Self {
                    return a.add(b.neg());
                }
                fn neg(a: Self) Self {
                    var out: [length]T = a.coeff;
                    for (&out) |*o| o.* = o.neg();
                    return .{ .coeff = out };
                }
                fn mul(a: Self, b: Self) Self {
                    var out: [length]T = undefined;
                    for (&out, a.coeff, b.coeff) |*o, x, y| {
                        o.* = x.mul(y);
                    }
                    return .{ .coeff = out };
                }
                /// Compute the evaluations of the polynomial on the roots of the
                /// polynomial X^n + 1 using a fast Fourier transform.
                ///
                /// Algorithm 1 from https://eprint.iacr.org/2016/504.pdf.
                fn fft(p: Self) Self {
                    comptime std.debug.assert(length == N);

                    var a = p.coeff;
                    var t: u32 = N;
                    var m: u32 = 1;
                    while (m < N) {
                        t >>= 1;
                        for (0..m) |i| {
                            const j1 = 2 * i * t;
                            const j2 = j1 + t - 1;
                            const s = precompute.positive[m + i];
                            switch ((j2 + 1) - j1) {
                                256, 128, 64, 32 => |distance| {
                                    for (0..distance) |b| {
                                        const u = a[j1 + b];
                                        const v = a[j1 + t + b].mul(s);
                                        a[j1 + b] = u.add(v);
                                        a[j1 + t + b] = u.sub(v);
                                    }
                                },
                                inline 16, 8, 4, 2 => |distance| {
                                    const vector = Fq.vector(distance);
                                    const Fv = vector.Fv;
                                    const u: Fv = @bitCast(a[j1..][0..distance].*);
                                    const v: Fv = vector.mul(@bitCast(a[j1 + t ..][0..distance].*), @splat(s.data));
                                    a[j1..][0..distance].* = @bitCast(vector.add(u, v));
                                    a[j1 + t ..][0..distance].* = @bitCast(vector.sub(u, v));
                                },
                                1 => {
                                    const u = a[j1];
                                    const v = a[j1 + t].mul(s);
                                    a[j1] = u.add(v);
                                    a[j1 + t] = u.sub(v);
                                },
                                else => unreachable,
                            }
                        }
                        m *= 2;
                    }

                    return .{ .coeff = a };
                }

                /// Compute the coefficients of the polynomial with the given evaluations
                /// on the roots of X^n + 1 using an inverse fast Fourier transform.
                ///
                /// Algorithm 2 from https://eprint.iacr.org/2016/504.pdf.
                fn ifft(p: Self) Self {
                    comptime std.debug.assert(length == N);

                    var a = p.coeff;
                    var t: u32 = 1;
                    var m: u32 = N;
                    while (m > 1) {
                        var j1: u32 = 0;
                        const h = m / 2;
                        for (0..h) |i| {
                            const j2 = j1 + t - 1;
                            // s = {\phi}_rev^-1[h + i]
                            const s = precompute.negative[h + i];
                            for (j1..j2 + 1) |j| {
                                const u = a[j];
                                const v = a[j + t];
                                a[j] = u.add(v);
                                a[j + t] = (u.sub(v)).mul(s);
                            }
                            // j1 = j1 + 2t
                            j1 += 2 * t;
                        }
                        t <<= 1;
                        m /= 2;
                    }

                    // a[j] = a[j] * n^-1 mod q
                    const ninv: Fq = comptime .init(precompute.inv(N));
                    for (&a) |*aj| {
                        aj.* = aj.mul(ninv);
                    }

                    return .{ .coeff = a };
                }
            };
        }

        pub fn verify(msg: []const u8, sig: Signature, pk: PublicKey) !void {
            const c = hashToPoint(msg, &sig.nonce);

            const s2_ntt = sig.s2.toField().fft();
            const h_ntt = pk.h.fft();
            const c_ntt = c.fft();

            // s1 <- c1 - s2 * pk.h mod q
            const s1 = c_ntt.sub(s2_ntt.mul(h_ntt)).ifft();

            // pass = ||(s1, s2)||^2 <= \beta^2
            // In order to avoid computing the square root, we use the squared norm and compare it to \beta^2.
            var norm: i64 = 0;
            for (s1.coeff, sig.s2.coeff) |i, j| {
                const value: i64 = i.balanced();
                norm += (value * value) + (@as(i64, j) * j);
            }
            const bound = switch (N) {
                512 => 34_034_726,
                1024 => 70_265_242,
                else => unreachable,
            };
            if (norm >= bound) return error.InvalidBound;
        }

        fn bit(bytes: []const u8, position: usize) u1 {
            const byte = position / 8;
            const idx = 7 - (position & 7);
            return @intCast((bytes[byte] >> @intCast(idx)) & 1);
        }

        pub fn decompress(s2: []const u8) !Polynomial(N, i16) {
            var out: [N]i16 = undefined;
            const length = s2.len * 8;
            var index: usize = 0;
            for (0..N) |i| {
                if (index + 8 >= length) return error.OutOfBounds;
                const sign: i16 = if (bit(s2, index) != 0) -1 else 1;
                index += 1;
                var low_bits: i16 = 0;
                for (0..7) |_| {
                    low_bits = (low_bits << 1) | bit(s2, index);
                    index += 1;
                }
                var high_bits: i16 = 0;
                while (index < length and bit(s2, index) == 0) {
                    high_bits += 1;
                    index += 1;
                }
                if (index >= length) return error.NotTerminator;
                index += 1;
                const result = @as(i32, sign) * ((high_bits << 7) | low_bits);
                if (result > Q - 1) return error.InvalidCoeff;
                out[i] = @intCast(result);
            }
            return .{ .coeff = out };
        }

        /// We repeatedly obtain 16-bit values from SHAKE256 (with input r || msg).
        /// If the value is between 0 and 61444, we reduce it modulo Q. Otherwise,
        /// the value is rejected a new one is sampeld.
        ///
        /// NOTE: This approach is inherently non-constant-time.
        ///
        /// https://eprint.iacr.org/2019/893.pdf describes a method for performing
        /// this in constant-time, by first gathering enough elements that the
        /// propability of not having enough under K * Q is negligible.
        ///
        /// This is only a consideration that needs to be made while signing a
        /// sensitive message. The downside of this approach is that it
        /// introduces a significant cost to verification performance.
        fn hashToPoint(msg: []const u8, r: *const [40]u8) Polynomial(N, Fq) {
            // K <- ⌊2^16 / Q⌋
            const K = (1 << 16) / Q;

            var state: Shake256 = .init(.{});
            state.update(r);
            state.update(msg);

            var i: u32 = 0;
            var coeffs: [N]Fq = undefined;
            while (i != N) {
                var sample: [2]u8 = undefined;
                state.squeeze(&sample);
                const t = (@as(u32, sample[0]) << 8) | sample[1];
                if (t < K * Q) {
                    coeffs[i] = .init(@intCast(t % Q));
                    i += 1;
                }
            }

            return .{ .coeff = coeffs };
        }
    };
}

test {
    _ = @import("falcon/test.zig");
    _ = @import("falcon/samplerz.zig");
}
