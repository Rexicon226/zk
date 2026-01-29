const std = @import("std");
const builtin = @import("builtin");
const sampler = @import("falcon/samplerz.zig");

const Shake256 = std.crypto.hash.sha3.Shake256;

pub const Falcon512 = Falcon(512);
pub const Falcon1024 = Falcon(1024);

fn Falcon(N: u32) type {
    return struct {
        const logn = std.math.log2(N);

        /// The integer modulus used in Falcon.
        const Q = 12 * 1024 + 1;

        comptime {
            switch (N) {
                512, 1024 => {},
                else => @compileError("unsupported falcon signature bit size"),
            }

            // Show that Q is NTT-friendly
            std.debug.assert(Q % (2 * N) == 1);
        }

        pub const PublicKey = struct {
            h: Polynomial(N, Fq),

            const V = @Vector(4, i16);
            const QV: V = @splat(Q);

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
                inline for (0..N / 4) |i| {
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
                    out.* = Fq.Vector(4).init(masked);
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

            const SIZE = switch (N) {
                512 => 666,
                1024 => 1280,
                else => unreachable,
            };

            /// NOTE: As signatures use compress/decompress, their length is variable.
            pub fn fromBytes(bytes: []const u8) !Signature {
                if (bytes.len > SIZE) return error.TooManyBytes;
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

        const Fq = struct {
            data: u32,

            const V = @Vector(4, i16);
            const QV: V = @splat(Q);

            const precompute = struct {
                const T = u64;

                // Takes 18ms to compute powers at comptime, in Zig 0.15.
                const positive = precompute.powers(psi);
                const negative = precompute.powers(inv(psi));
                const ninv: Fq = .init(inv(N));

                /// A primitive 2N-th root of unity in $\mathbb{Z}_q$.
                const psi = psi: {
                    const exp = (Q - 1) / (2 * N);
                    for (1..Q) |i| {
                        const g = powmod(i, exp);
                        const g2 = powmod(g, N);
                        if (g2 != 1) break :psi g;
                    }
                    @compileError("no primitive 2N-th root of unity!");
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

            fn Vector(L: u32) type {
                return struct {
                    data: Vl,

                    const Self = @This();
                    const Vl = @Vector(L, u32);
                    const Sl = @Vector(L, i16);

                    const Ql: Vl = @splat(Q);
                    const Qs: Sl = @splat(Q);
                    const zero: Vl = @splat(0);

                    /// Given @Vector(4, i16), returns [ init(v0), init(v1), init(v2), init(v3) ].
                    fn init(value: Sl) @Vector(L, u32) {
                        const one: Sl = @splat(1);
                        const predicate = value < (one - one);
                        const sign = @select(i16, predicate, -one, one);
                        const reduced = sign * @mod(sign * value, Qs);
                        return @intCast(reduced + Qs * @intFromBool(predicate));
                    }

                    fn from(fqs: *const [L]Fq) Self {
                        return .{ .data = @bitCast(fqs.*) };
                    }
                    fn to(a: Self) [L]Fq {
                        return @bitCast(a.data);
                    }

                    fn add(a: Self, b: Self) Self {
                        const s = a.data + b.data;
                        const d, const n: Vl = @subWithOverflow(s, Ql);
                        return .{ .data = d +% (Ql * n) };
                    }
                    fn sub(a: Self, b: Self) Self {
                        return a.add(b.neg());
                    }
                    fn neg(a: Self) Self {
                        const r = Ql - a.data;
                        return .{ .data = r * @intFromBool(a.data != zero) };
                    }
                    fn mul(a: Self, b: Self) Self {
                        return .{ .data = (a.data * b.data) % Ql };
                    }
                    fn splat(d: Fq) Self {
                        return .{ .data = @splat(d.data) };
                    }
                };
            }

            pub fn init(value: i16) Fq {
                const sign: i16 = if (value < 0) -1 else 1;
                const reduced = sign * @mod(sign * value, Q);
                return .{ .data = @intCast(reduced + Q * @as(i16, @intFromBool(value < 0))) };
            }

            fn add(a: Fq, b: Fq) Fq {
                const s = a.data + b.data;
                const d, const n: u32 = @subWithOverflow(s, Q);
                const r = d +% (Q * n);
                return .{ .data = r };
            }
            fn sub(a: Fq, b: Fq) Fq {
                return a.add(b.neg());
            }
            fn neg(a: Fq) Fq {
                const r = Q - a.data;
                return .{ .data = r * @intFromBool(a.data != 0) };
            }
            fn mul(a: Fq, b: Fq) Fq {
                return .{ .data = (a.data * b.data) % Q };
            }

            fn balanced(a: Fq) i16 {
                const value: i16 = @intCast(a.data);
                const g: i16 = @intFromBool(value > Q / 2);
                return value - Q * g;
            }
        };

        const Complex = struct {
            re: f64,
            im: f64,

            /// Precomputes the powers of $\psi$ in the complex space.
            ///
            /// A nice property of computing primitive roots in $\mathbb{C}$
            /// is that instead of needing to search for it, like we did in the
            /// finite field version, we get it for free in:
            /// $\psi = e^{\frac{i\pi}{N}}$
            ///
            /// We find the powers of $\psi$ with Euler's Formula:
            /// $$\psi^k = \cos\left(\frac{\pi k}{N}\right) + i \sin\left(\frac{\pi k}{N}\right)$$
            ///
            /// Remember that the n-th root of unity is a complex number $\omega$
            /// such that:
            /// $\omega^n = 1$
            ///
            /// All such roots are:
            /// $$\omega_k = e^{\frac{2\pi i k}{n}}, k = 0,1,\ldots,n - 1$$
            ///
            /// A primitive n-th root is one whose powers generate all n roots.
            /// We usually pick:
            /// $\omega = e^{\frac{2\pi i}{N}}$
            ///
            /// When we perform negacyclic FFT (like NTRU does), instead of
            /// evaluating at n-th roots of unity, we use 2N-th roots, and so we get:
            /// $\psi = e^{\frac{i\pi}{N}}$
            ///
            /// Then because:
            /// $\psi^N = e^{i \pi} = -1$
            /// our transformations are modulo $x^N + 1$, and we evalate polynomials at:
            /// $\psi^{2k + 1}, k = 0,\ldots, N - 1$
            const precompute = struct {
                const positive = powers(psi);
                const ninv = Complex.init(1.0 / @as(f64, N), 0.0);

                /// $\psi = e^{\frac{i\pi}{N}}$ (primitive 2N-th root of unity)
                const psi: Complex = psi: {
                    const theta = std.math.pi / @as(f64, N);
                    break :psi .init(@cos(theta), @sin(theta));
                };

                fn reverse(x: u64) u64 {
                    return @bitReverse(x) >> (64 - logn);
                }

                fn powers(x: Complex) [N]Complex {
                    @setEvalBranchQuota(10_000);
                    var out: [N]Complex = undefined;
                    var cur = Complex.init(1.0, 0.0);
                    out[reverse(0)] = cur;
                    for (1..N) |i| {
                        cur = Complex.mul(cur, x);
                        out[reverse(i)] = cur;
                    }
                    return out;
                }
            };

            fn Vector(L: u32) type {
                return struct {
                    re: V,
                    im: V,

                    const V = @Vector(L, f64);
                    const Self = @This();

                    fn from(c: *const [L]Complex) Self {
                        var re: V = undefined;
                        var im: V = undefined;
                        inline for (0..L) |i| {
                            re[i] = c[i].re;
                            im[i] = c[i].im;
                        }
                        return .{ .re = re, .im = im };
                    }
                    fn to(a: Self) [L]Complex {
                        var out: [L]Complex = undefined;
                        inline for (0..L) |i| {
                            out[i] = .{ .re = a.re[i], .im = a.im[i] };
                        }
                        return out;
                    }

                    fn add(a: Self, b: Self) Self {
                        return .{ .re = a.re + b.re, .im = a.im + b.im };
                    }
                    fn sub(a: Self, b: Self) Self {
                        return .{ .re = a.re - b.re, .im = a.im - b.im };
                    }
                    fn mul(a: Self, b: Self) Self {
                        const re = a.re * b.re - a.im * b.im;
                        const im = a.re * b.im + a.im * b.re;
                        return .{ .re = re, .im = im };
                    }

                    fn splat(c: Complex) Self {
                        return .{ .re = @splat(c.re), .im = @splat(c.im) };
                    }
                };
            }

            fn init(re: f64, im: f64) Complex {
                return .{ .re = re, .im = im };
            }

            /// (a + ib) + (c + id) == (a + c) + i (b + d)
            fn add(a: Complex, b: Complex) Complex {
                return .{ .re = a.re + b.re, .im = a.im + b.im };
            }
            /// (a + ib) - (c + id) == (a - c) + i (b - d)
            fn sub(a: Complex, b: Complex) Complex {
                return .{ .re = a.re - b.re, .im = a.im - b.im };
            }
            /// (a + ib) * (c + id) == (a*c - b*d) + i (a*d + b*c)
            fn mul(a: Complex, b: Complex) Complex {
                const re = a.re * b.re - a.im * b.im;
                const im = a.re * b.im + a.im * b.re;
                return .{ .re = re, .im = im };
            }
            /// (a + ib) / (c + id) == [(a + ib) * (c - id)] / (c*c + d*d)
            fn div(a: Complex, b: Complex) Complex {
                const norm_sqr = b.normSquare();
                const re = a.re * b.re + a.im * b.im;
                const im = a.im * b.re - a.re * b.im;
                return .{ .re = re / norm_sqr, .im = im / norm_sqr };
            }
            fn mulScalar(a: Complex, b: f64) Complex {
                return .{ .re = a.re * b, .im = a.im * b };
            }
            /// Returns the square of the norm. (re^2 + im^2).
            fn normSquare(c: Complex) f64 {
                return c.re * c.re + c.im * c.im;
            }

            fn conj(c: Complex) Complex {
                return .{ .re = c.re, .im = -c.im };
            }
        };

        fn Polynomial(length: comptime_int, T: type) type {
            return struct {
                coeff: [length]T,

                const Self = @This();
                comptime {
                    std.debug.assert(length < 4096);
                }

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

                /// NOTE: Performs Hadamard multiplication, not a convolutional.
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
                            const s = T.precompute.positive[m + i];
                            const distance = (j2 + 1) - j1;
                            switch (distance) {
                                inline 512, 256, 128, 64, 32, 16, 8, 4, 2, 1 => |d| {
                                    // We'll never hit the 512 element case in Falcon512.
                                    if (N == 512 and d == 512) unreachable;

                                    const Fv = T.Vector(d);
                                    const u: Fv = .from(a[j1..][0..d]);
                                    const v = Fv.from(a[j1 + t ..][0..d]).mul(.splat(s));
                                    a[j1..][0..d].* = u.add(v).to();
                                    a[j1 + t ..][0..d].* = u.sub(v).to();
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
                            const s = T.precompute.negative[h + i];
                            const distance = (j2 + 1) - j1;
                            switch (distance) {
                                inline 512, 256, 128, 64, 32, 16, 8, 4, 2, 1 => |d| {
                                    // We'll never hit the 512 element case in Falcon512.
                                    if (N == 512 and d == 512) unreachable;

                                    const Fv = T.Vector(d);
                                    const u: Fv = .from(a[j1..][0..d]);
                                    const v: Fv = .from(a[j1 + t ..][0..d]);
                                    a[j1..][0..d].* = u.add(v).to();
                                    a[j1 + t ..][0..d].* = (u.sub(v)).mul(.splat(s)).to();
                                },
                                else => unreachable,
                            }
                            // j1 = j1 + 2t
                            j1 += 2 * t;
                        }
                        t <<= 1;
                        m /= 2;
                    }

                    // a[j] = a[j] * n^-1 mod q
                    const ninv = T.precompute.ninv;
                    for (&a) |*aj| {
                        aj.* = aj.mul(ninv);
                    }

                    return .{ .coeff = a };
                }

                fn l2NormSquared(p: Self) f64 {
                    var sum: f64 = 0.0;
                    for (p.coeff) |coeff| {
                        const value: f64 = @floatFromInt(coeff);
                        sum += (value * value);
                    }
                    return sum;
                }

                fn inverse(p: Self) Self {
                    var new: Self = undefined;
                    for (&new.coeff, p.coeff) |*a, b| {
                        a.* = Complex.init(1.0, 0.0).div(b);
                    }
                    return new;
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
                // NOTE: LLVM vectorizes this quite well, no extra work needed.
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
        pub fn hashToPoint(msg: []const u8, r: *const [40]u8) Polynomial(N, Fq) {
            const K = (1 << 16) / Q; // K <- ⌊2^16 / Q⌋
            const lanes = 16;

            var state: Shake256 = .init(.{});
            state.update(r);
            state.update(msg);

            // We can amortize the cost of the shake by sampling many bytes at once,
            // allowing parallel Keccak, instead of just pulling 2 bytes per round.
            var sample: [128]u8 = undefined;
            var offset: usize = sample.len;

            // Worst case is that we're at N - 1 elements filled, and we will
            // then keep resampling S.lanes elements until mask > 0.
            var coeffs: [N + lanes]Fq = undefined;
            var i: u32 = 0;
            while (i < N) {
                if (offset >= sample.len) {
                    state.squeeze(&sample);
                    offset = 0;
                }

                if (comptime builtin.zig_backend == .stage2_llvm and
                    builtin.cpu.arch == .x86_64 and
                    builtin.cpu.has(.x86, .avx512f) and
                    // It only makes sense to use the vpcompress strategy on targets like Zen 5
                    // where the performance of vpcompressd isn't hundreds of cycles (like it is on Zen 4).
                    builtin.cpu.model != &std.Target.x86.cpu.znver4)
                {
                    const V = @Vector(lanes, u32);
                    const Fv = Fq.Vector(lanes);
                    const Mask = std.meta.Int(.unsigned, lanes);
                    const Kv: V = @splat(K * Q);

                    var batch: V = undefined;
                    inline for (0..lanes) |j| {
                        const idx = offset + j * 2;
                        batch[j] = (@as(u32, sample[idx]) << 8) | sample[idx + 1];
                    }

                    const mask: Mask = @bitCast(batch < Kv);
                    const compressed = asm ("vpcompressd %[dst], %[src] {%[k]} {z}"
                        : [dst] "=v" (-> V),
                        : [src] "v" (batch),
                          [k] "^Yk" (mask),
                    );
                    coeffs[i..][0..lanes].* = @bitCast(Fv.init(@intCast(compressed % Fv.Ql)));
                    offset += lanes * 2;
                    i += @popCount(mask);
                } else {
                    const t = (@as(u32, sample[offset]) << 8) | sample[offset + 1];
                    offset += 2;
                    if (t < K * Q) {
                        coeffs[i] = .init(@intCast(t % Q));
                        i += 1;
                    }
                }
            }

            return .{ .coeff = @bitCast(coeffs[0..N].*) };
        }

        const NtruGen = struct {
            f: Polynomial(N, i16),
            g: Polynomial(N, i16),
            F: Polynomial(N, i16),
            G: Polynomial(N, i16),
        };

        /// Samples 4 polynomials f, g, F, G such that  f * G - g * F = q mod (X^n + 1).
        ///
        /// Algorithm 5 from https://falcon-sign.info/falcon.pdf.
        fn ntruGen() NtruGen {
            loop: while (true) {
                const f = generate();
                const g = generate();

                // Ensure f is invertable mod q
                const f_ntt = f.toField().fft();
                for (f_ntt.coeff) |coeff| if (coeff.data == 0) continue :loop;

                const gamma = granSchmidtNormSquared(&f, &g);
                _ = gamma;
            }
        }

        /// Compute the Gram-Schmidt norm of B = [[g, -f], [G, -F]] from f and g.
        fn granSchmidtNormSquared(f: *const Polynomial(N, i16), g: *const Polynomial(N, i16)) f64 {
            const C = Polynomial(N, Complex);

            // ||(g, -f)||
            const norm_f_squared = f.l2NormSquared();
            const norm_g_squared = g.l2NormSquared();
            const gamma1 = norm_f_squared + norm_g_squared;

            // ||(qf* / (ff* + gg*), qg* / (ff* + gg*))||
            var f_fft: C = undefined;
            var g_fft: C = undefined;
            for (f.coeff, g.coeff, 0..) |a, b, i| {
                f_fft.coeff[i] = .init(@floatFromInt(a), 0.0);
                g_fft.coeff[i] = .init(@floatFromInt(b), 0.0);
            }
            f_fft = f_fft.fft();
            g_fft = g_fft.fft();

            var f_adj: C = undefined;
            var g_adj: C = undefined;
            for (f_fft.coeff, g_fft.coeff, 0..) |a, b, i| {
                f_adj.coeff[i] = a.conj();
                g_adj.coeff[i] = b.conj();
            }

            const ffgg = f_fft.mul(f_adj).add(g_fft.mul(g_adj));
            const ffgg_inverse = ffgg.inverse();

            var qf_over_ffgg: C = undefined;
            var qg_over_ffgg: C = undefined;
            for (&qf_over_ffgg.coeff, &qg_over_ffgg.coeff, 0..) |*a, *b, i| {
                a.* = f_adj.coeff[i].mulScalar(Q);
                b.* = g_adj.coeff[i].mulScalar(Q);
            }

            var norm_f_over_ffgg_squared: f64 = 0.0;
            var norm_g_over_ffgg_squared: f64 = 0.0;
            for (qf_over_ffgg.mul(ffgg_inverse).coeff, qg_over_ffgg.mul(ffgg_inverse).coeff) |a, b| {
                norm_f_over_ffgg_squared += a.mul(a.conj()).re;
                norm_g_over_ffgg_squared += b.mul(b.conj()).re;
            }
            const gamma2 = (norm_f_over_ffgg_squared / N) + (norm_g_over_ffgg_squared / N);

            return @max(gamma1, gamma2);
        }

        /// Generate a polynomial of degree at most (N - 1), with coefficients
        /// following a discrete Gaussian distribution $D_{Z, 0, sigma}$ with
        /// sigma = 1.17 * sqrt(Q / (2 * N)).
        fn generate() Polynomial(N, i16) {
            const rng = std.crypto.random;
            const mu = 0.0;
            const sigma_star = 1.17 * @sqrt(12289.0 / 8192.0);
            var f0: [4096]i16 = undefined;
            for (&f0) |*o| o.* = sampler.samplerz(
                mu,
                sigma_star,
                sigma_star - 0.001,
                rng,
            );
            var f: [N]i16 = @splat(0);
            const k = 4096 / N;
            for (0..N) |i| {
                var sum: i16 = 0;
                for (0..k) |j| sum += f0[i * k + j];
                f[i] = sum;
            }
            return .{ .coeff = f };
        }
    };
}

test {
    _ = @import("falcon/test.zig");
    _ = @import("falcon/samplerz.zig");
}

test "gs norm" {
    const P = Falcon512.Polynomial(512, i16);
    var f: P = undefined;
    var g: P = undefined;
    for (0..512) |i| {
        f.coeff[i] = @intCast(i % 5);
        g.coeff[i] = @as(i16, @intCast(i % 7)) - 4;
    }
    const norm_squared = Falcon512.granSchmidtNormSquared(&f, &g);
    try std.testing.expectApproxEqRel(5992556.183229722, norm_squared, 0.00001);
}
