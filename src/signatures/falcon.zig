const std = @import("std");
const data = @import("falcon/fft_data.zig");
const sampler = @import("falcon/samplerz.zig");

const Shake256 = std.crypto.hash.sha3.Shake256;

pub const Falcon512 = Falcon(512);

fn Falcon(N: usize) type {
    return struct {
        const logn = std.math.log2(N);
        const bits: enum { nine, ten } = switch (N) {
            512 => .nine,
            1024 => .ten,
            else => @compileError("unsupported falcon signature bit size"),
        };

        /// The integer modulus used in Falcon.
        const Q = 12 * 1024 + 1;

        const sigma = switch (bits) {
            .nine => 165.7366171829776,
            .ten => 168.38857144654395,
        };
        const sigma_min = switch (bits) {
            .nine => 1.2778336969128337,
            .ten => 1.298280334344292,
        };

        pub const PublicKey = struct {
            h: Polynomial(N, Felt),

            const BITS_PER_VALUE = 14;

            pub fn fromBytes(bytes: *const [1 + (14 * N / 8)]u8) !PublicKey {
                // first byte is the header, encoded as
                // 0 0 0 0 n n n n
                // where the leftmost 4 bits are 0
                // and nnnn encodes logn
                const header = bytes[0];
                if (header != logn) return error.InvalidHeader;

                // the rest of the bytes are the public key polynomial
                // each value (in the 0 to Q - 1 range) is encoded as a 14-bit sequence
                // (since Q = 12289, 14 bits per value is used). The encoded value are
                // concatted into a bit sequence of 14N bits, which are represented as 14N / 8 bytes.
                const h = bytes[1..];
                var position: usize = 0;
                var coeff: [N]Felt = undefined;
                for (0..N) |i| {
                    var val: i16 = 0;
                    for (0..BITS_PER_VALUE) |_| {
                        val = (val << 1) | bit(h, position);
                        position += 1;
                    }
                    if (val > Q - 1) return error.InvalidCoeff;
                    coeff[i] = .init(val);
                }
                return .{ .h = .{ .coeff = coeff } };
            }
        };

        pub const Signature = struct {
            /// random salt
            nonce: [40]u8,
            /// compressed s2 polynomial
            s2: []const u8,

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
            /// NOTE: This function *retains* a reference to `bytes`, since we perform
            /// the decompression while verifying, not here.
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
                    .s2 = bytes[41..],
                };
            }
        };

        pub const Felt = struct {
            data: u32,

            pub fn init(value: i16) Felt {
                const gtz_bool = value >= 0;
                const gtz_int: i16 = @intFromBool(gtz_bool);
                const gtz_sign = gtz_int - @intFromBool(!gtz_bool);
                const reduced = gtz_sign * @mod(gtz_sign * value, Q);
                const canon: u32 = @intCast(reduced + Q * (1 - gtz_int));
                return .{ .data = canon };
            }

            fn add(a: Felt, b: Felt) Felt {
                const s = a.data +% b.data;
                const d, const n = @subWithOverflow(s, Q);
                const r = d +% (Q * @as(u32, n));
                return .{ .data = r };
            }
            fn sub(a: Felt, b: Felt) Felt {
                return a.add(b.neg());
            }
            fn neg(a: Felt) Felt {
                const r = Q - a.data;
                return .{ .data = r * @intFromBool(a.data != 0) };
            }
            fn mul(a: Felt, b: Felt) Felt {
                return .{ .data = (a.data * b.data) % Q };
            }

            fn balanced(a: Felt) i16 {
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

                /// Generate a polynomial of degree at most (n - 1), with coefficients
                /// following a discrete Gaussian distribution D_{Z, 0, sigma} with
                /// sigma = 1.17 * sqrt(q / (2 * n)).
                pub fn generate() Self {
                    comptime std.debug.assert(T == i16);

                    const rng = std.crypto.random;
                    const mu = 0.0;
                    // 1.17 * sqrt(12289 / 8192)
                    const sigma_star = 1.43300980528773;
                    var f0: [4096]i16 = undefined;
                    for (&f0) |*o| o.* = sampler.samplerz(
                        mu,
                        sigma_star,
                        sigma_star - 0.001,
                        rng,
                    );
                    var f: [length]i16 = @splat(0);
                    const k = 4096 / length;
                    for (0..length) |i| {
                        var sum: i16 = 0;
                        for (0..k) |j| sum += f0[i * k + j];
                        f[i] = sum;
                    }
                    return .{ .coeff = f };
                }

                fn toField(a: Self) Polynomial(length, Felt) {
                    comptime std.debug.assert(T == i16);
                    var coeff: [length]Felt = undefined;
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
                fn hadamardMul(a: Self, b: Self) Self {
                    var out: [length]T = undefined;
                    for (&out, a.coeff, b.coeff) |*o, x, y| {
                        o.* = x.mul(y);
                    }
                    return .{ .coeff = out };
                }

                fn fft(p: Self) Self {
                    const psir = switch (T) {
                        Felt => data.BITREVERSED_POWERS,
                        else => @compileError("TODO"),
                    };
                    var coeff = p.coeff; // copy, since we'll be modifying
                    var t: usize = length;
                    var m: usize = 1;
                    while (m < length) {
                        t >>= 1;
                        for (0..m) |i| {
                            const j1 = 2 * i * t;
                            const j2 = j1 + t - 1;
                            const s = psir[m + i];
                            for (j1..j2 + 1) |j| {
                                const u = coeff[j];
                                const v = coeff[j + t].mul(s);
                                coeff[j] = u.add(v);
                                coeff[j + t] = u.sub(v);
                            }
                        }
                        m <<= 1;
                    }
                    return .{ .coeff = coeff };
                }
                fn ifft(p: Self) Self {
                    const ninv: Felt = .init(switch (bits) {
                        .nine => 12265,
                        .ten => 12277,
                    });
                    const psiir = switch (T) {
                        Felt => data.BITREVSERED_POWERS_INVERSE,
                        else => @compileError("TODO"),
                    };
                    var coeff = p.coeff;
                    var t: usize = 1;
                    var m: usize = length;
                    while (m > 1) {
                        const h = m / 2;
                        var j1: usize = 0;
                        for (0..h) |i| {
                            const j2 = j1 + t - 1;
                            const s = psiir[h + i];
                            for (j1..j2 + 1) |j| {
                                const u = coeff[j];
                                const v = coeff[j + t];
                                coeff[j] = u.add(v);
                                coeff[j + t] = (u.sub(v)).mul(s);
                            }
                            j1 += 2 * t;
                        }
                        t <<= 1;
                        m >>= 1;
                    }
                    for (&coeff) |*a| {
                        a.* = a.mul(ninv);
                    }
                    return .{ .coeff = coeff };
                }
            };
        }

        pub fn verify(msg: []const u8, sig: Signature, pk: PublicKey) !void {
            const c = hashToPoint(msg, &sig.nonce);
            const s2 = try decompress(sig.s2);

            const s2_ntt = s2.toField().fft();
            const h_ntt = pk.h.fft();
            const c_ntt = c.fft();

            // s1 = c - s2 * pk.h;
            const s1_ntt = c_ntt.sub(s2_ntt.hadamardMul(h_ntt));
            const s1 = s1_ntt.ifft();

            var length_squared: i64 = 0;
            for (s1.coeff, s2.coeff) |i, j| {
                const value: i64 = i.balanced();
                length_squared += (value * value);
                length_squared += @as(i64, j) * j;
            }
            const bound = switch (bits) {
                .nine => 34034726,
                .ten => 70265242,
            };
            if (length_squared >= bound) return error.InvalidBound;
        }

        fn bit(bytes: []const u8, position: usize) u1 {
            const byte = position / 8;
            const idx = 7 - (position & 7);
            return @intCast((bytes[byte] >> @intCast(idx)) & 1);
        }

        fn decompress(s2: []const u8) !Polynomial(N, i16) {
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
                out[i] = sign * ((high_bits << 7) | low_bits);
            }
            return .{ .coeff = out };
        }

        fn hashToPoint(msg: []const u8, r: *const [40]u8) Polynomial(N, Felt) {
            const K = (1 << 16) / Q;

            var state: Shake256 = .init(.{});
            state.update(r);
            state.update(msg);

            var i: u32 = 0;
            var coeffs: [N]Felt = undefined;
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
}
