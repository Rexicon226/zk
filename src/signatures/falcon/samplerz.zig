const std = @import("std");

/// Sample an integer from {0, ..., 18} according to the distribution χ, which
/// is close to the half-Gaussian distribution on the natural numbers with mean
/// 0 and standard deviation equal to sigma_max.
///
/// https://falcon-sign.info/falcon.pdf, Algorithm 12.
fn baseSampler(rng: std.Random) i16 {
    const RCDT: [18]u128 = .{
        3024686241123004913666,
        1564742784480091954050,
        636254429462080897535,
        199560484645026482916,
        47667343854657281903,
        8595902006365044063,
        1163297957344668388,
        117656387352093658,
        8867391802663976,
        496969357462633,
        20680885154299,
        638331848991,
        14602316184,
        247426747,
        3104126,
        28824,
        198,
        1,
    };

    var bytes: [72 / 8]u8 = undefined;
    rng.bytes(&bytes);
    // NOTE: if this bswap is too expensive, we can remove it, but this
    // is what the Falcon reference implementation does, so we need it for KATs.
    const u = std.mem.readInt(u72, &bytes, .big);
    var z0: u8 = 0;
    for (RCDT) |r| z0 += @intFromBool(u < r);
    return z0;
}

/// Compute an integer approximation of 2^63 * ccs * exp(-x).
///
/// https://falcon-sign.info/falcon.pdf, Algorithm 13.
///
/// Requires $x \in [0, ln(2)]$ and $ccs \in [0, 1]$.
fn approxExp(x: f64, ccs: f64) u64 {
    std.debug.assert(ccs >= 0.0 and ccs <= 1.0);
    std.debug.assert(x >= 0.0 and x <= std.math.ln2);

    // These constants are taken from FACCT (up to a scaling factor of 2^63):
    // https://eprint.iacr.org/2018/1234
    const C: [13]u64 = .{
        0x00000004741183A3,
        0x00000036548CFC06,
        0x0000024FDCBF140A,
        0x0000171D939DE045,
        0x0000D00CF58F6F84,
        0x000680681CF796E3,
        0x002D82D8305B0FEA,
        0x011111110E066FD0,
        0x0555555555070F00,
        0x155555555581FF00,
        0x400000000002B400,
        0x7FFFFFFFFFFF4800,
        0x8000000000000000,
    };

    // NOTE: y and z remain in [0, 2^63) for the whole algorithm.
    var y: u64 = C[0];
    var z: u64 = @intFromFloat((1 << 63) * x); // z ← ⌊2^63 · x⌋
    for (1..13) |u| {
        const zy = (@as(u128, z) * y) >> 63; // (z * y) fits into 126 bits, but we only need the top 63
        y = C[u] - @as(u64, @intCast(zy));
    }
    z = @intFromFloat((1 << 63) * ccs);
    return @truncate((@as(u128, z) * y) >> 63);
}

/// A random bool that is true with probability ≈ ccs · exp(−x).
///
/// https://falcon-sign.info/falcon.pdf, Algorithm 14.
///
/// Requires $x, ccs \gte 0$.
fn berExp(x: f64, ccs: f64, rng: std.Random) bool {
    std.debug.assert(x >= 0.0);
    std.debug.assert(ccs >= 0.0);
    const ln2 = std.math.ln2;

    const s: u64 = @intFromFloat(x / ln2);
    const r = x - @as(f64, @floatFromInt(s)) * ln2;
    //  z ≈ 2^{64−s} * ccs * exp(-r) = 2^{64} * ccs * exp(-r)
    const z: u64 = @intCast((2 * @as(u128, approxExp(r, ccs)) - 1) >> @min(s, 63));

    var i: u64 = 64;
    var w: i16 = 0;
    while (true) {
        i -= 8;
        w = @as(i16, rng.int(u8)) - @as(i16, @intCast((z >> @intCast(i)) & 0xFF));
        if (w != 0 or i == 0) break;
    }
    return w < 0;
}

// 3.13  Recommended Parameters
// - σ_max 1.8205
const sigma_max: f64 = 1.8205;
const inv_2sigma: f64 = 1.0 / (2.0 * sigma_max * sigma_max);

/// Sample an integer from the Gaussian distribution with given mean (mu) and standard deviation (sigma).
///
/// https://falcon-sign.info/falcon.pdf, Algorithm 15.
pub fn samplerz(mu: f64, sigma: f64, sigma_min: f64, rng: std.Random) i16 {
    std.debug.assert(sigma >= sigma_min and sigma <= sigma_max);
    const s = @floor(mu);
    const r = mu - s;
    const dss = 1 / (2 * sigma * sigma);
    const ccs = sigma_min / sigma;
    while (true) {
        const z0 = baseSampler(rng);
        const b: i16 = rng.int(u8) & 0x1;
        const z = b + (2 * b - 1) * z0;
        const zr = @as(f64, @floatFromInt(z)) - r;
        const left = std.math.pow(f64, zr, 2) * dss;
        const x = left - (std.math.pow(f64, @floatFromInt(z0), 2) * inv_2sigma);
        if (berExp(x, ccs, rng)) {
            return z + @as(i16, @intFromFloat(s));
        }
    }
}

// A testing RNG which has a precomputed rng schedule, as given by the test vectors.
const TestingRng = struct {
    bytes: []const u8,
    index: usize = 0,

    fn random(t: *TestingRng) std.Random {
        return .{
            .ptr = t,
            .fillFn = fill,
        };
    }

    fn fill(ctx: *anyopaque, buf: []u8) void {
        const rng: *TestingRng = @ptrCast(@alignCast(ctx));
        @memcpy(buf, rng.bytes[rng.index..][0..buf.len]);
        rng.index += buf.len;
    }
};

test approxExp {
    // These KATs can be reproduced with the following Sage script:
    //```sage
    // num_samples = 10
    // precision = 200
    // R = Reals(precision)
    //
    // print(f"const kats: [{num_samples}]struct {{ f64, f64, u64 }} = .{{")
    // for i in range(num_samples):
    //     x = RDF.random_element(0.0, 0.693147180559945)
    //     ccs = RDF.random_element(0.0, 1.0)
    //     res = round(2^63 * R(ccs) * exp(R(-x)))
    //     print(f"    .{{{x}, {ccs}, {res}}},")
    // print("};")
    // ```
    const precision = 1 << 14;
    const kats: [10]struct { f64, f64, u64 } = .{
        .{ 0.33182126770280423, 0.6861138384268145, 4541274565198145159 },
        .{ 0.3873825411187381, 0.7760534893842211, 4858959540663247764 },
        .{ 0.1280009513353102, 0.4571801982027057, 3710112097161776855 },
        .{ 0.35425758353427705, 0.20040377576586765, 1297010562439123728 },
        .{ 0.0674036050845544, 0.3049620486848702, 2629435424463466483 },
        .{ 0.6651429211116713, 0.5654230257519673, 2681608149733226558 },
        .{ 0.07293323766430207, 0.46100332882498296, 3952931472460456758 },
        .{ 0.16595510945544473, 0.1299224196354719, 1015080391928359517 },
        .{ 0.3078815024474865, 0.3407697772037853, 2310146700120736836 },
        .{ 0.690377107131847, 0.2288690322308946, 1058399904475218443 },
    };
    for (kats) |entry| {
        const x, const ccs, const answer = entry;
        const difference = @as(i128, answer) - approxExp(x, ccs);
        try std.testing.expect(@as(u64, @intCast(difference * difference)) <= precision * precision);
    }
}

test berExp {
    const kats = [_]struct {
        x: f64,
        ccs: f64,
        bytes: []const u8,
        answer: bool,
    }{
        .{ .x = 1.268_314_048_020_498_4, .ccs = 0.749_990_853_267_664_9, .bytes = "ea000000000000", .answer = false },
        .{ .x = 0.001_563_917_959_143_409_6, .ccs = 0.749_990_853_267_664_9, .bytes = "6c000000000000", .answer = true },
        .{ .x = 0.001_563_917_959_143_409_6, .ccs = 0.749_990_853_267_664_9, .bytes = "6c000000000000", .answer = true },
        .{ .x = 0.017_921_215_753_999_235, .ccs = 0.749_990_853_267_664_9, .bytes = "c2000000000000", .answer = false },
        .{ .x = 0.776_117_648_844_980_6, .ccs = 0.751_181_554_542_520_8, .bytes = "58000000000000", .answer = true },
    };
    for (kats) |entry| {
        var buffer: [7]u8 = undefined;
        const bytes = try std.fmt.hexToBytes(&buffer, entry.bytes);
        std.debug.assert(bytes.len == 7);
        var rng: TestingRng = .{ .bytes = bytes };
        const result = berExp(entry.x, entry.ccs, rng.random());
        try std.testing.expectEqual(entry.answer, result);
    }
}

test samplerz {
    const sigma_min = 1.277833697;
    // https://falcon-sign.info/falcon.pdf, Table 3.2, Page 44
    const kats = [_]struct { f64, f64, []const u8, i16 }{
        .{ -91.90471153063714, 1.7037990414754918, "0fc5442ff043d66e91d1eacac64ea5450a22941edc6c", -92 },
        .{ -8.322564895434937, 1.7037990414754918, "f4da0f8d8444d1a77265c2ef6f98bbbb4bee7db8d9b3", -8 },
        .{ -19.096516109216804, 1.7035823083824078, "db47f6d7fb9b19f25c36d6b9334d477a8bc0be68145d", -20 },
        .{ -11.335543982423326, 1.7035823083824078, "ae41b4f5209665c74d00dcc1a8168a7bb516b3190cb42c1ded26cd52aed770eca7dd334e0547bcc3c163ce0b", -12 },
        .{ 7.9386734193997555, 1.6984647769450156, "31054166c1012780c603ae9b833cec73f2f41ca5807cc89c92158834632f9b1555", 8 },
        .{ -28.990850086867255, 1.6984647769450156, "737e9d68a50a06dbbc6477", -30 },
        .{ -9.071257914091655, 1.6980782114808988, "a98ddd14bf0bf22061d632", -10 },
        .{ -43.88754568839566, 1.6980782114808988, "3cbf6818a68f7ab9991514", -41 },
        .{ -58.17435547946095, 1.7010983419195522, "6f8633f5bfa5d26848668e3d5ddd46958e97630410587c", -61 },
        .{ -43.58664906684732, 1.7010983419195522, "272bc6c25f5c5ee53f83c43a361fbc7cc91dc783e20a", -46 },
        .{ -34.70565203313315, 1.7009387219711465, "45443c59574c2c3b07e2e1d9071e6d133dbe32754b0a", -34 },
        .{ -44.36009577368896, 1.7009387219711465, "6ac116ed60c258e2cbaeab728c4823e6da36e18d08da5d0cc104e21cc7fd1f5ca8d9dbb675266c928448059e", -44 },
        .{ -21.783037079346236, 1.6958406126012802, "68163bc1e2cbf3e18e7426", -23 },
        .{ -39.68827784633828, 1.6958406126012802, "d6a1b51d76222a705a0259", -40 },
        .{ -18.488607061056847, 1.6955259305261838, "f0523bfaa8a394bf4ea5c10f842366fde286d6a30803", -22 },
        .{ -48.39610939101591, 1.6955259305261838, "87bd87e63374cee62127fc6931104aab64f136a0485b", -50 },
    };
    for (kats) |entry| {
        // Center, Standard Deviation, randombytes, Output z
        const mu, const sigma, const randombytes, const answer = entry;
        var buffer: [50]u8 = undefined;
        const bytes = try std.fmt.hexToBytes(&buffer, randombytes);
        var rng: TestingRng = .{ .bytes = bytes };
        const result = samplerz(mu, sigma, sigma_min, rng.random());
        try std.testing.expectEqual(answer, result);
    }
}
