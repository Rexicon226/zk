const std = @import("std");
const stdx = @import("stdx");

const ed25519 = @import("../curves/ed25519.zig");

const Edwards25519 = std.crypto.ecc.Edwards25519;
const Signature = std.crypto.sign.Ed25519.Signature;
const Pubkey = std.crypto.sign.Ed25519.PublicKey;
const Sha512 = std.crypto.hash.sha2.Sha512;
const CompressedScalar = [32]u8;

// TODO: verify batch of messages, generic

/// Verifies multiple signatures over the same message. The behaviour of this function
/// matches calling ed25519-dalek's `verify` (*not* `verify_strict`) in a loop over the messages.
pub fn verifyBatchOverSingleMessage(
    max: comptime_int,
    signatures: []const Signature,
    public_keys: []const Pubkey,
    message: []const u8,
) !void {
    std.debug.assert(signatures.len <= max);
    std.debug.assert(public_keys.len <= max);
    std.debug.assert(signatures.len == public_keys.len);

    var s_batch: stdx.BoundedArray(CompressedScalar, max) = .{};
    var a_batch: stdx.BoundedArray(Edwards25519, max) = .{};
    var hram_batch: stdx.BoundedArray(CompressedScalar, max) = .{};
    var expected_r_batch: stdx.BoundedArray(Edwards25519, max) = .{};

    for (signatures, public_keys) |signature, pubkey| {
        const r = signature.r;
        const s = signature.s;

        try Edwards25519.scalar.rejectNonCanonical(s);

        const a = try Edwards25519.fromBytes(pubkey.toBytes());
        const expected_r = try Edwards25519.fromBytes(r);

        try affineLowOrder(a);
        try affineLowOrder(expected_r);

        var h = Sha512.init(.{});
        h.update(&r);
        h.update(&pubkey.bytes);
        h.update(message);
        var hram64: [Sha512.digest_length]u8 = undefined;
        h.final(&hram64);

        expected_r_batch.appendAssumeCapacity(expected_r);
        s_batch.appendAssumeCapacity(s);
        a_batch.appendAssumeCapacity(a);
        hram_batch.appendAssumeCapacity(Edwards25519.scalar.reduce64(hram64));
    }

    for (
        a_batch.constSlice(),
        hram_batch.constSlice(),
        s_batch.constSlice(),
        expected_r_batch.constSlice(),
    ) |a, k, s, expected_r| {
        const r = ed25519.doubleBaseMul(k, a.neg(), s);
        if (!affineEqual(r, expected_r)) return error.InvalidSignature;
    }
}

/// See the doc-comment above `verifyBatchOverSingleMessage` for further detail,
/// but this is that same thing, just for single messages, and with the ability to toggle
/// between ed25519-dalek's `verify` and `verify_strict` semantics.
pub fn verifySignature(
    signature: Signature,
    pubkey: Pubkey,
    message: []const u8,
    strict: bool,
) !void {
    const s = signature.s;
    const r = signature.r;
    try Edwards25519.scalar.rejectNonCanonical(s);

    const a = try Edwards25519.fromBytes(pubkey.bytes);
    const expected_r = try Edwards25519.fromBytes(r);

    if (strict) {
        try affineLowOrder(a);
        try affineLowOrder(expected_r);
    }

    var h = Sha512.init(.{});
    h.update(&r);
    h.update(&pubkey.bytes);
    h.update(message);
    var hram64: [Sha512.digest_length]u8 = undefined;
    h.final(&hram64);

    const computed = ed25519.doubleBaseMul(Edwards25519.scalar.reduce64(hram64), a.neg(), s);
    if (!affineEqual(computed, expected_r)) return error.InvalidSignature;
}

/// Equate two ed25519 points with the assumption that b.z is 1.
/// b.z == 1 is common when we have just deserialized a point from the wire
pub fn affineEqual(a: Edwards25519, b: Edwards25519) bool {
    const x1 = b.x.mul(a.z);
    const y1 = b.y.mul(a.z);
    return x1.equivalent(a.x) and y1.equivalent(a.y);
}

/// Determines whether `a` is of small order (in the torision subgroup E[8]), but with the
/// assumption that `a.Z == 1`.
///
/// There are 8 points with an order <= 8:
/// ```ascii
/// Order | Point                   | Serialize Point
/// 1       (0,         1)            0100000000000000000000000000000000000000000000000000000000000000
/// 2       (0,         2^255 - 20)   ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
/// 4       (-sqrt(-1), 0)            0000000000000000000000000000000000000000000000000000000000000080
/// 4       (sqrt(-1),  0)            0000000000000000000000000000000000000000000000000000000000000000
/// 8       ...                       c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a
/// 8       ...                       c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa
/// 8       ...                       26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05
/// 8       ...                       26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85
///```
/// Since in this function we know that Z will be 1, we don't need to perform any
/// normalization to cancel out the projective denominator, instead just directly performing
/// checks on the x,y coordinates. You'll notice that low-order points when negated still
/// retain their low-order nature, so there are 4 "pairs" of low order points. This means
/// just checking a single coordinate of the point is enough to determine if it's in the blacklist,
/// meaning we only need 4 equivalence checks to cover all of the pairs.
pub fn affineLowOrder(a: Edwards25519) !void {
    // y coordinate of points 5 and 6
    const y0: Edwards25519.Fe = .{ .limbs = .{
        0x4d3d706a17c7,
        0x1aec1679749fb,
        0x14c80a83d9c40,
        0x3a763661c967d,
        0x7a03ac9277fdc,
    } };
    // y coordinate of points 7 and 8
    const y1: Edwards25519.Fe = .{ .limbs = .{
        0x7b2c28f95e826,
        0x6513e9868b604,
        0x6b37f57c263bf,
        0x4589c99e36982,
        0x5fc536d88023,
    } };

    if (a.x.isZero() // first pair
    or a.y.isZero() // second pair
    or a.y.equivalent(y0) // third pair
    or a.y.equivalent(y1) // fourth pair
    ) return error.WeakPublicKey;
}

test "eddsa test cases" {
    const Vec = struct {
        msg_hex: []const u8,
        public_key_hex: *const [64:0]u8,
        sig_hex: *const [128:0]u8,
        expected: ?anyerror,
    };

    // Entries based off of ed25519-dalek 2.0 `verify_strict`. Dalek sometimes returns slightly
    // different types of errors, due to differences in the order of input parsing, but the
    // main factor we care about is whether or not it accepts the signature.
    // sig fmt: off
    const entries = [_]Vec{
        Vec{
            .msg_hex = "8c93255d71dcab10e8f379c26200f3c7bd5f09d9bc3068d3ef4edeb4853022b6",
            .public_key_hex = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            .sig_hex = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a0000000000000000000000000000000000000000000000000000000000000000",
            .expected = error.WeakPublicKey, // 0
        },
        Vec{
            .msg_hex = "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
            .public_key_hex = "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
            .sig_hex = "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43a5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
            .expected = error.WeakPublicKey, // 1
        },
        Vec{
            .msg_hex = "48656c6c6f",
            .public_key_hex = "7d4d0e7f6153a69b6242b522abbee685fda4420f8834b108c3bdae369ef549fa",
            .sig_hex = "1c1ad976cbaae3b31dee07971cf92c928ce2091a85f5899f5e11ecec90fc9f8e93df18c5037ec9b29c07195ad284e63d548cd0a6fe358cc775bd6c1608d2c905",
            .expected = null,
        },
        Vec{
            .msg_hex = "9bd9f44f4dcc75bd531b56b2cd280b0bb38fc1cd6d1230e14861d861de092e79",
            .public_key_hex = "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
            .sig_hex = "9046a64750444938de19f227bb80485e92b83fdb4b6506c160484c016cc1852f87909e14428a7a1d62e9f22f3d3ad7802db02eb2e688b6c52fcd6648a98bd009",
            .expected = null, // 3 - mixed orders
        },
        Vec{
            .msg_hex = "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
            .public_key_hex = "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
            .sig_hex = "160a1cb0dc9c0258cd0a7d23e94d8fa878bcb1925f2c64246b2dee1796bed5125ec6bc982a269b723e0668e540911a9a6a58921d6925e434ab10aa7940551a09",
            .expected = error.InvalidSignature, // 4 - cofactored verification
        },
        Vec{
            .msg_hex = "e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec4011eaccd55b53f56c",
            .public_key_hex = "cdb267ce40c5cd45306fa5d2f29731459387dbf9eb933b7bd5aed9a765b88d4d",
            .sig_hex = "21122a84e0b5fca4052f5b1235c80a537878b38f3142356b2c2384ebad4668b7e40bc836dac0f71076f9abe3a53f9c03c1ceeeddb658d0030494ace586687405",
            .expected = error.InvalidSignature, // 5 - cofactored verification
        },
        Vec{
            .msg_hex = "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
            .public_key_hex = "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
            .sig_hex = "e96f66be976d82e60150baecff9906684aebb1ef181f67a7189ac78ea23b6c0e547f7690a0e2ddcd04d87dbc3490dc19b3b3052f7ff0538cb68afb369ba3a514",
            .expected = error.NonCanonical, // 6 - S > L
        },
        Vec{
            .msg_hex = "85e241a07d148b41e47d62c63f830dc7a6851a0b1f33ae4bb2f507fb6cffec40",
            .public_key_hex = "442aad9f089ad9e14647b1ef9099a1ff4798d78589e66f28eca69c11f582a623",
            .sig_hex = "8ce5b96c8f26d0ab6c47958c9e68b937104cd36e13c33566acd2fe8d38aa19427e71f98a473474f2f13f06f97c20d58cc3f54b8bd0d272f42b695dd7e89a8c22",
            .expected = error.NonCanonical, // 7 - S >> L
        },
        Vec{
            .msg_hex = "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
            .public_key_hex = "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
            .sig_hex = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff03be9678ac102edcd92b0210bb34d7428d12ffc5df5f37e359941266a4e35f0f",
            .expected = error.WeakPublicKey, // 8 - non-canonical R
        },
        Vec{
            .msg_hex = "9bedc267423725d473888631ebf45988bad3db83851ee85c85e241a07d148b41",
            .public_key_hex = "f7badec5b8abeaf699583992219b7b223f1df3fbbea919844e3f7c554a43dd43",
            .sig_hex = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffca8c5b64cd208982aa38d4936621a4775aa233aa0505711d8fdcfdaa943d4908",
            .expected = error.WeakPublicKey, // 9 - non-canonical R
        },
        Vec{
            .msg_hex = "e96b7021eb39c1a163b6da4e3093dcd3f21387da4cc4572be588fafae23c155b",
            .public_key_hex = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            .sig_hex = "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
            .expected = error.WeakPublicKey, // 10 - small-order A
        },
        Vec{
            .msg_hex = "39a591f5321bbe07fd5a23dc2f39d025d74526615746727ceefd6e82ae65c06f",
            .public_key_hex = "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            .sig_hex = "a9d55260f765261eb9b84e106f665e00b867287a761990d7135963ee0a7d59dca5bb704786be79fc476f91d3f3f89b03984d8068dcf1bb7dfc6637b45450ac04",
            .expected = error.WeakPublicKey, // 11 - small-order A
        },
    };
    // sig fmt: on

    for (entries) |entry| {
        var msg: [64 / 2]u8 = undefined;
        const msg_len = entry.msg_hex.len / 2;
        _ = try std.fmt.hexToBytes(msg[0..msg_len], entry.msg_hex);
        var public_key_bytes: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&public_key_bytes, entry.public_key_hex);
        var sig_bytes: [64]u8 = undefined;
        _ = try std.fmt.hexToBytes(&sig_bytes, entry.sig_hex);

        const public_key: Pubkey = try .fromBytes(public_key_bytes);
        const signature: Signature = .fromBytes(sig_bytes);

        const result = verifyBatchOverSingleMessage(
            1,
            &.{signature},
            &.{public_key},
            msg[0..msg_len],
        );

        if (entry.expected) |error_type| {
            try std.testing.expectError(error_type, result);
        } else {
            try result;
        }
    }
}

test "batch verification" {
    for (0..100) |_| {
        const key_pair1 = std.crypto.sign.Ed25519.KeyPair.generate();
        const key_pair2 = std.crypto.sign.Ed25519.KeyPair.generate();
        var msg1: [64]u8 = undefined;
        var msg2: [64]u8 = undefined;
        std.crypto.random.bytes(&msg1);
        std.crypto.random.bytes(&msg2);
        const sig1 = try key_pair1.sign(&msg1, null);
        const sig2 = try key_pair2.sign(&msg1, null);

        try verifyBatchOverSingleMessage(
            2,
            &.{ sig1, sig2 },
            &.{ key_pair1.public_key, key_pair2.public_key },
            &msg1,
        );

        try std.testing.expectError(
            error.InvalidSignature,
            verifyBatchOverSingleMessage(
                2,
                &.{ sig1, sig2 },
                &.{ key_pair1.public_key, key_pair1.public_key },
                &msg1,
            ),
        );

        try std.testing.expectError(
            error.InvalidSignature,
            verifyBatchOverSingleMessage(
                2,
                &.{ sig1, sig2 },
                &.{ key_pair1.public_key, key_pair2.public_key },
                &msg2,
            ),
        );
    }
}

test "wycheproof" {
    const groups = @import("tests/wycheproof.zig").groups;
    for (groups) |group| {
        var public_key_buffer: [32]u8 = undefined;
        const public_key = try std.fmt.hexToBytes(&public_key_buffer, group.pubkey);
        if (public_key.len != 32) continue;

        for (group.cases) |case| {
            var msg_buffer: [1024]u8 = undefined;
            const msg_len = case.msg.len / 2;
            const message = try std.fmt.hexToBytes(msg_buffer[0..msg_len], case.msg);

            var sig_buffer: [64]u8 = undefined;
            if (case.sig.len > 64 * 2) continue;
            const signature_bytes = try std.fmt.hexToBytes(&sig_buffer, case.sig);
            if (signature_bytes.len != 64) continue;

            const pubkey = Pubkey.fromBytes(public_key_buffer) catch continue;
            const signature: Signature = .fromBytes(sig_buffer);

            // Single verify
            {
                const result = verifyBatchOverSingleMessage(
                    1,
                    &.{signature},
                    &.{pubkey},
                    message,
                );

                switch (case.expected) {
                    .valid => try result,
                    .invalid => try std.testing.expect(std.meta.isError(result)),
                }
            }

            // Multi verify
            {
                const result = verifyBatchOverSingleMessage(
                    10, // more max than inputs
                    &.{ signature, signature, signature, signature },
                    &.{ pubkey, pubkey, pubkey, pubkey },
                    message,
                );

                switch (case.expected) {
                    .valid => try result,
                    .invalid => try std.testing.expect(std.meta.isError(result)),
                }
            }
        }
    }
}
