//! This file provides helpers to create Pedersen commitments over Ristretto255.
//!
//! A Pedersen commitment has the form
//!
//! $C = sG + \mu{H}$
//!
//! where:
//! - $s$ is the secret value encoded as a `Scalar`;
//! - $\mu$ is the opening (randomness) scalar;
//! - `G` and `H` are Ristretto basepoints.
//!
//! - https://blog.vortan.dev/elgamal/#pedersen_commitment
const std = @import("std");
const ed25519 = @import("curves/ed25519.zig");

const Ristretto255 = std.crypto.ecc.Ristretto255;
const Edwards25519 = std.crypto.ecc.Edwards25519;
const Scalar = Edwards25519.scalar.Scalar;

/// Pedersen basepoint `G` (compressed form -> `Ristretto255`).
///
/// This is the fixed generator used for encoding the value part of
/// a commitment. In the commitment forumla, this is the `G` term.
pub const G = b: {
    @setEvalBranchQuota(10_000);
    break :b Ristretto255.fromBytes(.{
        0xe2, 0xf2, 0xae, 0xa,  0x6a, 0xbc, 0x4e, 0x71,
        0xa8, 0x84, 0xa9, 0x61, 0xc5, 0x0,  0x51, 0x5f,
        0x58, 0xe3, 0xb,  0x6a, 0xa5, 0x82, 0xdd, 0x8d,
        0xb6, 0xa6, 0x59, 0x45, 0xe0, 0x8d, 0x2d, 0x76,
    }) catch unreachable;
};

/// Secondary generator `H` derived from `G`.
///
/// `H` is computed as a hash-to-ristretto of `SHA3-512(G)` and is
/// used as the randomness/opening base in the commitment formula. Using a
/// separate basepoint prevents knowledge of discrete logarithm relation
/// between `G` and `H`.
pub const H = b: {
    // We could compute `H` at comptime, but that would take *way* too long!
    // Maybe we could look into it once comptime execution is sped up a bit.
    @setEvalBranchQuota(10_000);
    break :b Ristretto255.fromBytes(.{
        0x8c, 0x92, 0x40, 0xb4, 0x56, 0xa9, 0xe6, 0xdc,
        0x65, 0xc3, 0x77, 0xa1, 0x4,  0x8d, 0x74, 0x5f,
        0x94, 0xa0, 0x8c, 0xdb, 0x7f, 0x44, 0xcb, 0xcd,
        0x7b, 0x46, 0xf3, 0x40, 0x48, 0x87, 0x11, 0x34,
    }) catch unreachable;
};

/// An Opening holds the randomness used to blind a Pedersen commitment.
pub const Opening = struct {
    mu: Scalar,

    /// Generate a uniformly random opening.
    pub fn random() Opening {
        return .{ .mu = Scalar.random() };
    }
};

/// A Commitment represents the pedersen commitment.
pub const Commitment = struct {
    point: Ristretto255,
};

/// Returns a commitment where the internal `point` equals $sG + \mu{H}$.
pub fn init(s: Scalar, opening: *const Opening) Commitment {
    const point = ed25519.mulMulti(
        2,
        &.{ G, H },
        &.{ s.toBytes(), opening.mu.toBytes() },
    );
    return .{ .point = point };
}

/// Creates a random opening/blind, and opens the commitment with it.
pub fn initScalar(s: Scalar) struct { Commitment, Opening } {
    const opening = Opening.random();
    return .{ init(s, &opening), opening };
}

/// Same thing as `initScalar`, but creates the scalar from an integer type.
pub fn initValue(comptime T: type, value: T) struct { Commitment, Opening } {
    const opening = Opening.random();
    return .{ initOpening(T, value, &opening), opening };
}

/// Same thing as `initValue`, but takes a user-provided opening.
pub fn initOpening(comptime T: type, value: T, opening: *const Opening) Commitment {
    const scalar = scalarFromInt(T, value);
    return init(scalar, opening);
}

/// Converts an integer `value` to a `Scalar` by writing its little-endian
/// representation into a 32-byte buffer and performing 5 barret reductions.
pub fn scalarFromInt(comptime T: type, value: T) Scalar {
    var buffer: [32]u8 = .{0} ** 32;
    std.mem.writeInt(T, buffer[0..@sizeOf(T)], value, .little);
    return Scalar.fromBytes(buffer);
}

/// A Pedersen-commited public key.
///
/// The user has:
/// - Secret key: $x \in \mathbb{Z}_q$
/// - Blinding: $r \in \mathbb{Z}_q$
///
/// The public key is a pedersen commitment to the secret:
///
/// $P = {G^x}{H^x}$
pub const PublicKey = struct {
    p: Commitment,

    pub fn fromSecretKey(sk: *const SecretKey, o: *const Opening) PublicKey {
        return .{ .p = init(sk.scalar, o) };
    }
};

pub const SecretKey = struct {
    scalar: Scalar,

    pub fn random() SecretKey {
        return .{ .scalar = .random() };
    }
};
