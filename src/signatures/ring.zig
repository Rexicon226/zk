//! This file implements different forms of ring signatures.
//!
//! Ring signatures are a form of signature that proves a message was
//! signed by someone in the set of public keys, but hides which particular
//! public key was responsible.
//!
//! The default "ring signature" schemes people usually talk about do not
//! have the ability to guarantee other useful properties, like uniqueness
//! (same signer cannot sign twice) and accountability.
//!
//! The general way ring signatures are implemented is through $\sigma$-protocols
//! (like Schnorr), OR-proofs, and Fiat-Shamir to remove the interaction.
//!
//! The signer:
//! 1. Simulates proofs for keys they don't know.
//! 2. Produces a real proof for the key they *do* know.
//! 3. Combines them together with a order-consistent hash (transcript).
//!
//! To a verifier, all proofs look identical, making them information-theoretically
//! secure. An attacker/malicious prover could spend an infinite amount of time
//! and resources trying to decern which proof was the "real" one, and would be
//! unable to.
//!
//! ## Extensions
//!
//! There are many extensions to ring signatures. Interesting ones include:
//! - Linkable ring signatures, which allow you to tell if the same signer signed
//! twice. This is often used to prevent double-spending, such as in Monero's
//! [RingCT](https://eprint.iacr.org/2015/1098.pdf) construct.
//! - Threshold ring signatures, where at least $k$ of $n$ must sign, but which $k$ in the
//! ring of $n$ public keys still remains anonymous.

const std = @import("std");
const builtin = @import("builtin");
const pedersen = @import("../pedersen.zig");
const merlin = @import("../merlin.zig");
const ed25519 = @import("../curves/ed25519.zig");

const Point = std.crypto.ecc.Ristretto255;
const Edwards25519 = std.crypto.ecc.Edwards25519;
const Scalar = Edwards25519.scalar.Scalar;

const KeyPair = pedersen.KeyPair;
const PublicKey = pedersen.PublicKey;
const SecretKey = pedersen.SecretKey;
const Opening = pedersen.Opening;

const Transcript = merlin.Transcript(enum {
    ringsig, // TODO: some sort of domain seperator for the initialization
});

/// We prove knowledge of one opening of one pedersen commitment in the ring,
/// without revealing which. We can achieve this via a sigma-protocol OR composition,
/// then make it non-interactive with Fiat-Shamir (we conveniently have merlin
/// implemented for other sigma protocols).
///
/// The signature structure:
/// $$\sigma = (c_1, z_{x,1}, z_{r,1}, ..., c_n, z_{x,n}, z_{r,n})$$
pub fn Signature(
    // The number of public keys in the signature ring.
    N: comptime_int,
) type {
    return struct {
        c: [N]Scalar,
        z_x: [N]Scalar,
        z_r: [N]Scalar,

        const RingSignature = @This();

        comptime {
            std.debug.assert(N >= 2);
        }

        const contract: Transcript.Contract = c: {
            const double: [2]Transcript.Input = .{
                .{ .label = "P", .type = .point },
                .{ .label = "T", .type = .point },
            };
            const inputs = (&double) ** N;
            // Ends in a challenge.
            break :c inputs ++ &[_]Transcript.Input{.{ .label = "challenge", .type = .challenge }};
        };

        pub fn init(
            /// The "ring" of public keys. Must already include the signer's public key.
            ring: *const [N]PublicKey,
            /// The _index_ of the signers public key in the ring.
            s: std.math.IntFittingRange(0, N - 1),
            /// The keypair that will be used to create the signature.
            kp: *const KeyPair,
        ) RingSignature {
            // Sanity check that we do indeed have the right index.
            if (builtin.mode == .Debug) {
                const claimed = ring[s];
                const ours = kp.pk;
                std.debug.assert(claimed.p.point.equivalent(ours.p.point));
            }

            var c: [N]Scalar = undefined;
            var z_x: [N]Scalar = undefined;
            var z_r: [N]Scalar = undefined;
            var T: [N]Point = undefined;

            // Real commitment for our index
            var alpha_x: Scalar = .random();
            var alpha_r: Scalar = .random();
            // Make sure to clear the ephemeral secret nonces.
            defer std.crypto.secureZero(u64, &alpha_x.limbs);
            defer std.crypto.secureZero(u64, &alpha_r.limbs);

            // Simulate proofs
            for (0..N) |i| {
                if (i == s) {
                    T[s] = pedersen.init(alpha_x, &.{ .mu = alpha_r }).point;
                } else {
                    c[i] = .random();
                    z_x[i] = .random();
                    z_r[i] = .random();
                    T[i] = commitment(ring[i].p.point, z_x[i], z_r[i], c[i]);
                }
            }

            // Fiat-shamir challenge
            comptime var session = Transcript.getSession(contract);
            defer session.finish();
            var transcript = Transcript.init(
                .ringsig,
                &.{.{ .label = "ring-size", .message = .{ .u64 = N } }},
            );

            inline for (ring, &T) |r, t| {
                @setEvalBranchQuota(N * 40);
                transcript.append(&session, .point, "P", r.p.point);
                transcript.append(&session, .point, "T", t);
            }
            const c_total = transcript.challengeScalar(&session, "challenge");

            // Compute the missing challenge (c[s])
            var sum_c: Scalar = .fromBytes(@splat(0));
            for (0..N) |i| {
                if (i == s) continue;
                sum_c = sum_c.add(c[i]);
            }

            // Real response
            c[s] = .fromBytes(Edwards25519.scalar.sub(c_total.toBytes(), sum_c.toBytes()));
            z_x[s] = (alpha_x.add(c[s].mul(kp.sk.scalar)));
            z_r[s] = (alpha_r.add(c[s].mul(kp.opening.mu)));

            return .{
                .c = c,
                .z_x = z_x,
                .z_r = z_r,
            };
        }

        pub fn verify(
            signature: *const RingSignature,
            ring: *const [N]PublicKey,
        ) error{InvalidRingSignature}!void {
            const c = &signature.c;
            const z_x = &signature.z_x;
            const z_r = &signature.z_r;

            var T: [N]Point = undefined;

            // Re-compute T_i
            for (0..N) |i| {
                T[i] = commitment(ring[i].p.point, z_x[i], z_r[i], c[i]);
            }

            // Re-compute the challenge.
            comptime var session = Transcript.getSession(contract);
            defer session.finish();
            var transcript = Transcript.init(
                .ringsig,
                &.{.{ .label = "ring-size", .message = .{ .u64 = N } }},
            );

            inline for (ring, &T) |r, t| {
                @setEvalBranchQuota(N * 40);
                transcript.append(&session, .point, "P", r.p.point);
                transcript.append(&session, .point, "T", t);
            }
            const c_check = transcript.challengeScalar(&session, "challenge");

            // Check challenge sum
            var sum_c: Scalar = c[0];
            for (1..N) |i| sum_c = (sum_c.add(c[i]));

            // Check that sum_c == c_check to verify the signature is correct.
            // TODO: is there a faster way to compare the scalars?
            if (!std.mem.eql(u8, &c_check.toBytes(), &sum_c.toBytes())) return error.InvalidRingSignature;
        }

        /// $$T_i = G^{z_x[i]} * H^{z_r[i]} * P_i^{-c[i]}$$
        fn commitment(P_i: Point, z_x: Scalar, z_r: Scalar, c_i: Scalar) Point {
            return ed25519.mulMulti(
                3,
                &.{ pedersen.G, pedersen.H, P_i },
                &.{ z_x.toBytes(), z_r.toBytes(), Edwards25519.scalar.neg(c_i.toBytes()) },
            );
        }
    };
}

test "basic ring signature" {
    const N = 10;
    const s = 1;

    // The signer's keypair
    const kp: KeyPair = .random();

    // Let the ring be R = {P_1, P_2, ..., P_n}
    // Signer is index s in the ring, knowing (x_s, r_s), aka. (secret, opening).
    var ring: [N]PublicKey = undefined;
    for (0..N) |i| {
        ring[i] = switch (i) {
            // Set to the signer's public key.
            s => kp.pk,
            // The *other* public keys, are generated here, but we don't know their secret keys.
            else => .{ .p = pedersen.initScalar(.random())[0] },
        };
    }

    const signature = Signature(N).init(&ring, s, &kp);
    try signature.verify(&ring);
}

test "verify ring doesn't contain signer's pubkey" {
    const N = 10;
    const s = 1;

    const kp: KeyPair = .random();

    var ring: [N]PublicKey = undefined;
    for (0..N) |i| {
        ring[i] = switch (i) {
            s => kp.pk,
            else => .{ .p = pedersen.initScalar(.random())[0] },
        };
    }

    const signature = Signature(N).init(&ring, s, &kp);

    // Incorrectly override the public key.
    ring[s] = ring[0];

    try std.testing.expectError(error.InvalidRingSignature, signature.verify(&ring));
}
