//! "Ring" signatures.

const std = @import("std");
const Point = std.crypto.ecc.Ristretto255;
const Edwards25519 = std.crypto.ecc.Edwards25519;
const Scalar = Edwards25519.scalar.Scalar;

const pedersen = @import("../pedersen.zig");
const PublicKey = pedersen.PublicKey;
const SecretKey = pedersen.SecretKey;
const Opening = pedersen.Opening;

const merlin = @import("../merlin.zig");
const Transcript = merlin.Transcript(enum {
    ringsig, // TODO: some sort of domain seperator for the initialization
});

// The number of keys in the ring.
const N = 2;
// The index of our key in the ring.
const s = 1;

const contract: Transcript.Contract = c: {
    const double: [2]Transcript.Input = .{
        .{ .label = "P", .type = .point },
        .{ .label = "T", .type = .point },
    };
    const inputs = (&double) ** N;
    // Ends in a challenge.
    break :c inputs ++ &[_]Transcript.Input{.{ .label = "challenge", .type = .challenge }};
};

const Signature = struct {
    c: [N]Scalar,
    z_x: [N]Scalar,
    z_r: [N]Scalar,
};

test "basic ring signature idea" {
    // The signer's keypair
    const signer_opening = Opening.random();
    const signer_secret = SecretKey.random();
    const signer_pubkey = PublicKey.fromSecretKey(
        &signer_secret,
        &signer_opening,
    );

    // Let the ring be R = {P_1, P_2, ..., P_n}
    // Signer is index s in the ring, knowing (x_s, r_s), aka. (secret, opening).
    var ring: [N]PublicKey = undefined;
    for (0..N) |i| {
        ring[i] = switch (i) {
            s => signer_pubkey,
            // The *other* public keys, are generated here, but we don't know their secret keys.
            else => .{ .p = pedersen.initScalar(.random())[0] },
        };
    }

    // We prove knowledge of one opening of one pedersen commitment in the ring, without revealing which.
    // We can achieve this via a sigma-protocol OR composition, then make it non-interactive with Fiat-Shamir
    // (we conveniently have merlin implemented for other sigma protocols).

    // The signature structure:
    // \sigma = (c_1, z_{x,1}, z_{r,1}, ..., z_{x,n}, z_{r_n})

    // Commit phase
    const signature: Signature = sig: {
        var c: [N]Scalar = undefined;
        var z_x: [N]Scalar = undefined;
        var z_r: [N]Scalar = undefined;
        var T: [N]Point = undefined;

        // Simulate proofs
        for (0..N) |i| {
            if (i == s) continue; // skip our entry

            const c_i: Scalar = .random();
            const z_x_i: Scalar = .random();
            const z_r_i: Scalar = .random();

            // T_i = G^{z_x[i]} * H^{z_r[i]} * P_i^{-c[i]}
            const G_z_x = try pedersen.G.mul(z_x_i.toBytes());
            const H_z_r = try pedersen.H.mul(z_r_i.toBytes());
            const P_i = try ring[i].p.point.mul(Edwards25519.scalar.neg(c_i.toBytes()));

            T[i] = G_z_x.add(H_z_r).add(P_i);
            c[i] = c_i;
            z_x[i] = z_x_i;
            z_r[i] = z_r_i;
        }

        // Real commitment for our index
        const alpha_x: Scalar = .random();
        const alpha_r: Scalar = .random();
        T[s] = pedersen.init(alpha_x, &.{ .mu = alpha_r }).point;

        // Fiat-shamir challenge
        comptime var session = Transcript.getSession(contract);
        defer session.finish();
        var transcript = Transcript.init(
            .ringsig,
            &.{.{ .label = "ring-size", .message = .{ .u64 = N } }},
        );

        inline for (&ring, &T) |r, t| {
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
        c[s] = .fromBytes(Edwards25519.scalar.sub(c_total.toBytes(), sum_c.toBytes()));

        // Real response
        z_x[s] = (alpha_x.add(c[s].mul(signer_secret.scalar)));
        z_r[s] = (alpha_r.add(c[s].mul(signer_opening.mu)));

        break :sig .{
            .c = c,
            .z_x = z_x,
            .z_r = z_r,
        };
    };

    // Verification phase (would be done on the verifier).
    {
        const c = &signature.c;
        const z_x = &signature.z_x;
        const z_r = &signature.z_r;

        var T: [N]Point = undefined;

        // Re-compute T_i
        for (0..N) |i| {
            const G_z_x = try pedersen.G.mul(z_x[i].toBytes());
            const H_z_r = try pedersen.H.mul(z_r[i].toBytes());
            const P_i = try ring[i].p.point.mul(Edwards25519.scalar.neg(c[i].toBytes()));
            T[i] = G_z_x.add(H_z_r).add(P_i);
        }

        // Re-compute the challenge.
        comptime var session = Transcript.getSession(contract);
        defer session.finish();
        var transcript = Transcript.init(
            .ringsig,
            &.{.{ .label = "ring-size", .message = .{ .u64 = N } }},
        );

        inline for (&ring, &T) |r, t| {
            transcript.append(&session, .point, "P", r.p.point);
            transcript.append(&session, .point, "T", t);
        }
        const c_check = transcript.challengeScalar(&session, "challenge");

        // Check challenge sum
        var sum_c: Scalar = .fromBytes(@splat(0));
        for (0..N) |i| {
            sum_c = (sum_c.add(c[i]));
        }

        // Check that sum_c == c_check to verify the signature is correct.
        if (!std.mem.eql(u8, &c_check.toBytes(), &sum_c.toBytes())) return error.InvalidSignatureRing;
    }
}
