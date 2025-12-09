/// Implements DekartProof as described in https://eprint.iacr.org/2025/1159.
fn Proof(comptime E: type, ell: comptime_int) type {
    const G1 = E.G1;
    const G2 = E.G2;
    _ = ell;

    return struct {
        hatC: G1,

        /// TODO: document the fake pedersen commitment
        const Homomorphism = struct {
            one: G1.Affine,
            two: G1.Affine,
        };

        const ProverKey = struct {
            vk: VerificationKey,
            ckey: CommitmentKey,
            max_n: usize,
        };

        const CommitmentKey = struct {
            xi: G1.Affine,
            tau: G1.Affine,
            lagrange: G1.Affine,
            // eval_dom

        };

        const VerificationKey = struct {
            xi: G1.Affine,
            lagrange: G1.Affine,
            hkzg: univariate.VerificationKey,
        };

        const univariate = struct {
            const VerificationKey = struct {
                xi: G2.Affine,
                tau: G2.Affine,
                generators: Generators,
            };
        };

        const Generators = struct {
            g1: G1.Affine,
            g2: G2.Affine,

            pub const init: Generators = .{
                .g1 = .generator,
                .g2 = .generator,
            };
        };
    };
}

test "dekart" {}
