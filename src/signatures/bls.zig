const bls = @import("../curves/bls.zig");
const G1 = bls.Bls12_381.G1;

const PublicKey = struct {};

const SecretKey = struct {};

pub fn generate(sk: []const u8) struct {
    SecretKey,
    PublicKey,
} {
    _ = sk;
}

test "bls sig" {}
