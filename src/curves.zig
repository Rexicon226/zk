pub const bn = @import("curves/bn.zig");
pub const bls = @import("curves/bls.zig");
pub const ed25519 = @import("curves/ed25519.zig");

pub const Bn254 = bn.Bn254;
pub const Bls12_381 = bls.Bls12_381;

test {
    _ = bn;
    _ = ed25519;
    _ = bls;
}
