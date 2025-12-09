pub const dekart = @import("range_proofs/dekart.zig");
pub const bulletproofs = @import("range_proofs/bulletproofs.zig");

pub const Bulletproof = bulletproofs.Proof;

test {
    _ = dekart;
    _ = bulletproofs;
}
