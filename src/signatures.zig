pub const eddsa = @import("signatures/eddsa.zig");
pub const ring = @import("signatures/ring.zig");

test {
    _ = eddsa;
    _ = ring;
}
