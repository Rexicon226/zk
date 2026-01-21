pub const eddsa = @import("signatures/eddsa.zig");
pub const ring = @import("signatures/ring.zig");
pub const falcon = @import("signatures/falcon.zig");

pub const Falcon512 = falcon.Falcon512;

test {
    _ = eddsa;
    _ = ring;
    _ = @import("signatures/falcon/test.zig");
}
