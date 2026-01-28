pub const eddsa = @import("signatures/eddsa.zig");
pub const ring = @import("signatures/ring.zig");
pub const falcon = @import("signatures/falcon.zig");

pub const Falcon512 = falcon.Falcon512;
pub const Falcon1024 = falcon.Falcon1024;

test {
    _ = eddsa;
    _ = ring;
    _ = falcon;
}
