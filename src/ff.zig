const int = @import("ff/int.zig");
pub const montgomery = @import("ff/montgomery.zig");

pub const Fp = montgomery.Fp;

test {
    _ = int;
    _ = montgomery;
}
