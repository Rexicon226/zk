const std = @import("std");

const V = @Vector(8, bool);
const Mask = u8;
pub fn main() !void {
    const x: V = .{ false, false, true, false, false, false, true, false };
    const result = foo(x);
    std.debug.print("result: {}\n", .{result});
}

fn foo(x: V) V {
    const mask: Mask = @bitCast(x);
    const before = @clz(mask);
    const after = @ctz(mask);
    const trues = ((~@as(Mask, 0) >> @intCast(after)) << @intCast(before + after)) >> @intCast(before);
    return @bitCast(mask | trues);
}
