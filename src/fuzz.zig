const std = @import("std");
const falcon = @import("signatures/falcon.zig");
const Falcon512 = falcon.Falcon512;

export fn LLVMFuzzerTestOneInput(data: [*]const u8, size: u64) i32 {
    errdefer |err| std.debug.panic("err: {}", .{err});

    const slice = data[0..size];
    std.mem.doNotOptimizeAway(Falcon512.decompress(slice));

    return 0;
}
