const std = @import("std");
const falcon = @import("signatures/falcon.zig");
const Falcon512 = falcon.Falcon512;
const Felt = Falcon512.Felt;

const Q = 12 * 1024 + 1;

fn bit(bytes: []const u8, position: usize) u1 {
    const byte = position / 8;
    const idx = 7 - (position & 7);
    return @intCast((bytes[byte] >> @intCast(idx)) & 1);
}

fn fromBytes(bytes: *const [897]u8) !Falcon512.PublicKey {
    // first byte is the header, encoded as
    // 0 0 0 0 n n n n
    // where the leftmost 4 bits are 0
    // and nnnn encodes logn
    const header = bytes[0];
    if (header != 9) return error.InvalidHeader;

    // the rest of the bytes are the public key polynomial
    // each value (in the 0 to Q - 1 range) is encoded as a 14-bit sequence
    // (since Q = 12289, 14 bits per value is used). The encoded value are
    // concatted into a bit sequence of 14N bits, which are represented as 14N / 8 bytes.
    const h = bytes[1..];
    var position: usize = 0;
    var coeff: [512]Felt = undefined;
    for (0..512) |i| {
        var val: i16 = 0;
        for (0..14) |_| {
            val = (val << 1) | bit(h, position);
            position += 1;
        }
        if (val > Q - 1) return error.InvalidCoeff;
        coeff[i] = .init(val);
    }
    return .{ .h = .{ .coeff = coeff } };
}

// export fn LLVMFuzzerTestOneInput(data: [*]const u8, size: u64) i32 {
//     errdefer |err| std.debug.panic("err: {}", .{err});

//     const slice = data[0..size];

//     var buffer: [897]u8 = @splat(0);
//     @memcpy(buffer[0..@min(slice.len, 897)], slice.ptr);
//     const result = Falcon512.PublicKey.fromBytes(&buffer);
//     const expected = fromBytes(&buffer);
//     std.testing.expectEqual(expected, result) catch std.posix.abort();

//     return 0;
// }

export fn LLVMFuzzerTestOneInput(data: [*]const u8, size: u64) i32 {
    errdefer |err| std.debug.panic("err: {}", .{err});

    const slice = data[0..size];
    std.mem.doNotOptimizeAway(Falcon512.decompress(slice));

    return 0;
}
