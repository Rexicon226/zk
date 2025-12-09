const std = @import("std");

pub const BoundedArray = @import("stdx/bounded_array.zig").BoundedArray;

/// Design ported over from: https://github.com/arkworks-rs/algebra/blob/750e28aab9fb5d66d4b7f8d8d9510bba633ae89d/ff/src/bits.rs
pub fn BitIterator(Int: type, endian: std.builtin.Endian, skip: bool) type {
    return struct {
        array: Array,
        index: u32,

        const Self = @This();
        const Limb = u32;
        const N = std.math.divCeil(usize, @sizeOf(Int), @sizeOf(Limb)) catch unreachable;
        const Array = [N]Limb;
        const Backing = std.meta.Int(.unsigned, @bitSizeOf(Array));
        const bits = @bitSizeOf(Limb);

        pub fn init(value: Int) Self {
            const backing: Backing = value;
            return .{
                .array = @bitCast(backing),
                .index = switch (endian) {
                    .big => @bitSizeOf(Int) - if (skip) @clz(value) else 0,
                    .little => if (skip) @compileError("TODO") else 0,
                },
            };
        }

        pub fn next(i: *Self) ?bool {
            if (i.index == switch (endian) {
                .big => 0,
                .little => @bitSizeOf(Int),
            }) return null;

            if (endian == .big) i.index -= 1;
            const part = i.index / bits;
            const bit = i.index - (bits * part);
            if (endian == .little) i.index += 1;

            return i.array[part] & (@as(Limb, 1) << @intCast(bit)) != 0;
        }
    };
}

const expectEqual = std.testing.expectEqual;

test "bit iterator basic" {
    {
        // Ensure the iterator is reading big endian correctly.
        const T = BitIterator(u64, .big, false);
        {
            var iterator = T.init(0);
            for (0..64) |_| try expectEqual(false, iterator.next());
            try expectEqual(null, iterator.next());
        }
        {
            var iterator = T.init(std.math.maxInt(u64));
            for (0..64) |_| try expectEqual(true, iterator.next());
            try expectEqual(null, iterator.next());
        }
        {
            var iterator = T.init(0b1010);
            for (0..60) |_| try expectEqual(false, iterator.next());
            try expectEqual(true, iterator.next());
            try expectEqual(false, iterator.next());
            try expectEqual(true, iterator.next());
            try expectEqual(false, iterator.next());
            try expectEqual(null, iterator.next());
        }
    }
    {
        // Test with skipping leading zeroes
        const T = BitIterator(u64, .big, true);
        {
            var iterator = T.init(0);
            try expectEqual(null, iterator.next());
        }
        {
            var iterator = T.init(std.math.maxInt(u64));
            for (0..64) |_| try expectEqual(true, iterator.next());
            try expectEqual(null, iterator.next());
        }
        {
            var iterator = T.init(0b1010);
            try expectEqual(true, iterator.next());
            try expectEqual(false, iterator.next());
            try expectEqual(true, iterator.next());
            try expectEqual(false, iterator.next());
            try expectEqual(null, iterator.next());
        }
    }
    {
        // Ensure the iterator is reading little endian correctly.
        const T = BitIterator(u64, .little, false);
        {
            var iterator = T.init(0);
            for (0..64) |_| try expectEqual(false, iterator.next());
            try expectEqual(null, iterator.next());
        }
        {
            var iterator = T.init(std.math.maxInt(u64));
            for (0..64) |_| try expectEqual(true, iterator.next());
            try expectEqual(null, iterator.next());
        }
        {
            var iterator = T.init(0b1010);
            try expectEqual(false, iterator.next());
            try expectEqual(true, iterator.next());
            try expectEqual(false, iterator.next());
            try expectEqual(true, iterator.next());
            for (4..64) |_| try expectEqual(false, iterator.next());
            try expectEqual(null, iterator.next());
        }
    }
}
