const std = @import("std");

pub fn BigInt(comptime bits: comptime_int) type {
    return extern struct {
        limbs: [N]Limb,

        const Limb = u64;
        const Self = @This();

        const BackingInt = std.meta.Int(.unsigned, @bitSizeOf(Self));
        const IntRepr = std.meta.Int(.unsigned, bits);

        const V = @Vector(N, Limb);
        pub const N = std.math.divCeil(u64, bits, 64) catch unreachable;

        pub const zero: Self = .{ .limbs = @splat(0) };
        pub const max: Self = .{ .limbs = @splat(std.math.maxInt(Limb)) };

        pub fn isEven(b: Self) bool {
            return b.limbs[0] & 1 == 0;
        }

        pub fn isZero(b: Self) bool {
            const vec: V = b.limbs;
            const z: V = @splat(0);
            return @reduce(.And, vec == z);
        }

        pub fn int(value: IntRepr) Self {
            var buffer: [N]Limb = undefined;
            std.mem.writeInt(BackingInt, @ptrCast(&buffer), @intCast(value), .little);
            return .{ .limbs = buffer };
        }

        pub fn toInt(b: Self) IntRepr {
            const backing = std.mem.readInt(BackingInt, @ptrCast(&b.limbs), .little);
            return @intCast(backing);
        }

        pub fn addWithCarry(b: *Self, other: Self) bool {
            var carry: u8 = 0;
            for (&b.limbs, other.limbs) |*s, o| {
                carry = helpers.adc(s, o, carry);
            }
            return carry != 0;
        }

        pub fn subWithBorrow(b: *Self, other: Self) bool {
            var borrow: u64 = 0;
            for (&b.limbs, other.limbs) |*s, o| {
                borrow = helpers.sbb(s, o, borrow);
            }
            return borrow != 0;
        }

        pub fn shl(b: *Self, rhs: u32) void {
            // If we try to shift out more bits than exist, we just set to zero instead of IB.
            if (rhs >= 64 * N) {
                b.* = .zero;
                return;
            }

            var r = rhs;
            while (r >= 64) : (r -= 64) {
                var t: u64 = 0;
                for (&b.limbs) |*limb| {
                    std.mem.swap(u64, &t, limb);
                }
            }

            if (r > 0) {
                var t: u64 = 0;
                for (&b.limbs) |*limb| {
                    const t2 = limb.* >> @intCast(64 - r);
                    limb.* <<= @intCast(r);
                    limb.* |= t2;
                    t = t2;
                }
            }
        }

        pub fn mul2(b: *Self) bool {
            var last: u64 = 0;
            for (&b.limbs) |*limb| {
                const tmp = limb.* >> 63;
                limb.* <<= 1;
                limb.* |= last;
                last = tmp;
            }
            return last != 0;
        }

        pub fn mul(b: Self, other: Self) struct { Self, Self } {
            if (b.isZero() or other.isZero()) return .{ .zero, .zero };

            var carry: u64 = 0;
            var r0: [N]u64 = @splat(0);
            var r1: [N]u64 = @splat(0);

            for (0..N) |i| {
                for (0..N) |j| {
                    const index = i + j;
                    const r = if (index < N) &r0[index] else &r1[index - N];
                    r.* = helpers.mac(
                        r.*,
                        b.limbs[i],
                        other.limbs[j],
                        &carry,
                    );
                }
                r1[i] = carry;
                carry = 0;
            }

            return .{
                .{ .limbs = r0 },
                .{ .limbs = r1 },
            };
        }

        pub fn mulLow(b: Self, other: Self) Self {
            if (b.isZero() or other.isZero()) return .zero;

            var result: Self = .zero;
            var carry: u64 = 0;

            for (0..N) |i| {
                for (0..N - i) |j| {
                    result.limbs[i + j] = helpers.mac(
                        result.limbs[i + j],
                        b.limbs[i],
                        other.limbs[j],
                        &carry,
                    );
                }
                carry = 0;
            }

            return result;
        }
    };
}

const helpers = struct {
    fn adc(a: *u64, b: u64, carry: u64) u8 {
        const tmp = @as(u128, a.*) + @as(u128, b) + @as(u128, carry);
        a.* = @truncate(tmp);
        return @truncate(tmp >> 64);
    }

    /// Smaller `carry` - can use more optimal instruction,
    /// https://www.intel.com/content/www/us/en/docs/intrinsics-guide/index.html#text=_addcarry_u64&ig_expand=175
    fn adcSmall(a: *u64, b: u64, carry: u8) u8 {
        // TODO: use more optimal instruction
        const tmp = @as(u128, a.*) + @as(u128, b) + @as(u128, carry);
        a.* = @truncate(tmp);
        return @truncate(tmp >> 64);
    }

    fn adcNoCarry(a: u64, b: u64, carry: *const u64) u64 {
        const tmp = @as(u128, a) + @as(u128, b) + @as(u128, carry.*);
        return @truncate(tmp);
    }

    fn sbb(a: *u64, b: u64, carry: u64) u64 {
        const tmp = (@as(u128, 1) << 64) + @as(u128, a.*) - @as(u128, b) - @as(u128, carry);
        a.* = @truncate(tmp);
        return @intFromBool(tmp >> 64 == 0);
    }

    fn sbbSmall(a: *u64, b: u64, carry: u8) u8 {
        const tmp = (@as(u128, 1) << 64) + @as(u128, a.*) - @as(u128, b) - @as(u128, carry);
        a.* = @truncate(tmp);
        return @intFromBool(tmp >> 64 == 0);
    }

    fn mac(a: u64, b: u64, c: u64, carry: *u64) u64 {
        const tmp = @as(u128, a) + (@as(u128, b) * @as(u128, c)) + carry.*;
        carry.* = @truncate(tmp >> 64);
        return @truncate(tmp);
    }

    fn macDiscard(a: u64, b: u64, c: u64, carry: *u64) void {
        const tmp = @as(u128, a) + (@as(u128, b) * @as(u128, c));
        carry.* = @truncate(tmp >> 64);
    }
};

test "init" {
    const B = BigInt(64);
    {
        const a = B.int(10);
        try std.testing.expectEqual(10, a.toInt());
    }
    {
        const a: B = .max;
        try std.testing.expectEqual(std.math.maxInt(u64), a.toInt());
    }
}

test "adc" {
    {
        var a: u64 = 5;
        const carry = helpers.adc(&a, 10, 0);
        try std.testing.expectEqual(15, a);
        try std.testing.expectEqual(0, carry);
    }
    {
        var a: u64 = std.math.maxInt(u64);
        const carry = helpers.adc(&a, 1, 0);
        try std.testing.expectEqual(0, a);
        try std.testing.expectEqual(1, carry);
    }
    {
        var a: u64 = 5;
        const carry = helpers.adc(&a, 10, 1);
        try std.testing.expectEqual(16, a);
        try std.testing.expectEqual(0, carry);
    }
    {
        var a: u64 = std.math.maxInt(u64) - 5;
        const carry = helpers.adc(&a, 10, 1);
        try std.testing.expectEqual(5, a);
        try std.testing.expectEqual(carry, 1);
    }
}

test "adc small" {
    {
        var a: u64 = 5;
        const carry = helpers.adcSmall(&a, 10, 0);
        try std.testing.expectEqual(15, a);
        try std.testing.expectEqual(0, carry);
    }
    {
        var a: u64 = std.math.maxInt(u64);
        const carry = helpers.adcSmall(&a, 1, 0);
        try std.testing.expectEqual(0, a);
        try std.testing.expectEqual(1, carry);
    }
    {
        var a: u64 = 5;
        const carry = helpers.adcSmall(&a, 10, 1);
        try std.testing.expectEqual(16, a);
        try std.testing.expectEqual(0, carry);
    }
    {
        var a: u64 = std.math.maxInt(u64) - 5;
        const carry = helpers.adcSmall(&a, 10, 1);
        try std.testing.expectEqual(5, a);
        try std.testing.expectEqual(carry, 1);
    }
}

test "adc no carry" {
    {
        const carry: u64 = 0;
        const result = helpers.adcNoCarry(5, 10, &carry);
        try std.testing.expectEqual(15, result);
        try std.testing.expectEqual(0, carry);
    }
    {
        const carry: u64 = 1;
        const result = helpers.adcNoCarry(5, 10, &carry);
        try std.testing.expectEqual(16, result);
        try std.testing.expectEqual(1, carry);
    }
    {
        const carry: u64 = 1;
        const result = helpers.adcNoCarry(std.math.maxInt(u64), 1, &carry);
        try std.testing.expectEqual(1, result);
        try std.testing.expectEqual(1, carry);
    }
}

test "sbb" {
    {
        var a: u64 = 15;
        const borrow = helpers.sbb(&a, 5, 0);
        try std.testing.expectEqual(10, a);
        try std.testing.expectEqual(0, borrow);
    }
    {
        var a: u64 = 5;
        const borrow = helpers.sbb(&a, 10, 0);
        try std.testing.expectEqual(std.math.maxInt(u64) - 4, a);
        try std.testing.expectEqual(1, borrow);
    }
    {
        var a: u64 = 15;
        const borrow = helpers.sbb(&a, 5, 1);
        try std.testing.expectEqual(9, a);
        try std.testing.expectEqual(0, borrow);
    }
    {
        var a: u64 = 0;
        const borrow = helpers.sbb(&a, std.math.maxInt(u64), 1);
        try std.testing.expectEqual(0, a);
        try std.testing.expectEqual(1, borrow);
    }
}

test "sbb small" {
    {
        var a: u64 = 15;
        const borrow = helpers.sbbSmall(&a, 5, 0);
        try std.testing.expectEqual(10, a);
        try std.testing.expectEqual(0, borrow);
    }
    {
        var a: u64 = 5;
        const borrow = helpers.sbbSmall(&a, 10, 0);
        try std.testing.expectEqual(std.math.maxInt(u64) - 4, a);
        try std.testing.expectEqual(1, borrow);
    }
    {
        var a: u64 = 15;
        const borrow = helpers.sbbSmall(&a, 5, 1);
        try std.testing.expectEqual(9, a);
        try std.testing.expectEqual(0, borrow);
    }
    {
        var a: u64 = 0;
        const borrow = helpers.sbbSmall(&a, std.math.maxInt(u64), 1);
        try std.testing.expectEqual(0, a);
        try std.testing.expectEqual(1, borrow);
    }
}

test "mac" {
    {
        var carry: u64 = 0;
        const result = helpers.mac(1, 2, 3, &carry);
        try std.testing.expectEqual(7, result);
        try std.testing.expectEqual(0, carry);
    }
    {
        var carry: u64 = 0;
        const result = helpers.mac(std.math.maxInt(u64), std.math.maxInt(u64), 1, &carry);
        try std.testing.expectEqual(std.math.maxInt(u64) - 1, result);
        try std.testing.expectEqual(1, carry);
    }
}

test "mac discard" {
    {
        var carry: u64 = 0;
        helpers.macDiscard(1, 2, 3, &carry);
        try std.testing.expectEqual(0, carry);
    }
    {
        var carry: u64 = 0;
        helpers.macDiscard(std.math.maxInt(u64), std.math.maxInt(u64), 1, &carry);
        try std.testing.expectEqual(1, carry);
    }
}

test "mac with carry" {
    {
        var carry: u64 = 0;
        helpers.macDiscard(1, 2, 3, &carry);
        try std.testing.expectEqual(0, carry);
    }
    {
        var carry: u64 = 0;
        helpers.macDiscard(std.math.maxInt(u64), std.math.maxInt(u64), 1, &carry);
        try std.testing.expectEqual(1, carry);
    }
}

// Test cases copied from arkworks/algebra
// https://github.com/arkworks-rs/algebra/blob/750e28aab9fb5d66d4b7f8d8d9510bba633ae89d/ff/src/biginteger/tests.rs
test "general" {
    const S = struct {
        fn run(comptime size: usize, one: comptime_int, two: comptime_int) !void {
            const B = BigInt(size);
            const zero: B = .zero;

            // a + 0 = a
            {
                var a: B = .int(one);
                try std.testing.expect(!a.addWithCarry(zero));
                try std.testing.expectEqual(one, a.toInt());
            }
            // a - 0 = a
            {
                var a: B = .int(one);
                try std.testing.expect(!a.subWithBorrow(zero));
                try std.testing.expectEqual(one, a.toInt());
            }
            // a - a = 0
            {
                var a: B = .int(one);
                try std.testing.expect(!a.subWithBorrow(a));
                try std.testing.expectEqual(0, a.toInt());
            }
            // a + b = b + a
            {
                var a: B = .int(one);
                var b: B = .int(two);

                try std.testing.expectEqual(
                    a.addWithCarry(.int(two)),
                    b.addWithCarry(.int(one)),
                );
                try std.testing.expectEqual(
                    a.toInt(),
                    b.toInt(),
                );
            }
            // a << 0 = a
            {
                var a: B = .int(one);
                a.shl(0);
                try std.testing.expectEqual(one, a.toInt());
            }
            // a * 2 = a + a
            {
                var a: B = .int(one);
                try std.testing.expect(!a.mul2());
                var b: B = .int(one);
                _ = b.addWithCarry(.int(one));
                try std.testing.expectEqual(a.toInt(), b.toInt());
            }
            // a * 1 = a
            {
                var a: B = .int(one);
                try std.testing.expectEqual(
                    a.toInt(),
                    a.mulLow(.int(1)).toInt(),
                );
            }
            // a * 2 = a + a
            {
                var a: B = .int(one);
                a = a.mulLow(.int(2));

                var b: B = .int(one);
                _ = b.addWithCarry(.int(one));

                try std.testing.expectEqual(
                    a.toInt(),
                    b.toInt(),
                );
            }
            // a * b = b * a
            try std.testing.expectEqual(
                B.int(one).mulLow(.int(two)).toInt(),
                B.int(two).mulLow(.int(one)).toInt(),
            );
            // a * 0 = 0
            try std.testing.expect(B.int(one).mulLow(.zero).isZero());
            // a * 2 * 2 ... * 2 = a *^2n
            {
                var a: B = .int(one);
                for (0..20) |_| {
                    a = a.mulLow(.int(2));
                }
                var b: B = .int(one);
                b.shl(20);
                try std.testing.expectEqual(
                    a.toInt(),
                    b.toInt(),
                );
            }
            // a * 0 = (0, 0)
            try std.testing.expectEqual(
                .{ B.zero, B.zero },
                B.int(one).mul(.zero),
            );
            // a * 1 = (a, 0)
            try std.testing.expectEqual(
                .{ B.int(one), B.zero },
                B.int(one).mul(.int(1)),
            );
            // max + max = max * 2
            {
                var max_plus_max: B = .max;
                _ = max_plus_max.addWithCarry(.max);

                try std.testing.expectEqual(
                    .{ max_plus_max, B.int(1) },
                    B.max.mul(.int(2)),
                );
            }
        }
    };

    try S.run(64, 1, 2);
    try S.run(128, 3, 4);
    try S.run(192, 1, 2);
    try S.run(256, 3, 4);
    try S.run(384, 1, 2);
    try S.run(512, 3, 4);
}
