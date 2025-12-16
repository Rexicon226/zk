const std = @import("std");
const stdx = @import("stdx");

pub const Params = struct {
    /// The order of the finite prime field that the integer is on. Must be a prime.
    order: comptime_int,
    /// Number of bytes used to serialize/encode a field element.
    serialized_size: usize,
    flags: enum { none, sw } = .none,

    fn checkPrime(order: comptime_int) !void {
        if (order < 2) return error.NotPrime;
        var i = 2;
        while (i * i <= order) : (i += 1) {
            if (order % i == 0) return error.NotPrime;
        }
    }
};

/// Element of a prime field.
pub fn Fp(comptime params: Params) type {
    return struct {
        base: Int,

        const Self = @This();

        pub const order = params.order;
        pub const serialized_size = params.serialized_size;
        pub const extension_degree = 1;

        pub const Flags = switch (params.flags) {
            .none => @compileError("not serializable"),
            .sw => @import("../curves/sw.zig").Flags,
        };
        const Int = std.math.IntFittingRange(0, params.order - 1);
        pub const bits = @sizeOf(Int) * 8;
        /// Integer type which "backs" the input. This is the largest we
        /// can allow into the `int` function, and still safely perform the
        /// R2 reduction.
        pub const Single = std.meta.Int(.unsigned, bits);
        /// Integer type large enough to add two reduced Fps together without overflow.
        const AddOne = std.meta.Int(.unsigned, bits + 1);
        /// Integer type large enough to multiply by R2 without overflow.
        const Double = std.meta.Int(.unsigned, bits * 2);

        const R = 1 << bits;
        const R2 = (R * R) % order;
        const mask = R - 1;
        const nprime = (-powi.modinv(order, R)) & mask;

        comptime {
            std.debug.assert(std.math.gcd(params.order, bits) == 1);
            std.debug.assert(params.order < R);
        }

        pub const zero: Self = .{ .base = 0 };
        pub const one: Self = .int(1);
        pub const negative_one: Self = Self.int(1).negate();

        pub fn int(value: Single) Self {
            if (value == 0) return .zero;
            return .{ .base = reduce(@as(Double, value) * R2) };
        }

        pub fn toInt(fp: Self) Int {
            return reduce(fp.base);
        }

        // TODO: make this generic, it is different for twisted edwards
        pub fn fromBytes(input: *const [serialized_size]u8, set_flags: ?*Flags) !Self {
            if (set_flags) |flags| {
                flags.* = @bitCast(input[0]);
                // If both flags are set, return an error.
                // https://github.com/arkworks-rs/algebra/blob/v0.4.2/ec/src/models/short_weierstrass/serialization_flags.rs#L75
                if (flags.infinity and flags.negative) return error.BothFlags;
            }

            var integer: Single = @bitCast(input.*);
            if (set_flags != null) integer &= ~@as(Single, Flags.mask);
            const swapped = @byteSwap(integer);
            if (swapped >= order) return error.TooLarge;
            return .int(swapped);
        }

        // TODO: figure out these bytes swap
        pub fn toBytes(a: Self, out: *[serialized_size]u8) void {
            const large: Single = a.toInt();
            out.* = @bitCast(@byteSwap(large));
        }

        fn reduce(t: Double) Int {
            const m = ((t & mask) * nprime) & mask;
            var u = (t + m * order) >> bits;
            if (u >= order)
                u -= order;
            return @intCast(u);
        }

        pub fn add(a: Self, b: Self) Self {
            var result = @as(AddOne, a.base) + b.base;
            if (result >= order)
                result -= order;
            return .{ .base = @intCast(result) };
        }

        pub fn sub(a: Self, b: Self) Self {
            const t = a.base;
            const y = b.base;
            var result: AddOne = t;
            if (y > t)
                result += order;
            return .{ .base = @intCast(result - y) };
        }

        pub fn mul(a: Self, b: Self) Self {
            const result = reduce(@as(Double, a.base) * b.base);
            return .{ .base = result };
        }

        pub fn sq(a: Self) Self {
            return a.mul(a);
        }

        pub fn dbl(a: Self) Self {
            return a.add(a);
        }

        pub fn triple(a: Self) Self {
            return add(a, add(a, a));
        }

        pub fn negate(a: Self) Self {
            return switch (a.base) {
                0 => a,
                else => |v| .{ .base = order - v },
            };
        }

        pub fn halve(a: Self) Self {
            const basis: AddOne = if (a.base & 0b1 != 0) order else 0;
            return .{ .base = @intCast((a.base + basis) / 2) };
        }

        pub fn pow(a: Self, comptime n: Single) Self {
            comptime std.debug.assert(n != 0);
            var r: Self = .one;
            var iterator = stdx.BitIterator(Single, .big, true).init(n);
            while (iterator.next()) |set| {
                r = r.sq();
                if (set) r = r.mul(a);
            }
            return r;
        }

        /// Inverses the finite field element with Fermat's Little Theorem:
        /// $$a^{p-1} \equiv 1 (\bmod p) \quad \text{for} \quad a \neq 0$$
        /// so:
        /// $$a^{p-2} \equiv a^{-1} (\bmod p)$$
        ///
        /// This holds for all non-zero elements of a prime field.
        ///
        /// TODO: consider returning ?Self for when `a.isZero()` returns true.
        /// We probably don't want to hardcode an assert like this, although
        /// a caller can always trivially check `isZero` themselves.
        pub fn inverse(a: Self) Self {
            std.debug.assert(!a.isZero());
            return a.pow(order - 2);
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.base == b.base;
        }

        pub fn isZero(a: Self) bool {
            return a.eql(.zero);
        }

        pub fn isOne(a: Self) bool {
            return a.eql(.one);
        }

        pub fn format(f: Self, writer: *std.Io.Writer) !void {
            try writer.print("0x{x:0>[1]}", .{ f.base, @sizeOf(Int) * 2 });
        }
    };
}

const powi = struct {
    const T = comptime_int;

    // TODO: replace with stdlib egcd when that's merged
    fn egcd(a: T, b: T, x: *T, y: *T) T {
        if (b == 0) {
            x.* = 1;
            y.* = 0;
            return a;
        }
        var x1 = 0;
        var y1 = 0;
        const g = egcd(b, @mod(a, b), &x1, &y1);
        x.* = y1;
        y.* = x1 - (a / b) * y1;
        return g;
    }

    fn modinv(L: T, R: T) T {
        var x = 0;
        var y = 0;
        const g = egcd(L, R, &x, &y);
        if (g != 1 and g != -1)
            @compileError("no inverse");

        x = @mod(x, R);
        if (x < 0) x += R;
        return x;
    }
};

const TestFp = Fp(.{ .order = 641, .serialized_size = 8 });

test "sub underflow" {
    const x = TestFp.int(300);
    const y = TestFp.int(500);
    const result = x.sub(y);
    try std.testing.expectEqual(
        441,
        result.toInt(),
    );
}

test "mul overflow" {
    const x = TestFp.int(300);
    const y = TestFp.int(500);
    const result = x.mul(y);
    try std.testing.expectEqual(6, result.toInt());
}

test "overflow/underflow edge cases" {
    inline for (.{ TestFp.add, TestFp.sub, TestFp.mul }) |func| {
        for (0..1000) |i| {
            for (0..1000) |j| {
                const x = TestFp.int(@intCast(i));
                const y = TestFp.int(@intCast(j));
                _ = func(x, y);
            }
        }
    }
}

test "computed values" {
    try std.testing.expectEqual(1 << 16, TestFp.R);
    try std.testing.expectEqual(49791, TestFp.nprime);
    try std.testing.expectEqual(640, TestFp.R2);
}

test "negate" {
    const x: TestFp = .int(300);
    const result = x.negate();
    try std.testing.expectEqual(341, result.toInt());
}
