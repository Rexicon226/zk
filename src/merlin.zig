//! Provides utilities for Merlin transcripts, message framing, etc.
//!
//! https://merlin.cool/use/protocol.html

const std = @import("std");
const build_options = @import("zk.zig").build_options;
const builtin = @import("builtin");

const Keccak1600 = std.crypto.core.keccak.KeccakF(1600);
const Ed25519 = std.crypto.ecc.Edwards25519;
const Scalar = Ed25519.scalar.Scalar;
const Ristretto255 = std.crypto.ecc.Ristretto255;

pub const Strobe128 = struct {
    state: Keccak1600,
    position: u8,
    begin: u8,
    flags: Flags,

    pub const Flags = packed struct(u8) {
        I: bool = false,
        A: bool = false,
        C: bool = false,
        T: bool = false,
        M: bool = false,
        K: bool = false,
        _padding: u2 = 0,
    };

    /// Hardcodes security level 128.
    pub const R = 166;

    pub fn init(label: []const u8) Strobe128 {
        const initial_state = state: {
            var state: [200]u8 = .{0} ** 200;
            state[0..6].* = .{ 1, R + 2, 1, 0, 1, 96 };
            state[6..18].* = "STROBEv1.0.2".*;

            var k = Keccak1600.init(state);
            k.permute();

            break :state k;
        };

        var strobe: Strobe128 = .{
            .state = initial_state,
            .position = 0,
            .begin = 0,
            .flags = .{},
        };
        strobe.metaAd(label, false);

        return strobe;
    }

    pub fn beginOp(self: *Strobe128, flags: Flags, more: bool) void {
        // Check if we're continuing a previous operation.
        if (more) {
            std.debug.assert(self.flags == flags);
            return;
        }

        // Skip adjusting direction information.
        std.debug.assert(!flags.T);

        const old_begin = self.begin;
        self.begin = self.position + 1;
        self.flags = flags;

        self.absorb(&.{ old_begin, @bitCast(flags) });

        // Force permute if C or K are set.
        const force_f = flags.C or flags.K;
        if (force_f and self.position != 0) {
            self.permuteState();
        }
    }

    fn permuteState(self: *Strobe128) void {
        const state: *[200]u8 = @ptrCast(&self.state.st);
        state[self.position] ^= self.begin;
        state[self.position + 1] ^= 0x04;
        state[R + 1] ^= 0x80;

        self.state.permute();
        self.position = 0;
        self.begin = 0;
    }

    fn absorb(self: *Strobe128, data: []const u8) void {
        const state: *[200]u8 = @ptrCast(&self.state.st);
        for (data) |byte| {
            state[self.position] ^= byte;
            self.position += 1;
            if (self.position == R) {
                self.permuteState();
            }
        }
    }

    fn squeeze(self: *Strobe128, destination: []u8) void {
        const state: *[200]u8 = @ptrCast(&self.state.st);
        for (destination) |*byte| {
            byte.* = state[self.position];
            state[self.position] = 0;
            self.position += 1;
            if (self.position == R) {
                self.permuteState();
            }
        }
    }

    fn overwrite(self: *Strobe128, destination: []const u8) void {
        const state: *[200]u8 = @ptrCast(&self.state.st);
        for (destination) |byte| {
            state[self.position] = byte;
            self.position += 1;
            if (self.position == R) {
                self.permuteState();
            }
        }
    }

    pub fn metaAd(self: *Strobe128, data: []const u8, more: bool) void {
        self.beginOp(.{ .M = true, .A = true }, more);
        self.absorb(data);
    }

    pub fn ad(self: *Strobe128, data: []const u8, more: bool) void {
        self.beginOp(.{ .A = true }, more);
        self.absorb(data);
    }

    pub fn prf(self: *Strobe128, destination: []u8, more: bool) void {
        self.beginOp(.{ .I = true, .A = true, .C = true }, more);
        self.squeeze(destination);
    }

    pub fn key(self: *Strobe128, destination: []u8, more: bool) void {
        self.beginOp(.{ .A = true, .C = true }, more);
        self.overwrite(destination);
    }

    test "conformance" {
        var s1 = Strobe128.init("Conformance Test Protocol");
        const msg: [1024]u8 = .{99} ** 1024;

        s1.metaAd("ms", false);
        s1.metaAd("g", true);
        s1.ad(&msg, false);

        var prf1: [32]u8 = .{0} ** 32;
        s1.metaAd("prf", false);
        s1.prf(&prf1, false);

        try std.testing.expectEqualSlices(
            u8,
            &.{
                0xb4, 0x8e, 0x64, 0x5c, 0xa1, 0x7c, 0x66, 0x7f,
                0xd5, 0x20, 0x6b, 0xa5, 0x7a, 0x6a, 0x22, 0x8d,
                0x72, 0xd8, 0xe1, 0x90, 0x38, 0x14, 0xd3, 0xf1,
                0x7f, 0x62, 0x29, 0x96, 0xd7, 0xcf, 0xef, 0xb0,
            },
            &prf1,
        );

        s1.metaAd("key", false);
        s1.key(&prf1, false);

        @memset(&prf1, 0);

        s1.metaAd("prf", false);
        s1.prf(&prf1, false);

        try std.testing.expectEqualSlices(
            u8,
            &.{
                0x7,  0xe4, 0x5c, 0xce, 0x80, 0x78, 0xce, 0xe2,
                0x59, 0xe3, 0xe3, 0x75, 0xbb, 0x85, 0xd7, 0x56,
                0x10, 0xe2, 0xd1, 0xe1, 0x20, 0x1c, 0x5f, 0x64,
                0x50, 0x45, 0xa1, 0x94, 0xed, 0xd4, 0x9f, 0xf8,
            },
            &prf1,
        );
    }
};

pub fn Transcript(Domains: type) type {
    return struct {
        strobe: Strobe128,

        const T = @This();

        const Setup = struct {
            label: []const u8,
            message: Message,
        };

        const Message = union(enum) {
            bytes: []const u8,
            point: Ristretto255,
            scalar: Scalar,
            u64: u64,
        };

        pub fn init(comptime seperator: Domains, inputs: []const Setup) T {
            var transcript: T = .{ .strobe = Strobe128.init("Merlin v1.0") };
            transcript.appendDomSep(seperator);
            for (inputs) |input| transcript.appendMessage(input.label, input.message);
            return transcript;
        }

        pub fn initTest(label: []const u8) T {
            comptime if (!build_options.allow_dangerous_transcript_helpers)
                @compileError("dangerous transcript helpers not enabled");
            var transcript: T = .{ .strobe = Strobe128.init("Merlin v1.0") };
            transcript.appendBytes("dom-sep", label);
            return transcript;
        }

        fn appendBytes(t: *T, label: []const u8, bytes: []const u8) void {
            var data_len: [4]u8 = undefined;
            std.mem.writeInt(u32, &data_len, @intCast(bytes.len), .little);
            t.strobe.metaAd(label, false);
            t.strobe.metaAd(&data_len, true);
            t.strobe.ad(bytes, false);
        }

        fn appendMessage(t: *T, label: []const u8, message: Message) void {
            var buffer: [64]u8 = @splat(0);
            const bytes: []const u8 = switch (message) {
                .bytes => |b| b,
                .point => |*point| &point.toBytes(),
                .scalar => |*scalar| &scalar.toBytes(),
                .u64 => |x| b: {
                    std.mem.writeInt(u64, buffer[0..8], x, .little);
                    break :b buffer[0..8];
                },
            };
            t.appendBytes(label, bytes);
        }

        pub inline fn append(
            t: *T,
            comptime session: *Session,
            comptime ty: Input.Type,
            comptime label: []const u8,
            data: ty.Data(),
        ) if (ty == .validate_point) error{IdentityElement}!void else void {
            // if validate_point fails to validate, we no longer want to check the contract
            // because the function calling append will now return early.
            errdefer session.cancel();

            if (ty == .bytes and !builtin.is_test)
                @compileError("message type `bytes` only allowed in tests");

            // assert correctness
            const input = comptime session.nextInput(ty, label);
            if (ty == .validate_point) try data.rejectIdentity();

            // add the message
            t.appendMessage(input.label, @unionInit(
                Message,
                @tagName(switch (ty) {
                    .validate_point => .point,
                    else => ty,
                }),
                data,
            ));
        }

        /// Helper function to be used in proof creation. We often need to test what will
        /// happen if points are zeroed, and to make sure that the verification fails.
        /// Shouldn't be used outside of the `init` functions.
        pub inline fn appendNoValidate(
            t: *T,
            comptime session: *Session,
            comptime label: []const u8,
            point: Ristretto255,
        ) void {
            const input = comptime session.nextInput(.validate_point, label);
            point.rejectIdentity() catch {}; // ignore the error
            t.appendMessage(input.label, .{ .point = point });
        }

        fn challengeBytes(
            t: *T,
            label: []const u8,
            destination: []u8,
        ) void {
            var data_len: [4]u8 = undefined;
            std.mem.writeInt(u32, &data_len, @intCast(destination.len), .little);

            t.strobe.metaAd(label, false);
            t.strobe.metaAd(&data_len, true);
            t.strobe.prf(destination, false);
        }

        pub inline fn challengeScalar(
            t: *T,
            comptime session: *Session,
            comptime label: []const u8,
        ) Scalar {
            const input = comptime session.nextInput(.challenge, label);
            var buffer: [64]u8 = @splat(0);
            t.challengeBytes(input.label, &buffer);
            // Specifically need reduce64 instead of Scalar.fromBytes64, since
            // we need the Barret reduction to be done with 10 limbs, not 5.
            const compressed = Ed25519.scalar.reduce64(buffer);
            return Scalar.fromBytes(compressed);
        }

        // domain seperation helpers

        pub fn appendDomSep(t: *T, comptime seperator: Domains) void {
            t.appendBytes("dom-sep", @tagName(seperator));
        }

        pub fn appendRangeProof(
            t: *T,
            comptime mode: enum { range, inner },
            n: comptime_int,
        ) void {
            t.appendDomSep(switch (mode) {
                .range => .@"range-proof",
                .inner => .@"inner-product",
            });
            t.appendMessage("n", .{ .u64 = n });
        }

        // sessions

        pub const Input = struct {
            label: []const u8,
            type: Type,

            const Type = enum {
                bytes,
                scalar,
                challenge,
                point,
                validate_point,

                pub fn Data(comptime t: Type) type {
                    return switch (t) {
                        .bytes => []const u8,
                        .scalar => Scalar,
                        .validate_point, .point => Ristretto255,
                        .challenge => unreachable, // call `challenge*`
                    };
                }
            };

            fn check(self: Input, t: Type, label: []const u8) void {
                std.debug.assert(self.type == t);
                std.debug.assert(std.mem.eql(u8, self.label, label));
            }
        };

        pub const Contract = []const Input;

        pub const Session = struct {
            i: u8,
            contract: Contract,
            err: bool, // if validate_point errors, we skip the finish() check

            pub inline fn nextInput(comptime self: *Session, t: Input.Type, label: []const u8) Input {
                comptime {
                    defer self.i += 1;
                    const input = self.contract[self.i];
                    input.check(t, label);
                    return input;
                }
            }

            pub inline fn finish(comptime self: *Session) void {
                // For performance, we have certain computations (specifically in `init` functions)
                // which skip the last parts of transcript when they aren't needed.
                //
                // By performing this check, we still ensure that they do those extra computations when in Debug mode,
                // but are allowed to skip them in a release build.
                if (builtin.mode == .Debug and !self.err and self.i != self.contract.len) {
                    @compileError("contract unfulfilled");
                }
            }

            inline fn cancel(comptime self: *Session) void {
                comptime self.err = true;
            }
        };

        pub inline fn getSession(comptime contract: []const Input) Session {
            comptime {
                // contract should always end in a challenge
                const last_contract = contract[contract.len - 1];
                std.debug.assert(last_contract.type == .challenge);
                return .{ .i = 0, .contract = contract, .err = false };
            }
        }
    };
}

test "equivalence" {
    const T = Transcript(enum {
        fn Data(_: @This()) type {
            unreachable;
        }
    });
    var transcript = T.initTest("test protocol");

    comptime var session = T.getSession(&.{
        .{ .label = "some label", .type = .bytes },
        .{ .label = "challenge", .type = .challenge },
    });
    transcript.append(&session, .bytes, "some label", "some data");

    var bytes: [32]u8 = undefined;
    transcript.challengeBytes("challenge", &bytes);

    try std.testing.expectEqualSlices(u8, &.{
        0xd5, 0xa2, 0x19, 0x72, 0xd0, 0xd5, 0xfe, 0x32,
        0xc,  0xd,  0x26, 0x3f, 0xac, 0x7f, 0xff, 0xb8,
        0x14, 0x5a, 0xa6, 0x40, 0xaf, 0x6e, 0x9b, 0xca,
        0x17, 0x7c, 0x3,  0xc7, 0xef, 0xcf, 0x6,  0x15,
    }, &bytes);
}
