const std = @import("std");
const stdx = @import("stdx");
const zk = @import("zk");

const log = std.log.scoped(.bench);
const pedersen = zk.pedersen;
const Bulletproof = zk.range_proofs.Bulletproof;

pub const zk_options: zk.Options = .{
    .allow_dangerous_transcript_helpers = true, // used in bulletproofs benchmarks
};

const Filter = enum {
    all,
    bulletproofs,
    ed25519,
    bn254,
    chacha,
    falcon,

    fn run(b: Filter, f: Filter) bool {
        if (b == .all) return true;
        return b == f;
    }
};

pub fn main() !void {
    const allocator = std.heap.smp_allocator;

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    const filter: Filter = switch (args.len) {
        1 => .all,
        2 => std.meta.stringToEnum(Filter, args[1]) orelse
            std.debug.panic("unknown filter: '{s}'", .{args[1]}),
        else => @panic("invalid number of arguments"),
    };

    log.info("using: ed25519 {s} backend", .{switch (zk.curves.ed25519.use_avx125) {
        true => "avx512",
        false => "generic (avx2/neon)",
    }});

    if (filter.run(.bulletproofs)) {
        try bulletproofs.run();
    }
    if (filter.run(.ed25519)) {
        try ed25519.run();
    }
    if (filter.run(.bn254)) {
        try bn254.run();
    }
    if (filter.run(.chacha)) {
        try chacha.run();
    }
    if (filter.run(.falcon)) {
        try falcon.run();
    }
}

const bulletproofs = struct {
    const Transcript = zk.range_proofs.bulletproofs.Transcript;

    const iterations = 100;
    const warmup = 10;

    fn run() !void {
        try roundtrip(32);
        try roundtrip(64);
        try roundtrip(128);
        try roundtrip(256);
    }

    fn roundtrip(comptime bits: u64) !void {
        const amount_1: u64 = std.math.maxInt(u8);
        const amount_2: u64 = 77;
        const amount_3: u64 = 99;
        const amount_4: u64 = 99;
        const amount_5: u64 = 11;
        const amount_6: u64 = 33;
        const amount_7: u64 = 99;
        const amount_8: u64 = 99;

        const commitment_1, const opening_1 = pedersen.initValue(u64, amount_1);
        const commitment_2, const opening_2 = pedersen.initValue(u64, amount_2);
        const commitment_3, const opening_3 = pedersen.initValue(u64, amount_3);
        const commitment_4, const opening_4 = pedersen.initValue(u64, amount_4);
        const commitment_5, const opening_5 = pedersen.initValue(u64, amount_5);
        const commitment_6, const opening_6 = pedersen.initValue(u64, amount_6);
        const commitment_7, const opening_7 = pedersen.initValue(u64, amount_7);
        const commitment_8, const opening_8 = pedersen.initValue(u64, amount_8);

        const part_size = bits / 8;

        // bench proving
        {
            var total: u64 = 0;
            for (0..iterations + warmup) |i| {
                var transcript = Transcript.initTest("benchmark");
                const start = now();
                std.mem.doNotOptimizeAway(Bulletproof(bits).init(&.{
                    amount_1, amount_2, amount_3, amount_4,
                    amount_5, amount_6, amount_7, amount_8,
                }, &.{
                    part_size, part_size, part_size, part_size,
                    part_size, part_size, part_size, part_size,
                }, &.{
                    opening_1, opening_2, opening_3, opening_4,
                    opening_5, opening_6, opening_7, opening_8,
                }, &transcript));
                if (i > warmup) total += now() - start;
            }

            log.info("Bulletproof({d}) proving time: {D}", .{ bits, total / iterations });
        }

        {
            var transcript = Transcript.initTest("benchmark");
            const proof = try Bulletproof(bits).init(&.{
                amount_1, amount_2, amount_3, amount_4,
                amount_5, amount_6, amount_7, amount_8,
            }, &.{
                part_size, part_size, part_size, part_size,
                part_size, part_size, part_size, part_size,
            }, &.{
                opening_1, opening_2, opening_3, opening_4,
                opening_5, opening_6, opening_7, opening_8,
            }, &transcript);

            var total: u64 = 0;
            for (0..iterations + warmup) |i| {
                var verify_transcript = Transcript.initTest("benchmark");
                const start = now();
                std.mem.doNotOptimizeAway(proof.verify(&.{
                    commitment_1, commitment_2, commitment_3, commitment_4,
                    commitment_5, commitment_6, commitment_7, commitment_8,
                }, &.{
                    part_size, part_size, part_size, part_size,
                    part_size, part_size, part_size, part_size,
                }, &verify_transcript));
                if (i > warmup) total += now() - start;
            }

            log.info("Bulletproof({d}) verify time: {D}", .{ bits, total / iterations });
        }
    }
};

const ed25519 = struct {
    const Ed25519 = std.crypto.sign.Ed25519;

    const iterations = 1000;
    const warmup = 100;

    fn run() !void {
        try verify();
    }

    fn verify() !void {
        const message = "test";

        const kp = Ed25519.KeyPair.generate();
        const signature = try kp.sign(message, null);

        const elapsed = bench(
            iterations,
            warmup,
            zk.signatures.eddsa.verifySignature,
            .{ signature, kp.public_key, message, true },
        );
        log.info("Ed25519.verify time: {D}", .{elapsed / iterations});
    }
};

const bn254 = struct {
    const Bn254 = zk.curves.Bn254;
    const G1 = Bn254.G1;
    const G2 = Bn254.G2;

    const iterations = 1000;
    const warmup = 100;

    fn run() !void {
        try pairing();
    }

    fn pairing() !void {
        // Known to be a valid pairing.
        const valid = "1c76476f4def4bb94541d57ebba1193381ffa7aa76ada664dd31c16024c43f593034dd2920f673e204fee2811c678745fc819b55d3e9d294e45c9b03a76aef41209dd15ebff5d46c4bd888e51a93cf99a7329636c63514396b4a452003a35bf704bf11ca01483bfa8b34b43561848d28905960114c8ac04049af4b6315a416782bb8324af6cfc93537a2ad1a445cfd0ca2a71acd7ac41fadbf933c2a51be344d120a2a4cf30c1bf9845f20c6fe39e07ea2cce61f0c9bb048165fe5e4de877550111e129f1cf1097710d41c4ac70fcdfa5ba2023c6ff1cbeac322de49d1b6df7c2032c61a830e3c17286de9462bf242fca2883585b93870a73853face6a6bf411198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa";

        var p: stdx.BoundedArray(G1.Affine, 10) = .{};
        var q: stdx.BoundedArray(G2.Affine, 10) = .{};
        std.debug.assert(valid.len % 192 == 0);

        const N = 192 * 10;
        var buffer: [N]u8 = .{0} ** N;
        const input = try std.fmt.hexToBytes(&buffer, valid);

        for (0..input.len / 192) |j| {
            try p.append(try .fromBytes(input[j * 192 ..][0..64]));
            try q.append(try .fromBytes(input[j * 192 ..][64..][0..128]));
        }

        const elapsed = bench(iterations, warmup, Bn254.compute, .{ p.constSlice(), q.constSlice() });
        log.info("Bn254 compute pairing with {d} pairs time: {D}", .{ valid.len / 2 / 192, elapsed / iterations });
    }
};

const chacha = struct {
    const ChaCha = zk.ciphers.ChaCha;

    const iterations = 1000;
    const warmup = 100;

    fn run() !void {
        var total: u64 = 0;
        for (0..100) |i| {
            std.mem.doNotOptimizeAway(i);

            var key: [32]u8 = @splat(0);
            std.mem.writeInt(u64, key[0..8], i, .little);
            var state: ChaCha(.twenty) = .init(key);

            const elapsed = bench(1024, 0, ChaCha(.twenty).int, .{&state});
            total += elapsed;
        }
        log.info("ChaCha(20): squeeze 1024 * 64 bits: {D}", .{total / iterations / 1024});
    }
};

const falcon = struct {
    const Falcon512 = zk.signatures.Falcon512;

    const iterations = 100_000;
    const warmup = 10_000;

    const signature_bytes: *const [666]u8 = &.{ 57, 22, 193, 37, 21, 37, 128, 147, 121, 153, 86, 54, 140, 223, 193, 130, 193, 202, 74, 52, 240, 119, 233, 36, 68, 22, 168, 196, 193, 63, 176, 202, 36, 30, 139, 122, 193, 113, 45, 40, 235, 11, 164, 166, 12, 198, 53, 151, 111, 248, 100, 105, 235, 37, 13, 107, 59, 184, 99, 146, 49, 176, 180, 89, 254, 175, 177, 124, 110, 228, 20, 223, 106, 108, 196, 205, 91, 109, 124, 211, 13, 81, 137, 174, 58, 72, 230, 113, 133, 50, 166, 188, 75, 219, 101, 207, 34, 72, 121, 152, 227, 249, 153, 222, 233, 148, 28, 76, 138, 105, 232, 184, 58, 55, 137, 188, 38, 34, 99, 112, 60, 20, 232, 106, 247, 93, 111, 38, 59, 193, 117, 126, 33, 80, 45, 69, 84, 132, 92, 48, 133, 147, 49, 150, 218, 185, 239, 222, 26, 217, 143, 40, 72, 27, 121, 87, 225, 75, 82, 200, 43, 28, 109, 147, 4, 238, 66, 70, 108, 90, 248, 203, 2, 72, 25, 90, 76, 235, 9, 167, 167, 255, 35, 247, 125, 123, 251, 222, 105, 40, 240, 60, 203, 203, 20, 181, 45, 105, 19, 38, 201, 70, 216, 190, 214, 117, 146, 204, 12, 150, 215, 33, 41, 90, 48, 233, 121, 219, 79, 2, 219, 235, 119, 133, 202, 133, 145, 157, 49, 187, 152, 254, 17, 73, 131, 36, 122, 86, 92, 141, 250, 12, 28, 179, 81, 134, 39, 150, 73, 29, 59, 205, 153, 55, 174, 21, 235, 131, 201, 207, 158, 198, 13, 249, 204, 82, 40, 153, 199, 22, 109, 255, 220, 163, 73, 228, 65, 227, 232, 194, 213, 11, 23, 118, 198, 149, 58, 70, 62, 68, 138, 190, 238, 204, 136, 146, 121, 220, 219, 205, 53, 173, 134, 32, 210, 220, 50, 240, 254, 39, 85, 37, 49, 16, 41, 168, 209, 19, 199, 209, 202, 53, 155, 73, 93, 161, 234, 190, 107, 85, 162, 95, 205, 49, 106, 26, 99, 150, 197, 36, 201, 161, 15, 78, 118, 38, 107, 96, 215, 124, 216, 36, 25, 176, 96, 217, 82, 224, 242, 54, 40, 115, 103, 84, 150, 78, 213, 84, 98, 167, 134, 114, 145, 226, 97, 58, 227, 160, 249, 41, 106, 227, 52, 223, 32, 63, 93, 138, 245, 229, 84, 251, 82, 235, 156, 255, 67, 132, 139, 236, 226, 139, 12, 165, 183, 96, 18, 90, 132, 246, 205, 156, 165, 195, 146, 67, 179, 132, 53, 243, 234, 180, 225, 15, 193, 27, 13, 126, 118, 166, 242, 150, 70, 21, 144, 68, 207, 119, 255, 167, 202, 236, 197, 80, 157, 103, 65, 174, 188, 231, 81, 53, 97, 5, 120, 33, 151, 116, 245, 100, 238, 193, 216, 235, 76, 189, 202, 73, 102, 72, 106, 28, 198, 53, 205, 230, 54, 191, 208, 117, 54, 153, 7, 247, 5, 63, 218, 12, 137, 47, 181, 94, 187, 173, 162, 209, 132, 209, 191, 53, 120, 168, 181, 249, 80, 50, 237, 136, 110, 77, 31, 82, 160, 128, 48, 144, 217, 129, 168, 165, 201, 83, 119, 17, 7, 216, 101, 127, 73, 3, 48, 92, 138, 221, 25, 228, 113, 163, 219, 108, 57, 138, 254, 228, 188, 236, 28, 124, 194, 12, 85, 65, 230, 61, 113, 70, 105, 31, 195, 125, 249, 205, 46, 239, 61, 157, 49, 180, 93, 204, 101, 241, 246, 89, 39, 93, 191, 123, 137, 181, 84, 101, 113, 47, 118, 239, 37, 97, 240, 70, 230, 173, 246, 113, 147, 230, 42, 229, 11, 221, 180, 142, 111, 26, 57, 142, 238, 77, 171, 160, 108, 82, 180, 17, 166, 252, 85, 154, 171, 119, 16, 209, 71, 158, 108, 38, 247, 235, 134, 109, 143, 29, 63, 104, 108, 142, 59, 253, 190, 70, 245, 119, 138, 245, 80, 217, 143, 28, 157, 82, 113, 186, 148, 116, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    const pubkey_bytes: *const [897]u8 = &.{ 9, 2, 206, 33, 107, 228, 44, 208, 79, 200, 76, 36, 199, 29, 19, 7, 142, 202, 7, 151, 110, 228, 173, 186, 44, 152, 35, 70, 216, 120, 192, 148, 118, 127, 226, 156, 52, 92, 226, 250, 135, 75, 238, 35, 158, 166, 11, 223, 167, 39, 165, 22, 130, 195, 223, 6, 162, 104, 73, 195, 247, 38, 70, 42, 89, 233, 196, 22, 99, 135, 186, 137, 86, 223, 201, 250, 98, 32, 149, 32, 237, 101, 57, 202, 221, 168, 249, 232, 17, 166, 142, 216, 105, 112, 19, 90, 213, 2, 109, 189, 22, 241, 89, 151, 164, 187, 190, 53, 104, 56, 215, 92, 122, 145, 52, 237, 184, 191, 37, 188, 186, 10, 3, 19, 119, 235, 240, 17, 13, 84, 115, 200, 70, 130, 123, 37, 107, 154, 180, 208, 38, 30, 65, 200, 219, 241, 164, 36, 182, 218, 31, 33, 208, 226, 26, 137, 189, 41, 148, 7, 79, 165, 54, 94, 167, 112, 14, 235, 210, 38, 148, 124, 250, 123, 225, 167, 101, 244, 215, 249, 39, 80, 2, 61, 242, 104, 148, 81, 46, 121, 72, 197, 100, 105, 232, 129, 209, 153, 218, 129, 53, 175, 193, 110, 82, 58, 248, 162, 63, 213, 128, 34, 174, 34, 154, 201, 92, 255, 9, 93, 111, 243, 44, 137, 13, 178, 41, 65, 25, 33, 144, 91, 59, 165, 45, 84, 181, 13, 236, 180, 77, 195, 215, 200, 153, 102, 121, 232, 40, 164, 59, 141, 6, 135, 232, 189, 224, 96, 197, 16, 21, 170, 158, 0, 12, 146, 89, 143, 5, 184, 112, 169, 75, 41, 1, 169, 225, 42, 233, 171, 242, 10, 81, 113, 74, 3, 106, 133, 28, 206, 137, 21, 66, 209, 235, 82, 126, 115, 16, 118, 212, 255, 47, 9, 186, 104, 148, 162, 9, 3, 202, 111, 167, 110, 19, 209, 45, 192, 171, 166, 185, 38, 237, 110, 137, 84, 132, 29, 192, 82, 74, 85, 227, 101, 108, 156, 25, 136, 94, 171, 101, 77, 134, 148, 147, 81, 251, 139, 2, 234, 50, 174, 113, 95, 9, 139, 226, 78, 131, 210, 226, 113, 204, 140, 36, 20, 142, 123, 213, 146, 89, 40, 56, 250, 85, 184, 138, 219, 137, 123, 229, 217, 150, 151, 227, 252, 172, 250, 192, 37, 180, 81, 246, 43, 108, 53, 98, 201, 239, 144, 113, 68, 87, 162, 246, 73, 34, 95, 112, 32, 233, 175, 219, 185, 42, 226, 190, 219, 166, 25, 51, 185, 5, 207, 212, 26, 3, 8, 43, 214, 223, 139, 36, 39, 236, 123, 252, 171, 42, 222, 22, 120, 156, 9, 103, 69, 103, 222, 17, 41, 193, 178, 246, 158, 156, 15, 143, 178, 55, 197, 93, 5, 207, 143, 105, 173, 139, 183, 39, 162, 8, 154, 67, 113, 30, 198, 202, 84, 182, 18, 193, 215, 47, 160, 43, 102, 64, 152, 120, 109, 8, 83, 209, 188, 152, 225, 74, 87, 144, 178, 202, 198, 199, 210, 72, 87, 208, 251, 68, 245, 217, 95, 52, 33, 51, 150, 134, 232, 175, 165, 186, 146, 75, 186, 148, 240, 115, 201, 9, 233, 251, 138, 208, 164, 98, 36, 214, 248, 27, 34, 162, 1, 174, 219, 168, 148, 194, 170, 68, 186, 214, 135, 77, 110, 36, 206, 27, 184, 63, 81, 230, 159, 52, 161, 64, 173, 136, 85, 79, 108, 71, 72, 255, 159, 100, 111, 13, 219, 211, 164, 133, 208, 186, 216, 5, 250, 41, 235, 153, 104, 24, 81, 113, 69, 5, 227, 113, 166, 74, 123, 207, 104, 151, 149, 129, 68, 145, 220, 157, 197, 39, 82, 233, 162, 127, 150, 244, 108, 232, 248, 164, 39, 149, 199, 16, 126, 193, 134, 120, 146, 73, 108, 145, 161, 119, 251, 128, 149, 13, 105, 59, 212, 173, 222, 48, 46, 144, 60, 65, 50, 236, 149, 56, 134, 141, 232, 207, 128, 95, 90, 33, 146, 150, 127, 166, 195, 80, 106, 26, 171, 60, 17, 161, 95, 30, 71, 179, 180, 110, 100, 151, 177, 90, 136, 46, 44, 200, 73, 161, 180, 66, 73, 233, 127, 97, 241, 107, 208, 236, 234, 213, 71, 221, 113, 197, 221, 165, 170, 138, 86, 254, 54, 49, 34, 21, 133, 46, 120, 218, 152, 93, 85, 164, 164, 216, 247, 20, 142, 69, 103, 209, 228, 103, 135, 194, 35, 135, 202, 74, 133, 240, 17, 227, 117, 196, 92, 202, 12, 224, 161, 91, 205, 19, 55, 189, 201, 39, 27, 250, 132, 115, 225, 136, 47, 51, 133, 88, 105, 125, 154, 175, 7, 90, 144, 120, 51, 90, 31, 184, 161, 179, 182, 233, 217, 207, 67, 98, 132, 6, 124, 88, 197, 164, 142, 4, 122, 64, 8, 208, 43, 124, 133, 7, 194, 238, 111, 136, 218, 76, 151, 246, 15, 117, 68, 76, 120, 132, 150, 103, 132, 50, 201, 95, 58, 146, 8, 180, 168, 193, 203, 198, 226, 212, 218, 97, 37, 61, 160, 129, 39, 94, 143, 52, 219, 228, 161, 236, 194, 34, 36, 195, 8, 0, 167, 117, 53, 116, 200, 149, 134, 149, 102, 108, 40, 149, 179, 92, 206, 7, 137, 68, 163, 16, 65, 165, 35, 131, 124, 237, 114, 23, 105, 15, 161, 124, 54, 203, 69, 146, 99, 53, 230, 123, 24, 4, 149, 157 };

    fn run() !void {
        try deserialize();
        try verify();
    }

    noinline fn deserialize() !void {
        const elapsed = bench(iterations, warmup, Falcon512.PublicKey.fromBytes, .{pubkey_bytes});
        log.info("Falcon512: deserialize {D}", .{elapsed / iterations});
    }

    noinline fn verify() !void {
        const data: []const u8 = &.{ 100, 97, 116, 97, 49 };

        const signature: Falcon512.Signature = try .fromBytes(signature_bytes);
        const pubkey: Falcon512.PublicKey = try .fromBytes(pubkey_bytes);

        const elapsed = bench(iterations, warmup, Falcon512.verify, .{ data, signature, pubkey });
        log.info("Falcon512: verify {D}", .{elapsed / iterations});
    }
};

fn now() u64 {
    asm volatile ("");
    return @intCast(std.time.nanoTimestamp());
}

noinline fn bench(iters: usize, warmup: usize, func: anytype, args: anytype) u64 {
    asm volatile ("");
    for (0..warmup) |i| {
        std.mem.doNotOptimizeAway(i);
        asm volatile ("");
        std.mem.doNotOptimizeAway(@call(.never_inline, func, args));
    }
    asm volatile ("");
    const start = now();
    for (0..iters) |i| {
        std.mem.doNotOptimizeAway(i);
        asm volatile ("");
        std.mem.doNotOptimizeAway(@call(.never_inline, func, args));
    }
    asm volatile ("");
    return now() - start;
}
