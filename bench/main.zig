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
}

const bulletproofs = struct {
    const Transcript = zk.range_proofs.bulletproofs.Transcript;

    const iterations = 100;
    const warmup = 10;

    fn run() !void {
        try bench(32);
        try bench(64);
        try bench(128);
        try bench(256);
    }

    fn bench(comptime bits: u64) !void {
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

        var total: u64 = 0;
        for (0..iterations + warmup) |i| {
            const start = now();
            std.mem.doNotOptimizeAway(zk.signatures.eddsa.verifySignature(
                signature,
                kp.public_key,
                message,
                true,
            ));
            if (i > warmup) total += now() - start;
        }

        log.info("Ed25519.verify time: {D}", .{total / iterations});
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

        var total: u64 = 0;
        for (0..iterations + warmup) |i| {
            std.mem.doNotOptimizeAway(i);

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

            const start = now();
            std.mem.doNotOptimizeAway(Bn254.compute(p.constSlice(), q.constSlice()));
            if (i > warmup) total += now() - start;
        }

        log.info("Bn254 compute pairing with {d} pairs time: {D}", .{ valid.len / 2 / 192, total / iterations });
    }
};

fn now() u64 {
    return @intCast(std.time.nanoTimestamp());
}
