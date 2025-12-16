//! A cryptography library focused on zero-knowledge, non-interactive proofs of all types.
//! Contains everything used to build up protocols from scratch, only using the stdlib as
//! a dependency.

pub const ciphers = @import("ciphers.zig");
pub const curves = @import("curves.zig");
pub const ff = @import("ff.zig");
pub const merlin = @import("merlin.zig");
pub const pedersen = @import("pedersen.zig");
pub const range_proofs = @import("range_proofs.zig");
pub const signatures = @import("signatures.zig");

/// Global comptime-known build options. Used for things like enabling dangerous
/// transcript helpers for use in benchmarks, etc.
pub const Options = struct {
    allow_dangerous_transcript_helpers: bool = builtin.is_test,
};

const builtin = @import("builtin");
const root = @import("root");
pub const build_options: Options = if (@hasDecl(root, "zk_options")) root.zk_options else .{};

test {
    _ = ciphers;
    _ = curves;
    _ = ff;
    _ = merlin;
    _ = pedersen;
    _ = range_proofs;
    _ = signatures;
}
