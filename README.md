## General cryptography library, somewhat focused on ZK, but has everything

There is no particular focus of this project, just an accumulation of cool
algorithms I have implemented over time.

NOTE: Is *not* audited nor has any proven security or correctness. Use at
your own risk!

Some notable implementations:

- AVX512 (52-bit limb) Edwards25519
- EdDSA 225 (compatible with `curve25519-dalek`)
- Fiat-Shamir transcripts (comptime verified to be used correctly)
- [Strobe](https://strobe.sourceforge.io/) implementation
- Basic finite field implementation, to-be-optimized
- Short Weierstrass 
    - BLS12-381
    - BN-254 (has pairing checks implemented)
- ChaCha (8,20), heavily SIMD optimized for AVX512
- Pedersen Commitments
- Many sigma-protocols based off of Pedersen commitments
- Bulletproofs implementation
- Falcon 512 signature verification
- (Non-linkable) Ring signature demo, similar to [Triptych construction](https://eprint.iacr.org/2020/018.pdf)