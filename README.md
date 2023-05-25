# miniscript-go

A Bitcoin [Miniscript](https://bitcoin.sipa.be/miniscript/) implementation in Go.

⚠️ Disclaimer: this implementation is not reviewed and not fully tested. Do not use it in
production. This is for educational purposes only. ⚠️

This implementation started out as a toy implementation for me to study Miniscript, which turned
into a [blog post
series](https://shiftcrypto.ch/blog/understanding-bitcoin-miniscript-part-1). [Part
3](https://shiftcrypto.ch/blog/understanding-bitcoin-miniscript-part-3/) of that series explains
some of the code found here.

That being said, I consider that this implementation is not far from being production ready.

Currently, only the P2WSH context is supported. Miniscript for Taproot was not yet well specified at
the time of writing. Currently, there is an [open PR at
bitcoin/bitcoin](https://github.com/bitcoin/bitcoin/pull/27255) which, when merged, can be taken as
a reference.

This implementation contains:

- miniscript parser
- type checker
- malleability check
- script length limit check (P2WSH standardness rule)
- op count check (P2WSH consensus rule)
- duplicate pubkey check
- script generation
- witness generation (satisfactions)
- unit tests that create receive addresses based on some miniscripts and spend from them again (see
  `TestRedeem()`).

Unit tests exist to check that this implementation's type checking passes some of the unit tests of
rust-miniscript. See [./testdata](./testdata).

Missing/todo:
- timelock mixing check
- stack size check (P2WSH standardness rule)
- exhaustive unit tests
- witness generation for thresh/multi currently has a naive implementation that is very inefficient
  (exponential runtime). This should be replace with a fast algorithm.
- maybe more
