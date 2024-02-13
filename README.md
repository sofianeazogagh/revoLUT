# revoLUT


## Using TFHE-rs with nightly toolchain in oblivious-tm-rs

First, install the needed Rust toolchain:
```bash
rustup toolchain install nightly
```

Then, you can either:
Manually specify the toolchain to use in each of the cargo commands:
For example:
```bash
cargo +nightly build
cargo +nightly run
```
Or override the toolchain to use for the current project:
```bash
rustup override set nightly
# cargo will use the `nightly` toolchain.
cargo build
```

## Caching keys

```bash
cargo test --release test_keygen -- --nocapture
```