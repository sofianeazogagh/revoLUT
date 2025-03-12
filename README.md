# revoLUT

This repository contains `revoLUT`, a Rust library that reimagines TFHE's Look-Up Tables (LUTs) in the context of homomorphic encryption. The LUTs are using as a first-class object to implement some data-oblivious algorithms.

## Using TFHE-rs with nightly toolchain

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

## Generate PrivateKey files

```bash
cargo run --release
```

## Running tests

```bash
cargo test --release TEST_NAME -- --nocapture
```

## Running benchmarks

```bash
cargo bench --bench BENCH_NAME
```