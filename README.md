# revoLUT : Rust efficient Versatile Oblivious Look-Up Tables

This repository contains `revoLUT`, a Rust library that reimagines TFHE's Look-Up Tables (LUTs) in the context of homomorphic encryption. The LUTs are using as a first-class object to implement some data-oblivious algorithms.

The paper related to this repository is available [here](https://eprint.iacr.org/2024/1935.pdf) (it hasn't been published yet but it was accepted as a poster at [FHE.org 2025](https://fhe.org/conferences/conference-2025/program)).

Warning: The library is currently under development and refactoring. However, here what we can do to start playing with the library.

## Running the examples

There are few examples in the folder `examples` that can be run by using the following command:
```bash
cargo run --example EXAMPLE_NAME
```
where `EXAMPLE_NAME` is the name of the example file without the `.rs` extension.


## Generate PrivateKey files

For the moment, the main function generate the private key files for the different parameters and save them in files named `PrivateKey<param_name>.toml`. 

```bash
cargo run --release
```

## Running tests

Several tests are present in the `lib.rs` file. To run them, use the following command:
```bash
cargo test --release TEST_NAME -- --nocapture
```

## Running benchmarks

Some benchmarks are present in the `benches` folder, especially for the different sorting algorithms. To run them, use the following command:

```bash
cargo bench --bench BENCH_NAME
```