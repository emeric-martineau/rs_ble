# C header generator to Rust

This projet convert C header to Rust file using [bindgend](https://github.com/rust-lang/rust-bindgen) crate.

In directory `include` put all file that you want convert.

Run `cargo build`. All file in `include` folder convert into `src` folder (one .h file give .rs file).

For bluetooth, you need install linux package:
 * clang,
 * libbluetooth-dev
 * bluez
