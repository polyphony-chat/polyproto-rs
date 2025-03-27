# Headaches involving `wasm-bindgen` and overall Rust ⇾ TS/JS bindgen

- `wasm-bindgen` does not support traits, or struct generics with trait bounds like `struct X<S: TraitImplementer>`
- Crates like `ts_rs` might help but would require a more complex build process to assemble a finished TS/JS project
- Worst case: Manually write JS/TS code to bridge the things unsupported by other bindgen libs
  - Would be immensely painful
- Other idea: LOADS of handwritten wrappers for Rust functions, also written in Rust but `wasm-bindgen` compatible.
- For traits like signature, we need to make an extremely generic impl that can be somehow instantiated from js/ts