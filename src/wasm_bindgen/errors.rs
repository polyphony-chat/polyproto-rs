use wasm_bindgen::prelude::*;

#[derive(Debug, Clone, Copy)]
#[wasm_bindgen(js_name = "PolyprotoError")]
pub enum JsConstraintError {
    InvalidInput,
}
