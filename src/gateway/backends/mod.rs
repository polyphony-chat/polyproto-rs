#[cfg(not(feature = "wasm"))]
pub type GatewayBackend = tungstenite::Backend;
#[cfg(not(feature = "wasm"))]
/// The tungstenite gateway backend. Used on non-wasm targets.
pub mod tungstenite;
#[cfg(feature = "wasm")]
/// The wasm gateway backend. Used only on the wasm-target.
pub mod wasm;
#[cfg(feature = "wasm")]
pub type GatewayBackend = wasm::Backend;

pub trait BackendBehavior {}
