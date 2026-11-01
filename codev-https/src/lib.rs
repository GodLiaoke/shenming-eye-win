//! Allowlisted HTTPS interception primitives.
//!
//! This crate intentionally separates TLS termination from the game UDP hot
//! path.  It can generate a private installation CA, mint per-host leaves,
//! relay decrypted TLS bytes through bounded observers and optionally record
//! those bytes in a private binary stream.  Nothing here publishes secrets to
//! the web API.

mod authority;
mod extractor;
mod policy;
mod proxy_handler;
mod recorder;
mod relay;

pub use authority::*;
pub use extractor::*;
pub use policy::*;
pub use proxy_handler::*;
pub use recorder::*;
pub use relay::*;
