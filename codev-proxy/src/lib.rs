//! Authenticated and strictly allowlisted SOCKS5 proxy.
//!
//! The proxy implements RFC 1928 TCP CONNECT and UDP ASSOCIATE plus RFC 1929
//! username/password authentication. It intentionally has no open-proxy mode:
//! every client must authenticate and every target must match the configured
//! host and port lists. TCP tunnel handling is injectable so the HTTPS crate
//! can later terminate selected TLS connections without creating a dependency
//! from this crate back to the MITM implementation.

mod config;
mod diagnostics;
mod netbind;
mod policy;
mod profile;
mod server;
mod token;

pub use config::*;
pub use diagnostics::*;
pub use netbind::*;
pub use policy::*;
pub use profile::*;
pub use server::*;
pub use token::*;
