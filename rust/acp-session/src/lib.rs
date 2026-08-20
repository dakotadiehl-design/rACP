//! Full-profile ACP session engine (Tokio).
//!
//! Handshake, capability/encoding negotiation, inbound admission, sequencing,
//! and loopback transport. This is the Rust counterpart of `acp.session.Session`.

pub mod negotiate;
pub mod registry;
pub mod remote;
pub mod session;

pub use acp_model::{Capability, NodeIdentity, Role};
pub use remote::{InvokeResult, RemoteAuthority, RemoteSession};
pub use session::{
    default_caps, identity, AnyTransport, FramedTcp, Loopback, Session, SessionError, SessionState,
};
