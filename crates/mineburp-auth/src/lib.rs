//! Microsoft and Minecraft session authentication.
//!
//! The crate deliberately has no UI or launcher dependencies. A desktop shell
//! can provide browser opening and durable credential storage independently.

mod client;
mod pkce;
mod store;

pub use client::{AuthClient, AuthConfig, AuthError, MinecraftProfile, MinecraftSession};
pub use pkce::{AuthorizationRequest, PkceVerifier};
#[cfg(feature = "os-keyring")]
pub use store::OsCredentialStore;
pub use store::{CredentialStore, CredentialStoreError, MemoryCredentialStore, StoredCredential};
