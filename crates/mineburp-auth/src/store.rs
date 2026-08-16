use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct StoredCredential {
    pub account_id: String,
    pub refresh_token: String,
}

impl std::fmt::Debug for StoredCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StoredCredential")
            .field("account_id", &self.account_id)
            .field("refresh_token", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum CredentialStoreError {
    #[error("credential store error: {0}")]
    Backend(String),
}

#[async_trait]
pub trait CredentialStore: Send + Sync + std::fmt::Debug {
    async fn save(&self, credential: StoredCredential) -> Result<(), CredentialStoreError>;
    async fn load(
        &self,
        account_id: &str,
    ) -> Result<Option<StoredCredential>, CredentialStoreError>;
    async fn remove(&self, account_id: &str) -> Result<(), CredentialStoreError>;
}

/// Volatile fallback used in tests and when no OS credential backend is wired.
#[derive(Debug, Clone, Default)]
pub struct MemoryCredentialStore {
    credentials: Arc<RwLock<HashMap<String, StoredCredential>>>,
}

#[async_trait]
impl CredentialStore for MemoryCredentialStore {
    async fn save(&self, credential: StoredCredential) -> Result<(), CredentialStoreError> {
        self.credentials
            .write()
            .insert(credential.account_id.clone(), credential);
        Ok(())
    }

    async fn load(
        &self,
        account_id: &str,
    ) -> Result<Option<StoredCredential>, CredentialStoreError> {
        Ok(self.credentials.read().get(account_id).cloned())
    }

    async fn remove(&self, account_id: &str) -> Result<(), CredentialStoreError> {
        self.credentials.write().remove(account_id);
        Ok(())
    }
}
