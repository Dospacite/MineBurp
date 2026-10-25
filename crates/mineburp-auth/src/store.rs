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

/// OS keyring-backed store. Uses the platform credential manager (Keychain,
/// Credential Manager, Secret Service) so refresh tokens survive restarts
/// without being written to a plaintext file.
#[cfg(feature = "os-keyring")]
#[derive(Debug, Clone)]
pub struct OsCredentialStore {
    service: String,
}

#[cfg(feature = "os-keyring")]
impl OsCredentialStore {
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    /// Runs one keyring operation on the blocking pool. Platform credential
    /// managers block on IPC (Secret Service over D-Bus, Keychain prompts), so
    /// calling them on an async worker would stall unrelated tasks.
    async fn with_entry<T, F>(
        &self,
        account_id: &str,
        operation: F,
    ) -> Result<T, CredentialStoreError>
    where
        T: Send + 'static,
        F: FnOnce(&keyring::Entry) -> Result<T, CredentialStoreError> + Send + 'static,
    {
        let service = self.service.clone();
        let account_id = account_id.to_owned();
        tokio::task::spawn_blocking(move || {
            let entry = keyring::Entry::new(&service, &account_id)
                .map_err(|e| CredentialStoreError::Backend(e.to_string()))?;
            operation(&entry)
        })
        .await
        .map_err(|e| CredentialStoreError::Backend(e.to_string()))?
    }
}

#[cfg(feature = "os-keyring")]
#[async_trait]
impl CredentialStore for OsCredentialStore {
    async fn save(&self, credential: StoredCredential) -> Result<(), CredentialStoreError> {
        let account_id = credential.account_id.clone();
        self.with_entry(&account_id, move |entry| {
            entry
                .set_password(&credential.refresh_token)
                .map_err(|e| CredentialStoreError::Backend(e.to_string()))
        })
        .await
    }

    async fn load(
        &self,
        account_id: &str,
    ) -> Result<Option<StoredCredential>, CredentialStoreError> {
        let owned = account_id.to_owned();
        self.with_entry(account_id, move |entry| match entry.get_password() {
            Ok(token) => Ok(Some(StoredCredential {
                account_id: owned,
                refresh_token: token,
            })),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(CredentialStoreError::Backend(e.to_string())),
        })
        .await
    }

    async fn remove(&self, account_id: &str) -> Result<(), CredentialStoreError> {
        self.with_entry(account_id, |entry| match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(CredentialStoreError::Backend(e.to_string())),
        })
        .await
    }
}
