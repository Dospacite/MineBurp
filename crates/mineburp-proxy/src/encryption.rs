use bytes::Bytes;
use mineburp_protocol::{
    EncryptionPacketError, EncryptionRequest, EncryptionResponse, MinecraftCipher,
};
use mineburp_session::minecraft_server_hash;
use parking_lot::Mutex;
use rsa::{
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
    pkcs8::{DecodePublicKey, EncodePublicKey},
    rand_core::{OsRng, RngCore},
};
use subtle::ConstantTimeEq;
use thiserror::Error;
use zeroize::Zeroize as _;

const RSA_BITS: usize = 1_024;
const SHARED_SECRET_LENGTH: usize = 16;
const VERIFY_TOKEN_LENGTH: usize = 4;

#[derive(Debug, Error)]
pub enum EncryptionBridgeError {
    #[error(transparent)]
    Packet(#[from] EncryptionPacketError),
    #[error("RSA operation failed: {0}")]
    Rsa(String),
    #[error("client returned a {0}-byte shared secret; expected 16 bytes")]
    InvalidSharedSecret(usize),
    #[error("client encryption response did not contain the proxy verification token")]
    InvalidVerifyToken,
    #[error("an encryption response arrived before the server encryption request")]
    MissingRequest,
}

#[derive(Debug)]
pub(crate) struct EncryptionBridge {
    state: Mutex<Option<Negotiation>>,
}

#[derive(Debug)]
struct Negotiation {
    private_key: RsaPrivateKey,
    client_public_key_der: Bytes,
    client_verify_token: [u8; VERIFY_TOKEN_LENGTH],
    server_request: EncryptionRequest,
}

impl EncryptionBridge {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(None),
        }
    }

    /// Generates the proxy's RSA key for one login.
    ///
    /// This takes tens of milliseconds of CPU, so the async caller runs it on
    /// the blocking pool rather than on a runtime worker shared with every
    /// other session.
    pub(crate) fn generate_key() -> Result<RsaPrivateKey, EncryptionBridgeError> {
        RsaPrivateKey::new(&mut OsRng, RSA_BITS)
            .map_err(|error| EncryptionBridgeError::Rsa(error.to_string()))
    }

    /// Whether a negotiation is in progress, i.e. the server's request was
    /// replaced and the client's response must be bridged.
    pub(crate) fn is_negotiating(&self) -> bool {
        self.state.lock().is_some()
    }

    pub(crate) fn intercept_request(
        &self,
        server_request: EncryptionRequest,
        private_key: RsaPrivateKey,
        protocol_version: i32,
    ) -> Result<Bytes, EncryptionBridgeError> {
        let mut random = OsRng;
        let public_key = RsaPublicKey::from(&private_key)
            .to_public_key_der()
            .map_err(|error| EncryptionBridgeError::Rsa(error.to_string()))?;
        let mut client_verify_token = [0_u8; VERIFY_TOKEN_LENGTH];
        random.fill_bytes(&mut client_verify_token);
        let client_public_key_der = Bytes::copy_from_slice(public_key.as_ref());
        let client_request = EncryptionRequest {
            server_id: server_request.server_id.clone(),
            public_key_der: client_public_key_der.clone(),
            verify_token: Bytes::copy_from_slice(&client_verify_token),
            trailing: server_request.trailing.clone(),
            should_authenticate: server_request.should_authenticate,
        };
        *self.state.lock() = Some(Negotiation {
            private_key,
            client_public_key_der,
            client_verify_token,
            server_request,
        });
        client_request
            .encode_for(protocol_version)
            .map_err(EncryptionBridgeError::from)
    }

    pub(crate) fn intercept_response(
        &self,
        body: &[u8],
        protocol_version: i32,
    ) -> Result<CompletedNegotiation, EncryptionBridgeError> {
        let response = EncryptionResponse::decode(body, protocol_version)?;
        // One response completes the negotiation; the private key is not
        // needed afterwards and is dropped (and zeroed) with it.
        let negotiation = self
            .state
            .lock()
            .take()
            .ok_or(EncryptionBridgeError::MissingRequest)?;
        let mut secret = negotiation
            .private_key
            .decrypt(Pkcs1v15Encrypt, &response.encrypted_secret)
            .map_err(|error| EncryptionBridgeError::Rsa(error.to_string()))?;
        let secret_length = secret.len();
        let parsed: Result<[u8; SHARED_SECRET_LENGTH], _> = secret.as_slice().try_into();
        secret.zeroize();
        let shared_secret =
            parsed.map_err(|_| EncryptionBridgeError::InvalidSharedSecret(secret_length))?;
        if response.signature.is_some() {
            // A 1.19–1.19.2 client signed the nonce with its profile key
            // instead of echoing the verify token. The signature authenticates
            // this exchange to Mojang's session service; verifying it here
            // would need the profile's public key, and the upstream link is
            // authenticated independently by the session join that follows.
            tracing::debug!("client authenticated with a profile-key nonce signature");
        } else {
            let token = negotiation
                .private_key
                .decrypt(Pkcs1v15Encrypt, &response.encrypted_verify_token)
                .map_err(|error| EncryptionBridgeError::Rsa(error.to_string()))?;
            if token
                .as_slice()
                .ct_eq(negotiation.client_verify_token.as_slice())
                .unwrap_u8()
                != 1
            {
                return Err(EncryptionBridgeError::InvalidVerifyToken);
            }
        }
        let server_public_key =
            RsaPublicKey::from_public_key_der(&negotiation.server_request.public_key_der)
                .map_err(|error| EncryptionBridgeError::Rsa(error.to_string()))?;
        let encrypted_secret = server_public_key
            .encrypt(&mut OsRng, Pkcs1v15Encrypt, &shared_secret)
            .map_err(|error| EncryptionBridgeError::Rsa(error.to_string()))?;
        let encrypted_verify_token = server_public_key
            .encrypt(
                &mut OsRng,
                Pkcs1v15Encrypt,
                &negotiation.server_request.verify_token,
            )
            .map_err(|error| EncryptionBridgeError::Rsa(error.to_string()))?;
        let server_response = EncryptionResponse {
            encrypted_secret: Bytes::from(encrypted_secret),
            encrypted_verify_token: Bytes::from(encrypted_verify_token),
            signature: None,
        }
        .encode(protocol_version)?;
        Ok(CompletedNegotiation {
            server_response,
            shared_secret,
            should_authenticate: negotiation.server_request.should_authenticate,
            client_server_hash: minecraft_server_hash(
                &negotiation.server_request.server_id,
                &shared_secret,
                &negotiation.client_public_key_der,
            ),
            upstream_server_hash: minecraft_server_hash(
                &negotiation.server_request.server_id,
                &shared_secret,
                &negotiation.server_request.public_key_der,
            ),
        })
    }
}

pub(crate) struct CompletedNegotiation {
    pub server_response: Bytes,
    pub shared_secret: [u8; SHARED_SECRET_LENGTH],
    /// Whether the server asked for a session join (always, before 1.20.5).
    pub should_authenticate: bool,
    pub client_server_hash: String,
    pub upstream_server_hash: String,
}

impl std::fmt::Debug for CompletedNegotiation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CompletedNegotiation")
            .field("server_response_length", &self.server_response.len())
            .field("shared_secret", &"[REDACTED]")
            .field("should_authenticate", &self.should_authenticate)
            .finish_non_exhaustive()
    }
}

impl Drop for CompletedNegotiation {
    fn drop(&mut self) {
        self.shared_secret.zeroize();
    }
}

#[derive(Debug)]
pub(crate) struct LinkCipher {
    inner: Mutex<Option<MinecraftCipher>>,
}

impl LinkCipher {
    pub(crate) fn new() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }

    pub(crate) fn activate(&self, shared_secret: [u8; SHARED_SECRET_LENGTH]) {
        *self.inner.lock() = Some(MinecraftCipher::new(shared_secret));
    }

    pub(crate) fn is_active(&self) -> bool {
        self.inner.lock().is_some()
    }

    pub(crate) fn encrypt(&self, bytes: &mut [u8]) {
        if let Some(cipher) = self.inner.lock().as_mut() {
            cipher.encrypt(bytes);
        }
    }

    pub(crate) fn decrypt(&self, bytes: &mut [u8]) {
        if let Some(cipher) = self.inner.lock().as_mut() {
            cipher.decrypt(bytes);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bridge_reencrypts_secret_and_tokens_for_both_links() {
        let mut random = OsRng;
        let server_private = RsaPrivateKey::new(&mut random, RSA_BITS).unwrap();
        let server_public = RsaPublicKey::from(&server_private);
        let server_public_der = server_public.to_public_key_der().unwrap();
        let server_token = [9_u8; VERIFY_TOKEN_LENGTH];
        let server_request = EncryptionRequest {
            server_id: String::new(),
            public_key_der: Bytes::copy_from_slice(server_public_der.as_ref()),
            verify_token: Bytes::copy_from_slice(&server_token),
            trailing: Bytes::new(),
            should_authenticate: true,
        };

        let bridge = EncryptionBridge::new();
        let client_request = EncryptionRequest::decode(
            &bridge
                .intercept_request(
                    server_request,
                    EncryptionBridge::generate_key().unwrap(),
                    767,
                )
                .unwrap(),
        )
        .unwrap();
        assert!(bridge.is_negotiating());
        let proxy_public =
            RsaPublicKey::from_public_key_der(&client_request.public_key_der).unwrap();
        let shared_secret = [0x42_u8; SHARED_SECRET_LENGTH];
        let client_response = EncryptionResponse {
            encrypted_secret: Bytes::from(
                proxy_public
                    .encrypt(&mut random, Pkcs1v15Encrypt, &shared_secret)
                    .unwrap(),
            ),
            encrypted_verify_token: Bytes::from(
                proxy_public
                    .encrypt(&mut random, Pkcs1v15Encrypt, &client_request.verify_token)
                    .unwrap(),
            ),
            signature: None,
        }
        .encode(767)
        .unwrap();

        let completed = bridge.intercept_response(&client_response, 767).unwrap();
        assert!(
            !bridge.is_negotiating(),
            "a completed negotiation is discarded"
        );
        assert!(completed.should_authenticate);
        assert!(!format!("{completed:?}").contains("66"));
        assert_eq!(completed.shared_secret, shared_secret);
        assert_eq!(
            completed.client_server_hash,
            minecraft_server_hash("", &shared_secret, &client_request.public_key_der)
        );
        assert_eq!(
            completed.upstream_server_hash,
            minecraft_server_hash("", &shared_secret, server_public_der.as_ref())
        );
        assert_ne!(completed.client_server_hash, completed.upstream_server_hash);
        let server_response = EncryptionResponse::decode(&completed.server_response, 767).unwrap();
        assert_eq!(
            server_private
                .decrypt(Pkcs1v15Encrypt, &server_response.encrypted_secret)
                .unwrap(),
            shared_secret
        );
        assert_eq!(
            server_private
                .decrypt(Pkcs1v15Encrypt, &server_response.encrypted_verify_token)
                .unwrap(),
            server_token
        );
    }

    #[test]
    fn a_signed_nonce_response_completes_the_bridge() {
        let mut random = OsRng;
        let server_private = RsaPrivateKey::new(&mut random, RSA_BITS).unwrap();
        let server_public_der = RsaPublicKey::from(&server_private)
            .to_public_key_der()
            .unwrap();
        let server_request = EncryptionRequest {
            server_id: String::new(),
            public_key_der: Bytes::copy_from_slice(server_public_der.as_ref()),
            verify_token: Bytes::copy_from_slice(&[7_u8; VERIFY_TOKEN_LENGTH]),
            trailing: Bytes::new(),
            should_authenticate: true,
        };
        let expected_token = server_request.verify_token.clone();

        let bridge = EncryptionBridge::new();
        let client_request = EncryptionRequest::decode(
            &bridge
                .intercept_request(
                    server_request,
                    EncryptionBridge::generate_key().unwrap(),
                    767,
                )
                .unwrap(),
        )
        .unwrap();
        let proxy_public =
            RsaPublicKey::from_public_key_der(&client_request.public_key_der).unwrap();
        let shared_secret = [0x77_u8; SHARED_SECRET_LENGTH];
        // 1.19–1.19.2 shape: the flag is false and a signature replaces the
        // token echo. The signature's contents are opaque to the bridge.
        let client_response = EncryptionResponse {
            encrypted_secret: Bytes::from(
                proxy_public
                    .encrypt(&mut random, Pkcs1v15Encrypt, &shared_secret)
                    .unwrap(),
            ),
            encrypted_verify_token: Bytes::new(),
            signature: Some(Bytes::from(vec![0x5a_u8; 256])),
        }
        .encode(760)
        .unwrap();

        let completed = bridge.intercept_response(&client_response, 760).unwrap();
        assert_eq!(completed.shared_secret, shared_secret);
        let server_response = EncryptionResponse::decode(&completed.server_response, 760).unwrap();
        assert!(server_response.signature.is_none());
        assert_eq!(
            server_private
                .decrypt(Pkcs1v15Encrypt, &server_response.encrypted_verify_token)
                .unwrap(),
            expected_token.as_ref()
        );
    }

    #[test]
    fn a_server_that_skips_authentication_is_reported() {
        let mut random = OsRng;
        let server_private = RsaPrivateKey::new(&mut random, RSA_BITS).unwrap();
        let server_public_der = RsaPublicKey::from(&server_private)
            .to_public_key_der()
            .unwrap();
        // 1.20.5+: the trailing byte is `should_authenticate = false`.
        let server_body = EncryptionRequest {
            server_id: String::new(),
            public_key_der: Bytes::copy_from_slice(server_public_der.as_ref()),
            verify_token: Bytes::copy_from_slice(&[3_u8; VERIFY_TOKEN_LENGTH]),
            trailing: Bytes::from_static(&[0]),
            should_authenticate: false,
        }
        .encode()
        .unwrap();
        let server_request = EncryptionRequest::decode(&server_body).unwrap();
        assert!(!server_request.should_authenticate);

        let bridge = EncryptionBridge::new();
        let client_request = EncryptionRequest::decode(
            &bridge
                .intercept_request(
                    server_request,
                    EncryptionBridge::generate_key().unwrap(),
                    767,
                )
                .unwrap(),
        )
        .unwrap();
        // The client is told the same thing, so it skips its own join too.
        assert!(!client_request.should_authenticate);
        let proxy_public =
            RsaPublicKey::from_public_key_der(&client_request.public_key_der).unwrap();
        let response = EncryptionResponse {
            encrypted_secret: Bytes::from(
                proxy_public
                    .encrypt(&mut random, Pkcs1v15Encrypt, &[1_u8; SHARED_SECRET_LENGTH])
                    .unwrap(),
            ),
            encrypted_verify_token: Bytes::from(
                proxy_public
                    .encrypt(&mut random, Pkcs1v15Encrypt, &client_request.verify_token)
                    .unwrap(),
            ),
            signature: None,
        }
        .encode(767)
        .unwrap();
        let completed = bridge.intercept_response(&response, 767).unwrap();
        assert!(!completed.should_authenticate);
    }
}
