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

    pub(crate) fn intercept_request(&self, body: &[u8]) -> Result<Bytes, EncryptionBridgeError> {
        let server_request = EncryptionRequest::decode(body)?;
        let mut random = OsRng;
        let private_key = RsaPrivateKey::new(&mut random, RSA_BITS)
            .map_err(|error| EncryptionBridgeError::Rsa(error.to_string()))?;
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
        };
        *self.state.lock() = Some(Negotiation {
            private_key,
            client_public_key_der,
            client_verify_token,
            server_request,
        });
        client_request.encode().map_err(EncryptionBridgeError::from)
    }

    pub(crate) fn intercept_response(
        &self,
        body: &[u8],
        protocol_version: i32,
    ) -> Result<CompletedNegotiation, EncryptionBridgeError> {
        let response = EncryptionResponse::decode(body, protocol_version)?;
        let state = self.state.lock();
        let negotiation = state
            .as_ref()
            .ok_or(EncryptionBridgeError::MissingRequest)?;
        let secret = negotiation
            .private_key
            .decrypt(Pkcs1v15Encrypt, &response.encrypted_secret)
            .map_err(|error| EncryptionBridgeError::Rsa(error.to_string()))?;
        let secret_length = secret.len();
        let shared_secret: [u8; SHARED_SECRET_LENGTH] = secret
            .try_into()
            .map_err(|_| EncryptionBridgeError::InvalidSharedSecret(secret_length))?;
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
        }
        .encode(protocol_version)?;
        Ok(CompletedNegotiation {
            server_response,
            shared_secret,
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

#[derive(Debug)]
pub(crate) struct CompletedNegotiation {
    pub server_response: Bytes,
    pub shared_secret: [u8; SHARED_SECRET_LENGTH],
    pub client_server_hash: String,
    pub upstream_server_hash: String,
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
        };

        let bridge = EncryptionBridge::new();
        let client_request = EncryptionRequest::decode(
            &bridge
                .intercept_request(&server_request.encode().unwrap())
                .unwrap(),
        )
        .unwrap();
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
        }
        .encode(767)
        .unwrap();

        let completed = bridge.intercept_response(&client_response, 767).unwrap();
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
}
