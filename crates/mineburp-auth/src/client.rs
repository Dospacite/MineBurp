use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use mineburp_session::minecraft_server_hash;
use rand::RngCore;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use url::Url;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{AuthorizationRequest, PkceVerifier};

const AUTHORIZE_ENDPOINT: &str =
    "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize";
const TOKEN_ENDPOINT: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
const XBOX_AUTH_ENDPOINT: &str = "https://user.auth.xboxlive.com/user/authenticate";
const XSTS_ENDPOINT: &str = "https://xsts.auth.xboxlive.com/xsts/authorize";
const MINECRAFT_LOGIN_ENDPOINT: &str =
    "https://api.minecraftservices.com/authentication/login_with_xbox";
const MINECRAFT_PROFILE_ENDPOINT: &str = "https://api.minecraftservices.com/minecraft/profile";
const MINECRAFT_JOIN_ENDPOINT: &str = "https://sessionserver.mojang.com/session/minecraft/join";

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub client_id: String,
    pub redirect_uri: Url,
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct MinecraftProfile {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct MinecraftSession {
    pub profile: MinecraftProfile,
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at_epoch_seconds: u64,
}

impl std::fmt::Debug for MinecraftSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MinecraftSession")
            .field("profile", &self.profile)
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("expires_at_epoch_seconds", &self.expires_at_epoch_seconds)
            .finish()
    }
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("authentication request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("invalid authentication URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("authentication service rejected the request: {0}")]
    Rejected(String),
    #[error("authentication response omitted {0}")]
    Missing(&'static str),
}

#[derive(Debug, Clone)]
pub struct AuthClient {
    http: Client,
    config: AuthConfig,
}

impl AuthClient {
    #[must_use]
    pub fn new(config: AuthConfig) -> Self {
        Self {
            http: Client::new(),
            config,
        }
    }

    /// Builds a Microsoft OAuth authorization URL and a fresh PKCE verifier.
    ///
    /// # Errors
    ///
    /// Returns an error if the configured authorization endpoint cannot be parsed.
    pub fn authorization_request(&self) -> Result<AuthorizationRequest, AuthError> {
        let verifier = PkceVerifier::generate();
        let mut state_bytes = [0_u8; 24];
        rand::rng().fill_bytes(&mut state_bytes);
        let state = URL_SAFE_NO_PAD.encode(state_bytes);
        let mut url = Url::parse(AUTHORIZE_ENDPOINT)?;
        url.query_pairs_mut()
            .append_pair("client_id", &self.config.client_id)
            .append_pair("response_type", "code")
            .append_pair("redirect_uri", self.config.redirect_uri.as_str())
            .append_pair("scope", "XboxLive.signin offline_access")
            .append_pair("state", &state)
            .append_pair("code_challenge", &verifier.challenge())
            .append_pair("code_challenge_method", "S256")
            .append_pair("prompt", "select_account");
        Ok(AuthorizationRequest {
            url,
            state,
            verifier: Some(verifier),
        })
    }

    /// Exchanges an authorization code and completes the Xbox/Minecraft token chain.
    ///
    /// # Errors
    ///
    /// Returns an error when an identity service rejects a request, a network
    /// operation fails, or a required claim is absent.
    pub async fn exchange_code(
        &self,
        code: &str,
        verifier: &PkceVerifier,
    ) -> Result<MinecraftSession, AuthError> {
        let microsoft = self
            .token_request(&[
                ("client_id", self.config.client_id.as_str()),
                ("code", code),
                ("grant_type", "authorization_code"),
                ("redirect_uri", self.config.redirect_uri.as_str()),
                ("code_verifier", verifier.expose()),
            ])
            .await?;
        self.complete_chain(microsoft).await
    }

    /// Refreshes a Microsoft token and rebuilds the downstream Minecraft session.
    ///
    /// # Errors
    ///
    /// Returns an error when an identity service rejects a request, a network
    /// operation fails, or a required claim is absent.
    pub async fn refresh(&self, refresh_token: &str) -> Result<MinecraftSession, AuthError> {
        let microsoft = self
            .token_request(&[
                ("client_id", self.config.client_id.as_str()),
                ("refresh_token", refresh_token),
                ("grant_type", "refresh_token"),
                ("redirect_uri", self.config.redirect_uri.as_str()),
            ])
            .await?;
        self.complete_chain(microsoft).await
    }

    /// Registers the selected profile with Mojang's session server hash.
    ///
    /// # Errors
    ///
    /// Returns an error when the session service rejects the token or the
    /// request cannot be completed.
    pub async fn join_server(
        &self,
        session: &MinecraftSession,
        server_id: &str,
        shared_secret: &[u8],
        public_key: &[u8],
    ) -> Result<(), AuthError> {
        let digest = minecraft_server_hash(server_id, shared_secret, public_key);
        self.join_server_hash(session, &digest).await
    }

    /// Registers the selected profile with an already computed Minecraft
    /// server hash.
    ///
    /// # Errors
    ///
    /// Returns an error when the session service rejects the token or the
    /// request cannot be completed.
    pub async fn join_server_hash(
        &self,
        session: &MinecraftSession,
        server_hash: &str,
    ) -> Result<(), AuthError> {
        let response = self
            .http
            .post(MINECRAFT_JOIN_ENDPOINT)
            .json(&json!({
                "accessToken": session.access_token,
                "selectedProfile": session.profile.id,
                "serverId": server_hash,
            }))
            .send()
            .await?;
        ensure_success(response).await.map(|_| ())
    }

    async fn token_request(&self, form: &[(&str, &str)]) -> Result<MicrosoftToken, AuthError> {
        let response = self.http.post(TOKEN_ENDPOINT).form(form).send().await?;
        decode_response(response).await
    }

    async fn complete_chain(
        &self,
        microsoft: MicrosoftToken,
    ) -> Result<MinecraftSession, AuthError> {
        let xbox: XboxToken = decode_response(
            self.http
                .post(XBOX_AUTH_ENDPOINT)
                .json(&json!({
                    "Properties": {
                        "AuthMethod": "RPS",
                        "SiteName": "user.auth.xboxlive.com",
                        "RpsTicket": format!("d={}", microsoft.access_token),
                    },
                    "RelyingParty": "http://auth.xboxlive.com",
                    "TokenType": "JWT",
                }))
                .send()
                .await?,
        )
        .await?;
        let xsts: XboxToken = decode_response(
            self.http
                .post(XSTS_ENDPOINT)
                .json(&json!({
                    "Properties": {
                        "SandboxId": "RETAIL",
                        "UserTokens": [xbox.token],
                    },
                    "RelyingParty": "rp://api.minecraftservices.com/",
                    "TokenType": "JWT",
                }))
                .send()
                .await?,
        )
        .await?;
        let user_hash = xsts
            .display_claims
            .xui
            .first()
            .map(|claim| claim.uhs.as_str())
            .ok_or(AuthError::Missing("Xbox user hash"))?;
        let minecraft: MinecraftAccessToken = decode_response(
            self.http
                .post(MINECRAFT_LOGIN_ENDPOINT)
                .json(&json!({
                    "identityToken": format!("XBL3.0 x={user_hash};{}", xsts.token),
                }))
                .send()
                .await?,
        )
        .await?;
        let profile: MinecraftProfile = decode_response(
            self.http
                .get(MINECRAFT_PROFILE_ENDPOINT)
                .bearer_auth(&minecraft.access_token)
                .send()
                .await?,
        )
        .await?;
        Ok(MinecraftSession {
            profile,
            access_token: minecraft.access_token,
            refresh_token: microsoft.refresh_token,
            expires_at_epoch_seconds: now_seconds().saturating_add(minecraft.expires_in),
        })
    }
}

#[derive(Debug, Deserialize)]
struct MicrosoftToken {
    access_token: String,
    refresh_token: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct XboxToken {
    token: String,
    display_claims: DisplayClaims,
}

#[derive(Debug, Deserialize)]
struct DisplayClaims {
    xui: Vec<UserClaim>,
}

#[derive(Debug, Deserialize)]
struct UserClaim {
    uhs: String,
}

#[derive(Debug, Deserialize)]
struct MinecraftAccessToken {
    access_token: String,
    expires_in: u64,
}

async fn decode_response<T: for<'de> Deserialize<'de>>(
    response: reqwest::Response,
) -> Result<T, AuthError> {
    let response = ensure_success(response).await?;
    Ok(response.json().await?)
}

async fn ensure_success(response: reqwest::Response) -> Result<reqwest::Response, AuthError> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    Err(AuthError::Rejected(format!("{status}: {body}")))
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use mineburp_session::minecraft_server_hash;

    #[test]
    fn formats_signed_minecraft_hash() {
        assert_eq!(
            minecraft_server_hash("Notch", &[], &[]),
            "4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48"
        );
    }
}
