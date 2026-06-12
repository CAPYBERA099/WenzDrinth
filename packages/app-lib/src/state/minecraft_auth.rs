use crate::ErrorKind;
use crate::util::fetch::INSECURE_REQWEST_CLIENT;
use chrono::{DateTime, Duration, TimeZone, Utc};
use dashmap::DashMap;
use heck::ToTitleCase;
use p256::ecdsa::SigningKey;
use p256::pkcs8::{EncodePrivateKey, LineEnding};
use reqwest::{Response, StatusCode, Url};
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::borrow::Cow;
use std::collections::HashMap;
use std::future::Future;
use std::hash::{BuildHasherDefault, DefaultHasher};
use std::ops::Deref;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use uuid::Uuid;

// ── ely.by configuration ────────────────────────────────────────────────
const ELY_CLIENT_ID: &str = "wenzrinth";
const ELY_CLIENT_SECRET: &str = "";
const ELY_AUTH_URL: &str = "https://account.ely.by/oauth2/v1";
const ELY_TOKEN_URL: &str = "https://account.ely.by/api/oauth2/v1/token";
const ELY_PROFILE_URL: &str = "https://account.ely.by/api/account/v1/info";
const ELY_REDIRECT_URI: &str = "http://localhost:25575/callback";
const ELY_SESSION_URL: &str = "https://authserver.ely.by";

pub const AUTHLIB_INJECTOR_URL: &str =
    "https://authlib-injector.yushi.moe/artifact/latest/authlib-injector.jar";

pub const ELY_AUTHLIB_SERVER: &str = "https://authserver.ely.by";

/// User-Agent used for Minecraft services API requests.
pub const MINECRAFT_SERVICES_USER_AGENT: &str =
    "WenzDrinth (https://github.com/CAPYBERA099/WenzDrinth)";

// ── Legacy types (kept for legacy_converter compatibility) ──────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceToken {
    pub issue_instant: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub token: String,
    pub display_claims: HashMap<String, serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceTokenKey {
    pub id: Uuid,
    #[serde(skip, default)]
    pub key: Option<SigningKey>,
    pub x: String,
    pub y: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeviceTokenPair {
    pub token: DeviceToken,
    pub key: DeviceTokenKey,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RequestWithDate<T> {
    pub date: DateTime<Utc>,
    pub value: T,
}

impl DeviceTokenPair {
    pub async fn upsert(
        &self,
        exec: impl sqlx::Executor<'_, Database = sqlx::Sqlite>,
    ) -> crate::Result<()> {
        let uuid = self.key.id.as_hyphenated().to_string();
        let issue_instant = self.token.issue_instant.timestamp();
        let not_after = self.token.not_after.timestamp();
        let key = self
            .key
            .key
            .as_ref()
            .expect("DeviceTokenPair.key must be set when upserting")
            .to_pkcs8_pem(LineEnding::default())
            .map_err(MinecraftAuthenticationError::PEMSerialize)?
            .to_string();
        let display_claims = serde_json::to_string(&self.token.display_claims)?;

        sqlx::query!(
            "
            INSERT INTO minecraft_device_tokens (id, uuid, private_key, x, y, issue_instant, not_after, token, display_claims)
            VALUES (0, $1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (id) DO UPDATE SET
                uuid = $1,
                private_key = $2,
                x = $3,
                y = $4,
                issue_instant = $5,
                not_after = $6,
                token = $7,
                display_claims = jsonb($8)
            ",
            uuid,
            key,
            self.key.x,
            self.key.y,
            issue_instant,
            not_after,
            self.token.token,
            display_claims,
        )
        .execute(exec)
        .await?;

        Ok(())
    }
}

// ── Auth steps ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub enum MinecraftAuthStep {
    ElyOAuthToken,
    ElyRefreshToken,
    ElyProfile,
}

#[derive(thiserror::Error, Debug)]
pub enum MinecraftAuthenticationError {
    #[error("Failed to serialize body to JSON during step {step:?}: {source}")]
    SerializeBody {
        step: MinecraftAuthStep,
        #[source]
        source: serde_json::Error,
    },
    #[error(
        "Failed to deserialize response to JSON during step {step:?}: {source}. Status Code: {status_code} Body: {raw}"
    )]
    DeserializeResponse {
        step: MinecraftAuthStep,
        raw: String,
        #[source]
        source: serde_json::Error,
        status_code: StatusCode,
    },
    #[error("Request failed during step {step:?}: {source}")]
    Request {
        step: MinecraftAuthStep,
        #[source]
        source: reqwest::Error,
    },
    #[error("ely.by authentication error: {0}")]
    ElyError(String),
    #[error("PEM serialization error")]
    PEMSerialize(#[from] p256::pkcs8::Error),
}

// ── Login flow ──────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct MinecraftLoginFlow {
    pub auth_request_uri: String,
}

/// Simple percent-encoding for URL parameters.
fn percent_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len() * 3);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push('%');
                result.push_str(&format!("{:02X}", byte));
            }
        }
    }
    result
}

/// Begin the ely.by OAuth2 login flow.
#[tracing::instrument]
pub async fn login_begin(
    _exec: impl sqlx::Executor<'_, Database = sqlx::Sqlite> + Copy,
) -> crate::Result<MinecraftLoginFlow> {
    let redirect_encoded = percent_encode(ELY_REDIRECT_URI);
    let auth_url = format!(
        "{ELY_AUTH_URL}/{ELY_CLIENT_ID}?\
         redirect_uri={redirect_encoded}&\
         response_type=code&\
         scope=account_info+minecraft_server_session&\
         prompt=select_account",
    );

    Ok(MinecraftLoginFlow {
        auth_request_uri: auth_url,
    })
}

/// Finish the ely.by OAuth2 login flow.
#[tracing::instrument]
pub async fn login_finish(
    code: &str,
    _flow: MinecraftLoginFlow,
    exec: impl sqlx::Executor<'_, Database = sqlx::Sqlite> + Copy,
) -> crate::Result<Credentials> {
    let oauth_token = ely_token_exchange(code).await?;
    let ely_profile = ely_fetch_profile(&oauth_token.access_token).await?;

    let credentials = Credentials {
        offline_profile: MinecraftProfile {
            id: ely_profile.uuid,
            name: ely_profile.username.clone(),
            skins: Vec::new(),
            capes: Vec::new(),
            fetch_time: Some(Instant::now()),
        },
        access_token: oauth_token.access_token,
        refresh_token: oauth_token.refresh_token,
        expires: Utc::now()
            + Duration::seconds(oauth_token.expires_in as i64),
        active: true,
    };

    credentials.upsert(exec).await?;
    Ok(credentials)
}

// ── ely.by OAuth token exchange ─────────────────────────────────────────

#[derive(Deserialize, Debug)]
struct ElyOAuthToken {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

#[tracing::instrument]
async fn ely_token_exchange(
    code: &str,
) -> Result<ElyOAuthToken, MinecraftAuthenticationError> {
    let mut params = HashMap::new();
    params.insert("client_id", ELY_CLIENT_ID);
    params.insert("client_secret", ELY_CLIENT_SECRET);
    params.insert("redirect_uri", ELY_REDIRECT_URI);
    params.insert("grant_type", "authorization_code");
    params.insert("code", code);

    let res = auth_retry(|| {
        INSECURE_REQWEST_CLIENT
            .post(ELY_TOKEN_URL)
            .header("Accept", "application/json")
            .form(&params)
            .send()
    })
    .await
    .map_err(|source| MinecraftAuthenticationError::Request {
        source,
        step: MinecraftAuthStep::ElyOAuthToken,
    })?;

    let status = res.status();
    let text = res.text().await.map_err(|source| {
        MinecraftAuthenticationError::Request {
            source,
            step: MinecraftAuthStep::ElyOAuthToken,
        }
    })?;

    serde_json::from_str(&text).map_err(|source| {
        MinecraftAuthenticationError::DeserializeResponse {
            source,
            raw: text,
            step: MinecraftAuthStep::ElyOAuthToken,
            status_code: status,
        }
    })
}

#[tracing::instrument]
async fn ely_token_refresh(
    refresh_token: &str,
) -> Result<ElyOAuthToken, MinecraftAuthenticationError> {
    let mut params = HashMap::new();
    params.insert("client_id", ELY_CLIENT_ID);
    params.insert("client_secret", ELY_CLIENT_SECRET);
    params.insert("grant_type", "refresh_token");
    params.insert("refresh_token", refresh_token);

    let res = auth_retry(|| {
        INSECURE_REQWEST_CLIENT
            .post(ELY_TOKEN_URL)
            .header("Accept", "application/json")
            .form(&params)
            .send()
    })
    .await
    .map_err(|source| MinecraftAuthenticationError::Request {
        source,
        step: MinecraftAuthStep::ElyRefreshToken,
    })?;

    let status = res.status();
    let text = res.text().await.map_err(|source| {
        MinecraftAuthenticationError::Request {
            source,
            step: MinecraftAuthStep::ElyRefreshToken,
        }
    })?;

    serde_json::from_str(&text).map_err(|source| {
        MinecraftAuthenticationError::DeserializeResponse {
            source,
            raw: text,
            step: MinecraftAuthStep::ElyRefreshToken,
            status_code: status,
        }
    })
}

// ── ely.by profile ──────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
struct ElyProfile {
    pub uuid: Uuid,
    pub username: String,
}

#[tracing::instrument]
async fn ely_fetch_profile(
    access_token: &str,
) -> Result<ElyProfile, MinecraftAuthenticationError> {
    let res = auth_retry(|| {
        INSECURE_REQWEST_CLIENT
            .get(ELY_PROFILE_URL)
            .header("Accept", "application/json")
            .bearer_auth(access_token)
            .send()
    })
    .await
    .map_err(|source| MinecraftAuthenticationError::Request {
        source,
        step: MinecraftAuthStep::ElyProfile,
    })?;

    let status = res.status();
    let text = res.text().await.map_err(|source| {
        MinecraftAuthenticationError::Request {
            source,
            step: MinecraftAuthStep::ElyProfile,
        }
    })?;

    serde_json::from_str(&text).map_err(|source| {
        MinecraftAuthenticationError::DeserializeResponse {
            source,
            raw: text,
            step: MinecraftAuthStep::ElyProfile,
            status_code: status,
        }
    })
}

/// Fetch minecraft-compatible profile from ely.by session server.
async fn minecraft_profile(
    access_token: &str,
) -> Result<MinecraftProfile, MinecraftAuthenticationError> {
    let ely_profile = ely_fetch_profile(access_token).await?;

    let url = format!(
        "{ELY_SESSION_URL}/session/minecraft/profile/{}",
        ely_profile.uuid.simple()
    );

    let res = auth_retry(|| {
        INSECURE_REQWEST_CLIENT
            .get(&url)
            .header("Accept", "application/json")
            .timeout(std::time::Duration::from_secs(10))
            .send()
    })
    .await
    .map_err(|source| MinecraftAuthenticationError::Request {
        source,
        step: MinecraftAuthStep::ElyProfile,
    })?;

    let status = res.status();
    let text = res.text().await.map_err(|source| {
        MinecraftAuthenticationError::Request {
            source,
            step: MinecraftAuthStep::ElyProfile,
        }
    })?;

    let mut profile =
        serde_json::from_str::<MinecraftProfile>(&text).map_err(|source| {
            MinecraftAuthenticationError::DeserializeResponse {
                source,
                raw: text,
                step: MinecraftAuthStep::ElyProfile,
                status_code: status,
            }
        })?;
    profile.fetch_time = Some(Instant::now());
    Ok(profile)
}

// ── Credentials ─────────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct Credentials {
    #[serde(rename = "profile")]
    pub offline_profile: MinecraftProfile,
    pub access_token: String,
    pub refresh_token: String,
    pub expires: DateTime<Utc>,
    pub active: bool,
}

pub(super) enum ProfileCacheEntry {
    Hit(Arc<MinecraftProfile>),
    AuthErrorBackoff {
        likely_expired_token: String,
        last_attempt: Instant,
    },
}

pub(super) static PROFILE_CACHE: Mutex<
    HashMap<Uuid, ProfileCacheEntry, BuildHasherDefault<DefaultHasher>>,
> = Mutex::const_new(HashMap::with_hasher(BuildHasherDefault::new()));

const ONLINE_PROFILE_CACHE_MAX_AGE: std::time::Duration =
    std::time::Duration::from_secs(60);
const ONLINE_PROFILE_LIVE_STATE_MAX_AGE: std::time::Duration =
    std::time::Duration::from_secs(5);
const ONLINE_PROFILE_AUTH_ERROR_BACKOFF: std::time::Duration =
    std::time::Duration::from_secs(60);

#[derive(Debug, Clone, Copy)]
enum OnlineProfileCacheIntent {
    NormalRead,
    LiveStateRead,
    RefreshFromMojang,
}

impl OnlineProfileCacheIntent {
    fn max_age(self) -> std::time::Duration {
        match self {
            Self::NormalRead => ONLINE_PROFILE_CACHE_MAX_AGE,
            Self::LiveStateRead => ONLINE_PROFILE_LIVE_STATE_MAX_AGE,
            Self::RefreshFromMojang => std::time::Duration::ZERO,
        }
    }

    fn can_use_stale_on_fetch_error(self) -> bool {
        matches!(self, Self::LiveStateRead)
    }
}

impl Credentials {
    async fn refresh(
        &mut self,
        exec: impl sqlx::Executor<'_, Database = sqlx::Sqlite> + Copy,
    ) -> crate::Result<()> {
        if self.expires > Utc::now() + Duration::minutes(5) {
            return Ok(());
        }

        let oauth_token = ely_token_refresh(&self.refresh_token).await?;

        self.access_token = oauth_token.access_token;
        self.refresh_token = oauth_token.refresh_token;
        self.expires =
            Utc::now() + Duration::seconds(oauth_token.expires_in as i64);

        self.upsert(exec).await?;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    pub async fn online_profile(&self) -> Option<Arc<MinecraftProfile>> {
        self.online_profile_with_cache_intent(
            OnlineProfileCacheIntent::NormalRead,
        )
        .await
    }

    #[tracing::instrument(skip(self))]
    pub async fn online_profile_fresh(&self) -> Option<Arc<MinecraftProfile>> {
        self.online_profile_with_cache_intent(
            OnlineProfileCacheIntent::LiveStateRead,
        )
        .await
    }

    #[tracing::instrument(skip(self))]
    pub async fn refresh_online_profile(
        &self,
    ) -> Option<Arc<MinecraftProfile>> {
        self.online_profile_with_cache_intent(
            OnlineProfileCacheIntent::RefreshFromMojang,
        )
        .await
    }

    async fn online_profile_with_cache_intent(
        &self,
        cache_intent: OnlineProfileCacheIntent,
    ) -> Option<Arc<MinecraftProfile>> {
        let max_age = cache_intent.max_age();
        let stale_profile = {
            let mut profile_cache = PROFILE_CACHE.lock().await;
            let mut remove_cached_entry = false;

            let stale_profile = if let Some(cache_entry) =
                profile_cache.get(&self.offline_profile.id)
            {
                match cache_entry {
                    ProfileCacheEntry::Hit(profile)
                        if profile.is_fresh(max_age) =>
                    {
                        return Some(Arc::clone(profile));
                    }
                    ProfileCacheEntry::Hit(profile) => {
                        Some(Arc::clone(profile))
                    }
                    ProfileCacheEntry::AuthErrorBackoff {
                        likely_expired_token,
                        last_attempt,
                    } if &self.access_token != likely_expired_token
                        || Instant::now()
                            .saturating_duration_since(*last_attempt)
                            > ONLINE_PROFILE_AUTH_ERROR_BACKOFF =>
                    {
                        remove_cached_entry = true;
                        None
                    }
                    ProfileCacheEntry::AuthErrorBackoff { .. } => {
                        return None;
                    }
                }
            } else {
                None
            };

            if remove_cached_entry {
                profile_cache.remove(&self.offline_profile.id);
            }

            stale_profile
        };

        match minecraft_profile(&self.access_token).await {
            Ok(profile) => {
                let profile = Arc::new(profile);
                let cache_entry = ProfileCacheEntry::Hit(Arc::clone(&profile));

                let mut profile_cache = PROFILE_CACHE.lock().await;
                if self.offline_profile.id != profile.id {
                    profile_cache.remove(&self.offline_profile.id);
                }
                profile_cache.insert(profile.id, cache_entry);

                Some(profile)
            }
            Err(
                err @ MinecraftAuthenticationError::DeserializeResponse {
                    status_code: StatusCode::UNAUTHORIZED,
                    ..
                },
            ) => {
                tracing::warn!(
                    "Failed to fetch online profile for UUID {} likely due to stale credentials, backing off: {err}",
                    self.offline_profile.id
                );

                let mut profile_cache = PROFILE_CACHE.lock().await;
                profile_cache.insert(
                    self.offline_profile.id,
                    ProfileCacheEntry::AuthErrorBackoff {
                        likely_expired_token: self.access_token.clone(),
                        last_attempt: Instant::now(),
                    },
                );

                None
            }
            Err(err) => {
                tracing::warn!(
                    "Failed to fetch online profile for UUID {}: {err}",
                    self.offline_profile.id
                );

                if cache_intent.can_use_stale_on_fetch_error() {
                    stale_profile
                } else {
                    None
                }
            }
        }
    }

    pub async fn maybe_online_profile(
        &self,
    ) -> MaybeOnlineMinecraftProfile<'_> {
        let online_profile = self.online_profile().await;
        online_profile.map_or_else(
            || MaybeOnlineMinecraftProfile::Offline(&self.offline_profile),
            MaybeOnlineMinecraftProfile::Online,
        )
    }

    #[tracing::instrument]
    pub async fn get_default_credential(
        exec: impl sqlx::Executor<'_, Database = sqlx::Sqlite> + Copy,
    ) -> crate::Result<Option<Credentials>> {
        let credentials = Self::get_active(exec).await?;

        if let Some(mut creds) = credentials {
            match creds.refresh(exec).await {
                Ok(()) => Ok(Some(creds)),
                Err(err) => {
                    tracing::warn!(
                        "Could not refresh credentials, using cached: {err}",
                    );
                    Ok(Some(creds))
                }
            }
        } else {
            Ok(None)
        }
    }

    // NOTE: SQL strings must match .sqlx/ cached queries EXACTLY (whitespace matters!)
    #[tracing::instrument]
    pub async fn get_active(
        exec: impl sqlx::Executor<'_, Database = sqlx::Sqlite> + Copy,
    ) -> crate::Result<Option<Credentials>> {
        let res = sqlx::query!(
            "
            SELECT
                uuid, active, username, access_token, refresh_token, expires
            FROM minecraft_users
            WHERE active = TRUE
            "
        )
        .fetch_optional(exec)
        .await?;

        Ok(res.map(|row| Credentials {
            offline_profile: MinecraftProfile {
                id: Uuid::parse_str(&row.uuid).unwrap_or_default(),
                name: row.username,
                skins: Vec::new(),
                capes: Vec::new(),
                fetch_time: None,
            },
            access_token: row.access_token,
            refresh_token: row.refresh_token,
            expires: Utc
                .timestamp_opt(row.expires, 0)
                .single()
                .unwrap_or_else(Utc::now),
            active: row.active == 1,
        }))
    }

    #[tracing::instrument]
    pub async fn get_all(
        exec: impl sqlx::Executor<'_, Database = sqlx::Sqlite> + Copy,
    ) -> crate::Result<DashMap<Uuid, Credentials>> {
        let res = sqlx::query!(
            "
            SELECT
                uuid, active, username, access_token, refresh_token, expires
            FROM minecraft_users
            "
        )
        .fetch_all(exec)
        .await?;

        let map = DashMap::new();
        for row in res {
            let uuid = Uuid::parse_str(&row.uuid).unwrap_or_default();
            map.insert(uuid, Credentials {
                offline_profile: MinecraftProfile {
                    id: uuid,
                    name: row.username,
                    skins: Vec::new(),
                    capes: Vec::new(),
                    fetch_time: None,
                },
                access_token: row.access_token,
                refresh_token: row.refresh_token,
                expires: Utc
                    .timestamp_opt(row.expires, 0)
                    .single()
                    .unwrap_or_else(Utc::now),
                active: row.active == 1,
            });
        }

        Ok(map)
    }

    #[tracing::instrument(skip(self))]
    pub async fn upsert(
        &self,
        exec: impl sqlx::Executor<'_, Database = sqlx::Sqlite> + Copy,
    ) -> crate::Result<()> {
        let profile = self.maybe_online_profile().await;
        let expires = self.expires.timestamp();
        let uuid = profile.id.as_hyphenated().to_string();

        if self.active {
            sqlx::query!(
                "
                UPDATE minecraft_users
                SET active = FALSE
                ",
            )
            .execute(exec)
            .await?;
        }

        sqlx::query!(
            "
            INSERT INTO minecraft_users (uuid, active, username, access_token, refresh_token, expires)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (uuid) DO UPDATE SET
                active = $2,
                username = $3,
                access_token = $4,
                refresh_token = $5,
                expires = $6
            ",
            uuid,
            self.active,
            profile.name,
            self.access_token,
            self.refresh_token,
            expires,
        )
        .execute(exec)
        .await?;

        Ok(())
    }

    #[tracing::instrument]
    pub async fn remove(
        uuid: Uuid,
        exec: impl sqlx::Executor<'_, Database = sqlx::Sqlite> + Copy,
    ) -> crate::Result<()> {
        sqlx::query!(
            "
            DELETE FROM minecraft_users WHERE uuid = $1
            ",
            uuid,
        )
        .execute(exec)
        .await?;

        let mut profile_cache = PROFILE_CACHE.lock().await;
        profile_cache.remove(&uuid);

        Ok(())
    }
}

// ── Serialize Credentials for Tauri ─────────────────────────────────────
impl Serialize for Credentials {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut s = serializer.serialize_struct("Credentials", 5)?;
        s.serialize_field("id", &self.offline_profile.id)?;
        s.serialize_field("username", &self.offline_profile.name)?;
        s.serialize_field("access_token", &self.access_token)?;
        s.serialize_field("active", &self.active)?;
        s.serialize_field("profile", &self.offline_profile)?;
        s.end()
    }
}

// ── MinecraftProfile ────────────────────────────────────────────────────

#[derive(
    sqlx::Type, Deserialize, Serialize, Debug, Copy, Clone, PartialEq, Eq,
)]
#[serde(rename_all = "UPPERCASE")]
#[sqlx(rename_all = "UPPERCASE")]
pub enum MinecraftSkinVariant {
    Classic,
    Slim,
    #[serde(other)]
    Unknown,
}

#[derive(
    sqlx::Type, Deserialize, Serialize, Debug, Copy, Clone, PartialEq, Eq,
)]
#[serde(rename_all = "UPPERCASE")]
#[sqlx(rename_all = "UPPERCASE")]
pub enum MinecraftCharacterExpressionState {
    Active,
    Classic,
    Emoting,
    #[serde(other)]
    Unknown,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct MinecraftSkin {
    /// The UUID of this skin object.
    pub id: Uuid,
    /// The selection state of the skin.
    pub state: MinecraftCharacterExpressionState,
    /// The URL to the skin texture.
    pub url: Arc<Url>,
    /// A hash of the skin texture.
    #[serde(
        default,
        rename = "textureKey"
    )]
    pub texture_key: Option<Arc<str>>,
    /// The player model variant this skin is for.
    pub variant: MinecraftSkinVariant,
    /// User-friendly name for the skin.
    #[serde(
        default,
        rename = "alias",
        deserialize_with = "normalize_skin_alias_case"
    )]
    pub name: Option<String>,
}

fn normalize_skin_alias_case<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Ok(<Option<Cow<'_, str>>>::deserialize(deserializer)?
        .map(|alias| alias.to_title_case()))
}

impl MinecraftSkin {
    /// Robustly computes the texture key for this skin.
    pub fn texture_key(&self) -> Arc<str> {
        self.texture_key.as_ref().cloned().unwrap_or_else(|| {
            self.url
                .path_segments()
                .and_then(|mut path_segments| {
                    path_segments.next_back().map(String::from)
                })
                .unwrap_or_else(|| self.id.as_simple().to_string())
                .into()
        })
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct MinecraftCape {
    /// The UUID of the cape.
    pub id: Uuid,
    /// The selection state of the cape.
    pub state: MinecraftCharacterExpressionState,
    /// The URL to the cape texture.
    pub url: Arc<Url>,
    /// The user-friendly name for the cape.
    #[serde(rename = "alias")]
    pub name: Arc<str>,
}

#[derive(Deserialize, Serialize, Debug, Default, Clone)]
pub struct MinecraftProfile {
    /// The UUID of the player.
    #[serde(default)]
    pub id: Uuid,
    /// The username of the player.
    pub name: String,
    /// The skins the player is known to have.
    pub skins: Vec<MinecraftSkin>,
    /// The capes the player is known to have.
    pub capes: Vec<MinecraftCape>,
    #[serde(skip)]
    pub fetch_time: Option<Instant>,
}

impl MinecraftProfile {
    fn is_fresh(&self, max_age: std::time::Duration) -> bool {
        self.fetch_time.is_some_and(|last_profile_fetch_time| {
            Instant::now().saturating_duration_since(last_profile_fetch_time)
                < max_age
        })
    }

    /// Returns the currently selected skin for this profile.
    pub fn current_skin(&self) -> crate::Result<&MinecraftSkin> {
        Ok(self
            .skins
            .iter()
            .find(|skin| {
                skin.state == MinecraftCharacterExpressionState::Active
            })
            .ok_or_else(|| {
                ErrorKind::OtherError("No active skin found".into())
            })?)
    }

    /// Returns the currently selected cape for this profile.
    pub fn current_cape(&self) -> Option<&MinecraftCape> {
        self.capes.iter().find(|cape| {
            cape.state == MinecraftCharacterExpressionState::Active
        })
    }
}

pub enum MaybeOnlineMinecraftProfile<'profile> {
    Online(Arc<MinecraftProfile>),
    Offline(&'profile MinecraftProfile),
}

impl<'profile> MaybeOnlineMinecraftProfile<'profile> {
    pub fn is_online(&self) -> bool {
        matches!(self, Self::Online(_))
    }
}

impl Deref for MaybeOnlineMinecraftProfile<'_> {
    type Target = MinecraftProfile;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Online(p) => p,
            Self::Offline(p) => p,
        }
    }
}

// ── Utility ─────────────────────────────────────────────────────────────

#[tracing::instrument(skip(reqwest_request))]
async fn auth_retry<F>(
    reqwest_request: impl Fn() -> F,
) -> Result<reqwest::Response, reqwest::Error>
where
    F: Future<Output = Result<Response, reqwest::Error>>,
{
    const RETRY_COUNT: usize = 5;
    const RETRY_WAIT: std::time::Duration =
        std::time::Duration::from_millis(250);

    let mut resp = reqwest_request().await;
    for i in 0..RETRY_COUNT {
        match &resp {
            Ok(_) => break,
            Err(err) => {
                if err.is_connect() || err.is_timeout() {
                    if i < RETRY_COUNT - 1 {
                        tracing::debug!(
                            "Request failed with connect error, retrying...",
                        );
                        tokio::time::sleep(RETRY_WAIT).await;
                        resp = reqwest_request().await;
                    } else {
                        break;
                    }
                }
            }
        }
    }

    resp
}
