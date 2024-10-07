use actix_web::{delete, get, post, put, web, HttpResponse, Responder, ResponseError};
use anyhow::Result;
use dotenv::dotenv;
use log;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::env;
use thiserror::Error;

// Import necessary traits and types for authentication
use actix_web::{dev::Payload, error::ErrorUnauthorized, http::header, Error, FromRequest, HttpRequest};
use async_trait::async_trait;
use futures::future::{err, ok, Ready};

use argon2::{self, Config};
use rand::RngCore;
use rand::rngs::OsRng;
use base64::{engine::general_purpose, Engine as _};

type AppResult<T> = Result<T, AppError>;
const COLLECTION: &'static str = "i";
const PRIVATE: &[&str] = &[""];

#[derive(Error, Debug)]
pub struct AppError {
    t: String,
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.t)
    }
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        log::error!("{}", self.to_string());
        HttpResponse::InternalServerError().finish()
    }
}

impl AppError {
    fn new(m: &str, e: impl std::error::Error) -> Self {
        AppError {
            t: format!("{}: {}", m, e.to_string()),
        }
    }

    fn new_plain(m: &str) -> Self {
        AppError { t: m.to_string() }
    }
}

// Authentication extractor
pub struct Auth {
    pub user: String,
}

#[async_trait(?Send)]
impl FromRequest for Auth {
    type Error = Error;

    async fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Result<Self, Self::Error> {
        let client = reqwest::Client::new();

        if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
            if let Ok(auth_str) = auth_header.to_str() {
                // Remove "Bearer " prefix if present
                let token = auth_str.trim_start_matches("Bearer ").to_string();

                // Validate the token
                if let Ok(username) = get_username_by_token(&client, &token).await {
                    return Ok(Auth { user: username });
                } else {
                    return Err(ErrorUnauthorized("Invalid token"));
                }
            }
        }
        Err(ErrorUnauthorized("Unauthorized"))
    }
}

#[shuttle_runtime::main]
async fn actix_web() -> shuttle_actix_web::ShuttleActixWeb<
    impl FnOnce(&mut actix_web::web::ServiceConfig) + Send + Clone + 'static,
> {
    dotenv().ok();

    let config = move |cfg: &mut web::ServiceConfig| {
        cfg.service(register)
            .service(login)
            .service(logout)
            .service(handle_get)
            .service(handle_delete)
            .service(handle_add)
            .service(handle_set)
            .service(handle_search);
    };

    Ok(config.into())
}

fn qdrant_path(path: &str) -> AppResult<String> {
    Ok(format!(
        "{}/{}",
        env::var("QDRANT_URL").map_err(|e| AppError::new("QDRANT_URL env var", e))?,
        path
    ))
}

// --- HANDLERS ---

#[post("/register")]
async fn register(reg_data: web::Json<RegistrationData>) -> Result<impl Responder, AppError> {
    let reg_data = reg_data.into_inner();

    // Hash the password using Argon2
    let salt: [u8; 16] = rand::thread_rng().gen();
    let config = Config::default();
    let password_hash = argon2::hash_encoded(reg_data.password.as_bytes(), &salt, &config)
        .map_err(|e| AppError::new("Hashing password", e))?;

    // Create the User struct
    let user = User {
        username: reg_data.username.clone(),
        password_hash,
    };

    // Store the user in Qdrant
    let client = reqwest::Client::new();
    // Use the username as the point ID
    let point_id = user.username.clone();

    let payload = json!({
        "username": user.username,
        "password_hash": user.password_hash,
    });

    client
        .put(&qdrant_path(&format!(
            "collections/{}/points?wait",
            COLLECTION
        ))?)
        .header("Content-Type", "application/json")
        .body(format!(
            r#"{{"points": [{{"id":"{}", "payload": {}}}]}}"#,
            point_id, payload.to_string()
        ))
        .send()
        .await
        .map_err(|e| AppError::new("upsert user point", e))?;

    Ok(HttpResponse::Ok().finish())
}

#[post("/login")]
async fn login(login_data: web::Json<LoginData>) -> Result<impl Responder, AppError> {
    let login_data = login_data.into_inner();

    let client = reqwest::Client::new();
    // Fetch the user from Qdrant
    let user = get_user_by_username(&client, &login_data.username).await?;

    // Verify the password
    let password_match = argon2::verify_encoded(
        &user.password_hash,
        login_data.password.as_bytes(),
    )
    .map_err(|e| AppError::new("Verifying password", e))?;

    if password_match {
        // Generate a secure token
        let token = generate_secure_token();

        // Store the token in Qdrant associated with the user
        store_token_for_user(&client, &login_data.username, &token).await?;

        // Return the token to the user
        Ok(HttpResponse::Ok().json(json!({ "token": token })))
    } else {
        Ok(HttpResponse::Unauthorized().json("Invalid credentials"))
    }
}

#[post("/logout")]
async fn logout(auth: Auth) -> Result<impl Responder, AppError> {
    let client = reqwest::Client::new();

    // Remove the token from the user's payload

    client
        .post(&qdrant_path(&format!(
            "collections/{}/points/payload/delete?wait",
            COLLECTION
        ))?)
        .header("Content-Type", "application/json")
        .body(format!(
            r#"{{
                "points": ["{}"],
                "keys": ["token"]
            }}"#,
            auth.user
        ))
        .send()
        .await
        .map_err(|e| AppError::new("logout request", e))?;

    Ok(HttpResponse::Ok().finish())
}

#[post("/search")]
async fn handle_search(auth: Auth, q: web::Json<SearchQuery>) -> Result<impl Responder, AppError> {
    let q = q.into_inner();
    let client = reqwest::Client::new();
    let embedding = serde_json::to_string(
        &get_embedding(&q.q)
            .await
            .map_err(|e| AppError::new("getting embedding", e))?,
    )
    .map_err(|e| AppError::new("converting embedding to string in handle search request", e))?;

    let res: serde_json::Value = client
        .post(&qdrant_path(&format!(
            "/collections/{}/points/search",
            COLLECTION
        ))?)
        .header("Content-Type", "application/json")
        .body(format!(
            r#"{{
                "vector": {},
                "limit": {}
            }}"#,
            embedding, q.l
        ))
        .send()
        .await
        .map_err(|e| AppError::new("search_points request", e))?
        .json()
        .await
        .map_err(|e| AppError::new("parse search_points response", e))?;

    Ok(HttpResponse::Ok().json(res))
}

#[get("/")]
async fn handle_get(auth: Auth, query: web::Query<ItemQuery>) -> Result<impl Responder, AppError> {
    let query = query.into_inner();
    let client = reqwest::Client::new();

    match get_point_payload(&client, &query.i).await {
        Ok(payload) => {
            if PRIVATE.contains(&payload.c.as_str()) {
                if payload.u == auth.user {
                    Ok(HttpResponse::Ok().json(&payload.v))
                } else {
                    Ok(HttpResponse::Unauthorized().json("Unauthorized"))
                }
            } else {
                Ok(HttpResponse::Ok().json(&payload))
            }
        }
        Err(_) => Ok(HttpResponse::NotFound().json("Not Found")),
    }
}

#[delete("/")]
async fn handle_delete(auth: Auth, query: web::Query<ItemQuery>) -> Result<impl Responder, AppError> {
    let query = query.into_inner();
    let client = reqwest::Client::new();
    let item = get_point_payload(&client, &query.i)
        .await
        .map_err(|e| AppError::new("getting point payload", e))?;

    if item.u == auth.user {
        client
            .post(&qdrant_path(&format!(
                "/collections/{}/points/delete",
                COLLECTION
            ))?)
            .header("Content-Type", "application/json")
            .body(format!(
                r#"{{
                    "points": [{}]
                }}"#,
                query.i
            ))
            .send()
            .await
            .map_err(|e| AppError::new("delete_point request", e))?;

        Ok(HttpResponse::Ok().finish())
    } else {
        Ok(HttpResponse::Unauthorized().finish())
    }
}

#[post("/")]
async fn handle_add(auth: Auth, s: web::Json<Set>) -> Result<impl Responder, AppError> {
    let s = s.into_inner();
    let client = reqwest::Client::new();
    add(&client, &auth.user, s)
        .await
        .map_err(|e| AppError::new("adding point", e))?;
    Ok(HttpResponse::Ok().finish())
}

#[put("/")]
async fn handle_set(auth: Auth, s: web::Json<Set>) -> Result<impl Responder, AppError> {
    let s = s.into_inner();
    let client = reqwest::Client::new();
    match get_point_payload(&client, &s.i).await {
        Ok(existing_item) => {
            if existing_item.u == auth.user {
                set(&client, &auth.user, s)
                    .await
                    .map_err(|e| AppError::new("setting point", e))?;
                Ok(HttpResponse::Ok().finish())
            } else {
                Ok(HttpResponse::Unauthorized().finish())
            }
        }
        Err(_) => Ok(HttpResponse::NotFound().finish()),
    }
}

// --- REQUEST HELPERS ---

async fn get_username_by_token(client: &reqwest::Client, token: &str) -> AppResult<String> {
    // Build the filter
    let filter = json!({
        "must": [{
            "key": "token",
            "match": { "value": token }
        }]
    });

    // Perform the search

    #[derive(Deserialize)]
    struct ResultItem {
        id: String,
        payload: Option<UserPayload>,
    }

    #[derive(Deserialize)]
    struct Response {
        time: Option<f32>,
        status: Option<String>,
        result: Vec<ResultItem>,
    }

    #[derive(Deserialize)]
    struct UserPayload {
        username: String,
        token: String,
    }

    let response: Response = client
        .post(&qdrant_path(&format!(
            "/collections/{}/points/scroll",
            COLLECTION
        ))?)
        .json(&json!({
            "filter": filter,
            "limit": 1,
            "with_payload": true,
        }))
        .send()
        .await
        .map_err(|e| AppError::new("get_username_by_token request", e))?
        .json()
        .await
        .map_err(|e| AppError::new("parse get_username_by_token response", e))?;

    if let Some(result_item) = response.result.get(0) {
        if let Some(payload) = &result_item.payload {
            let username = payload.username.clone();
            Ok(username)
        } else {
            Err(AppError::new_plain("Token not associated with any user"))
        }
    } else {
        Err(AppError::new_plain("Invalid token"))
    }
}

async fn get_user_by_username(client: &reqwest::Client, username: &str) -> AppResult<User> {
    #[derive(Deserialize)]
    struct ResultItem {
        id: String,
        payload: Option<UserPayload>,
    }

    #[derive(Deserialize)]
    struct Response {
        time: Option<f32>,
        status: Option<String>,
        result: Vec<ResultItem>,
    }

    #[derive(Deserialize)]
    struct UserPayload {
        username: String,
        password_hash: String,
    }

    let response: Response = client
        .get(&qdrant_path(&format!(
            "/collections/{}/points/{}",
            COLLECTION, username
        ))?)
        .send()
        .await
        .map_err(|e| AppError::new("get_user request", e))?
        .json()
        .await
        .map_err(|e| AppError::new("parse get_user response", e))?;

    if let Some(result_item) = response.result.get(0) {
        if let Some(payload) = &result_item.payload {
            let user = User {
                username: payload.username.clone(),
                password_hash: payload.password_hash.clone(),
            };
            Ok(user)
        } else {
            Err(AppError::new_plain("User not found"))
        }
    } else {
        Err(AppError::new_plain("User not found"))
    }
}

fn generate_secure_token() -> String {
    let mut bytes = [0u8; 32]; // 256 bits of entropy
    OsRng.fill_bytes(&mut bytes);
    general_purpose::URL_SAFE_NO_PAD.encode(&bytes)
}

async fn store_token_for_user(client: &reqwest::Client, username: &str, token: &str) -> AppResult<()> {
    // Update the user point in Qdrant to include the token

    let payload = json!({
        "token": token,
    });

    client
        .post(&qdrant_path(&format!(
            "collections/{}/points/payload?wait",
            COLLECTION
        ))?)
        .header("Content-Type", "application/json")
        .body(format!(
            r#"{{
                "points": ["{}"],
                "payload": {}
            }}"#,
            username, payload.to_string()
        ))
        .send()
        .await
        .map_err(|e| AppError::new("store_token_for_user request", e))?;

    Ok(())
}

async fn get_embedding(query: &str) -> AppResult<serde_json::Value> {
    let url = env::var("EMBEDDING_URL")
        .unwrap_or_else(|_| "https://fastembedserver.shuttleapp.rs/embeddings".to_string());
    Ok(reqwest::Client::new()
        .post(&url)
        .json(&json!({ "input": query }))
        .send()
        .await
        .map_err(|e| AppError::new("sending get_embedding request", e))?
        .json::<serde_json::Value>()
        .await
        .map_err(|e| AppError::new("parsing get_embedding response to json", e))?["data"][0]
        ["embedding"]
        .clone())
}

async fn get_point_payload(client: &reqwest::Client, i: &str) -> AppResult<ResPayload> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum SN {
        String(String),
        Integer(i64),
    }
    #[derive(Deserialize)]
    struct ResultItem {
        id: Option<SN>,
        version: i64,
        score: f32,
        payload: Option<ResPayload>,
        vector: Option<serde_json::Value>,
        shard_key: Option<serde_json::Value>,
    }
    #[derive(Deserialize)]
    struct Response {
        time: Option<f32>,
        status: Option<String>,
        result: Vec<ResultItem>,
    }
    let response: Response = client
        .get(&qdrant_path(&format!(
            "/collections/{}/points/{}",
            COLLECTION, i
        ))?)
        .send()
        .await
        .map_err(|e| AppError::new("get_point request", e))?
        .json()
        .await
        .map_err(|e| AppError::new("parse get_point response", e))?;

    response
        .result
        .get(0)
        .and_then(|res| res.payload.clone())
        .ok_or_else(|| AppError::new_plain("get_point_payload - no payload on point"))
}

async fn add(client: &reqwest::Client, user: &str, s: Set) -> AppResult<()> {
    let embedding = get_embedding(&s.v).await?.to_string();
    let payload = json!({
        "c": "",  // category
        "u": user,
        "v": s.v,
    });
    client
        .put(&qdrant_path(&format!(
            "collections/{}/points?wait",
            COLLECTION
        ))?)
        .header("Content-Type", "application/json")
        .body(format!(
            r#"{{"points": [{{"id":"{}", "payload": {}, "vector": {}}}]}}"#,
            s.i, payload.to_string(), embedding
        ))
        .send()
        .await
        .map_err(|e| AppError::new("upsert_points", e))?;
    Ok(())
}

async fn set(client: &reqwest::Client, user: &str, s: Set) -> AppResult<()> {
    let embedding = get_embedding(&s.v).await?.to_string();
    let payload = json!({
        "c": "",  // category
        "u": user,
        "v": s.v,
    });
    client
        .post(&qdrant_path(&format!(
            "collections/{}/points?wait",
            COLLECTION
        ))?)
        .header("Content-Type", "application/json")
        .body(format!(
            r#"{{"points": [{{"id":"{}", "payload": {}, "vector": {}}}]}}"#,
            s.i, payload.to_string(), embedding
        ))
        .send()
        .await
        .map_err(|e| AppError::new("upsert_points", e))?;
    Ok(())
}

// --- STRUCTS ---

#[derive(Deserialize)]
struct RegistrationData {
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct LoginData {
    username: String,
    password: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct User {
    username: String,
    password_hash: String,
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,      // Query string
    l: u64,         // Limit
    r: Vec<String>, // Attributes to return
}

#[derive(Deserialize, Serialize, Clone)]
struct Item {
    u: String,            // User
    i: String,            // ID
    v: serde_json::Value, // Value field
    p: bool,              // Private field
}

#[derive(Deserialize)]
struct ItemQuery {
    i: String,
    c: String,
}

#[derive(Debug, Deserialize)]
struct Set {
    i: String, // id
    v: String, // value
               // p: bool // private
}

#[derive(Serialize, Deserialize, Clone)]
struct ResPayload {
    c: String, // Category the point belongs to
    u: String, // User that created it
    v: String,
}
