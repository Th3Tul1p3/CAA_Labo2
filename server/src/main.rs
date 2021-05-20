use actix_web::{get, post, web, Error, HttpRequest, HttpResponse};
use futures::StreamExt;
//use aead::{generic_array::GenericArray, Aead, NewAead};
//use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`
//use hmac::{Hmac, Mac, NewMac};
use rand_core::{OsRng, RngCore};
//use sha2::Sha256;
use sodiumoxide::crypto::pwhash::argon2id13;
//use std::fs::File;
//use std::io::prelude::*;
use crate::argon2id13::Salt;
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use serde_json;
use std::collections::HashMap;

static mut USER_TOKEN: Vec<UserToken> = Vec::new();
static mut USER_CHALLENGE: Vec<UserChallenge> = Vec::new();

#[derive(Debug)]
struct User {
    username: String,
    salt: Salt,
    password_kdf: [u8; 32],
    secret: String,
}

struct UserToken {
    username: String,
    token: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct UserChallenge {
    username: String,
    challenge: u64,
    salt: Salt,
}

#[derive(Serialize, Deserialize, Debug)]
struct SaltArgon {
    salt: Salt,
}

lazy_static! {
    static ref USER_DB: HashMap<&'static str, User> = {
        let mut map = HashMap::new();
        sodiumoxide::init().unwrap();
        let salt = argon2id13::gen_salt();
        let mut key = [0u8; 32];
        sodiumoxide::init().unwrap();
        argon2id13::derive_key(
            &mut key,
            "P@ssw0rd".as_bytes(),
            &salt,
            argon2id13::OPSLIMIT_INTERACTIVE,
            argon2id13::MEMLIMIT_INTERACTIVE,
        )
        .unwrap();
        map.insert(
            "jerome",
            User {
                username: "jerome".to_string(),
                salt: salt,
                password_kdf: key,
                secret: "salut".to_string(),
            },
        );
        map
    };
}

#[get("/server/{user_id}")] // <- define path parameters
async fn username(web::Path(user_id): web::Path<String>) -> HttpResponse {
    match USER_DB.get::<str>(&user_id.to_string()) {
        Some(username) => {
            let m = UserChallenge {
                username: user_id.to_string(),
                salt: username.salt,
                challenge: OsRng.next_u64(),
            };
            HttpResponse::Ok().body(serde_json::to_string(&m).unwrap())
        }
        None => HttpResponse::NotFound().finish(),
    }
}

#[post("/server/{user_id}")] // <- define path parameters
async fn username_post(web::Path(user_id): web::Path<String>) -> HttpResponse {
    println!("Post request");
    HttpResponse::Ok().finish()
}

#[get("/body")]
async fn body(mut body: web::Payload, req: HttpRequest) -> Result<HttpResponse, Error> {
    let mut bytes = web::BytesMut::new();
    while let Some(item) = body.next().await {
        let item = item?;
        bytes.extend_from_slice(&item);
    }
    let test = req.headers().get("test").unwrap();
    println!("{:?}", test);
    println!("{:?}", &bytes);
    unsafe {
        //USER_TOKEN.push("jerome".to_string());
    }
    Ok(HttpResponse::Ok().finish())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Le serveur est prêt à recevoir des requêtes");
    use actix_web::{App, HttpServer};

    HttpServer::new(|| App::new().service(username).service(body).service(username_post))
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
