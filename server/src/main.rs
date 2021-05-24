use actix_web::{get, post, web, Error, HttpRequest, HttpResponse};
use futures::StreamExt;
//use aead::{generic_array::GenericArray, Aead, NewAead};
//use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`
use crate::argon2id13::Salt;
use hmac::{Hmac, Mac, NewMac};
use lazy_static::lazy_static;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::Sha256;
use sodiumoxide::crypto::pwhash::argon2id13;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fs::File;
use std::io::prelude::*;
use std::str;
use uuid::Uuid;

static mut USER_TOKEN: Vec<(String, String)> = Vec::new();
static mut USER_CHALLENGE: Vec<(String, u64)> = Vec::new();

#[derive(Debug)]
struct User {
    username: String,
    salt: Salt,
    password_kdf: [u8; 32],
    secret: String,
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

#[derive(Deserialize, Debug)]
struct ComputedChallenge {
    challenge: [u8; 32],
}

lazy_static! {
    static ref USER_DB: HashMap<&'static str, User> = {
        let mut map = HashMap::new();

        // Cette partie se fait normalement sur le client mais est volontairement
        // mise sur le serveur pour simplifié
        let salt = argon2id13::gen_salt();
        let mut key = [0u8; 32];
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

#[get("/server/{user_id}")]
async fn username(web::Path(user_id): web::Path<String>) -> HttpResponse {
    match USER_DB.get::<str>(&user_id.to_string()) {
        Some(username) => {
            let m = UserChallenge {
                username: user_id.to_string(),
                salt: username.salt,
                challenge: OsRng.next_u64(),
            };
            unsafe {
                USER_CHALLENGE.push((user_id, m.challenge));
            }
            HttpResponse::Ok().body(serde_json::to_string(&m).unwrap())
        }
        None => HttpResponse::NotFound().finish(),
    }
}

#[post("/server/{user_id}")] // <- define path parameters
async fn username_post(
    web::Path(user_id): web::Path<String>,
    mut body: web::Payload,
) -> HttpResponse {
    // check dans la DB si l'utilisateur est présent
    let user = match USER_DB.get::<str>(&user_id.to_string()) {
        Some(user) => user,
        None => {
            return HttpResponse::NotFound().finish();
        }
    };

    // lecture du body pour avoir le challenge envoyé
    let mut bytes = web::BytesMut::new();
    while let Some(item) = body.next().await {
        let item = item.unwrap();
        bytes.extend_from_slice(&item);
    }

    // on désérialise le challenge envoyé
    let computed_challenge: ComputedChallenge =
        serde_json::from_str(str::from_utf8(&bytes).unwrap()).unwrap();

    // récupération du challenge envoyé au client
    let challenge_to_compute: u64;
    unsafe {
        let index = USER_CHALLENGE.iter().position(|x| x.0 == user_id).unwrap();
        challenge_to_compute = USER_CHALLENGE.get(index).unwrap().1;
        USER_CHALLENGE.remove(index);
    }

    // Fait le mac à partir de la kdf dans la DB
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_varkey(&user.password_kdf).expect("HMAC Error");
    mac.update(&challenge_to_compute.to_be_bytes());
    let challenge: [u8; 32] = mac
        .finalize()
        .into_bytes()
        .as_slice()
        .try_into()
        .expect("Wrong length");

    // on teste si les valeurs sont identiques
    if challenge == computed_challenge.challenge {
        let user_token: String = Uuid::new_v4().hyphenated().to_string();
        unsafe {
            USER_TOKEN.push((user_id, user_token.clone()));
        }
        return HttpResponse::Ok().header("Token", user_token).finish();
    }
    HttpResponse::NonAuthoritativeInformation().finish()
}

/*#[get("/body")]
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
}*/

#[post("/upload")]
async fn upload(mut body: web::Payload, req: HttpRequest) -> HttpResponse {
    // lire et vérifier le Token
    let token : &str = req.headers().get("Token").unwrap().to_str().unwrap();
    if !check_token(token){
        return HttpResponse::NonAuthoritativeInformation().finish();
    }

    // lire le body
    let mut bytes = web::BytesMut::new();
    while let Some(item) = body.next().await {
        let item = item.unwrap();
        bytes.extend_from_slice(&item);
    }
    let res: Vec<u8> = bytes.to_vec();

    let filename : &str = req.headers().get("filename").unwrap().to_str().unwrap();
    println!("{:?}", filename);
    let mut file = File::create(filename).unwrap();
    file.write_all(&res).unwrap();
    HttpResponse::Ok().finish()
}

#[get("/download")]
async fn download(req: HttpRequest) -> HttpResponse {
    // lire et vérifier le Token
    let token : &str = req.headers().get("Token").unwrap().to_str().unwrap();
    if !check_token(token){
        return HttpResponse::NonAuthoritativeInformation().finish();
    }
    HttpResponse::Ok().finish()
}

#[get("/list")]
async fn get_list(req: HttpRequest) -> HttpResponse {
    // lire et vérifier le Token
    let token : &str = req.headers().get("Token").unwrap().to_str().unwrap();
    if !check_token(token){
        return HttpResponse::NonAuthoritativeInformation().finish();
    }
    HttpResponse::Ok().finish()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Le serveur est prêt à recevoir des requêtes");
    use actix_web::{App, HttpServer};

    HttpServer::new(|| {
        App::new()
            .service(username)
            .service(username_post)
            .service(upload)
            .service(download)
            .service(get_list)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

fn check_token (token:&str)-> bool{
    unsafe {
        for pair in USER_TOKEN.iter(){
            if pair.1 == token{
                return true;
            }
        }
    }
    return false;
}
