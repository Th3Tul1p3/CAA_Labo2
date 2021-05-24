use crate::argon2id13::Salt;
use actix_web::{get, post, web, HttpRequest, HttpResponse};
use aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm;
use futures::StreamExt;
use google_authenticator::{ErrorCorrectionLevel, GoogleAuthenticator};
use hmac::{Hmac, Mac, NewMac};
use lazy_static::lazy_static;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::Sha256;
use sodiumoxide::crypto::pwhash::argon2id13;
use std::collections::HashMap;
use std::convert::TryInto;
use std::env;
use std::fs;
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
struct Metadata {
    file_name: String,
    username: Vec<String>,
    nonce: [u8; 12],
    key: Vec<u8>,
}

#[derive(Deserialize, Debug)]
struct ComputedChallenge {
    challenge: [u8; 32],
}

lazy_static! {
    static ref USER_DB: HashMap<&'static str, User> = {
        let mut map = HashMap::new();
        // configuration google authenticator
let auth = GoogleAuthenticator::new();

        // Cette partie se fait normalement sur le client mais elle est volontairement
        // mise sur le serveur pour simplifié l'architecture
        let salt = argon2id13::gen_salt();
        let mut key = [0u8; 32];
        argon2id13::derive_key(
            &mut key,
            "P@ssw0rd".as_bytes(),
            &salt,
            /*argon2id13::OPSLIMIT_SENSITIVE,
            argon2id13::MEMLIMIT_SENSITIVE,*/
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
                secret: auth.create_secret(32),
            },
        );
        map
    };
}

#[get("/server/{user_id}")]
async fn username(web::Path(user_id): web::Path<String>) -> HttpResponse {
    // regarde si l'utilisateur est dans la DB, si oui on lui envoie un challenge à résoudre
    match USER_DB.get::<str>(&user_id.to_string()) {
        Some(username) => {
            let user_challenge = UserChallenge {
                username: user_id.to_string(),
                salt: username.salt,
                challenge: OsRng.next_u64(),
            };
            unsafe {
                USER_CHALLENGE.push((user_id, user_challenge.challenge));
            }
            HttpResponse::Ok().body(serde_json::to_string(&user_challenge).unwrap())
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
        return HttpResponse::Ok().finish();
    }
    HttpResponse::NonAuthoritativeInformation().finish()
}

#[get("/2fa/{user_id}")]
async fn get_code(web::Path(user_id): web::Path<String>) -> HttpResponse {
    // configuration google authenticator
    let auth = GoogleAuthenticator::new();

    // check dans la DB si l'utilisateur est présent
    let user = match USER_DB.get::<str>(&user_id.to_string()) {
        Some(user) => user,
        None => {
            return HttpResponse::NotFound().finish();
        }
    };

    // création du code QR
    let url = auth.qr_code_url(
        &user.secret,
        "qr_code",
        "name",
        200,
        200,
        ErrorCorrectionLevel::High,
    );

    HttpResponse::Ok().body(url)
}

#[post("/2fa/{user_id}")]
async fn validate_code(web::Path(user_id): web::Path<String>, req: HttpRequest) -> HttpResponse {
    // configuration google authenticator
    let auth = GoogleAuthenticator::new();

    // check dans la DB si l'utilisateur est présent
    let user = match USER_DB.get::<str>(&user_id.to_string()) {
        Some(user) => user,
        None => {
            return HttpResponse::NotFound().finish();
        }
    };

    // récupère le code dans le header
    let input_code: &str = req.headers().get("Code").unwrap().to_str().unwrap();
    if !auth.verify_code(&user.secret, &input_code, 0, 0) {
        println!("Mauvais code.");
        return HttpResponse::Unauthorized().finish();
    }

    // si ok, un token est envoyé à l'utilisateur pour les prochains échanges
    let user_token: String = Uuid::new_v4().hyphenated().to_string();
    unsafe {
        USER_TOKEN.push((user_id, user_token.clone()));
    }

    HttpResponse::Ok().header("Token", user_token).finish()
}

#[post("/upload")]
async fn upload(mut body: web::Payload, req: HttpRequest) -> HttpResponse {
    // lire et vérifier le Token
    if !check_token(&req) {
        return HttpResponse::NonAuthoritativeInformation().finish();
    }

    // lire le body
    let mut bytes = web::BytesMut::new();
    while let Some(item) = body.next().await {
        let item = item.unwrap();
        bytes.extend_from_slice(&item);
    }
    let res: Vec<u8> = bytes.to_vec();

    // écriture des données dans un fichier
    let mut file = File::create(req.headers().get("filename").unwrap().to_str().unwrap()).unwrap();
    file.write_all(&res).unwrap();
    HttpResponse::Ok().finish()
}

#[get("/download")]
async fn download(req: HttpRequest) -> HttpResponse {
    // lire et vérifier le Token
    let filename: &str = req.headers().get("FileName").unwrap().to_str().unwrap();

    if !check_token(&req) {
        return HttpResponse::NonAuthoritativeInformation().finish();
    }

    let work_file = env::current_dir().unwrap().join(&filename);
    // ouvrir et lire le fichier
    let mut file = match File::open(work_file) {
        Ok(result) => result,
        Err(_) => {
            return HttpResponse::NoContent().finish();
        }
    };
    let mut ciphertext: Vec<u8> = Vec::new();
    file.read_to_end(&mut ciphertext).unwrap();

    HttpResponse::Ok().body(ciphertext)
}

#[get("/list")]
async fn get_list(req: HttpRequest) -> HttpResponse {
    // lire et vérifier le Token
    let user_name: &str = req.headers().get("Username").unwrap().to_str().unwrap();
    // check dans la DB si l'utilisateur est présent
    let user = match USER_DB.get::<str>(&user_name.to_string()) {
        Some(user) => user,
        None => {
            return HttpResponse::NotFound().finish();
        }
    };

    // préparation des clés pour AES-GCM et du nonce
    let key_aes = GenericArray::clone_from_slice(&user.password_kdf);
    let aead = Aes256Gcm::new(key_aes);

    if !check_token(&req) {
        return HttpResponse::NonAuthoritativeInformation().finish();
    }

    let mut file_list: Vec<String> = Vec::new();
    // on lit le contenu du répertoire
    let paths = fs::read_dir("./").unwrap();

    for path in paths {
        let file = path.unwrap().path().into_os_string().into_string().unwrap();
        // pour tous les fichiers est de type metadonnée
        if file.contains(".metadata") {
            let mut current_file = File::open(&file).expect("Unable to open the file");
            let mut contents = String::new();
            current_file
                .read_to_string(&mut contents)
                .expect("Unable to read the file");
            let meta: Metadata = serde_json::from_str(&contents).unwrap();
            if meta.username.contains(&user_name.to_string()) {
                file_list.push(file.split(".metadata").collect());
            }
        }
    }
    HttpResponse::Ok().body(serde_json::to_string(&file_list).unwrap())
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("Le serveur est prêt à recevoir des requêtes");
    use actix_web::{App, HttpServer};

    HttpServer::new(|| {
        App::new()
            .service(username)
            .service(username_post)
            .service(get_code)
            .service(validate_code)
            .service(upload)
            .service(download)
            .service(get_list)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

pub fn verifiy_2fa(user_secret: &str, token: String) -> bool {
    let auth = GoogleAuthenticator::new();
    if !auth.verify_code(user_secret, &token, 0, 0) {
        println!("Mauvais code.");
        return false;
    }
    true
}

fn check_token(req: &HttpRequest) -> bool {
    let token: &str = req.headers().get("Token").unwrap().to_str().unwrap();
    let user: &str = req.headers().get("Username").unwrap().to_str().unwrap();
    unsafe {
        for pair in USER_TOKEN.iter() {
            if pair.0 == user && pair.1 == token {
                return true;
            }
        }
    }
    return false;
}
