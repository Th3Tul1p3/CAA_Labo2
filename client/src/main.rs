use crate::argon2id13::Salt;
use hmac::{Hmac, Mac, NewMac};
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::Sha256;
use sodiumoxide::crypto::pwhash::argon2id13;
use std::convert::TryInto;
use ureq;
use ureq::Error;

fn main() {
    let token = authentication();
    if !token.is_empty(){
        uplpoad(token.clone());
        get_list(token.clone());
        download(token.clone());
    }
}

#[derive(Deserialize, Debug)]
struct UserChallenge {
    username: String,
    challenge: u64,
    salt: Salt,
}

#[derive(Serialize, Deserialize, Debug)]
struct ComputedChallenge {
    challenge: [u8; 32],
}

fn authentication() -> String{
    // demande du challenge au serveur
    let res = ureq::get("http://127.0.0.1:8080/server/jerome")
        .call()
        .unwrap()
        .into_string()
        .unwrap();

    // désérialisation sur challenge reçu
    let user_challenge: UserChallenge = serde_json::from_str(&res).unwrap();

    // déravation de la clé à partir du sel reçu
    let mut key = [0u8; 32];
    argon2id13::derive_key(
        &mut key,
        "P@ssw0rd".as_bytes(),
        &user_challenge.salt,
        argon2id13::OPSLIMIT_INTERACTIVE,
        argon2id13::MEMLIMIT_INTERACTIVE,
    )
    .unwrap();

    // exécution du hmac de la valeur reçue
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_varkey(&key).expect("HMAC Error");
    mac.update(&user_challenge.challenge.to_be_bytes());
    let x: [u8; 32] = mac
        .finalize()
        .into_bytes()
        .as_slice()
        .try_into()
        .expect("Wrong length");
    let challenge = ComputedChallenge { challenge: x };

    // envoi du MAC au serveur
    match ureq::post("http://127.0.0.1:8080/server/jerome")
        .set("Username", &user_challenge.username)
        .send_string(&serde_json::to_string(&challenge).unwrap())
    {
        Ok(request) => {
            return request.header("Token").unwrap().to_string();
        }
        Err(Error::Status(code, response)) => {
            println!("{:?} {:?}", code, response);
            return "".to_string();
        }
        Err(_) => {
            return "".to_string();
        }
    };
}

fn get_list(token : String) {
    /*ureq::get("http://127.0.0.1:8080/server/jerome/list")
    .call()
    .unwrap();*/
}

fn uplpoad(token : String) {}

fn download(token : String) {}
