use crate::argon2id13::Salt;
use aes_gcm::aead::{Aead, NewAead};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use ecies::{decrypt, encrypt, utils::generate_keypair, PublicKey, SecretKey};
use hmac::{Hmac, Mac, NewMac};
use rand_core::{OsRng, RngCore};
use read_input::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json;
use sha2::Sha256;
use sodiumoxide::crypto::pwhash::argon2id13;
use std::convert::TryInto;
use std::env;
use std::fs::File;
use std::io::prelude::*;
use std::str;
use ureq;
use ureq::Error;

fn main() {
    println!("Génération de votre paire de clé asymétrique");
    let (sk, pk) = generate_keypair();
    println!("Début du processus d'authentification");
    let token = authentication();
    if !token.is_empty() {
        println!("Vous êtes authentifié, upload du fichier [shadow]");
        uplpoad(token.clone(), pk, "shadow".to_string());
        println!("Demande la liste des fichiers que vous pouvez consulter");
        get_list(token.clone());
        println!("Téléchargement du fichier shadow");
        download(token.clone(), "shadow".to_string(), sk);
    }
}

#[derive(Deserialize, Debug)]
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

#[derive(Serialize, Deserialize, Debug)]
struct ComputedChallenge {
    challenge: [u8; 32],
}

fn authentication() -> String {
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
        argon2id13::OPSLIMIT_SENSITIVE,
        argon2id13::MEMLIMIT_SENSITIVE,
    )
    .unwrap();

    // process du hmac de la valeur reçue
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
        Ok(_) => {}
        Err(Error::Status(code, response)) => {
            println!("{:?} {:?}", code, response);
        }
        Err(_) => {}
    };

    // normalement fait dans lors de l'enregistrement
    // affichage de l'URL du secret
    let url = ureq::get("http://127.0.0.1:8080/2fa/jerome")
        .call()
        .unwrap()
        .into_string()
        .unwrap();
    println!("L'url de votre secret {:?}", url);

    // attend l'entrée utilisateur du code
    let input_token: String = input()
        .repeat_msg("Veuillez rentrer votre jeton de double authentification s.v.p.\n")
        .get();

    // si le code est ok, on reçoit un token pour les futures échanges
    match ureq::post("http://127.0.0.1:8080/2fa/jerome")
        .set("Code", &input_token)
        .call()
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

fn get_list(token: String) {
    let resp = ureq::get("http://127.0.0.1:8080/list")
        .set("Token", &token)
        .set("Username", "jerome")
        .call().unwrap();

    let mut test = resp.into_reader();
    let mut buf = Vec::new();
    test.read_to_end(& mut buf).unwrap();

    let key_aes = Key::from_slice(b"an example very very secret key.");
    let aead = Aes256Gcm::new(key_aes);
    let nonce = Nonce::from_slice(b"unique nonce");

    let plaintext = aead
        .decrypt(nonce, buf.as_ref())
        .expect("decryption failure!");

    // désérialisation sur challenge reçu
    println!(
        "Voici la liste des fichiers auxquelles vous avez accès: \n{}",
        String::from_utf8(plaintext).unwrap()
    );
}

fn uplpoad(token: String, pub_key: PublicKey, file_name: String) {
    let work_file = env::current_dir().unwrap().join(&file_name);

    // ouvrir et lire le fichier
    let mut file = File::open(work_file).expect("Unable to open the file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Unable to read the file");

    // dérivation de la clé
    let salt = argon2id13::gen_salt();
    let mut key = [0u8; 32];
    argon2id13::derive_key(
        &mut key,
        "P@ssw0rd".as_bytes(),
        &salt,
        argon2id13::OPSLIMIT_SENSITIVE,
        argon2id13::MEMLIMIT_SENSITIVE,
    )
    .unwrap();

    // préparation des clés pour AES-GCM et du nonce
    let key_aes = Key::from_slice(&key);
    let aead = Aes256Gcm::new(key_aes);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let nonce_aes = Nonce::from_slice(&nonce);

    // chiffrement des données AES-GCM
    let ciphertext = aead
        .encrypt(nonce_aes, contents.as_bytes().as_ref())
        .expect("encryption failure!");

    //let x: [u8; 12] = nonce_aes.as_slice().try_into().expect("Wrong length");

    // chiffrement de de la clé symétrique avec ECIES
    let _encrypted_key: Vec<u8> = encrypt(&pub_key.serialize(), &key).unwrap();

    // préparation des metadata du fichier
    let metadata: Metadata = Metadata {
        file_name: "filename".to_string(),
        username: vec!["jerome".to_string()],
        nonce,
        key: _encrypted_key,
    };

    let mut file = File::create("cipher").unwrap();
    file.write_all(&ciphertext).unwrap();

    let mut metada_file = file_name.to_owned();
    metada_file.push_str(".metadata");
    let metadata_file = env::current_dir().unwrap().join(&metada_file);
    File::create(&metadata_file).unwrap();

    let serialized_metadata = serde_json::to_string(&metadata).unwrap();

    // mettre le chiffré dans le body et envoyer avec le token et le nom de fichier
    match ureq::post("http://127.0.0.1:8080/upload")
        .set("FileName", &file_name)
        .set("Token", &token)
        .set("Username", "jerome")
        .send_bytes(&ciphertext)
    {
        Ok(_) => {}
        Err(Error::Status(code, response)) => {
            println!("{:?} {:?}", code, response);
        }
        Err(_) => {}
    };

    // mettre le fichier metadata dans le body et envoyer avec le token et le nom de fichier
    match ureq::post("http://127.0.0.1:8080/upload")
        .set("FileName", &metada_file)
        .set("Token", &token)
        .set("Username", "jerome")
        .send_string(&serialized_metadata)
    {
        Ok(_) => {}
        Err(Error::Status(code, response)) => {
            println!("{:?} {:?}", code, response);
        }
        Err(_) => {}
    };
}

fn download(token: String, file_name: String, sk: SecretKey) {
    // téléchargé le chiffré
    let mut cipher_stream = ureq::get("http://127.0.0.1:8080/download")
        .set("FileName", &file_name)
        .set("Token", &token)
        .set("Username", "jerome")
        .call()
        .unwrap()
        .into_reader();
    let mut cipher: Vec<u8> = Vec::new();
    cipher_stream.read_to_end(&mut cipher).unwrap();

    // téléchargé les métadonnées
    let mut metada_file = file_name.to_owned();
    metada_file.push_str(".metadata");
    let resp = ureq::get("http://127.0.0.1:8080/download")
        .set("FileName", &metada_file)
        .set("Token", &token)
        .set("Username", "jerome")
        .call()
        .unwrap()
        .into_string()
        .unwrap();

    // déchiffrer la clés
    let metadata: Metadata = serde_json::from_str(&resp).unwrap();
    let decrypted_key: Vec<u8> = decrypt(&sk.serialize(), &metadata.key).unwrap();

    // déchiffrer les données
    // préparation des clés pour AES-GCM et du nonce
    let key_aes = Key::clone_from_slice(&decrypted_key);
    let aead = Aes256Gcm::new(&key_aes);
    let nonce_aes = Nonce::from_slice(&metadata.nonce);

    // chiffrement des données AES-GCM
    let plaintext = aead
        .decrypt(&nonce_aes, cipher.as_ref())
        .expect("encryption failure!");
    let string: String = String::from_utf8_lossy(&plaintext).to_string();

    println!(
        "Le contenu du fichier téléchargé est: \n{}",
        String::from_utf8_lossy(&plaintext)
    );

    // écrire dans un fichier
    let mut file = File::create("filename").unwrap();
    file.write_all(&string.as_bytes()).unwrap();
}
