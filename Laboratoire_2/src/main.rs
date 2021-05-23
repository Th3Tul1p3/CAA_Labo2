use aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm::Aes256Gcm; // Or `Aes128Gcm`
use ecies::{decrypt, encrypt, utils::generate_keypair};
use hmac::{Hmac, Mac, NewMac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use sodiumoxide::crypto::pwhash::argon2id13;
use std::fs::File;
use std::io::prelude::*;

fn main() {
    const MSG: &str = "helloworld";
    let (sk, pk) = generate_keypair();
    let (sk, pk) = (&sk.serialize(), &pk.serialize());

    let msg = MSG.as_bytes();
    assert_eq!(
        msg,
        decrypt(sk, &encrypt(pk, msg).unwrap()).unwrap().as_slice()
    );

    let random_u64 = OsRng.next_u64();
    println!("{:?}", random_u64);

    let mut file = File::open("/test.txt").expect("Unable to open the file");
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .expect("Unable to read the file");
    println!("{}", contents);

    let salt = argon2id13::gen_salt();
    let mut key = [0u8; 32];
    let derivation_key = argon2id13::derive_key(
        &mut key,
        "P@ssw0rd".as_bytes(),
        &salt,
        argon2id13::OPSLIMIT_INTERACTIVE,
        argon2id13::MEMLIMIT_INTERACTIVE,
    )
    .unwrap();
    println!("Key : {:?}", derivation_key);

    let key_aes = GenericArray::clone_from_slice(&key);
    let aead = Aes256Gcm::new(key_aes);

    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    let nonce_aes = GenericArray::from_slice(&nonce); // 96-bits; unique per message
    let ciphertext = aead
        .encrypt(nonce_aes, b"plaintext message".as_ref())
        .expect("encryption failure!");
    let plaintext = aead
        .decrypt(nonce_aes, ciphertext.as_ref())
        .expect("decryption failure!");
    assert_eq!(&plaintext, b"plaintext message");

    // Create alias for HMAC-SHA256
    type HmacSha256 = Hmac<Sha256>;

    // Create HMAC-SHA256 instance which implements `Mac` trait
    let mut mac =
        HmacSha256::new_varkey(b"my secret and secure key").expect("HMAC can take key of any size");
    mac.update(b"input message");

    // `result` has type `Output` which is a thin wrapper around array of
    // bytes for providing constant time equality check
    let result = mac.finalize();
    // To get underlying array use `into_bytes` method, but be careful, since
    // incorrect use of the code value may permit timing attacks which defeat
    // the security provided by the `Output`
    let code_bytes = result.into_bytes();

    let mut mac =
        HmacSha256::new_varkey(b"my secret and secure key").expect("HMAC can take key of any size");

    mac.update(b"input message");

    // `verify` will return `Ok(())` if code is correct, `Err(MacError)` otherwise
    mac.verify(&code_bytes).unwrap();
}

pub fn verify(hash: [u8; 128], passwd: &str) -> bool {
    sodiumoxide::init().unwrap();
    match argon2id13::HashedPassword::from_slice(&hash) {
        Some(hp) => argon2id13::pwhash_verify(&hp, passwd.as_bytes()),
        _ => false,
    }
}
