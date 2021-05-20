use crate::argon2id13::Salt;
use serde::Deserialize;
use serde_json;
use sodiumoxide::crypto::pwhash::argon2id13;
use ureq;

fn main() {
    let res = authentication();
    let salt: UserChallenge = serde_json::from_str(&res).unwrap();
    println!("{:?}", salt.salt);
}

#[derive(Deserialize, Debug)]
struct UserChallenge {
    username: String,
    challenge: u64,
    salt: Salt,
}

fn authentication() -> String {
    ureq::post("http://127.0.0.1:8080/server/jerome")
    .set("X-My-Header", "Secret")
    .set("Username", "jerome").call().unwrap();
    ureq::get("http://127.0.0.1:8080/server/jerome")
        .call()
        .unwrap()
        .into_string()
        .unwrap()
}

fn get_list(){
    ureq::get("http://127.0.0.1:8080/server/jerome/list")
        .call()
        .unwrap();
}

fn uplpoad(){

}

fn download(){

}
