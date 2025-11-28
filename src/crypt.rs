use super::{handle_unwrap, config::Config, utils::to_hex};

use argon2::{password_hash::{rand_core::{OsRng, RngCore}, PasswordHash, PasswordHasher, PasswordVerifier, SaltString}, Argon2};
use chacha20poly1305::{aead::{Aead, AeadCore, KeyInit}, XChaCha20Poly1305, Key, XNonce};
use std::{ops::Range, time::Duration};
use zeroize::{Zeroize, Zeroizing};
use totp_rs::{Secret, TOTP};
use base64::prelude::*;

pub fn generate_cookie_key() -> String {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);

    let mut hex_string = String::with_capacity(64);
    for byte in &key {
        hex_string.push_str(&format!("{:02x}", byte));
    }
    key.zeroize();
    hex_string
}

pub fn rand_str(size: usize) -> String {
    const DICT: &[u8; 62] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = Vec::with_capacity(size);
    let mut key = [0u8; 1024];
    let mut i = 0;
    OsRng.fill_bytes(&mut key);

    while out.len() < size {
        if i >= key.len() {
            OsRng.fill_bytes(&mut key);
            i = 0;
        }
        let idx = key[i];
        i+=1;

        if idx < 62 * 4 {
            out.push(DICT[(idx % 62) as usize]);
        }
    }

    String::from_utf8(out).unwrap()
}

pub fn check_totp(secret: &str, code: &str) -> bool {
    if let Ok(secret) = Secret::Encoded(secret.to_string()).to_bytes() {
        if let Ok(totp) = TOTP::new(totp_rs::Algorithm::SHA1, 6,1,30, secret, None, "".to_string()) {
            if let Ok(res) = totp.check_current(code) { return res }
        }
    }
    
    false
}

pub fn hash_password(conf: &Config, plain: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(OsRng);
    let params = argon2::Params::new(conf.hash_mem_cost*1024, conf.hash_time_cost, conf.hash_parallel_cost, None)?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    Ok(argon2.hash_password(plain.as_bytes(), &salt)?.to_string())
}

pub fn verify_password(conf: &Config, hash: &str, input: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed_hash) => {
            match argon2::Params::new(conf.hash_mem_cost*1024, conf.hash_time_cost, conf.hash_parallel_cost, None) {
                Ok(params) => {
                    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
                    argon2.verify_password(input.as_bytes(), &parsed_hash).is_ok()
                },
                Err(_) => false
            }
        },
        Err(_) => false,
    }
}

pub fn get_hash_salt(hash: &str) -> Result<String, argon2::password_hash::Error> {
    let pwd_hash = PasswordHash::new(hash)?;

    if let Some(salt) = pwd_hash.salt {
        Ok(salt.as_str().to_string())
    } else {
        Err(argon2::password_hash::Error::PhcStringField)
    }
}

//handle_unwrap exit OK cus only used in cli
pub fn print_totp_qr_cli(name: &str, secret: &str) {
    println!("\nTOTP SECRET: {}", secret);
    let secret = handle_unwrap!(Secret::Encoded(secret.to_string()).to_bytes());
    let totp = handle_unwrap!(TOTP::new(totp_rs::Algorithm::SHA1, 6,1,30, secret, Some("rotproxy".to_string()), name.to_string()));
    println!("TOTP QR code:\n");
    let _ = qr2term::print_qr(totp.get_url());
}

pub fn new_secret() -> String {
    Secret::generate_secret().to_encoded().to_string()
}

pub fn rand_between(min: u64, max: u64) -> u64 {
    let mut rng = OsRng;
    let v    = rng.next_u64();
    let range = max - min + 1;
    min + (v % range)
}

pub fn kdf_encrypt(conf: &Config, plaintext: &str, password: &str, salt: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut kdf_bytes = [0u8; 32];

    let params = argon2::Params::new(conf.hash_mem_cost*1024, conf.hash_time_cost, conf.hash_parallel_cost, None)?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2.hash_password_into(password.as_bytes(), salt.as_bytes(), &mut kdf_bytes)?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&kdf_bytes));
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message
    
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes().as_ref())?;
    kdf_bytes.zeroize();

    let mut buf = Vec::with_capacity(nonce.len() + ciphertext.len());
    buf.extend_from_slice(&nonce);
    buf.extend_from_slice(&ciphertext);


    Ok(BASE64_STANDARD.encode(buf))
}

pub fn kdf_decrypt(conf: &Config, encrypted: &str, password: &str, salt: &str) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
    let mut kdf_bytes = [0u8; 32];

    let params = argon2::Params::new(conf.hash_mem_cost*1024, conf.hash_time_cost, conf.hash_parallel_cost, None)?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2.hash_password_into(password.as_bytes(), salt.as_bytes(), &mut kdf_bytes)?;

    let cipher = XChaCha20Poly1305::new(Key::from_slice(&kdf_bytes));

    let encrypted_bytes = BASE64_STANDARD.decode(encrypted)?;

    let (nonce_bytes, ciphertext) = encrypted_bytes.split_at(24);

    let nonce = XNonce::from_slice(nonce_bytes);

    let decrypted = cipher.decrypt(nonce, ciphertext)?;

    kdf_bytes.zeroize();

    Ok(Zeroizing::new(String::from_utf8(decrypted)?))
}

pub fn magic_hash(magic_str: &str, hash_size: usize, time: Duration, range: Range<usize>) -> String {
    let now = chrono::Utc::now();
    let now_ts = now.timestamp();

    // Floor to the nearest multiple of time
    let step = time.as_secs();
    let floored = if step != 0 {
        now_ts - (now_ts % step as i64)
    } else {
        0
    };

    let to_hash = format!("{}:{}", magic_str, floored);

    let mut hasher = blake3::Hasher::new();
    hasher.update(to_hash.as_bytes());

    let mut xof = hasher.finalize_xof();

    let mut buf = vec![0u8; if hash_size < 32 { 32 } else { hash_size }];
    xof.fill(&mut buf);

    let hash = to_hex(&buf);

    let hash_ret_end = if range.end == usize::MAX || range.end > hash.len() {
        hash.len()
    } else {
        range.end
    };

    hash.chars().skip(range.start).take(hash_ret_end - range.start).collect()
}