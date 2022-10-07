use std::{env, io};
use {
    aes_gcm::{
        aead::{Aead, KeyInit},
        Aes256Gcm, Nonce,
    },
    generic_array::GenericArray,
    rand::prelude::*,
};

use crate::{ByteStr, ByteString};

pub fn encrypt_data(data: &ByteStr) -> io::Result<(ByteString, ByteString)> {
    let random_nonce = rand::thread_rng().gen::<[u8; 12]>();
    let nonce = Nonce::from_slice(&random_nonce); // 96-bits; unique per message
    let encrypted_data = cipher()?
        .encrypt(nonce, data)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to encrypt data"))?;
    Ok((encrypted_data, nonce.to_vec()))
}

pub fn decrypt_data(data: &ByteStr, nonce: &ByteStr) -> io::Result<ByteString> {
    cipher()?
        .decrypt(Nonce::from_slice(nonce), data)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to decrypt data"))
}

fn cipher() -> io::Result<Aes256Gcm> {
    let encryption_key = encryption_key()?;
    Ok(Aes256Gcm::new(GenericArray::from_slice(&encryption_key)))
}

fn encryption_key() -> io::Result<Vec<u8>> {
    let encoded_key = env::var("AKVDB_KEY")
        .expect("Expected an encryption key in AKVDB_KEY environment variable");
    base_62::decode(&encoded_key)
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Couldn't decode encryption key"))
}
