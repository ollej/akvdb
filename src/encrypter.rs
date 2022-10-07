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

pub struct Encrypter {
    cipher: Aes256Gcm,
}

impl Encrypter {
    pub fn from_env() -> Self {
        let key = Self::encoded_key().expect("Failed to read encryption key");
        let encryption_key = Self::encryption_key(key).expect("Failed to read encryption key");
        Self::from_key(encryption_key)
    }

    pub fn from_key(key: Vec<u8>) -> Self {
        Self {
            cipher: Self::cipher(key).expect("Couldn't setup encryption"),
        }
    }

    pub fn encrypt(&self, data: &ByteStr) -> io::Result<(ByteString, ByteString)> {
        let random_nonce = rand::thread_rng().gen::<[u8; 12]>();
        let nonce = Nonce::from_slice(&random_nonce); // 96-bits; unique per message
        let encrypted_data = self
            .cipher
            .encrypt(nonce, data)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to encrypt data"))?;
        Ok((encrypted_data, nonce.to_vec()))
    }

    pub fn decrypt(&self, data: &ByteStr, nonce: &ByteStr) -> io::Result<ByteString> {
        self.cipher
            .decrypt(Nonce::from_slice(nonce), data)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to decrypt data"))
    }

    fn cipher(encryption_key: Vec<u8>) -> io::Result<Aes256Gcm> {
        Ok(Aes256Gcm::new(GenericArray::from_slice(&encryption_key)))
    }

    fn encoded_key() -> io::Result<String> {
        env::var("AKVDB_KEY").map_err(|_| {
            io::Error::new(
                io::ErrorKind::Other,
                "Expected an encryption key in AKVDB_KEY environment variable",
            )
        })
    }

    fn encryption_key(encoded_key: String) -> io::Result<Vec<u8>> {
        base_62::decode(&encoded_key)
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Couldn't decode encryption key"))
    }
}
