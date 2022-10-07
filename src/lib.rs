#[macro_use]
extern crate serde_derive;
extern crate byteorder;

mod encrypter;

use encrypter::Encrypter;
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    io::{self, prelude::*, BufReader, BufWriter, SeekFrom},
    path::Path,
};
use {
    byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt},
    lazy_static::lazy_static,
};

lazy_static! {
    static ref ENCRYPTER: Encrypter = Encrypter::from_env();
}

pub type ByteString = Vec<u8>;
pub type ByteStr = [u8];

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyValuePair {
    pub key: ByteString,
    pub value: ByteString,
}

#[derive(Debug)]
pub struct ActionKV {
    f: File,
    pub index: HashMap<ByteString, u64>,
}

impl ActionKV {
    pub fn open(path: &Path) -> io::Result<Self> {
        let f = OpenOptions::new()
            // relevant option set.
            .read(true)
            .write(true)
            .create(true)
            .append(true)
            .open(path)?;
        Ok(ActionKV {
            f,
            index: HashMap::new(),
        })
    }

    /// Assumes that f is already at the right place in the file
    fn process_record<R: Read>(f: &mut R) -> io::Result<KeyValuePair> {
        let mut saved_checksum = [0; 32];
        f.read_exact(&mut saved_checksum)?;
        let mut saved_nonce = [0; 12];
        f.read_exact(&mut saved_nonce)?;
        let key_len = f.read_u32::<LittleEndian>()?;
        let val_len = f.read_u32::<LittleEndian>()?;
        let data_len = key_len + val_len;

        let mut data = ByteString::with_capacity(data_len as usize);

        {
            // f.by_ref() is required because .take(n) creates a new Read instance. Using a reference within this block allows
            // us to sidestep ownership issues.
            f.by_ref().take(data_len as u64).read_to_end(&mut data)?;
        }
        debug_assert_eq!(data.len(), data_len as usize);

        let checksum: [u8; 32] = blake3::hash(&data).as_bytes().clone();
        if checksum != saved_checksum {
            panic!(
                "data corruption encountered ({:08x?} != {:08x?})",
                checksum, saved_checksum
            );
        }

        let val = data.split_off(key_len as usize);
        let key = data;

        let decrypted_data = ENCRYPTER.decrypt(&val, &saved_nonce)?;

        Ok(KeyValuePair {
            key,
            value: decrypted_data,
        })
    }

    pub fn seek_to_end(&mut self) -> io::Result<u64> {
        self.f.seek(SeekFrom::End(0))
    }

    pub fn load(&mut self) -> io::Result<()> {
        let mut f = BufReader::new(&mut self.f);

        loop {
            let current_position = f.seek(SeekFrom::Current(0))?;

            let maybe_kv = ActionKV::process_record(&mut f);
            let kv = match maybe_kv {
                Ok(kv) => kv,
                Err(err) => {
                    match err.kind() {
                        io::ErrorKind::UnexpectedEof => {
                            // "Unexpected" is relative. The application may not have expected it, but we expect files to be finite.
                            break;
                        }
                        _ => return Err(err),
                    }
                }
            };

            self.index.insert(kv.key, current_position);
        }

        Ok(())
    }

    pub fn get(&mut self, key: &ByteStr) -> io::Result<Option<ByteString>> {
        // we need to wrap Option within Result to allow for the possibilities of I/O errors as well as missing values
        // occuring
        let position = match self.index.get(key) {
            None => return Ok(None),
            Some(position) => *position,
        };

        let kv = self.get_at(position)?;

        Ok(Some(ByteString::from(kv.value)))
    }

    pub fn get_at(&mut self, position: u64) -> io::Result<KeyValuePair> {
        let mut f = BufReader::new(&mut self.f);
        f.seek(SeekFrom::Start(position))?;
        let kv = ActionKV::process_record(&mut f)?;

        Ok(kv)
    }

    pub fn find(&self, target: &ByteStr) -> io::Result<Option<(u64, ByteString)>> {
        let mut f = BufReader::new(&self.f);

        let mut found: Option<(u64, ByteString)> = None;

        loop {
            let position = f.seek(SeekFrom::Current(0))?;

            let maybe_kv = ActionKV::process_record(&mut f);
            let kv = match maybe_kv {
                Ok(kv) => kv,
                Err(err) => {
                    match err.kind() {
                        io::ErrorKind::UnexpectedEof => {
                            // "Unexpected" is relative. The application may not have expected it, but we expect files to be finite.
                            break;
                        }
                        _ => return Err(err),
                    }
                }
            };

            if kv.key == target {
                found = Some((position, kv.value));
            }

            // important to keep looping until the end of the file,
            // in case the key has been overwritten
        }

        Ok(found)
    }

    pub fn insert(&mut self, key: &ByteStr, value: &ByteStr) -> io::Result<()> {
        let position = self.insert_but_ignore_index(key, value)?;

        self.index.insert(key.to_vec(), position);
        Ok(())
    }

    pub fn insert_but_ignore_index(&mut self, key: &ByteStr, value: &ByteStr) -> io::Result<u64> {
        let mut f = BufWriter::new(&mut self.f);

        let (encrypted_data, nonce) = ENCRYPTER.encrypt(value)?;

        let key_len = key.len();
        let val_len = encrypted_data.len();
        let mut tmp = ByteString::with_capacity(key_len + val_len);

        for byte in key {
            tmp.push(*byte);
        }

        for byte in encrypted_data {
            tmp.push(byte);
        }

        let checksum = blake3::hash(&tmp);

        let next_byte = SeekFrom::End(0);
        let current_position = f.seek(SeekFrom::Current(0))?;
        f.seek(next_byte)?;
        f.write(checksum.as_bytes())?;
        f.write(&nonce)?;
        f.write_u32::<LittleEndian>(key_len as u32)?;
        f.write_u32::<LittleEndian>(val_len as u32)?;
        f.write_all(&mut tmp)?;

        Ok(current_position)
    }

    #[inline]
    pub fn update(&mut self, key: &ByteStr, value: &ByteStr) -> io::Result<()> {
        self.insert(key, value)
    }

    #[inline]
    pub fn delete(&mut self, key: &ByteStr) -> io::Result<()> {
        self.insert(key, b"")
    }
}
