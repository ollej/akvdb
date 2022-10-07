extern crate bincode;
extern crate libakvdb;

use libakvdb::{ActionKV, ByteString};
use std::{collections::HashMap, path::PathBuf};
use {
    aes_gcm::{
        aead::{KeyInit, OsRng},
        Aes256Gcm,
    },
    clap::Parser,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to database file
    #[arg(short, long)]
    database: Option<PathBuf>,

    /// Action to perform on database
    #[command(subcommand)]
    action: Action,
}

#[derive(clap::Subcommand, Clone, Debug)]
enum Action {
    /// <KEY> - Get an entry from the database
    Get {
        /// Key name to operate on
        key: String,
    },
    /// <KEY> - Delete an entry from the database
    Delete {
        /// Key name to operate on
        key: String,
    },
    /// <KEY> <VALUE> - Insert an entry into the database
    Insert {
        /// Key name to operate on
        key: String,

        /// Value to insert
        value: String,
    },
    /// <KEY> <VALUE> - Update an entry in the database
    Update {
        /// Key name to operate on
        key: String,

        /// Value to update
        value: String,
    },
    /// Print a randomized key to use for encryption
    Key,
}

fn open_database(path: Option<PathBuf>) -> ActionKV {
    let path = path.expect("Path to database required for action.");
    ActionKV::open(&path).expect("Unable to open database file.")
}

fn load_database(path: Option<PathBuf>) -> ActionKV {
    let mut akv = open_database(path);
    akv.load().expect("unable to load data");
    akv
}

fn store_index_on_disk(a: &mut ActionKV, index_key: &[u8]) {
    a.index.remove(index_key);
    let index_as_bytes = bincode::serialize(&a.index).unwrap();
    a.index = std::collections::HashMap::new();
    a.insert(index_key, &index_as_bytes).unwrap();
}

fn main() {
    const INDEX_KEY: &[u8] = b"+index";

    let args = Args::parse();

    match args.action {
        Action::Get { key } => {
            let mut akv = open_database(args.database);
            let index: HashMap<ByteString, u64> = match akv.find(INDEX_KEY) {
                Ok(Some((_position, index_as_bytes))) => {
                    bincode::deserialize(&index_as_bytes).unwrap()
                }
                Ok(None) => {
                    akv.load().expect("unable to load data");
                    akv.index.clone()
                }
                Err(_) => panic!("unable to open file"),
            };

            match index.get(key.as_bytes()) {
                None => eprintln!("{:?} not found", key),
                Some(&i) => {
                    let kv = akv.get_at(i).unwrap();
                    if let Ok(value) = String::from_utf8(kv.value.clone()) {
                        println!("{} = {:?}", key, value)
                    } else {
                        println!("{} = {:?}", key, kv.value)
                    }
                }
            }
        }
        // Other actions can actually remain as-is. In a long-standing application, it would be
        // necessary to clean up the index. As this utility is one-shot, it isn't essential here.
        Action::Delete { key } => {
            let mut akv = load_database(args.database);
            akv.delete(key.as_ref()).unwrap();
            store_index_on_disk(&mut akv, INDEX_KEY);
        }
        Action::Insert { key, value } => {
            let mut akv = load_database(args.database);
            akv.insert(key.as_ref(), value.as_ref()).unwrap();
            store_index_on_disk(&mut akv, INDEX_KEY);
        }
        Action::Update { key, value } => {
            let mut akv = load_database(args.database);
            akv.update(key.as_ref(), value.as_ref()).unwrap();
            store_index_on_disk(&mut akv, INDEX_KEY);
        }
        Action::Key => {
            let key = Aes256Gcm::generate_key(&mut OsRng);
            let encoded_key = base_62::encode(key.as_slice());
            println!("{}", encoded_key);
        }
    }
}
