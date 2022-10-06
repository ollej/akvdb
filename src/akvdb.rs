extern crate bincode;
extern crate libactionkv;

//use std::io::prelude::*;
use libactionkv::{ActionKV, ByteString};
use std::collections::HashMap;

#[cfg(target_os = "windows")]
const USAGE: &'static str = "
Usage:
    akv_mem.exe FILE get KEY
    akv_mem.exe FILE delete KEY
    akv_mem.exe FILE insert KEY VALUE
    akv_mem.exe FILE update KEY VALUE
";

#[cfg(not(target_os = "windows"))]
const USAGE: &'static str = "
Usage:
    akv_mem FILE get KEY
    akv_mem FILE delete KEY
    akv_mem FILE insert KEY VALUE
    akv_mem FILE update KEY VALUE
";

fn store_index_on_disk(a: &mut ActionKV, index_key: &[u8]) {
    a.index.remove(index_key);
    let index_as_bytes = bincode::serialize(&a.index).unwrap();
    a.index = std::collections::HashMap::new();
    a.insert(index_key, &index_as_bytes).unwrap();
}

fn main() {
    const INDEX_KEY: &[u8] = b"+index";

    let args: Vec<String> = std::env::args().collect();
    let fname = args.get(1).expect(&USAGE);
    let action = args.get(2).expect(&USAGE).as_ref();
    let key = args.get(3).expect(&USAGE).as_ref();
    let maybe_value = args.get(4);

    let path = std::path::Path::new(&fname);
    let mut akv = ActionKV::open(path).expect("unable to open file");

    match action {
        "get" => {
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

            match index.get(key) {
                None => eprintln!("{:?} not found", key),
                Some(&i) => {
                    let kv = akv.get_at(i).unwrap();
                    println!("{:?}", kv.value)
                }
            }
        }
        // Other actions can actually remain as-is. In a long-standing application, it would be
        // necessary to clean up the index. As this utility is one-shot, it isn't essential here.
        "delete" => {
            akv.load().expect("unable to load data");
            akv.delete(key).unwrap();
            store_index_on_disk(&mut akv, INDEX_KEY);
        }

        "insert" => {
            akv.load().expect("unable to load data");
            let value = maybe_value.expect(&USAGE).as_ref();
            akv.insert(key, value).unwrap();
            store_index_on_disk(&mut akv, INDEX_KEY);
        }
        "update" => {
            akv.load().expect("unable to load data");
            let value = maybe_value.expect(&USAGE).as_ref();
            akv.update(key, value).unwrap();
            store_index_on_disk(&mut akv, INDEX_KEY);
        }
        _ => eprintln!("{}", &USAGE),
    }
}
