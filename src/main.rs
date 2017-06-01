extern crate itertools;
extern crate rand;
extern crate regex;
extern crate secp256k1;
extern crate tiny_keccak;
extern crate num_cpus;

use rand::OsRng;
use regex::RegexBuilder;
use secp256k1::Secp256k1;
use std::fmt::Write;
use std::env;
use std::sync::Mutex;
use std::thread;
use std::sync::Arc;

const ADDRESS_LENGTH: usize = 40;
const ADDRESS_BYTES: usize = ADDRESS_LENGTH / 2;
const KECCAK_OUTPUT_BYTES: usize = 32;
const ADDRESS_BYTE_INDEX: usize = KECCAK_OUTPUT_BYTES - ADDRESS_BYTES;

struct BruteforceResult {
    address: String,
    private_key: String,
}

fn to_hex_string(slice: &[u8], expected_string_size: usize) -> String {
    let mut result = String::with_capacity(expected_string_size);

    for &byte in slice {
        write!(&mut result, "{:02x}", byte).expect("Unable to format the public key.");
    }

    result
}

fn main() {
    let mut args_iter = env::args();
    args_iter.next();
    let args = itertools::join(args_iter, " ");
    let regex = Arc::new(match RegexBuilder::new(&args).case_insensitive(true)
                                              .multi_line(false)
                                              .dot_matches_new_line(false)
                                              .ignore_whitespace(true)
                                              .unicode(true)
                                              .build() {
        Ok(result) => result,
        Err(error) => {
            println!("Invalid regex: {}", error);
            return;
        }
    });
    let thread_count = num_cpus::get();
    let mut threads = Vec::with_capacity(thread_count);
    let result: Arc<Mutex<Option<BruteforceResult>>> = Arc::new(Mutex::new(None));
    let alg = Arc::new(Secp256k1::new());

    for _ in 0..thread_count {
        let regex = regex.clone();
        let result = result.clone();
        let alg = alg.clone();

        threads.push(thread::spawn(move || {
            'dance:
            loop {
                {
                    let result_guard = result.lock().unwrap();

                    if let Some(_) = *result_guard {
                        break 'dance;
                    }
                }

                let mut rng = OsRng::new()
                    .expect("Could not create a secure random number generator. Please file a GitHub issue.");
                let (private_key, public_key) = alg.generate_keypair(&mut rng)
                    .expect("Could not generate a random keypair. Please file a GitHub issue.");
                let public_key_array = &public_key.serialize_vec(&alg, false)[1..];
                let keccak = tiny_keccak::keccak256(public_key_array);
                let address = to_hex_string(&keccak[ADDRESS_BYTE_INDEX..], 40);  // get rid of the constant 0x04 byte

                if regex.is_match(&address) {
                    *result.lock().unwrap() = Some(BruteforceResult {
                        address,
                        private_key: to_hex_string(&private_key[..], 64),
                    });
                    break 'dance;
                }
            }
        }));
    }

    for thread in threads {
        thread.join().unwrap();
    }

    let result = result.lock().unwrap();
    let result = result.as_ref().unwrap();

    println!("Found address: 0x{}", result.address);
    println!("Generated private key: {}", result.private_key);
    println!("Import this private key into an ethereum wallet in order to use the address.");
    println!("Buy me a cup of coffee; my ethereum address: 0xc0ffee3bd37d408910ecab316a07269fc49a20ee");
}
