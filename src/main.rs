extern crate itertools;
extern crate rand;
extern crate regex;
extern crate secp256k1;
extern crate tiny_keccak;
extern crate num_cpus;
extern crate termcolor;

use rand::OsRng;
use regex::RegexBuilder;
use secp256k1::Secp256k1;
use std::fmt::Write;
use std::io::Write as IoWrite;
use std::env;
use std::sync::Mutex;
use std::thread;
use std::sync::Arc;
use std::time::Duration;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

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

macro_rules! cprintln {
    ($color_choice:expr, $fg:expr, $bg:expr, $($rest:tt)+) => {
        let mut stdout = StandardStream::stdout($color_choice);
        stdout.set_color(ColorSpec::new().set_fg($fg).set_bg($bg))
            .expect("Could not set the text formatting.");
        writeln!(&mut stdout, $($rest)+).expect("Could not output text.");
    }
}

macro_rules! cprint {
    ($color_choice:expr, $fg:expr, $bg:expr, $($rest:tt)+) => {
        let mut stdout = StandardStream::stdout($color_choice);
        stdout.set_color(ColorSpec::new().set_fg($fg).set_bg($bg))
            .expect("Could not set the text formatting.");
        write!(&mut stdout, $($rest)+).expect("Could not output text.");
    }
}

fn main() {
    let color_choice = ColorChoice::Auto;  // TODO: make an argument for this
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
            cprintln!(color_choice, Some(Color::Red), None, "Invalid regex: {}", error);
            return;
        }
    });
    let thread_count = num_cpus::get();
    let mut threads = Vec::with_capacity(thread_count);
    let result: Arc<Mutex<Option<BruteforceResult>>> = Arc::new(Mutex::new(None));
    let iterations_this_second: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
    let alg = Arc::new(Secp256k1::new());

    cprintln!(color_choice, None, None, "---------------------------------------------------------------------------------------");
    cprint!(color_choice, None, None, "Looking for an address matching the following pattern: ");
    cprintln!(color_choice, Some(Color::Yellow), None, "{}", args);
    cprintln!(color_choice, None, None, "---------------------------------------------------------------------------------------");

    for _ in 0..thread_count {
        let regex = regex.clone();
        let result = result.clone();
        let alg = alg.clone();
        let iterations_this_second = iterations_this_second.clone();

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

                *iterations_this_second.lock().unwrap() += 1;
            }
        }));
    }

    {
        let result = result.clone();

        thread::spawn(move || {
            'dance:
            loop {
                thread::sleep(Duration::from_secs(1));

                {
                    let result_guard = result.lock().unwrap();

                    if let Some(_) = *result_guard {
                        break 'dance;
                    }
                }

                let mut iterations_per_second = iterations_this_second.lock().unwrap();
                cprint!(color_choice, Some(Color::Blue), None, "{}", *iterations_per_second);
                cprintln!(color_choice, None, None, " addresses / second");
                *iterations_per_second = 0;
            }
        });
    }

    for thread in threads {
        thread.join().unwrap();
    }

    let result = result.lock().unwrap();
    let result = result.as_ref().unwrap();

    cprintln!(color_choice, None, None, "---------------------------------------------------------------------------------------");
    cprint!(color_choice, None, None, "Found address: ");
    cprintln!(color_choice, Some(Color::Yellow), None, "0x{}", result.address);
    cprint!(color_choice, None, None, "Generated private key: ");
    cprintln!(color_choice, Some(Color::Red), None, "{}", result.private_key);
    cprintln!(color_choice, None, None, "Import this private key into an ethereum wallet in order to use the address.");
    cprintln!(color_choice, Some(Color::Green), None, "Buy me a cup of coffee; my ethereum address: 0xc0ffee3bd37d408910ecab316a07269fc49a20ee");
    cprintln!(color_choice, None, None, "---------------------------------------------------------------------------------------");
}
