#[macro_use]
extern crate clap;
#[macro_use]
extern crate lazy_static;
extern crate rayon;
extern crate rand;
extern crate regex;
extern crate secp256k1;
extern crate tiny_keccak;
extern crate num_cpus;
extern crate termcolor;
#[macro_use]
extern crate generic_array;
extern crate typenum;

#[macro_use]
mod macros;
mod patterns;

use patterns::{Patterns, StringPatterns, RegexPatterns};
use std::fmt::Write;
use std::sync::Mutex;
use std::sync::RwLock;
use std::thread;
use std::thread::JoinHandle;
use std::sync::Arc;
use std::sync::atomic::{Ordering, AtomicUsize};
use std::time::Duration;
use clap::{Arg, ArgMatches};
use rand::{Rng, OsRng};
use regex::Regex;
use secp256k1::Secp256k1;
use secp256k1::key::{SecretKey, PublicKey};
use secp256k1::constants::SECRET_KEY_SIZE;
use termcolor::{Color, ColorChoice, Buffer, BufferWriter};
use typenum::U40;

type AddressLengthType = U40;

const ADDRESS_LENGTH: usize = 40;
const ADDRESS_BYTES: usize = ADDRESS_LENGTH / 2;
const KECCAK_OUTPUT_BYTES: usize = 32;
const ADDRESS_BYTE_INDEX: usize = KECCAK_OUTPUT_BYTES - ADDRESS_BYTES;

lazy_static! {
    static ref ADDRESS_PATTERN: Regex = Regex::new(r"^[0-9a-f]{1,40}$").unwrap();
}

struct BruteforceResult {
    address: String,
    private_key: String,
}

fn parse_color_choice(string: &str) -> Result<ColorChoice, ()> {
    Ok(match string {
           "always" => ColorChoice::Always,
           "always_ansi" => ColorChoice::AlwaysAnsi,
           "auto" => ColorChoice::Auto,
           "never" => ColorChoice::Never,
           _ => return Err(()),
       })
}

fn to_hex_string(slice: &[u8], expected_string_size: usize) -> String {
    let mut result = String::with_capacity(expected_string_size);

    for &byte in slice {
        write!(&mut result, "{:02x}", byte).expect("Unable to format the public key.");
    }

    result
}

fn increment(bytes: &mut [u8]) -> bool {
    let len = bytes.len();
    let (mut rest, last) = bytes.split_at_mut(len - 1);

    if last[0] == 0xFF {
        last[0] = 0x00;

        if rest.len() > 0 {
            increment(&mut rest)
        } else {
            true
        }
    } else {
        last[0] += 1;

        false
    }
}

fn main() {
    let matches = app_from_crate!()
        .arg(Arg::with_name("regexp")
             .long("regexp")
             .short("e")
             .help("Use regex pattern matching")
             .long_help("By default, an address is accepted when the beginning matches one of the
strings provided as the patterns. This flag changes the functionality from
plain string matching to regex pattern matching."))
        .arg(Arg::with_name("quiet")
             .long("quiet")
             .short("q")
             .help("Output only the results")
             .long_help("Output only the resulting address and private key separated by a space."))
        .arg(Arg::with_name("color")
             .long("color")
             .short("c")
             .help("Changes the color formatting strategy")
             .long_help("Changes the color formatting strategy in the following way:
    always      -- Try very hard to emit colors. This includes
                   emitting ANSI colors on Windows if the console
                   API is unavailable.
    always_ansi -- like always, except it never tries to use
                   anything other than emitting ANSI color codes.
    auto        -- Try to use colors, but don't force the issue.
                   If the console isn't available on Windows, or
                   if TERM=dumb, for example, then don't use colors.
    never       -- Never emit colors.\n")
             .takes_value(true)
             .possible_values(&["always", "always_ansi", "auto", "never"])
             .default_value("auto"))
        .arg(Arg::with_name("stream")
             .long("stream")
             .short("s")
             .help("Keep outputting results")
             .long_help("Instead of outputting a single result, keep outputting until terminated."))
        .arg(Arg::with_name("incremental")
             .long("incremental")
             .help("Only use the system random number generator once, may improve performance at
the cost of security")
             .long_help("Instead of generating a random secret key for every attempt to match the
address, generate the random secret key once for each thread and then just increment the secret key
to derive the next address over and over."))
        .arg(Arg::with_name("PATTERN")
             .help("The pattern to match the address against")
             .long_help("The pattern to match the address against.
If no patterns are provided, they are read from the stdin (standard input),
where each pattern is on a separate line.
Addresses are outputted if the beginning matches one of these patterns.
If the `--regexp` flag is used, the addresses are matched against these
patterns as regex patterns, which replaces the basic string comparison.")
             .multiple(true))
        .get_matches();

    let quiet = matches.is_present("quiet");
    let incremental = matches.is_present("incremental");
    let color_choice = parse_color_choice(matches.value_of("color").unwrap()).unwrap();
    let buffer_writer = Arc::new(Mutex::new(BufferWriter::stdout(color_choice)));

    if matches.is_present("regexp") {
        let patterns = Arc::new(RegexPatterns::new(buffer_writer.clone(), &matches));

        main_pattern_type_selected(matches, quiet, incremental, buffer_writer, patterns);
    } else {
        let patterns = Arc::new(StringPatterns::new(buffer_writer.clone(), &matches));

        main_pattern_type_selected(matches, quiet, incremental, buffer_writer, patterns);
    };
}

#[derive(Clone)]
struct Context<P: Patterns + 'static> {
    buffer_writer: Arc<Mutex<BufferWriter>>,
    working_threads: Arc<Mutex<usize>>,
    patterns: Arc<P>,
    result: Arc<RwLock<Option<BruteforceResult>>>,
    alg: Arc<Secp256k1>,
    iterations_this_second: Arc<AtomicUsize>,
    incremental: bool,
    quiet: bool,
}

fn main_pattern_type_selected<P: Patterns + 'static>(matches: ArgMatches,
                                                     quiet: bool,
                                                     incremental: bool,
                                                     buffer_writer: Arc<Mutex<BufferWriter>>,
                                                     patterns: Arc<P>) {
    if patterns.len() <= 0 {
        let mut stdout = buffer_writer.lock().unwrap().buffer();
        cprintln!(false,
                  stdout,
                  Color::Red,
                  "Please, provide at least one valid pattern.");
        buffer_writer
            .lock()
            .unwrap()
            .print(&stdout)
            .expect("Could not write to stdout.");
        std::process::exit(1);
    }

    let thread_count = num_cpus::get();
    let alg = Arc::new(Secp256k1::new());
    let mut first = true;

    loop {
        let mut threads = Vec::with_capacity(thread_count);
        let result: Arc<RwLock<Option<BruteforceResult>>> = Arc::new(RwLock::new(None));
        let iterations_this_second = Arc::new(AtomicUsize::new(0));
        let working_threads = Arc::new(Mutex::new(thread_count));
        let context = Context {
            buffer_writer: buffer_writer.clone(),
            working_threads,
            patterns: patterns.clone(),
            result,
            alg: alg.clone(),
            iterations_this_second,
            incremental,
            quiet,
        };

        if first {
            announce_introduction(&context);
            first = false;
        }

        for _ in 0..thread_count {
            let context = context.clone();

            threads.push(spawn_worker_thread(context));
        }

        // Note:
        // Buffers are intended for correct concurrency.
        let sync_buffer: Arc<Mutex<Option<Buffer>>> = Arc::new(Mutex::new(None));

        {
            let buffer_writer = buffer_writer.clone();
            let sync_buffer = sync_buffer.clone();
            let result = context.result.clone();
            let context = context.clone();

            thread::spawn(move || 'dance: loop {
                thread::sleep(Duration::from_secs(1));

                {
                    let result_guard = result.read().unwrap();

                    if let Some(_) = *result_guard {
                        break 'dance;
                    }
                }

                let mut buffer = buffer_writer.lock().unwrap().buffer();
                let iterations_per_second = context.iterations_this_second.swap(0, Ordering::Relaxed);
                cprint!(quiet, buffer, Color::Cyan, "{}", iterations_per_second);
                cprintln!(quiet, buffer, Color::White, " addresses / second");
                *sync_buffer.lock().unwrap() = Some(buffer);
            });
        }

        'dance: loop {
            if *context.working_threads.lock().unwrap() <= 0 {
                break 'dance;
            }

            if let Some(ref buffer) = *sync_buffer.lock().unwrap() {
                buffer_writer
                    .lock()
                    .unwrap()
                    .print(buffer)
                    .expect("Could not write to stdout.");
            }

            *sync_buffer.lock().unwrap() = None;

            thread::sleep(Duration::from_millis(10));
        }

        for thread in threads {
            thread.join().unwrap();
        }

        let result = context.result.read().unwrap();
        let result = result.as_ref().unwrap();

        announce_result(&context, &result);

        if !matches.is_present("stream") {
            break;
        }
    }
}

fn spawn_worker_thread<P: Patterns + 'static>(context: Context<P>) -> JoinHandle<()> {
    let mut rng = OsRng::new()
        .expect("Could not create a secure random number generator. Please file a GitHub issue.");
    let mut bytes = [0u8; SECRET_KEY_SIZE];

    rng.fill_bytes(&mut bytes);

    let mut derive_next_secret_key: Box<FnMut(&mut [u8]) + Send> = if context.incremental {
        Box::new(|seckey| { increment(seckey); })
    } else {
        Box::new(move |seckey| rng.fill_bytes(seckey))
    };

    thread::spawn(move || {
        'dance:
        loop {
            {
                let result_guard = context.result.read().unwrap();

                if let Some(_) = *result_guard {
                    break 'dance;
                }
            }

            let private_key = match SecretKey::from_slice(&*context.alg, &bytes) {
                Ok(private_key) => private_key,
                Err(_) => continue,
            };
            let public_key = match PublicKey::from_secret_key(&*context.alg, &private_key) {
                Ok(public_key) => public_key,
                Err(_) => continue,
            };
            let public_key_array = &public_key.serialize()[1..];
            let keccak = tiny_keccak::keccak256(public_key_array);
            let address = to_hex_string(&keccak[ADDRESS_BYTE_INDEX..], 40);  // get rid of the constant 0x04 byte

            if context.patterns.contains(&address) {
                *context.result.write().unwrap() = Some(BruteforceResult {
                    address,
                    private_key: to_hex_string(&private_key[..], 64),
                });
                break 'dance;
            }

            context.iterations_this_second.fetch_add(1, Ordering::Relaxed);

            derive_next_secret_key(&mut bytes);
        }

        *context.working_threads.lock().unwrap() -= 1;
    })
}

fn announce_introduction<P: Patterns + 'static>(context: &Context<P>) {
    let mut stdout = context.buffer_writer.lock().unwrap().buffer();
    cprintln!(context.quiet,
              stdout,
              Color::White,
              "---------------------------------------------------------------------------------------");

    if context.patterns.len() <= 1 {
        cprint!(context.quiet,
                stdout,
                Color::White,
                "Looking for an address matching ");
    } else {
        cprint!(context.quiet,
                stdout,
                Color::White,
                "Looking for an address matching any of ");
    }

    cprint!(context.quiet, stdout, Color::Cyan, "{}", context.patterns.len());

    if context.patterns.len() <= 1 {
        cprint!(context.quiet, stdout, Color::White, " pattern");
    } else {
        cprint!(context.quiet, stdout, Color::White, " patterns");
    }

    cprintln!(context.quiet, stdout, Color::White, "");
    cprintln!(context.quiet,
              stdout,
              Color::White,
              "---------------------------------------------------------------------------------------");
    context.buffer_writer
        .lock()
        .unwrap()
        .print(&stdout)
        .expect("Could not write to stdout.");
}

fn announce_result<P: Patterns + 'static>(context: &Context<P>, result: &BruteforceResult) {
    {
        let mut stdout = context.buffer_writer.lock().unwrap().buffer();
        cprintln!(context.quiet,
                  stdout,
                  Color::White,
                  "---------------------------------------------------------------------------------------");
        cprint!(context.quiet, stdout, Color::White, "Found address: ");
        cprintln!(context.quiet, stdout, Color::Yellow, "0x{}", result.address);
        cprint!(context.quiet, stdout, Color::White, "Generated private key: ");
        cprintln!(context.quiet, stdout, Color::Red, "{}", result.private_key);
        cprintln!(context.quiet,
                  stdout,
                  Color::White,
                  "Import this private key into an ethereum wallet in order to use the address.");
        cprintln!(context.quiet,
                  stdout,
                  Color::Green,
                  "Buy me a cup of coffee; my ethereum address: 0xc0ffee3bd37d408910ecab316a07269fc49a20ee");
        cprintln!(context.quiet,
                  stdout,
                  Color::White,
                  "---------------------------------------------------------------------------------------");
        context.buffer_writer
            .lock()
            .unwrap()
            .print(&stdout)
            .expect("Could not write to stdout.");
    }

    if context.quiet {
        println!("0x{} {}", result.address, result.private_key);
    }
}
