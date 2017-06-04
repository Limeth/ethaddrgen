#[macro_use]
extern crate clap;
#[macro_use]
extern crate lazy_static;
extern crate itertools;
extern crate rand;
extern crate regex;
extern crate secp256k1;
extern crate tiny_keccak;
extern crate num_cpus;
extern crate termcolor;

use clap::{Arg, ArgMatches};
use rand::OsRng;
use regex::{Regex, RegexBuilder};
use secp256k1::Secp256k1;
use std::io::BufRead;
use std::fmt::Write;
use std::io::Write as IoWrite;
use std::sync::Mutex;
use std::thread;
use std::sync::Arc;
use std::time::Duration;
use std::fmt::Display;
use termcolor::{Color, ColorChoice, ColorSpec, StandardStream, WriteColor};
use std::ops::Deref;

const ADDRESS_LENGTH: usize = 40;
const ADDRESS_BYTES: usize = ADDRESS_LENGTH / 2;
const KECCAK_OUTPUT_BYTES: usize = 32;
const ADDRESS_BYTE_INDEX: usize = KECCAK_OUTPUT_BYTES - ADDRESS_BYTES;

lazy_static! {
    static ref ADDRESS_PATTERN: Regex = Regex::new(r"^[0-9a-f]{1,40}$").unwrap();
}

macro_rules! cprintln {
    ($surpress:expr, $color_choice:expr, $fg:expr, $bg:expr, $($rest:tt)+) => {
        if !$surpress {
            let mut stdout = StandardStream::stdout($color_choice);
            stdout.set_color(ColorSpec::new().set_fg($fg).set_bg($bg))
                .expect("Could not set the text formatting.");
            writeln!(&mut stdout, $($rest)+).expect("Could not output text.");
        }
    }
}

macro_rules! cprint {
    ($surpress:expr, $color_choice:expr, $fg:expr, $bg:expr, $($rest:tt)+) => {
        if !$surpress {
            let mut stdout = StandardStream::stdout($color_choice);
            stdout.set_color(ColorSpec::new().set_fg($fg).set_bg($bg))
                .expect("Could not set the text formatting.");
            write!(&mut stdout, $($rest)+).expect("Could not output text.");
        }
    }
}

struct BruteforceResult {
    address: String,
    private_key: String,
}

#[derive(Copy, Clone)]
enum PatternType {
    String,
    Regex,
}

trait Pattern: Display + Send + Sync {
    fn matches(&self, string: &str) -> bool;
}

impl Pattern for Regex {
    fn matches(&self, string: &str) -> bool {
        self.is_match(string)
    }
}

impl Pattern for String {
    fn matches(&self, string: &str) -> bool {
        string.starts_with(self)
    }
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

fn parse_pattern<T: AsRef<str>>(string: T,
                                pattern_type: PatternType)
                                -> Result<Box<Pattern>, String> {
    match pattern_type {
        PatternType::String => {
            let string = string.as_ref().to_lowercase();

            if !ADDRESS_PATTERN.is_match(&string) {
                return Err("Pattern contains invalid characters".to_string());
            }

            return Ok(Box::new(string));
        }
        PatternType::Regex => {
            match RegexBuilder::new(string.as_ref())
                      .case_insensitive(true)
                      .multi_line(false)
                      .dot_matches_new_line(false)
                      .ignore_whitespace(true)
                      .unicode(true)
                      .build() {
                Ok(result) => return Ok(Box::new(result)),
                Err(error) => return Err(format!("Invalid regex: {}", error)),
            }
        }
    }
}

fn read_patterns(matches: &ArgMatches) -> Vec<String> {
    if let Some(args) = matches.values_of("PATTERN") {
        args.map(str::to_string).collect()
    } else {
        let mut result = Vec::new();
        let stdin = std::io::stdin();

        for line in stdin.lock().lines() {
            match line {
                Ok(line) => result.push(line),
                Err(error) => panic!("{}", error),
            }
        }

        result
    }
}

fn get_patterns(color_choice: ColorChoice, matches: &ArgMatches) -> Vec<Box<Pattern>> {
    let mut result: Vec<Box<Pattern>> = Vec::new();
    let raw_patterns = read_patterns(matches);
    let pattern_type = if matches.is_present("regexp") {
        PatternType::Regex
    } else {
        PatternType::String
    };

    for raw_pattern in raw_patterns {
        if raw_pattern.is_empty() {
            continue;
        }

        match parse_pattern(&raw_pattern, pattern_type) {
            Ok(pattern) => result.push(pattern),
            Err(error) => {
                cprint!(matches.is_present("quiet"),
                        color_choice,
                        Some(Color::Yellow),
                        None,
                        "Skipping pattern '{}': ",
                        &raw_pattern);
                cprintln!(matches.is_present("quiet"),
                          color_choice,
                          None,
                          None,
                          "{}",
                          error);
            }
        }
    }

    result
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
    let color_choice = parse_color_choice(matches.value_of("color").unwrap()).unwrap();
    let patterns = Arc::new(get_patterns(color_choice, &matches));

    if patterns.is_empty() {
        cprintln!(false,
                  color_choice,
                  Some(Color::Red),
                  None,
                  "Please, provide at least one valid pattern.");
        std::process::exit(1);
    }

    cprintln!(quiet,
              color_choice,
              None,
              None,
              "---------------------------------------------------------------------------------------");
    cprint!(quiet,
            color_choice,
            None,
            None,
            "Looking for an address matching ");
    cprint!(quiet,
            color_choice,
            Some(Color::Blue),
            None,
            "{}",
            patterns.len());
    cprint!(quiet, color_choice, None, None, " pattern");

    if patterns.len() > 1 {
        cprint!(quiet, color_choice, None, None, "s");
    }

    cprintln!(quiet, color_choice, None, None, "");
    cprintln!(quiet,
              color_choice,
              None,
              None,
              "---------------------------------------------------------------------------------------");

    let thread_count = num_cpus::get();

    loop {
        let mut threads = Vec::with_capacity(thread_count);
        let result: Arc<Mutex<Option<BruteforceResult>>> = Arc::new(Mutex::new(None));
        let iterations_this_second: Arc<Mutex<u32>> = Arc::new(Mutex::new(0));
        let alg = Arc::new(Secp256k1::new());

        for _ in 0..thread_count {
            let patterns = patterns.clone();
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

                    for pattern in patterns.deref() {
                        if pattern.matches(&address) {
                            *result.lock().unwrap() = Some(BruteforceResult {
                                address,
                                private_key: to_hex_string(&private_key[..], 64),
                            });
                            break 'dance;
                        }
                    }

                    *iterations_this_second.lock().unwrap() += 1;
                }
            }));
        }

        {
            let result = result.clone();

            thread::spawn(move || 'dance: loop {
                              thread::sleep(Duration::from_secs(1));

                              {
                                  let result_guard = result.lock().unwrap();

                                  if let Some(_) = *result_guard {
                                      break 'dance;
                                  }
                              }

                              let mut iterations_per_second =
                                  iterations_this_second.lock().unwrap();
                              cprint!(quiet,
                                      color_choice,
                                      Some(Color::Blue),
                                      None,
                                      "{}",
                                      *iterations_per_second);
                              cprintln!(quiet, color_choice, None, None, " addresses / second");
                              *iterations_per_second = 0;
                          });
        }

        for thread in threads {
            thread.join().unwrap();
        }

        let result = result.lock().unwrap();
        let result = result.as_ref().unwrap();

        cprintln!(quiet,
                  color_choice,
                  None,
                  None,
                  "---------------------------------------------------------------------------------------");
        cprint!(quiet, color_choice, None, None, "Found address: ");
        cprintln!(quiet,
                  color_choice,
                  Some(Color::Yellow),
                  None,
                  "0x{}",
                  result.address);
        cprint!(quiet, color_choice, None, None, "Generated private key: ");
        cprintln!(quiet,
                  color_choice,
                  Some(Color::Red),
                  None,
                  "{}",
                  result.private_key);
        cprintln!(quiet,
                  color_choice,
                  None,
                  None,
                  "Import this private key into an ethereum wallet in order to use the address.");
        cprintln!(quiet,
                  color_choice,
                  Some(Color::Green),
                  None,
                  "Buy me a cup of coffee; my ethereum address: 0xc0ffee3bd37d408910ecab316a07269fc49a20ee");
        cprintln!(quiet,
                  color_choice,
                  None,
                  None,
                  "---------------------------------------------------------------------------------------");

        if quiet {
            println!("0x{} {}", result.address, result.private_key);
        }

        if !matches.is_present("stream") {
            break;
        }
    }
}
