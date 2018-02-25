mod string;
mod regex;

pub use self::string::*;
pub use self::regex::*;

use std;
use std::fmt::Display;
use std::io::BufRead;
use std::sync::{Arc, Mutex};
use clap::ArgMatches;
use termcolor::{BufferWriter, Color};

trait Pattern: Display + Send + Sync + Sized {
    fn matches(&self, string: &str) -> bool;
    fn parse<T: AsRef<str>>(string: T) -> Result<Self, String>;
}

pub trait Patterns: Sync + Send {
    fn contains(&self, address: &String) -> bool;
    fn len(&self) -> usize;
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

fn parse_patterns<P: Pattern>(buffer_writer: Arc<Mutex<BufferWriter>>,
                              matches: &ArgMatches)
                              -> Vec<P> {
    // TODO: Use rayon (everywhere)
    let mut vec: Vec<P> = Vec::new();
    let raw_patterns = read_patterns(matches);

    for raw_pattern in raw_patterns {
        if raw_pattern.is_empty() {
            continue;
        }

        match <P as Pattern>::parse(&raw_pattern) {
            Ok(pattern) => vec.push(pattern),
            Err(error) => {
                let mut stdout = buffer_writer.lock().unwrap().buffer();
                cprint!(matches.is_present("quiet"),
                        stdout,
                        Color::Yellow,
                        "Skipping pattern '{}': ",
                        &raw_pattern);
                cprintln!(matches.is_present("quiet"),
                          stdout,
                          Color::White,
                          "{}",
                          error);
                buffer_writer
                    .lock()
                    .unwrap()
                    .print(&stdout)
                    .expect("Could not write to stdout.");
            }
        }
    }

    vec
}
