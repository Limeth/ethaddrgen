use patterns::{Pattern, Patterns, parse_patterns};
use std::sync::{Arc, Mutex};
use regex::{Regex, RegexBuilder};
use clap::ArgMatches;
use termcolor::BufferWriter;

impl Pattern for Regex {
    fn matches(&self, string: &str) -> bool {
        self.is_match(string)
    }

    fn parse<T: AsRef<str>>(string: T) -> Result<Self, String> {
        match RegexBuilder::new(string.as_ref())
                  .case_insensitive(true)
                  .multi_line(false)
                  .dot_matches_new_line(false)
                  .ignore_whitespace(true)
                  .unicode(true)
                  .build() {
            Ok(result) => return Ok(result),
            Err(error) => return Err(format!("Invalid regex: {}", error)),
        }
    }
}

pub struct RegexPatterns {
    vec: Vec<Regex>,
}

impl RegexPatterns {
    pub fn new(buffer_writer: Arc<Mutex<BufferWriter>>, matches: &ArgMatches) -> RegexPatterns {
        RegexPatterns { vec: parse_patterns(buffer_writer, matches) }
    }
}

impl Patterns for RegexPatterns {
    fn contains(&self, address: &String) -> bool {
        // Linear search
        for pattern in &self.vec {
            if pattern.matches(address) {
                return true;
            }
        }

        return false;
    }

    fn len(&self) -> usize {
        self.vec.len()
    }
}
