use ::{ADDRESS_PATTERN, AddressLengthType};
use ::patterns::{Pattern, Patterns, parse_patterns};
use std::borrow::Borrow;
use std::sync::{Arc, Mutex};
use clap::ArgMatches;
use generic_array::GenericArray;
use termcolor::BufferWriter;
use rayon::prelude::*;

impl Pattern for String {
    fn matches(&self, string: &str) -> bool {
        string.starts_with(self)
    }

    fn parse<T: AsRef<str>>(string: T) -> Result<Self, String> {
        let string = string.as_ref().to_lowercase();

        if !ADDRESS_PATTERN.is_match(&string) {
            return Err("Pattern contains invalid characters".to_string());
        }

        return Ok(string);
    }
}

pub struct StringPatterns {
    // Strings of length `n` are in the `n-1`th index of this array
    sorted_vecs: GenericArray<Option<Vec<String>>, AddressLengthType>,
}

impl StringPatterns {
    pub fn new(buffer_writer: Arc<Mutex<BufferWriter>>,
           matches: &ArgMatches) -> StringPatterns {
        let patterns = parse_patterns::<String>(buffer_writer, matches);
        let patterns_by_len: Arc<GenericArray<Mutex<Option<Vec<String>>>, AddressLengthType>> = Arc::new(arr![Mutex<Option<Vec<String>>>; Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None), Mutex::new(None)]);

        patterns.par_iter()
            .for_each(|pattern| {
                let patterns_by_len_borrowed: &GenericArray<Mutex<Option<Vec<String>>>, AddressLengthType> = patterns_by_len.borrow();
                let mut vec = patterns_by_len_borrowed[pattern.len() - 1].lock().expect("Something panicked somewhere, oops. Please report this incident to the author.");
                let vec = vec.get_or_insert_with(Vec::new);

                vec.push(pattern.clone());
            });


        let patterns_by_len_borrowed: GenericArray<Mutex<Option<Vec<String>>>, AddressLengthType> = Arc::try_unwrap(patterns_by_len).unwrap_or_else(|_| panic!("Couldn't unwrap petterns."));
        let sorted_vecs = patterns_by_len_borrowed.map(|item| {
            let item: Option<Vec<String>> = item.into_inner().unwrap();

            item.map(|mut vec| {
                vec.sort();
                vec.dedup();
                vec
            })
        });

        StringPatterns {
            sorted_vecs,
        }
    }
}

impl Patterns for StringPatterns {
    fn contains(&self, address: &String) -> bool {
        // Try match from shortest to longest patterns
        for (index, option_vec) in self.sorted_vecs.iter().enumerate() {
            if let &Some(ref vec) = option_vec {
                let pattern_len = index + 1;
                let target_address_slice = &address[0..pattern_len];

                if vec.binary_search_by(|item| item.as_str().cmp(target_address_slice)).is_ok() {
                    return true;
                }
            }
        }

        return false;
    }

    fn len(&self) -> usize {
        self.sorted_vecs.par_iter()
            .filter(|opt| opt.is_some())
            .map(|opt| opt.as_ref().unwrap().len())
            .sum()
    }
}
