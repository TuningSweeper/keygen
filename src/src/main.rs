#![allow(unused_imports)]
#![allow(unused_assignments)]

#[path = "random.rs"] mod random;
use random::{generate_u64_os, generate_u64_rdrand, generate_u64_cpujitter, generate_u64};

#[path = "alphabet.rs"] mod alphabet;
use alphabet::{alphabet_commonsafe_get_element, alphabet_commonsafe_get_count, alphabet_normal_get_element, alphabet_normal_get_count, alphabet_ascii_get_element, alphabet_ascii_get_count, alphabet_assembly_get_element, alphabet_assembly_get_count};
use zeroize::Zeroize;

use std::env;
use std::fmt;
use std::str::FromStr;
use clap::{App, Arg};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const PACKAGE_NAME: &str = env!("CARGO_PKG_NAME");

enum RandomSource {
    Combined,
    Rdrand,
    Os,
    CpuJitter,
    CpuJitterRaw,
}

impl fmt::Debug for RandomSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RandomSource::Combined => write!(f, "combined"),
            RandomSource::Rdrand => write!(f, "rdrand"),
            RandomSource::Os => write!(f, "os"),
            RandomSource::CpuJitter => write!(f, "cpujitter"),
            RandomSource::CpuJitterRaw => write!(f, "cpujitter-raw"),
        }
    }
}

impl FromStr for RandomSource {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "combined" => Ok(RandomSource::Combined),
            "rdrand" => Ok(RandomSource::Rdrand),
            "os" => Ok(RandomSource::Os),
            "cpujitter" => Ok(RandomSource::CpuJitter),
            "cpujitter-raw" => Ok(RandomSource::CpuJitterRaw),
            _ => Err(()),
        }
    }
}

struct Config {
    debug: bool,
    bits: u32,
    alphabet: String,
    delimiter: String,
    count: usize,
    rngtest: Option<(RandomSource, u32, NumFormat)>,
}

enum NumFormat {
    RawBinary,
    U8,
    U16,
    U32,
    U64,
}

impl FromStr for NumFormat {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "raw" => Ok(NumFormat::RawBinary),
            "u8" => Ok(NumFormat::U8),
            "u16" => Ok(NumFormat::U16),
            "u32" => Ok(NumFormat::U32),
            "u64" => Ok(NumFormat::U64),
            _ => Err(()),
        }
    }
}

fn print_formatted_value(value: u64, mode: NumFormat) {
    match mode {
        NumFormat::RawBinary => {
            
            for shift in (0..=56).step_by(8) {
                let byte = ((value >> shift) & 0xFF) as u8;
                print!("{}", byte as char);
            }
            
        }
        NumFormat::U8 => {
            let bytes: [u8; 8] = value.to_be_bytes();
            for byte in &bytes {
                println!("{}", byte);
            }
        }
        NumFormat::U16 => {
            let bytes: [u8; 8] = value.to_be_bytes();
            let u16_values: [u16; 4] = [
                u16::from_be_bytes([bytes[0], bytes[1]]),
                u16::from_be_bytes([bytes[2], bytes[3]]),
                u16::from_be_bytes([bytes[4], bytes[5]]),
                u16::from_be_bytes([bytes[6], bytes[7]]),
            ];
            for u16_value in &u16_values {
                println!("{}", u16_value);
            }
        }
        NumFormat::U32 => {
            let bytes: [u8; 8] = value.to_be_bytes();
            let u32_values: [u32; 2] = [
                u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
                u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            ];
            for u32_value in &u32_values {
                println!("{}", u32_value);
            }
        }
        NumFormat::U64 => {
            let bytes: [u8; 8] = value.to_be_bytes();
            let u64_value = u64::from_be_bytes(bytes);
            println!("{}", u64_value);
        }

    }
}

fn main() {
    let matches = App::new(PACKAGE_NAME)
        .version(VERSION)
        .about("Generates random passwords and keys.")
        .arg(
            Arg::with_name("debug")
                .long("debug")
                .help("Enable debug mode"),
        )
        .arg(
            Arg::with_name("alphabet")
                .short("a")
                .long("alphabet")
                .value_name("ALPHABET")
                .possible_values(&["words-fi", "commonsafe", "normal", "ascii", "assembly"])
                .help("Specify the alphabet to use for random value generation"),
        )
        .arg(
            Arg::with_name("bits")
                .short("b")
                .long("bits")
                .value_name("BITS")
                .help("Specify the amount of bits for each random value"),
        )
        .arg(
            Arg::with_name("count")
                .short("c")
                .long("count")
                .value_name("COUNT")
                .help("Number of passwords to generate"),
        )
        .arg(
            Arg::with_name("delimiter")
                .short("d")
                .long("delimiter")
                .value_name("DELIMITER")
                .requires_all(&["bits", "alphabet"]) 
                .help("Sets the delimiter between each letter or word")
                .takes_value(true),            
        )
        .arg(
            Arg::with_name("rngtest")
                .short("r")
                .long("rngtest")
                .value_name("generator")
                .possible_values(&["rdrand", "os", "cpujitter", "cpujitter-raw"])
                .takes_value(true)
                .help("Optional test mode for RNG testing. Will provide raw bytes to stdout.")
                .conflicts_with_all(&["bits", "alphabet", "count"]), // Conflicts with other options
        )
        .arg(
            Arg::with_name("size")
                .short("s")
                .long("size")
                .value_name("data size (u64 words)")
                .requires_all(&["rngtest"]) // Requires rngtest if used
                .takes_value(true)
                .help("Specifies the generated data size in u64 words for RNG testing.")
                .conflicts_with_all(&["bits", "alphabet", "count"]), // Conflicts with other options
        )
        .arg(
            Arg::with_name("format")
                .long("format")
                .short("f")
                .value_name("format")
                .requires_all(&["rngtest"]) // Requires rngtest if used
                .possible_values(&["raw", "u8", "u16", "u32", "u64"])
                .required_if("rngtest", "generator") // Required if rngtest option is used
                .help("Specifies the data format for RNG testing."),
        )
        .get_matches();

    let config = Config {
        debug: matches.is_present("debug"),
        bits: matches.value_of("bits").map(|b| b.parse().unwrap()).unwrap_or(256),
        alphabet: matches.value_of("alphabet").unwrap_or("commonsafe").to_string(),
        count: matches.value_of("count").map(|i| i.parse::<usize>().unwrap_or(1)).unwrap_or(1),
        delimiter: matches.value_of("delimiter").unwrap_or("").to_string(),

        rngtest: if matches.is_present("rngtest") {
            let generator_str = matches.value_of("rngtest").unwrap();
            let generator = RandomSource::from_str(generator_str).expect("Invalid generator");
            let data_size = matches.value_of("size").map(|s| s.parse::<u32>().unwrap_or(1)).unwrap_or(1);
            let num_format_str = matches.value_of("format").unwrap_or("u64");
            let num_format = NumFormat::from_str(num_format_str).expect("Invalid number format");
            Some((generator, data_size, num_format))
        } else {
            None
        }
    };

    if let Some((generator, data_size, data_format)) = &config.rngtest {
        let num_values = *data_size as u64;

        // Choose the appropriate generator function based on the selected generator
        let generator_fn: fn() -> Option<u64> = match generator {
            RandomSource::Rdrand => random::generate_u64_rdrand,
            RandomSource::Os => random::generate_u64_os,
            RandomSource::CpuJitter => random::generate_u64_cpujitter,
            RandomSource::CpuJitterRaw => random::generate_u64_cpujitter_raw,
            _ => unimplemented!(),
        };

        for _ in 0..num_values {
            if let Some(value) = generator_fn() {
                match data_format {
                    NumFormat::U8 => print_formatted_value(value, NumFormat::U8),
                    NumFormat::U16 => print_formatted_value(value, NumFormat::U16),
                    NumFormat::U32 => print_formatted_value(value, NumFormat::U32),
                    NumFormat::U64 => print_formatted_value(value, NumFormat::U64),
                    NumFormat::RawBinary => print_formatted_value(value, NumFormat::RawBinary),
                }
            }
        }

        std::process::exit(0);
    }


    let mut alphabet_item: fn(usize) -> Option<String> = |_| None;
    let mut alphabet_count: fn() -> usize = || 0;
    
    // Match the alphabet count and generator functions to the selected alphabet
    match config.alphabet.as_str() {
    
        "words-fi" => {
            alphabet_count = alphabet::alphabet_wordsfi_get_count;
            alphabet_item = alphabet::alphabet_wordsfi_get_element;
        }
        "commonsafe" => {
            alphabet_count = alphabet::alphabet_commonsafe_get_count;
            alphabet_item = alphabet::alphabet_commonsafe_get_element;
        }
        "normal" => {
            alphabet_count = alphabet::alphabet_normal_get_count;
            alphabet_item = alphabet::alphabet_normal_get_element;
        }
        "ascii" => {
            alphabet_count = alphabet::alphabet_ascii_get_count;
            alphabet_item = alphabet::alphabet_ascii_get_element;
        }
        "assembly" => {
            alphabet_count = alphabet::alphabet_assembly_get_count;
            alphabet_item = alphabet::alphabet_assembly_get_element;
        }
        _ => {
            print!("Error: Unknown alphabet specified. Exiting");
            std::process::exit(1);
        },
    }

    if config.debug {
        println!("Using alphabet: {}", config.alphabet);
        println!("alphabet_count: {}", alphabet_count());
        println!("request bits: {}", config.bits);
    }

    // Find the number of characters needed
    let bits_per_element= (alphabet_count() as f64).log2();
    let num_elements = (config.bits as f64 / bits_per_element as f64).ceil() as u32;

    if config.debug {
        println!("Bits per element: {}", bits_per_element);
        println!("Num of elements: {}", num_elements);
    }

    // Create the password(s)
    for _ in 0..config.count {
        let mut password_string = String::new();

        for i in 0..num_elements {
            // pull out a random value that does not result in modulo bias
            let mut random_value: Option<u64> = None;
            while random_value.is_none() {
                let val = generate_u64();
                if val.unwrap() <= (u64::MAX - (alphabet_count() as u64)) {
                    random_value = val;
                }
            }
            
            // get the corresponding alphabet element
            let random_index = (random_value.unwrap() % alphabet_count() as u64) as usize;
            let random_element = alphabet_item(random_index).unwrap();
            password_string.push_str(&random_element);
            if i < num_elements - 1 {
                password_string.push_str(&config.delimiter);
            }
        }

        println!("{}", password_string);
    }

    std::process::exit(0);
}
