#[path = "hmac_drbg.rs"] mod hmac_drbg;
use hmac_drbg::HmacDrbg;

use std::fmt;
use std::arch::asm;
use std::process;
use std::fs::read_to_string;
use std::time::{SystemTime, UNIX_EPOCH};
use tiny_keccak::Hasher;
use tiny_keccak::Sha3;
use lazy_static::lazy_static;
use zeroize::Zeroize;
use getrandom::getrandom;



fn u64_to_bytes(val: u64) -> [u8; 8] {
    [
        (val >> 56) as u8,
        (val >> 48) as u8,
        (val >> 40) as u8,
        (val >> 32) as u8,
        (val >> 24) as u8,
        (val >> 16) as u8,
        (val >> 8) as u8,
        val as u8,
    ]
}


fn vec_u8_to_u64(bytes: &[u8]) -> Option<u64> {
    if bytes.len() != 8 {
        return None; // Ensure that the input has exactly 8 bytes
    }

    let mut result: u64 = 0;
    for &byte in bytes {
        result = (result << 8) | u64::from(byte);
    }

    Some(result)
}


struct BitVector {
    bits: Vec<bool>,
}


impl BitVector {
    fn new() -> Self {
        BitVector { bits: Vec::new() }
    }

    fn add_bit(&mut self, bit: bool) {
        self.bits.push(bit);
    }

    fn is_full(&self) -> bool {
        self.bits.len() == 64
    }

    fn to_u64(&self) -> u64 {
        let mut result: u64 = 0;
        for (i, &bit) in self.bits.iter().enumerate() {
            if bit {
                result |= 1u64 << i;
            }
        }
        result
    }    
}

impl fmt::Debug for BitVector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BitVector {{ bits: {:?} }}", self.bits)
    }
}


#[cfg(target_os = "linux")]
fn check_entropy_pool() {
    const MIN_ENTROPY_THRESHOLD: u64 = 200; // Adjust this threshold as needed

    if let Ok(entropy_avail) = read_to_string("/proc/sys/kernel/random/entropy_avail") {
        let entropy_avail: u64 = entropy_avail.trim().parse().unwrap_or(0);

        if entropy_avail < MIN_ENTROPY_THRESHOLD {
            eprintln!("Error: Entropy pool is low ({} bytes). Exiting.", entropy_avail);
            process::exit(1);
        }
    } else {
        eprintln!("Error: Failed to read entropy_avail. Cannot check entropy pool.");
        process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn check_entropy_pool() {
    // On non-Linux systems (e.g., Windows), we can not check the amount of entropy available.
}


/* Return U64 random number from the OS.
   On Linux will use getrandom() syscall. Fallback to /dev/urandom and /dev/random
   On Windows will use BCryptGenRandom() API.
   On MacOS will use getentropy(). Fallback to /dev/urandom
*/
pub fn generate_u64_os() -> Option<u64> {
    let mut random_bytes = [0u8; 8];

    check_entropy_pool();

    if let Ok(_) = getrandom(&mut random_bytes) {
        let random_u64 = u64::from_le_bytes(random_bytes);
        Some(random_u64)
    } else {
        eprintln!("Error: OS rand failed. Exiting.");
        std::process::exit(1);        
    }
}


/* Return U64 random number from the CPU RDRAND instruction.
   If the CPU does not support RDRAND, the program will exit.
   This effectively limits the program to only run on Intel & AMD CPUs.
*/
pub fn generate_u64_rdrand() -> Option<u64> {
    let mut result: u64 = 0;
    let mut success: i8 = 0;

    unsafe {
        asm!(
            "rdrand {0}; setc {1}",
            out(reg) result,
            out(reg_byte) success,
        );
    }

    if success != 0 {
        Some(result)
    } else {
        eprintln!("Error: rdrand failed. Exiting.");
        std::process::exit(1);        
    }
}


// generate_u64_cpujitter()
// SHA3 (Keccack) is used to provide a u64 random number from 512 bits of cpujitter entropy bits.
// Rationale for this is that the cpujitter is not 100% random, but it is still a good source of entropy.
// Also, using the HMAC DRBG with the current personalization string (*that contains the timestamp*)
// would result in difficulties when estimating the randomness of the generated random numbers.
pub fn generate_u64_cpujitter() -> Option<u64> {

    // Let's take 512 (8 * 64) bits of cpujitter entropy
    let mut combined_data = Vec::new();
    for _ in 0..8 {
        if let Some(raw_value) = generate_u64_cpujitter_raw() {
            combined_data.extend_from_slice(&u64_to_bytes(raw_value));
        }
    }

    // Hash the combined data with SHA3 (Keccak)
    let mut sha3 = Sha3::v256();
    let mut hash_result = [0u8; 32];
    sha3.update(&combined_data);
    sha3.finalize(&mut hash_result);

    // Return the first 64 bits as u64
    let random_value = vec_u8_to_u64(&hash_result[..8]);
    random_value
}


/* Returns U64 from collected CPU jitter. The amount of raw entropy is around 6bits / byte. */
pub fn generate_u64_cpujitter_raw() -> Option<u64> {
    let mut bit_vector = BitVector::new();
    let mut loop_count = 0;

    loop {
        let start = std::time::Instant::now();
        let end = std::time::Instant::now();
        let time_diff1 = end.duration_since(start).as_nanos() as u64;

        let start = std::time::Instant::now();
        let end = std::time::Instant::now();
        let time_diff2 = end.duration_since(start).as_nanos() as u64;

        if time_diff1 != time_diff2 {
            if time_diff1 > time_diff2 {
                bit_vector.add_bit(true);
            } else {
                bit_vector.add_bit(false);
            }
        }

        // Check if the BitVector is full or if the loop count has reached maximum number of tries.
        if bit_vector.is_full() {
            break;
        }

        loop_count += 1;
        if loop_count >= 32768 {
            eprintln!("Error: Unable to create cpu jitter entropy. System too busy or idle? Exiting.");
            std::process::exit(1);
        }
    }

    let result = bit_vector.to_u64();
    Some(result)
}



lazy_static! {
    static ref PREVIOUS_TIMESTAMP: std::sync::Mutex<(u64, u32)> = std::sync::Mutex::new((0, 0));
}

/* Personalization string combines a fixed string ("kissa123", Finnish for cat123) and both seconds and nanoseconds
   of current timestamp. This ensures that the personalization string is unique for each call.
*/
fn generate_personalization_string() -> [u8; 32] {
    let mut personalization_string: [u8; 32] = [0; 32];

    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards");
    let timestamp_secs = timestamp.as_secs();
    let timestamp_nanos = timestamp.subsec_nanos();

    // Compare with previous timestamp
    let mut prev_timestamp = PREVIOUS_TIMESTAMP.lock().unwrap();
    if timestamp_secs < prev_timestamp.0 || (timestamp_secs == prev_timestamp.0 && timestamp_nanos <= prev_timestamp.1) {
        eprintln!("Error: time went backwards. Exiting.");
        std::process::exit(1);
    }

    *prev_timestamp = (timestamp_secs, timestamp_nanos);

    // Copy the string bytes
    let hardcoded_str = "kissa123";
    personalization_string[..hardcoded_str.len()].copy_from_slice(hardcoded_str.as_bytes());

    // Copy the timestamp seconds bytes
    let secs_range = hardcoded_str.len()..hardcoded_str.len() + 8;
    personalization_string[secs_range].copy_from_slice(&timestamp_secs.to_le_bytes());

    // Copy the timestamp nanoseconds bytes
    let nanos_range = hardcoded_str.len() + 8..hardcoded_str.len() + 12;
    personalization_string[nanos_range].copy_from_slice(&timestamp_nanos.to_le_bytes());

    personalization_string
}




// Generate a random u64 combining three different sources
pub fn generate_u64() -> Option<u64> {

    // Generate a 1536 bit seed from three different random number sources.
    // Thats 8 * 64 = 512 bits from each source.
    let mut seed: Vec<u8> = Vec::new();

    for _ in 0..8 {
        let val = generate_u64_os();
        let u64_bytes = u64_to_bytes(val.unwrap());
        seed.extend_from_slice(&u64_bytes);

        let val = generate_u64_rdrand();
        let u64_bytes = u64_to_bytes(val.unwrap());
        seed.extend_from_slice(&u64_bytes);

        let val = generate_u64_cpujitter();
        let u64_bytes = u64_to_bytes(val.unwrap());
        seed.extend_from_slice(&u64_bytes);
    }

    // Generate a deterministic, but each time unique, personalization string
    let mut personalization_string: [u8; 32] = generate_personalization_string();

    // Generate the u64 random number using HMAC DRBG
    let mut drbg = HmacDrbg::new(&seed, &personalization_string);
    let random_bytes = drbg.generate_bytes(8);
    let random_value = vec_u8_to_u64(&random_bytes);

    personalization_string.zeroize();
    seed.zeroize();

    random_value
}