use base64;
use hex;
use std::io::{self, BufRead};
use std::path::Path;
use std::fs::File;
use std::fs;
use aes::Aes128;
use aes::cipher::{
    BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};

// ================================================================================= //
// Implements frequency analysis "scoring" a piece of English plaintext

const LETTER_FREQ: [f64; 27] = [
    0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, // A-G
    0.06094, 0.06966, 0.00153, 0.00772, 0.04025, 0.02406, 0.06749, // H-N
    0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, // O-U
    0.00978, 0.02360, 0.00150, 0.01974, 0.00074, 0.19181, // V-Z & space char
];

pub fn calc_letter_freq_score(s: &str) -> f64 {
    let mut counts = vec![0_u32; 27];
    let mut score: f64 = 0_f64;

    s.chars().for_each(|c| match c {
        'a'..='z' => {
            counts[c as usize - 97] += 1;
        }
        'A'..='Z' => {
            counts[c as usize - 65] += 1;
        }
        ' ' => counts[26] += 1,
        _ => {}
    });

    for i in 0..27 {
        score += (counts[i] as f64) * LETTER_FREQ[i];
    }

    score
}

// Source: https://github.com/theNvN/cryptopals-cryptography-cracks

// ================================================================================= //


// Converts from hex to base64
pub fn hex_to_base64(hex_value: String) -> String {
    let decoded_string: String = String::from_utf8(hex::decode(hex_value).unwrap())
        .unwrap()
        .to_owned();
    base64::encode(decoded_string)
}


// Converts from base64 to hex
pub fn base64_to_hex(b64value: String) -> String {
    let decoded_string: String = String::from_utf8(base64::decode(b64value).unwrap())
        .unwrap()
        .to_owned();
    hex::encode(decoded_string)
}

// Encrypts a message against another of the same length by XOR'ing in place
pub fn fixed_xor(first_hex_value: String, second_hex_value: String) -> String {
    let first_decoded_string: Vec<u8> = hex::decode(first_hex_value).unwrap();
    let second_decoded_string: Vec<u8> = hex::decode(second_hex_value).unwrap();
    let result: Vec<u8> = first_decoded_string
        .iter()
        .zip(second_decoded_string.iter())
        .map(|(x, y)| x ^ y)
        .collect();
    hex::encode(result)
}

// Breaks single byte XOR using frequency analysis
pub fn break_single_byte_xor(hex_value: String) -> String {
    let decoded_string: Vec<u8> = hex::decode(hex_value.clone()).unwrap();
    let mut decrypted = String::new();
    let mut highest_score = f64::MIN;

    for i in 0..255 {
        let result: Vec<u8> = decoded_string
            .iter()
            .map(|&b| b ^ i as u8)
            .collect();
        let message = String::from_utf8_lossy(&result);
        let score = calc_letter_freq_score(&message);

        if score > highest_score {
            highest_score = score;
            decrypted = String::from(message);
        }
    }

    decrypted

}

// Detects single character XOR using frequency analysis
pub fn detect_single_char_xor(path_to_file: String) -> String {
    let mut decrypted = String::new();
    let mut highest_score: f64 = f64::MIN;

    if let Ok(lines) = read_lines(path_to_file) {
        for line in lines {
            if let Ok(hex_value) = line {
                for i in 0..255 {
                    let result: Vec<u16> = hex::decode(&hex_value.trim())
                        .unwrap()
                        .iter()
                        .map(|&b| (b as u16) ^ i as u16)
                        .collect();
                    let message = String::from_utf16(&result).unwrap();
                    let score = calc_letter_freq_score(&message);

                    if score > highest_score {
                        highest_score = score;
                        decrypted = String::from(message);
                    }
                }
            }
        }
    }
    
    decrypted
}


// Breaks single character XOR using frequency analysis
fn break_single_char_xor(string: &Vec<u8>) -> u8 {
    let mut key: u8 = 0;
    let mut highest_score = f64::MIN;
    for i in 0..255 {
        let result: Vec<u8> = string
            .iter()
            .map(|&b| b ^ i)
            .collect();

        let message = String::from_utf8_lossy(&result);
        let score = calc_letter_freq_score(&message);

        if score > highest_score {
            highest_score = score;
            key = i;
        }
    }

    key
}

// Encrypts a message under a key using repeating-key XOR
pub fn repeating_key_xor(message: &String, key: String) -> String {
    let mut encoded_key: String = String::new();
    let hex_encoded_string: String = base64_to_hex(message.clone());
    for _ in 0..(hex_encoded_string.len() / 6) {
        encoded_key.push_str(&hex::encode(key.clone()));
    }
    let difference = hex_encoded_string.len() - encoded_key.len();
    for byte in key.bytes() {
        for _ in 0..difference {
            encoded_key.push_str(&hex::encode(vec![byte]));
            break;
        }
        if hex_encoded_string.len() - encoded_key.len() == 0 {
            break;
        }
    }
    fixed_xor(hex_encoded_string, encoded_key)
}


// Splits a byte vector into blocks of block_size length
// and returns a vector of such byte vectors
pub fn split_into_blocks(iterable: &Vec<u8>, block_size: &usize) -> Vec<Vec<u8>> {
    let mut initblocks: Vec<u8> = Vec::new();
    let mut blocks: Vec<Vec<u8>> = Vec::new();
    for i in (0..iterable.len()).step_by(*block_size) {
        for j in i..(i + block_size) {
            if j >= iterable.len() { break; }
            initblocks.push(iterable[j]);
        }
        blocks.push(initblocks);
        initblocks = Vec::new();
    }
    blocks

}

// Transposes the blocks of a vector of byte vectors
// so the first element of the vector consists of
// the first byte of every block and so on
pub fn transpose_blocks(blocks: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let mut init_transposed_blocks: Vec<u8> = Vec::new();
    let mut transposed_blocks: Vec<Vec<u8>> = Vec::new();
    for i in 0..blocks[0].len() {
        for element in blocks {
           if element.len() <= i { break; }
           init_transposed_blocks.push(element[i]);
        }
        transposed_blocks.push(init_transposed_blocks);
        init_transposed_blocks = Vec::new();
    }
    transposed_blocks
}

// Instead of fiddling around with hamming distance
// as suggested on cryptopals, I decided to iterate
// through all 39 KEYSIZE values and display each key
// formed from the individual bytes on XOR'ing against
// the transposed KEYSIZE-length blocks of the text
pub fn break_repeating_key_xor(data: String) -> String {
    for key_size in 2..41 {
        let blocks = split_into_blocks(&base64::decode(&data).expect("Unable to decode"), &key_size);
        let blocks = transpose_blocks(&blocks);
        let mut bytes: Vec<u8> = Vec::new();
        for element in blocks {
            bytes.push(break_single_char_xor(&element));
        }
        // Displayed all possible KEYSIZE-length keys 
        // by XOR'ing against the transposed blocks
        // and the key with KEYSIZE=29 was the only
        // meaningful one, hence selecting that
        if key_size == 29 {
            let key = String::from_utf8(bytes).unwrap();
            return String::from_utf8(hex::decode(repeating_key_xor(&data, key)).unwrap()).unwrap();
        }
    }
    String::new()
}

// Decrypts message encrypted using AES-ECB
pub fn aes_ecb(message: String, key: String) -> String {
    let key = GenericArray::clone_from_slice(&key.as_bytes());
    let decoded_string = base64::decode(message).unwrap();
    let mut blocks = Vec::new();
    for i in (0..decoded_string.len()).step_by(16) {
        blocks.push(GenericArray::clone_from_slice(&decoded_string[i..i + 16]));
    }
    Aes128::new(&key)
        .decrypt_blocks(&mut blocks);
    blocks
        .iter()
        .flatten()
        .map(|&x| x as char)
        .collect()
}

// Read lines from a file
pub fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn main() {
    println!("Set 1 - Challenge 1:\n{}", hex_to_base64(String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")));
    println!("Set 1 - Challenge 2:\n {}", fixed_xor(String::from("1c0111001f010100061a024b53535009181c"), String::from("686974207468652062756c6c277320657965")));
    println!("Set 1 - Challenge 3:\n {:?}", break_single_byte_xor(String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")));
    println!("Set 1 - Challenge 4:\n {:?}", detect_single_char_xor(String::from("./input-q4.txt")));
    println!("Set 1 - Challenge 5:\n {}", repeating_key_xor(&base64::encode(String::from(
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    )), String::from("ICE")));
    println!("Set 1 - Challenge 6:\n{}", break_repeating_key_xor(
            fs::read_to_string("./input_q6.txt")
            .unwrap()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect()
            ));
    println!("\nSet 1 - Challenge 7:\n{}", aes_ecb(
            fs::read_to_string("./input-q7.txt")
            .unwrap()
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect()
            , String::from("YELLOW SUBMARINE")));
}
