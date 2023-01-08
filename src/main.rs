use base64;
use hex;
use std::collections::HashMap;
use std::io::{self, BufRead};
use std::path::Path;
use std::fs::File;

pub fn hex_to_base64(hex_value: String) -> String {
    let decoded_string: String = String::from_utf8(hex::decode(hex_value).unwrap())
        .unwrap()
        .to_owned();
    base64::encode(decoded_string)
}

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

pub fn single_byte_xor(hex_value: String) -> HashMap<String, String> {
    let decoded_string: Vec<u8> = hex::decode(hex_value.clone()).unwrap();
    let mut key: String = String::new();
    let mut map: HashMap<u8, u8> = HashMap::new();
    let mut finalmap: HashMap<String, String> = HashMap::new();
    let mut maxfreq: u8 = 0;
    let mut ele: u8 = 0;
    for element in decoded_string {
        let count = map.entry(element).or_insert(0);
        *count += 1;
    }
    for (key, value) in map.clone() {
        if maxfreq < value {
            maxfreq = value;
            ele = key;
        }
    }

    let maxfreq: Vec<String> = vec![
        String::from("e"),
        String::from("t"), 
        String::from("a"),
        String::from(" ")];

    for element in &maxfreq {
        for _ in 0..hex_value.len() {
            let xor_val: u8 = *hex::decode(hex::encode(element)).unwrap().get(0).unwrap();
            key.push_str(&hex::encode(vec![ele ^ xor_val])); 
        }
        finalmap.insert(element.to_string(), match String::from_utf8(hex::decode(fixed_xor(hex_value.clone(), key.clone())).unwrap()) {
            Ok(string) => string,
            Err(_) => String::new(),
        });
        key = String::new();
    }
    finalmap
}

pub fn detect_single_char_xor(path_to_file: String) {
    if let Ok(lines) = read_lines(path_to_file) {
        for line in lines {
            if let Ok(hex_value) = line {
                println!("{}", &hex_value.trim().to_string());
                println!("{:?}", single_byte_xor(hex_value.trim().to_string()));
            }
        }
    };
}

pub fn repeating_key_xor(message: String, key: String) -> String {
    let mut encoded_key: String = String::new();
    let hex_encoded_string: String = hex::encode(message);
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

pub fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where P: AsRef<Path>, {
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

pub fn calculate_hamming_dist(first: String, second: String) -> u32 {
    let mut count: u32 = 0;
    for element in hex::decode(
        fixed_xor(hex::encode(first), 
        hex::encode(second)))
        .unwrap() {
        let binary = format!("{:b}", element);
        for character in binary.to_string().chars() {
            if character == '1'{
                count += 1;
            }
        }
    }
    count

}

pub fn main() {
    println!("Set 1 - Challenge 1: {}", hex_to_base64(String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")));
    println!("Set 1 - Challenge 2: {}", fixed_xor(String::from("1c0111001f010100061a024b53535009181c"), String::from("686974207468652062756c6c277320657965")));
    println!("Set 1 - Challenge 3: {:?}", single_byte_xor(String::from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")));
    println!("Set 1 - Challenge 4:");
    detect_single_char_xor(String::from("./input-q4.txt"));
    println!("Set 1 - Challenge 5: {}", repeating_key_xor(String::from(
        "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    ), String::from("ICE")));
    println!("{}", calculate_hamming_dist(String::from("this is a test"), String::from("wokka wokka!!!")));
}

