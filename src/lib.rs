extern crate rustc_serialize;
extern crate hamming;
extern crate crypto;
extern crate itertools;

use rustc_serialize::hex::{ToHex, FromHex};
use rustc_serialize::base64::{FromBase64, ToBase64, Config, CharacterSet, Newline};
use std::collections::BTreeMap;
use crypto::{ symmetriccipher, buffer, aes, blockmodes };
use crypto::buffer::{ ReadBuffer, WriteBuffer, BufferResult };
use itertools::Itertools;

const BASE64_CONFIG: Config = Config {
        char_set : CharacterSet::Standard,
        newline : Newline::LF,
        pad : true,
        line_length : None
    };

fn fixed_xor(buffer: &[u8], key: &[u8]) -> Vec<u8> {
    let key_cycle = key.iter().cycle();
    buffer.iter().zip(key_cycle).map(|(b, k)| b^k).collect()
}

fn score_str(input: &str) -> i32 {
    //ETAOINSHRDLU
    input.chars().fold(0, |score, c| {
        score + match c {
            'E'|'e' => 13,
            'T'|'t' => 12,
            'A'|'a' => 11,
            'O'|'o' => 10,
            'I'|'i' => 9,
            'N'|'n' => 8,
            'S'|'s' => 7,
            'H'|'h' => 6,
            'R'|'r' => 5,
            'D'|'d' => 4,
            'L'|'l' => 3,
            'U'|'u' => 2,
            ' ' => 1,
            _ => 0
        }
    })
}

fn single_byte_cypher_xor(buffer: &[u8], num_results: usize) -> Vec<(i32, u8)> {
    let mut decrypt = BTreeMap::new();

    for i in 0..127 as u8 {
        let decrypted_buf = fixed_xor(buffer, &vec![i]);
        let decrypted_str_result = String::from_utf8(decrypted_buf);
        if decrypted_str_result.is_ok() {
            let decrypted_str = decrypted_str_result.unwrap();
            decrypt.insert(score_str(&decrypted_str), i);
        }
    }

    decrypt.iter().rev().take(num_results).map(|(i, c)| (*i, *c)).collect()
}

fn average_hamming_distance(buffer: &[u8], chunk_size: usize) -> f32 {
    let (even, odd) : 
        (Vec<(usize, &[u8])>, Vec<(usize, &[u8])>) = buffer.chunks(chunk_size)
                                                            .enumerate()
                                                            .partition(|&(i, _)| {
                                                                i % 2 == 0
                                                            });
                                                            
    (even.iter().zip(odd.iter()).filter(|&(a, b)|{
        a.1.len() == b.1.len()
    }).fold(0, |acc, (a, b)| {
        acc + hamming::distance(a.1, b.1)
    }) as f32 / even.len() as f32) / chunk_size as f32
}

fn rank_keysizes(buffer: &[u8], (start, end): (usize, usize)) -> Vec<(usize)> {
    let mut distances = BTreeMap::new();

    for keysize in start..end {
        let distance = (average_hamming_distance(buffer, keysize) * 1000 as f32) as i32;
        distances.insert(distance, keysize);
    }

    distances.iter().map(|(key, val)| *val).collect()
}

fn gen_key_with_keysize(buffer: &[u8], keysize: usize) -> Vec<u8> {
    let chunks = buffer.chunks(keysize).collect::<Vec<&[u8]>>();
    
    (0..keysize).map(|i| {
        chunks.iter().map(|v| {
            if i < v.len() {
                v[i]
            } else {
                0
            }
        }).collect::<Vec<u8>>()
    }).enumerate().map(|(i, buf)| {
        single_byte_cypher_xor(&buf, 1)[0].1
    }).collect()
}

fn aes_128_ecb_decrypt(encrypted_data: &[u8], key: &[u8]) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor = aes::ecb_decryptor(
            aes::KeySize::KeySize128,
            key,
            blockmodes::NoPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => { }
        }
    }

    Ok(final_result)
}

fn get_num_matching_chunks(buffer: &[u8], chunk_size: usize) -> usize {
    buffer.chunks(chunk_size)
            .combinations(2)
            .filter(|chunks_vec| {
                chunks_vec[0].eq(chunks_vec[1])
            }).count()
}

#[test]
fn challenge_1() {
    let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    let hex_buffer = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_string().from_hex().unwrap();
    
    let base64_str = hex_buffer.to_base64(BASE64_CONFIG);

    assert_eq!(expected, base64_str);
}

#[test]
fn challenge_2() {
    let expected = "746865206b696420646f6e277420706c6179";
    let buffer = "1c0111001f010100061a024b53535009181c".to_string().from_hex().unwrap();
    let key = "686974207468652062756c6c277320657965".to_string().from_hex().unwrap();

    let xor = fixed_xor(&buffer, &key);
    let xor_str = xor.to_hex();

    assert_eq!(expected, xor_str);
}

#[test]
fn challenge_3() {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".to_string().from_hex().unwrap();
    let top_3 = single_byte_cypher_xor(&input, 3);

    for (score, result) in top_3 {
        println!("{} => {}", score, result as char);
    }

    assert!(true);
}

#[test]
fn challenge_4() {
    let input = include_str!("../input/challenge_4.txt");

    let mut best = BTreeMap::new();

    for line in input.lines() {
        for (score, result) in single_byte_cypher_xor(&line.to_string().from_hex().unwrap(), 3) {
            best.insert(score, result as char);
        }
    }

    for (score, result) in best.iter().rev().take(5) {
        println!("{} => {}", score, result);
    }

    assert!(true);
}

#[test]
fn challenge_5() {
    let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";

    let input = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";

    let key = "ICE";

    let encrypted = fixed_xor(&input.as_bytes(), &key.as_bytes());
    let encrypted_hex_str = encrypted.to_hex();

    assert_eq!(expected, encrypted_hex_str);
}

#[test]
fn hamming_test() {
    assert_eq!(37, hamming::distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()));
}

#[test]
fn challenge_6() {
    let input : String = include_str!("../input/challenge_6.txt").lines().collect();
    let as_bytes = input.from_base64().unwrap();

    let keysizes = rank_keysizes(&as_bytes, (2,40));
    let key = gen_key_with_keysize(&as_bytes, keysizes[0]);
    let decrypted = String::from_utf8(fixed_xor(&as_bytes, &key)).unwrap();

    println!("{}", decrypted);

    assert!(true);
}

#[test]
fn challenge_7() {
    let input : String = include_str!("../input/challenge_7.txt").lines().collect();
    let as_bytes = input.from_base64().unwrap();
    let key = "YELLOW SUBMARINE".as_bytes();
    let decrypted_data = aes_128_ecb_decrypt(&as_bytes, &key).ok().unwrap();
    println!("{}", String::from_utf8(decrypted_data).unwrap());

    assert!(true);
}

#[test]
fn challenge_8() {
    let input = include_str!("../input/challenge_8.txt");
    let mut line_matches = Vec::new();
    for line in input.lines() {
        line_matches.push((get_num_matching_chunks(line.as_bytes(), 16), line));
    }

    for result in line_matches {
        if result.0 > 0 {
            println!("{} => {:?}", result.0, result.1);
        }       
    }

    assert!(true);
}