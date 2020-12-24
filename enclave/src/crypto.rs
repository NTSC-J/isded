use std::prelude::v1::*;
use sgx_types::*;
use sgx_tcrypto::rsgx_rijndael128GCM_decrypt as sgx_decrypt;

// encrypted data structure:
// iv (random): 12 bytes (plaintext)
// mac: 16 bytes (plaintext)
// data: arbitrary bytes (encrypted)

// FIXME: error handling
pub fn decrypt(key: &sgx_aes_gcm_128bit_key_t, src: &[u8]) -> Vec<u8> {
    let iv = &src[..12];
    let aad = [0u8; 0];
    let mac = {
        let mut mac = [0u8; 16];
        mac.copy_from_slice(&src[12..12 + 16]);
        mac
    };
    let ciphertext = &src[12 + 16..];
    let mut plaintext = vec![0u8; src.len() - (12 + 16)];

    sgx_decrypt(key, ciphertext, iv, &aad, &mac, &mut plaintext).unwrap();
    plaintext
}

