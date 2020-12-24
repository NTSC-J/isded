use sgx_types::*;
use sgx_ucrypto::rsgx_rijndael128GCM_encrypt as sgx_encrypt;
use std::io::Write;
use rand::Rng;
use std::mem::size_of;

// encrypted data structure:
// iv (random): 12 bytes (plaintext)
// mac: 16 bytes (plaintext)
// data: arbitrary bytes (encrypted)

pub fn encrypt(key: &sgx_aes_gcm_128bit_key_t, src: &[u8]) -> Vec<u8> {
    let iv = rand::thread_rng().gen::<[u8; 12]>();
    let aad = [0u8; 0];
    let mut dst = vec![0u8; src.len()];
    let mut mac = vec![0u8; size_of::<sgx_aes_gcm_128bit_tag_t>()]; // 12 bytes
    let mac_ref = unsafe {
        (mac.as_mut_ptr() as *mut sgx_aes_gcm_128bit_tag_t).as_mut().unwrap()
    };
    // TODO: error handling
    sgx_encrypt(key, src, &iv, &aad, &mut dst, mac_ref).unwrap();

    let mut ret = Vec::new();
    ret.write_all(&iv).unwrap();
    ret.write_all(&mac).unwrap();
    ret.write_all(&dst).unwrap();
    ret
}

