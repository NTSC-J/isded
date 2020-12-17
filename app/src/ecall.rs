#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
//#![allow(improper_ctypes)]
//#![allow(dead_code)]

use sgx_types::*;

// TODO: bindgenに任せたい
//include!(concat!(env!("OUT_DIR"), "/Enclave_u.rs"));
extern {
    pub fn set_qe_info(eid: sgx_enclave_id_t, retval: *mut i64,
                       target_info: *const sgx_target_info_t,
                       epid_group_id: *const sgx_epid_group_id_t) -> sgx_status_t;
    pub fn start_request(eid: sgx_enclave_id_t, retval: *mut i64,
                         ga: *const sgx_ec256_public_t,
                         nonce: *const sgx_quote_nonce_t,
                         report: *mut sgx_report_t) -> sgx_status_t;
    pub fn store_file(eid: sgx_enclave_id_t, retval: *mut i64,
                      ciphertext: *const uint8_t, ciphertext_len: uint64_t,
                      mac: *const sgx_aes_gcm_128bit_tag_t,
                      filename: *const c_char) -> sgx_status_t;
    pub fn open_file(eid: sgx_enclave_id_t, retval: *mut i64,
                     filename: *const c_char) -> sgx_status_t;
    pub fn read_file(eid: sgx_enclave_id_t, retval: *mut i64,
                     handle: i64, buf: *mut u8, count: u64) -> sgx_status_t;
    pub fn test_policy(eid: sgx_enclave_id_t, retval: *mut i64,
                       policy: *const c_char,
                       times: uint64_t) -> sgx_status_t;
    pub fn ecall_test(eid: sgx_enclave_id_t) -> sgx_status_t;
}

// TODO: FIXME: エラー処理
#[macro_export]
macro_rules! ecall {
    ($enclave:expr, $name:ident($($arg:expr),*)) => {
        {
            let mut r = 0i64;
            let s = $name($enclave.geteid(), &mut r, $($arg),*);
            match s {
                sgx_status_t::SGX_SUCCESS => if r < 0 {
                    eprintln!("ecall error: {}", r)
                },
                _ => eprintln!("sgx error: {}", s)
            };
            r
        }
    }
}
