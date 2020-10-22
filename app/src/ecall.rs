#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
//#![allow(improper_ctypes)]
//#![allow(dead_code)]

use sgx_types::*;

// TODO: bindgenに任せたい
//include!(concat!(env!("OUT_DIR"), "/Enclave_u.rs"));
extern {
    pub fn set_qe_info(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                       target_info: *const sgx_target_info_t,
                       epid_group_id: *const sgx_epid_group_id_t) -> sgx_status_t;
    pub fn start_request(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                         ga: *const sgx_ec256_public_t,
                         nonce: *const sgx_quote_nonce_t,
                         report: *mut sgx_report_t) -> sgx_status_t;
    pub fn store_file(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                      ciphertext: *const uint8_t, ciphertext_len: uint64_t,
                      mac: *const sgx_aes_gcm_128bit_tag_t,
                      filename: *const c_char) -> sgx_status_t;
    pub fn open_file(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                     filename: *const c_char) -> sgx_status_t;
    pub fn create_file(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                       policy: *const c_char,
                       input_name: *const c_char,
                       output_name: *const c_char) -> sgx_status_t;
    pub fn ecall_test(eid: sgx_enclave_id_t) -> sgx_status_t;
}

#[macro_export]
macro_rules! ecall {
    ($enclave:expr, $name:ident, $($arg:expr),*) => {
        {
            let mut r = sgx_status_t::SGX_ERROR_UNEXPECTED;
            let s = $name($enclave.geteid(), &mut r, $($arg),*);
            match s {
                sgx_status_t::SGX_SUCCESS => Ok(r),
                _ => Err(s)
            }
        }
    }
}
