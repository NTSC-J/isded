#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
//#![allow(improper_ctypes)]
//#![allow(dead_code)]

use sgx_types::*;

extern {
    pub fn set_qe_info(eid: sgx_enclave_id_t, retval: *mut i64,
                       target_info: *const sgx_target_info_t,
                       epid_group_id: *const sgx_epid_group_id_t) -> sgx_status_t;
    pub fn start_request(eid: sgx_enclave_id_t, retval: *mut i64,
                         ga: *const sgx_ec256_public_t,
                         nonce: *const sgx_quote_nonce_t,
                         report: *mut sgx_report_t) -> sgx_status_t;
    pub fn isded_open(eid: sgx_enclave_id_t, retval: *mut i64,
                filename: *const c_char) -> sgx_status_t;
    pub fn isded_open_new(eid: sgx_enclave_id_t, retval: *mut i64,
                    filename: *const c_char,
                    epolicy: *const u8,
                    epolicy_len: usize) -> sgx_status_t;
    pub fn isded_read(eid: sgx_enclave_id_t, retval: *mut i64,
                handle: i64, buf: *mut u8, count: usize) -> sgx_status_t;
    pub fn isded_write(eid: sgx_enclave_id_t, retval: *mut i64,
                 handle: i64, echunk: *const u8, echunk_len: usize) -> sgx_status_t;
    #[allow(dead_code)]
    pub fn isded_seek(eid: sgx_enclave_id_t, retval: *mut i64,
                handle: i64, offset: i64, whence: i64) -> sgx_status_t;
    pub fn isded_close(eid: sgx_enclave_id_t, retval: *mut i64,
                 handle: i64) -> sgx_status_t;
    pub fn test_policy(eid: sgx_enclave_id_t, retval: *mut i64,
                       policy: *const c_char,
                       times: u64) -> sgx_status_t;
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
