//#![crate_name = "selfdestructionenclave"]
//#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[allow(unused_imports)]
#[macro_use]
extern crate sgx_tstd as std;

extern crate sgx_tseal;
#[macro_use]
extern crate lazy_static;
extern crate libc;
extern crate serde;
extern crate serde_json;

use sgx_types::*;
use sgx_types::marker::ContiguousMemory;
use std::sync::SgxMutex;
use libc::c_char;
use std::ffi::CStr;
use std::str;
use std::ptr;
use std::convert::TryInto;
use std::time;
use sgx_tseal::SgxSealedData;
use serde::{Serialize, Deserialize};

//impl SecretData {
//    fn output_allowed(&self) -> Boolean {
//        if let Some(t) = output_condition.time {
//            return false; // TODO
//        }
//        if let Some(t) = output_condition.access_count && t <= access_count {
//            return false;
//        }
//        true
//    }
//}
//
//lazy_static! {
//    static ref SECRET: SgxMutex<Option<SecretData>> = SgxMutex::new(None);
//}

// ローカルのファイルを読み込み
#[no_mangle]
pub extern "C" fn load_file(buf: * const u8, size: u64) -> sgx_status_t {
    eprintln!("load_file(buf: {:?}, size: {})", buf, size);
//    let mut secret = if let Ok(x) = SECRET.lock() { x } else { return SGX_ERROR_INVALID_STATE };
//    unsafe {
//        let buf = buf as * mut sgx_sealed_data_t; // なぜmut?
//        let sealed_data = if let Some(x) = SgxSealedData::<SecretData>::from_raw_sealed_data_t(buf, size) { x } else { return SGX_ERROR_FILE_BAD_STATUS };
//        let unsealed_data = match sealed_data.unseal_data() { Ok(x) => x, Err(e) => return e };
//        *secret = Some(*unseal_data.get_decrypt_txt());
//        dbg!(&secret);
//    }
    sgx_status_t::SGX_SUCCESS
}

// ローカルにファイルを作る
// 戻り値: サイズ（エラーの際は負値）
pub extern "C" fn create_file(policy_sexp: * const c_char, input: * const u8, input_size: u64) -> u64 {
    eprintln!("create_file(policy_sexp: {:?}, input: {:?}, input_size: {})", policy_sexp, input, input_size);
    let policy_sexp = CStr::from_ptr(policy_sexp).to_str().unwrap();
    0
}

// ファイルを書き込む
pub extern "C" fn save_file(output: * mut u8) -> sgx_status_t {
    sgx_status_t::SGX_SUCCESS
}

