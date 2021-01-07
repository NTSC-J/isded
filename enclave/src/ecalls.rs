use std::prelude::v1::*;
use crate::{file, jwtmc, output_policy, crypto};
use crate::error::{Error, Result};
use crate::file::ISDEDFile;
use lazy_static::lazy_static;
use libc::c_char;
use sgx_tcrypto::{SgxEccHandle, rsgx_sha256_slice};
use sgx_types::*;
use std::backtrace::{self, PrintFormat};
use std::convert::TryInto;
use std::ffi::CStr;
use std::io::Write;
use std::sync::SgxMutex as Mutex;
use rand::distributions::{Distribution, Uniform};
use std::collections::BTreeMap;
use std::io::{Read, Seek};

const MC_ADDR: (&str, u16) = ("jwtmc", 7777);

lazy_static! {
    static ref QE_INFO: Mutex<Option<(sgx_target_info_t, sgx_epid_group_id_t)>> = Mutex::new(None);
    static ref KEY: Mutex<Option<(sgx_ec256_private_t, sgx_ec256_public_t)>> = Mutex::new(None);
    static ref DHKEY: Mutex<Option<sgx_ec256_dh_shared_t>> = Mutex::new(None);
    static ref NONCE: Mutex<Option<sgx_quote_nonce_t>> = Mutex::new(None);
    static ref OPEN_HANDLES: Mutex<BTreeMap<i64, ISDEDFile>> = Mutex::new(BTreeMap::new());
}

fn dh_aes_key() -> sgx_aes_gcm_128bit_key_t {
    let dhkey = DHKEY.lock().unwrap().unwrap(); // TODO
    let mut key = sgx_aes_gcm_128bit_key_t::default();
    key.clone_from_slice(&dhkey.s[..16]);
    key
}

// derived from easy_ffi-0.1.0

/// takes a fn definition that returns Result<(), Error> or Result<i64, Error>
/// and emits a fn definition that returns i64
/// Ok(()) becomes 0 and Err(_) becomes the corresponding negative value
macro_rules! ecall_define {
    (
        $(#[$attr:meta])*
        fn $fn_name:ident (
            $($(#[edl($e:expr)])* $arg:ident : $arg_ty:ty),* $(,)*
        ) -> Result<$ok_ty:tt> // needed to be tt
        $body:tt
    ) => (
        #[no_mangle]
        $(#[$attr])*
        pub extern "C" fn $fn_name($($arg:$arg_ty),*) -> i64 {
            let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Full); // TODO
            // TODO: std::panic::catch_unwind
            let result: Result<$ok_ty> = (|| { $body })();
            match result {
                #[allow(unused_variables)]
                Ok(x) => to_i64!(x, $ok_ty),
                Err(e) => e.into(),
            }
        }
    );
}

macro_rules! to_i64 {
    ($e:expr, ()) => {0};
    ($e:expr, i64) => {$e};
}

include!("ecall_impl.rs");
