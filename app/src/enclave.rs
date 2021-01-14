#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
//#![allow(improper_ctypes)]
//#![allow(dead_code)]

use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::path::Path;
use std::fs::OpenOptions;
use std::fmt::Debug;
use std::io::{Read, Write, Seek, SeekFrom};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum EnclaveError {
    #[error("SGX error {0:?}")]
    SgxError(sgx_status_t),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("ECall error {0}")]
    ECallError(i64),
}
impl From<sgx_status_t> for EnclaveError {
    fn from(s: sgx_status_t) -> Self {
        Self::SgxError(s)
    }
}
pub type EnclaveResult<T> = Result<T, EnclaveError>;

pub struct Enclave {
    inner: SgxEnclave
}

impl Enclave {
    pub fn create<P: AsRef<Path>, Q: AsRef<Path>>(enclave_path: &P, token_path: &Q, debug: bool) -> EnclaveResult<Self> {
        let mut launch_token: sgx_launch_token_t = [0u8; 1024];
        let mut launch_token_updated = 0i32;
        // Step 1: try to retrieve the launch token saved by last transaction
        //         if there is no token, then create a new one.
        //
        // try to get the saved token */
        let mut token_file = OpenOptions::new().read(true).write(true).create(true).open(&token_path)?;
        if token_file.read_exact(&mut launch_token).is_err() {
            // token file new or invalid, resetting buffer.
            launch_token = [0u8; 1024];
        }

        // Step 2: call sgx_create_enclave to initialize an enclave instance
        // Debug Support: set 2nd parameter to 1
        let mut misc_attr = sgx_misc_attribute_t {
            secs_attr: sgx_attributes_t {
                flags: 0,
                xfrm: 0
            },
            misc_select: 0
        };
        let enclave = SgxEnclave::create(
            &enclave_path,
            debug.into(),
            &mut launch_token,
            &mut launch_token_updated,
            &mut misc_attr)?;

        // Step 3: save the launch token if it is updated
        if launch_token_updated != 0 {
            info!("Saving new enclave launch token");
            token_file.seek(SeekFrom::Start(0))?;
            token_file.write_all(&launch_token)?;
        }

        Ok(Enclave {
            inner: enclave
        })
    }
}

macro_rules! ecall_define {
    (
        $(#[$attr:meta])*
        fn $fn_name:ident (
            $($(#[edl($e:expr)])* $arg:ident : $arg_ty:ty),* $(,)*
        ) -> Result<$ok_ty:tt> // needed to be tt
        $body:tt
    ) => (
        extern {
            #[allow(dead_code)]
            fn $fn_name(eid: sgx_enclave_id_t, retval: *mut i64, $($arg:$arg_ty),*) -> sgx_status_t;
        }
        impl Enclave {
            #[allow(dead_code)]
            pub unsafe fn $fn_name(&self, $($arg:$arg_ty),*) -> EnclaveResult<i64> {
                let mut retval = 0i64;
                let status = $fn_name(self.inner.geteid(), &mut retval, $($arg),*);
                if status != sgx_status_t::SGX_SUCCESS {
                    return Err(EnclaveError::SgxError(status));
                }
                if retval < 0 {
                    return Err(EnclaveError::ECallError(retval));
                }
                Ok(retval)
            }
        }
    )
}
include!("../../enclave/src/ecall_impl.rs");
