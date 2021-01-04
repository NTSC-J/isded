#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
//#![allow(improper_ctypes)]
//#![allow(dead_code)]

use sgx_types::*;

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
            pub fn $fn_name(eid: sgx_enclave_id_t, retval: *mut i64, $($arg:$arg_ty),*) -> sgx_status_t;
        }
    )
}
include!("../../enclave/src/ecall_impl.rs");

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
