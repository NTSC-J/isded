use std::fs::OpenOptions;
use std::io::Write;
use std::os::raw::c_char;
use sgx_types::*;

const EDL_FILE: &'static str = "obj/Enclave.edl";

trait CTypeName {
    fn c_type_name() -> String;
}

macro_rules! impl_ctn {
    ($tn:ty, $ctn:expr) => (
        impl CTypeName for $tn {
            fn c_type_name() -> String { format!("{} ", $ctn) }
        }
    );
    ($tn:ty) => (impl_ctn!{$tn, stringify!($tn)});
}

impl<T: CTypeName> CTypeName for *const T {
    fn c_type_name() -> String { format!("const {}*", <T>::c_type_name()) }
}
impl<T: CTypeName> CTypeName for *mut T {
    fn c_type_name() -> String { format!("{}*", <T>::c_type_name()) }
}

impl_ctn!(u8, "uint8_t");
impl_ctn!(u64, "uint64_t");
impl_ctn!(i64, "int64_t");
impl_ctn!(c_char, "char");
impl_ctn!(usize, "size_t");
impl_ctn!(sgx_target_info_t);
impl_ctn!(sgx_epid_group_id_t);
impl_ctn!(sgx_report_t);
impl_ctn!(sgx_ec256_public_t);
impl_ctn!(sgx_quote_nonce_t);

macro_rules! args_to_edl {
    () => ("".to_string());
    ($arg:ident : $arg_ty:ty) =>
        (format!("{}{}", <$arg_ty>::c_type_name(), stringify!($arg)));
    (#[edl($e:expr)] $arg:ident : $arg_ty:ty) =>
        (format!("[{}] {}", $e, args_to_edl!($arg : $arg_ty)));
    ($arg:ident : $arg_ty:ty, $($tail:tt)*) =>
        (format!("{}, {}", args_to_edl!($arg : $arg_ty), args_to_edl!($($tail)*)));
    (#[edl($e:expr)] $arg:ident : $arg_ty:ty, $($tail:tt)*) =>
        (format!("{}, {}", args_to_edl!(#[edl($e)] $arg : $arg_ty), args_to_edl!($($tail)*)));
    ($(,)*) => ("".to_string());
}

fn main() {
    let mut edlfile = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(EDL_FILE).unwrap();

    write!(&mut edlfile, r#"// Copyright (C) 2020 Fuga Kato

enclave {{
    from "sgx_tstd.edl" import *;
    from "sgx_stdio.edl" import *;
    from "sgx_backtrace.edl" import *;
    from "sgx_tstdc.edl" import *;
    from "sgx_file.edl" import *;
    from "sgx_tprotected_fs.edl" import *;
    from "sgx_net.edl" import *;
    include "sgx_tcrypto.h"
    include "sgx_tkey_exchange.h"

    trusted {{
"#).unwrap();

    macro_rules! ecall_define {
        (
            $(#[$attr:meta])*
            fn $fn_name:ident (
                $($args:tt)*
            ) -> Result<$ok_ty:tt> // needed to be tt
            $body:tt
        ) => (
            writeln!(&mut edlfile,
                    "        public int64_t {}({});",
                    stringify!($fn_name),
                    args_to_edl!($($args)*)).unwrap();
        )
    }

    include!("obj/ecall_impl_.rs");

    write!(&mut edlfile, r#"    }};
}};
"#).unwrap();
}
