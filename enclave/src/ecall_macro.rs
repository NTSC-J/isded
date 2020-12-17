// derived from easy_ffi-0.1.0

/// takes a fn definition that returns Result<(), Error> or Result<i64, Error>
/// and emits a fn definition that returns i64
/// Ok(()) becomes 0 and Err(_) becomes the corresponding negative value
#[macro_export]
macro_rules! ecall_define {
    (
        $(#[$attr:meta])*
        fn $fn_name:ident (
            $($arg:ident : $arg_ty:ty),* $(,)*
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
    (
        $(#[$attr:meta])*
        fn $fn_name:ident (
            $($arg:ident : $arg_ty:ty),* $(,)*
        )
        $body:tt
    ) => (
        #[no_mangle]
        $(#[$attr])*
        pub extern "C" fn $fn_name($($arg:$arg_ty),*) {
            let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Full); // TODO
            $body
        }
    );
}

#[macro_export]
macro_rules! to_i64 {
    ($e:expr, ()) => {0};
    ($e:expr, i64) => {$e};
}
