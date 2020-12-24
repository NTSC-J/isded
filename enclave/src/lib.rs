#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![feature(const_fn)]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

mod error;
mod ecall;
mod ecall_macro;
//mod guid;
mod jwtmc;
mod output_policy;
mod file;
mod s_expression;
//mod wave64;
mod crypto;

pub use ecall::*;
