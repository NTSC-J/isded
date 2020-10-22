#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![feature(const_if_match)]
#![feature(const_fn)]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

mod guid;
mod jwtmc;
mod output_policy;
mod s_expression;
mod wave64;
mod ecall;

pub use ecall::*;
