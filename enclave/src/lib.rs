// Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//
//  * Redistributions of source code must retain the above copyright
//    notice, this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in
//    the documentation and/or other materials provided with the
//    distribution.
//  * Neither the name of Baidu, Inc., nor the names of its
//    contributors may be used to endorse or promote products derived
//    from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#![crate_name = "sealenclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[allow(unused_imports)]
#[macro_use]
extern crate sgx_tstd as std;

extern crate sgx_tseal;
use sgx_tseal::SgxSealedData;

#[macro_use]
extern crate lazy_static;

use sgx_types::*;
use sgx_types::marker::ContiguousMemory;
use std::sync::SgxMutex;

extern crate libc;
use libc::c_char;
use std::ffi::CStr;
use std::str;
use std::ptr;

extern crate serde;
use serde::{Serialize, Deserialize};
extern crate serde_json;

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
struct SecretData {
    x: i64
}
unsafe impl ContiguousMemory for SecretData { }
impl SecretData {
    fn update(&mut self) -> SecretData {
        self.x += 1;
        *self
    }
}

lazy_static! {
    static ref SECRET: SgxMutex<Option<SecretData>> = SgxMutex::new(None);
}

// SECRETを初期化
#[no_mangle]
pub extern "C" fn initialize(json: * const c_char) -> i64 {
    eprintln!("initialize");
    let mut secret = match SECRET.lock() {
        Ok(x) => match *x {
            Some(_) => return -1,
            None => x
        },
        Err(_) => return -2
    };
    let json: &CStr = unsafe { CStr::from_ptr(json) };
    let json: &str = json.to_str().unwrap();

    let deser = serde_json::from_str(&json);
    match deser {
        Ok(x) => *secret = Some(x),
        Err(_) => return -3
    }
    dbg!(*secret);
    0
}

// JSONにしてそのまま出力
#[no_mangle]
pub extern "C" fn get_raw_data(dest: * mut u8, dest_size: usize) -> i64 {
    eprintln!("get_raw_data");
    let secret = match SECRET.lock() {
        Ok(x) => match *x {
            None => return -1,
            Some(y) => y
        },
        Err(_) => return -2
    };
    dbg!(&secret);
    let json = serde_json::to_string(&secret).unwrap();
    if json.len() <= dest_size {
        unsafe { ptr::copy(json.as_ptr(), dest, json.len()); }
    }
    json.len() as i64
}

// データを操作する
#[no_mangle]
pub extern "C" fn update() -> i64 {
    eprintln!("update");
    if let Ok(mut x) = SECRET.lock() {
        if let Some(mut y) = *x {
            x.replace(y.update());
            dbg!(*x);
        } else {
            return -1
        }
    } else {
        return -2
    }
    0
}

// Sealして出力
#[no_mangle]
pub extern "C" fn save(sealed_dest: * mut u8, sealed_dest_size: u32) -> i64 {
    eprintln!("save(dest: {:?}, size: {})", sealed_dest, sealed_dest_size);
    let secret = match SECRET.lock() {
        Ok(x) => match *x {
            None => return -1,
            Some(y) => y
        },
        Err(_) => return -2
    };
    dbg!(&secret);
    let add: [u8; 0] = [0_u8; 0]; // additional dataは使わない
    let sealed_data = if let Ok(x) = SgxSealedData::<SecretData>::seal_data(&add, &secret) { x } else { return -4 };
    // TODO: カウンタを追加
    unsafe {
        let sealed_dest = sealed_dest as * mut sgx_sealed_data_t;
        if let None = sealed_data.to_raw_sealed_data_t(sealed_dest, sealed_dest_size) { return -5; }
    }
    2048 // TODO: sealed_dataの大きさを返す
}

// Sealされたデータを読み込み
#[no_mangle]
pub extern "C" fn restore(sealed_src: * const u8, sealed_src_size: u32) -> i64 {
    eprintln!("restore(src: {:?}, size: {})", sealed_src, sealed_src_size);
    let mut secret = match SECRET.lock() {
        Ok(x) => if let None = *x { x } else { return -1 },
        Err(_) => return -2
    };
    // TODO: カウンタを検証
    unsafe {
        let sealed_src = sealed_src as * mut sgx_sealed_data_t;
        let sealed_data = if let Some(x) = SgxSealedData::<SecretData>::from_raw_sealed_data_t(sealed_src, sealed_src_size) { x } else { return -3 };
        let unsealed_data = if let Ok(x) = sealed_data.unseal_data() { x } else { return -4 };
        *secret = Some(*unsealed_data.get_decrypt_txt());
    }
    dbg!(&secret);
    0
}

