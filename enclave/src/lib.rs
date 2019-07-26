// Copyright (C) 2017-2019 Baidu, Inc. All Rights Reserved.
//
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

#![crate_name = "helloworldsampleenclave"]
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

use sgx_types::*;
use sgx_types::marker::ContiguousMemory;

#[no_mangle]
pub extern "C" fn get_counter(sealed_raw: * mut u8, sealed_raw_size: u32) -> u64 {
    let opt = from_sealed_raw_for_fixed::<u64>(sealed_raw, sealed_raw_size);
    let sealed_data = match opt {
        Some(x) => x,
        None => {
            return std::u64::MAX;
        }
    };
    let unsealed_data = sealed_data.unseal_data().unwrap();
    let ret = unsealed_data.get_decrypt_txt();
    set_counter(ret + 1, sealed_raw, sealed_raw_size);
    *ret
}

#[no_mangle]
pub extern "C" fn set_counter(v: u64, sealed_raw: * mut u8, sealed_raw_size: u32) {
    let add: [u8; 0] = [0_u8; 0]; // additional data
    let sealed_data = SgxSealedData::<u64>::seal_data(&add, &v).unwrap();
    
    to_sealed_raw_for_fixed(&sealed_data, sealed_raw, sealed_raw_size);
}

fn to_sealed_raw_for_fixed<T: Copy + ContiguousMemory>(sealed_data: &SgxSealedData<T>, sealed_raw: * mut u8, sealed_raw_size: u32) -> Option<* mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_raw as * mut sgx_sealed_data_t, sealed_raw_size)
    }
}

fn from_sealed_raw_for_fixed<'a, T: Copy + ContiguousMemory>(sealed_raw: * mut u8, sealed_raw_size: u32) -> Option<SgxSealedData<'a, T>> {
    unsafe {
        SgxSealedData::<T>::from_raw_sealed_data_t(sealed_raw as * mut sgx_sealed_data_t, sealed_raw_size)
    }
}

