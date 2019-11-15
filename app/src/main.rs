// Copyright (C) 2019 Fuga Kato
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

extern crate sgx_types;
extern crate sgx_urts;
extern crate dirs;

use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::io::{Read, Write};
use std::result::Result;
use std::fs;
use std::fs::OpenOptions;
use std::path;
use std::ffi::CString;
use std::convert::TryInto;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";
static ENCLAVE_TOKEN: &'static str = "enclave.token";
static DATA_FILE: &'static str = "sealeddata.bin";

// TODO: bindgenでこのブロックを自動生成
extern {
    fn initialize(eid: sgx_enclave_id_t, retval: * mut i64, json: * const c_char) -> sgx_status_t;
    fn update(eid: sgx_enclave_id_t, retval: * mut i64) -> sgx_status_t;
    fn get_raw_data(eid: sgx_enclave_id_t, retval: * mut i64, dest: * mut u8, dest_size: usize) -> sgx_status_t;
    fn save(eid: sgx_enclave_id_t, retval: * mut i64, sealed_dest: * mut u8, sealed_dest_size: u32) -> sgx_status_t;
    fn restore(eid: sgx_enclave_id_t, retval: * mut i64, sealed_src: * const u8, sealed_src_size: u32) -> sgx_status_t;
}

fn main() -> Result<(), std::io::Error> {
    let enclave = init_enclave().expect("init_enclave failed!");
    let mut r = 0_i64;

    let mut data_file = match OpenOptions::new().read(true).write(true).append(false).open(DATA_FILE) {
        Ok(mut f) => {
            let mut sealed_data = Vec::new();
            f.read_to_end(&mut sealed_data)?;
            unsafe { restore(enclave.geteid(), &mut r, sealed_data.as_ptr(), sealed_data.len() as u32); }
            if r != 0 { eprintln!("restore failed (returned {})", r); }
            f
        },
        Err(_) => {
            let json = CString::new("{\"x\": 0}")?;
            unsafe { initialize(enclave.geteid(), &mut r, json.as_ptr()); }
            if r != 0 {
                panic!("initialize failed (returned {})", r);
            }
            fs::File::create(DATA_FILE)?
        }
    };

    for _ in 0..2 {
        unsafe { update(enclave.geteid(), &mut r); }
        if r != 0 { eprintln!("update failed (returned {})", r); }
    }

    let mut raw_json: Vec<u8> = vec![0_u8; 2048];
    unsafe { get_raw_data(enclave.geteid(), &mut r, raw_json.as_mut_ptr(), raw_json.len()); }
    if r < 0 {
        panic!("get_raw_data failed (returned {})", r);
    }
    println!("raw json: {}", String::from_utf8(raw_json).unwrap());

    let mut sealed_data = vec![0_u8; 2048];
    loop {
        unsafe { save(enclave.geteid(), &mut r, sealed_data.as_mut_ptr(), sealed_data.len() as u32); }
        if r < 0 || sealed_data.len() < r.try_into().unwrap() {
            panic!("save failed (returned {})", r);
        }
        let data_size = r.try_into().unwrap();
        let vec_size = sealed_data.len();
        sealed_data.resize(data_size, 0_u8);
        eprintln!("sealed data size: {}", data_size);
        if data_size <= vec_size { break; }
        eprintln!("retrying save");
    }
    data_file.write_all(&sealed_data)?;

    enclave.destroy();

    Ok(())
}

fn init_enclave() -> SgxResult<SgxEnclave> {

    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // Step 1: try to retrieve the launch token saved by last transaction
    //         if there is no token, then create a new one.
    //
    // try to get the token saved in $HOME */
    let mut home_dir = path::PathBuf::new();
    let use_token = match dirs::home_dir() {
        Some(path) => {
            println!("[+] Home dir is {}", path.display());
            home_dir = path;
            true
        },
        None => {
            println!("[-] Cannot get home dir");
            false
        }
    };

    let token_file: path::PathBuf = home_dir.join(ENCLAVE_TOKEN);;
    if use_token == true {
        match fs::File::open(&token_file) {
            Err(_) => {
                println!("[-] Open token file {} error! Will create one.", token_file.as_path().to_str().unwrap());
            },
            Ok(mut f) => {
                println!("[+] Open token file success! ");
                match f.read(&mut launch_token) {
                    Ok(1024) => {
                        println!("[+] Token file valid!");
                    },
                    _ => println!("[+] Token file invalid, will create new token file"),
                }
            }
        }
    }

    // Step 2: call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    let enclave = try!(SgxEnclave::create(ENCLAVE_FILE,
                                          debug,
                                          &mut launch_token,
                                          &mut launch_token_updated,
                                          &mut misc_attr));

    // Step 3: save the launch token if it is updated
    if use_token == true && launch_token_updated != 0 {
        // reopen the file with write capablity
        match fs::File::create(&token_file) {
            Ok(mut f) => {
                match f.write_all(&launch_token) {
                    Ok(()) => println!("[+] Saved updated launch token!"),
                    Err(_) => println!("[-] Failed to save updated launch token!"),
                }
            },
            Err(_) => {
                println!("[-] Failed to save updated enclave token, but doesn't matter");
            },
        }
    }

    Ok(enclave)
}

