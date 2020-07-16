#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

mod s_expression;
mod output_policy;
use sgx_types::sgx_status_t;
use libc::c_char;
use std::ffi::CStr;
use std::ffi::CString;
use std::io::{copy, stdout, Read, Write};
use std::vec::Vec;
use sgx_tprotected_fs::SgxFileStream;
use std::untrusted::fs::File;

// std::io::copy()が使えるように、Read, Writeを実装
struct MySgxFileStream {
    file: SgxFileStream
}
impl Read for MySgxFileStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file.read(buf).map_err(|x| { std::io::Error::from_raw_os_error(x) })
    }
}
impl Write for MySgxFileStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf).map_err(|x| { std::io::Error::from_raw_os_error(x) })
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush().map_err(|x| { std::io::Error::from_raw_os_error(x) })
    }
}
impl From<SgxFileStream> for MySgxFileStream {
    fn from(file: SgxFileStream) -> Self {
        MySgxFileStream {
            file: file
        }
    }
}

// ローカルのファイルを読み込み
#[no_mangle]
pub extern "C" fn open_file(filename: * const c_char) -> sgx_status_t {
    let filename = unsafe { CStr::from_ptr(filename) };
    let r = CString::new("r").unwrap();
    let file = SgxFileStream::open_auto_key(filename, &r).expect("failed to open file");
    
    let mut policy_len: [u8; 8] = [0; 8];
    if 8 != file.read(&mut policy_len).expect("failed to read policy length") {
        panic!("file ended while reading policy length");
    }
    let policy_len = usize::from_le_bytes(policy_len);
    let mut policy: Vec<u8> = vec![0; policy_len];
    if policy.len() != file.read(&mut policy).expect("failed to read policy") {
        panic!("file ended while reading policy");
    }
    let policy = std::str::from_utf8(&policy).expect("invalid utf8");

    if output_policy::output_allowed(policy) {
        let mut data_len: [u8; 8] = [0; 8];
        if 8 != file.read(&mut data_len).expect("failed to read data length") {
            panic!("file ended while reading data length");
        }
        //let data_len = usize::from_le_bytes(data_len);
        // FIXME: データの長さを無視している
        copy(&mut MySgxFileStream::from(file), &mut stdout()).expect("failed to output");
    } else {
        eprintln!("access forbidden");
    }
    // TODO: MCを更新

    sgx_status_t::SGX_SUCCESS
}

// ローカルにファイルを作る
#[no_mangle]
pub extern "C" fn create_file(policy: * const c_char, input_filename: * const c_char, output_filename: * const c_char) -> sgx_status_t {
    let policy = unsafe { CStr::from_ptr(policy).to_str().expect("error converting from C string") };
    let input_filename = unsafe { CStr::from_ptr(input_filename).to_str().expect("error converting from C string") };
    let output_filename = unsafe { CStr::from_ptr(output_filename) };

    output_policy::validate(policy).expect("invalid policy");

    let mut input_file = File::open(&input_filename).expect("failed to open input file");
    let w = CString::new("w").unwrap();
    let output_file = SgxFileStream::open_auto_key(output_filename, &w).expect("failed to open output file");
    output_file.write(&policy.len().to_le_bytes()).expect("failed to write policy length"); // usize; 8 bytes on target
    output_file.write(policy.as_bytes()).expect("failed to write policy");

    let input_len = input_file.metadata().expect("failed to acquire metadata").len();
    output_file.write(&input_len.to_le_bytes()).expect("failed to write data length");
    // FIXME: ファイルサイズが変わるかもしれない
    copy(&mut input_file, &mut MySgxFileStream::from(output_file)).expect("failed to write actual data");

    sgx_status_t::SGX_SUCCESS
}

