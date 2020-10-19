#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#![feature(const_if_match)]
#![feature(const_fn)]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

mod output_policy;
mod s_expression;
mod jwtmc;
mod guid;
mod wave64;

use lazy_static::lazy_static;
use libc::c_char;
use sgx_tcrypto::rsgx_rijndael128GCM_decrypt as decrypt;
use sgx_tcrypto::SgxEccHandle;
use sgx_tprotected_fs::SgxFileStream;
use sgx_types::*;
use std::convert::TryInto;
use std::ffi::CStr;
use std::ffi::CString;
use std::io::{copy, stdout, Read, Write};
use std::slice;
use std::sync::SgxMutex as Mutex;
use std::untrusted::fs::File;
use std::vec::Vec;

const MC_ADDR: (&str, u16) = ("localhost", 7777);

// FIXME: tprotected_fs の auto_key は MRSIGNER に紐づく

// std::io::copy()が使えるように、Read, Writeを実装
struct MySgxFileStream {
    file: SgxFileStream,
}
impl Read for MySgxFileStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file
            .read(buf)
            .map_err(|x| std::io::Error::from_raw_os_error(x))
    }
}
impl Write for MySgxFileStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file
            .write(buf)
            .map_err(|x| std::io::Error::from_raw_os_error(x))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file
            .flush()
            .map_err(|x| std::io::Error::from_raw_os_error(x))
    }
}
impl From<SgxFileStream> for MySgxFileStream {
    fn from(file: SgxFileStream) -> Self {
        MySgxFileStream { file: file }
    }
}

lazy_static! {
    static ref QE_INFO: Mutex<Option<(sgx_target_info_t, sgx_epid_group_id_t)>> = Mutex::new(None);
    static ref KEY: Mutex<Option<(sgx_ec256_private_t, sgx_ec256_public_t)>> = Mutex::new(None);
    static ref DHKEY: Mutex<Option<sgx_ec256_dh_shared_t>> = Mutex::new(None);
    static ref NONCE: Mutex<Option<sgx_quote_nonce_t>> = Mutex::new(None);
}

// Enable ? operator
// TODO: should use std::convert::{From, Into} ?
fn convert_err(result: SgxResult<()>) -> sgx_status_t {
    match result {
        Ok(()) => sgx_status_t::SGX_SUCCESS,
        Err(s) => s,
    }
}
fn rconvert_err(status: sgx_status_t) -> SgxResult<()> {
    match status {
        sgx_status_t::SGX_SUCCESS => Ok(()),
        s => Err(s),
    }
}

/// Set QE's measurement (target_info) and EPID group ID
#[no_mangle]
pub unsafe extern "C" fn set_qe_info(
    target_info: *const sgx_target_info_t,
    epid_group_id: *const sgx_epid_group_id_t,
) -> sgx_status_t {
    let mut qe_info = QE_INFO.lock().unwrap(); // TODO
    qe_info.replace((*target_info, *epid_group_id));

    sgx_status_t::SGX_SUCCESS
}

/// process start request from SP and create REPORT for QE
/// DH key is calculated within this function
unsafe fn start_request_(
    ga: &sgx_ec256_public_t,
    nonce: &sgx_quote_nonce_t,
    report: &mut sgx_report_t,
) -> SgxResult<()> {
    let handle = SgxEccHandle::new();
    handle.open()?;

    let mut key = KEY.lock().unwrap(); // TODO
    let (private_key, public_key) = handle.create_key_pair()?;
    key.replace((private_key, public_key));

    let mut dhkey = DHKEY.lock().unwrap(); // TODO
    dhkey.replace(handle.compute_shared_dhkey(&private_key, ga)?);

    let mut nonce_ = NONCE.lock().unwrap(); // TODO
    nonce_.replace(*nonce);

    // report_data: Additional data bound with REPORT
    // contains this enclave's public key (gb)
    // TODO: should include ga too?
    let report_data = {
        let mut r = sgx_report_data_t::default();
        // TODO: reverse?
        r.d[..32].clone_from_slice(&public_key.gx);
        r.d[32..].clone_from_slice(&public_key.gy);
        r
    };

    let qe_info = QE_INFO.lock().unwrap().unwrap(); //TODO
    let target_info = qe_info.0;
    rconvert_err(sgx_create_report(&target_info, &report_data, report))?;

    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn start_request(
    ga: *const sgx_ec256_public_t,
    nonce: *const sgx_quote_nonce_t,
    report: *mut sgx_report_t,
) -> sgx_status_t {
    let ga = &*ga;
    let nonce = &*nonce;
    let report = &mut *report;

    convert_err(start_request_(ga, nonce, report))
}

unsafe fn store_file_(
    ciphertext: &[u8],
    mac: &sgx_aes_gcm_128bit_tag_t,
    filename: *const c_char,
) -> SgxResult<()> {
    let dhkey = DHKEY.lock().unwrap().unwrap(); // TODO
    let nonce = NONCE.lock().unwrap().unwrap(); // TODO

    let mut key = sgx_aes_gcm_128bit_key_t::default();
    key.clone_from_slice(&dhkey.s[..16]);
    let mut iv = [0u8; 12];
    iv.clone_from_slice(&nonce.rand[..12]);
    let aad = [0u8; 0];
    let mut plaintext = vec![0u8; ciphertext.len()];

    // TODO: buffered input
    decrypt(&key, ciphertext, &iv, &aad, mac, &mut plaintext)?;

    let mut policy_len = [0u8; 8];
    policy_len.clone_from_slice(&plaintext[0..8]);
    let policy_len = u64::from_be_bytes(policy_len);
    let policy = std::str::from_utf8(&plaintext[8..(8 + policy_len).try_into().unwrap()])
        .map_err(|_| sgx_status_t::SGX_ERROR_INVALID_PARAMETER)?;
    let mut msg_len = [0u8; 8];
    msg_len.clone_from_slice(
        &plaintext[(8 + policy_len).try_into().unwrap()..(8 + policy_len + 8).try_into().unwrap()],
    );
    let msg_len = u64::from_be_bytes(msg_len);
    let msg = &plaintext[(8 + policy_len + 8).try_into().unwrap()
        ..(8 + policy_len + 8 + msg_len).try_into().unwrap()];
    // TODO: environment, MC handle and value

    // TODO: error
    let (key, ctr) = jwtmc::ctr_init(&MC_ADDR).expect("ctr_init failed");
    println!("hii!");

    let w = CString::new("w").unwrap();
    let output_file = SgxFileStream::open_auto_key(CStr::from_ptr(filename), &w)
        .map_err(|_| sgx_status_t::SGX_ERROR_UNEXPECTED)?;
    output_file
        .write(&policy_len.to_be_bytes())
        .map_err(|_| sgx_status_t::SGX_ERROR_UNEXPECTED)?;
    output_file
        .write(&policy.as_bytes())
        .map_err(|_| sgx_status_t::SGX_ERROR_UNEXPECTED)?;
    output_file
        .write(&key.to_le_bytes())
        .unwrap();
    output_file
        .write(&ctr.to_le_bytes())
        .unwrap();
    output_file
        .write(&msg_len.to_be_bytes())
        .map_err(|_| sgx_status_t::SGX_ERROR_UNEXPECTED)?;
    output_file
        .write(&msg)
        .map_err(|_| sgx_status_t::SGX_ERROR_UNEXPECTED)?;

    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn store_file(
    ciphertext: *const uint8_t,
    ciphertext_len: uint64_t,
    mac: *const sgx_aes_gcm_128bit_tag_t,
    filename: *const c_char,
) -> sgx_status_t {
    let ciphertext = slice::from_raw_parts(ciphertext, ciphertext_len.try_into().unwrap());
    let mac = mac.as_ref().unwrap();

    convert_err(store_file_(ciphertext, mac, filename))
}

// ローカルのファイルを読み込み
#[no_mangle]
pub extern "C" fn open_file(filename: *const c_char) -> sgx_status_t {
    let filename = unsafe { CStr::from_ptr(filename) };
    let r = CString::new("r").unwrap();
    let file = SgxFileStream::open_auto_key(filename, &r).expect("failed to open file");
    let mut file = MySgxFileStream::from(file);

    let mut policy_len: [u8; 8] = [0; 8];
    file.read_exact(&mut policy_len)
        .expect("failed to read policy length");
    let policy_len = u64::from_be_bytes(policy_len);
    let mut policy: Vec<u8> = vec![0; policy_len.try_into().unwrap()];
    file.read_exact(&mut policy).expect("failed to read policy");
    let policy = std::str::from_utf8(&policy).expect("invalid utf8");
    let mut key = [0u8; 8];
    file.read_exact(&mut key).unwrap();
    let key = jwtmc::Key::from_le_bytes(key);
    let mut ctr = [0u8; 8];
    file.read_exact(&mut ctr).unwrap();
    let ctr = jwtmc::Ctr::from_le_bytes(ctr);

    // TODO: random access
    if output_policy::output_allowed(policy) {
        let mut data_len: [u8; 8] = [0; 8];
        file.read_exact(&mut data_len)
            .expect("failed to read data length");
        let data_len = u64::from_be_bytes(data_len);
        let mut data = vec![0u8; data_len as usize];
        file.read_exact(&mut data).unwrap(); // FIXME: でかいデータだと失敗する
        //let mut input = MySgxFileStream::from(file).take(data_len);
        //copy(&mut input, &mut stdout()).expect("failed to output");
        stdout().write_all(&data).unwrap();

        jwtmc::ctr_access(&MC_ADDR, key, 1.0).expect("ctr_access failed");
        
        //file.drop(); // close
        let w = CString::new("w").unwrap();
        let mut file = SgxFileStream::open_auto_key(filename, &w).expect("failed to open file");
        let mut file = MySgxFileStream::from(file);
        file.write(&policy_len.to_be_bytes()).unwrap();
        file.write(&policy.as_bytes()).unwrap();
        file.write(&key.to_le_bytes()).unwrap();
        file.write(&ctr.to_le_bytes()).unwrap();
        file.write(&data_len.to_be_bytes()).unwrap();
        file.write(&data).unwrap();
    } else {
        eprintln!("access forbidden");
    }

    sgx_status_t::SGX_SUCCESS
}

// ローカルにファイルを作る
#[no_mangle]
pub extern "C" fn create_file(
    policy: *const c_char,
    input_filename: *const c_char,
    output_filename: *const c_char,
) -> sgx_status_t {
    let policy = unsafe {
        CStr::from_ptr(policy)
            .to_str()
            .expect("error converting from C string")
    };
    let input_filename = unsafe {
        CStr::from_ptr(input_filename)
            .to_str()
            .expect("error converting from C string")
    };
    let output_filename = unsafe { CStr::from_ptr(output_filename) };

    output_policy::validate(policy).expect("invalid policy");

    let mut input_file = File::open(&input_filename).expect("failed to open input file");
    let w = CString::new("w").unwrap();
    let output_file =
        SgxFileStream::open_auto_key(output_filename, &w).expect("failed to open output file");
    output_file
        .write(&policy.len().to_le_bytes())
        .expect("failed to write policy length"); // usize; 8 bytes on target
    output_file
        .write(policy.as_bytes())
        .expect("failed to write policy");

    let input_len = input_file
        .metadata()
        .expect("failed to acquire metadata")
        .len();
    output_file
        .write(&input_len.to_le_bytes())
        .expect("failed to write data length");
    // FIXME: ファイルサイズが変わるかもしれない
    copy(&mut input_file, &mut MySgxFileStream::from(output_file))
        .expect("failed to write actual data");

    sgx_status_t::SGX_SUCCESS
}
