use lazy_static::lazy_static;
use libc::c_char;
use sgx_tcrypto::rsgx_rijndael128GCM_decrypt as decrypt;
use sgx_tcrypto::SgxEccHandle;
use sgx_types::*;
use std::backtrace::{self, PrintFormat};
use std::convert::TryInto;
use std::ffi::CStr;
use std::ffi::CString;
use std::string::ToString;
use std::io::{stdout, Write};
use std::slice;
use std::sync::SgxMutex as Mutex;
use thiserror::Error;
use crate::{jwtmc, output_policy, file};

const MC_ADDR: (&str, u16) = ("jwtmc", 7777);

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

#[derive(Debug, Error)]
pub enum ISDEDError {
    #[error("The policy doesn't allow output")]
    PolicyError,
    #[error("File rollback detected (MC: expected {0}, read {1})")]
    RollbackError(jwtmc::Ctr, jwtmc::Ctr),
    #[error(transparent)]
    SGXError(#[from] sgx_status_t),
    #[error(transparent)]
    FileError(#[from] file::FileError),
    #[error(transparent)]
    JWTMCError(#[from] jwtmc::JWTMCError),
}

pub type ISDEDResult<T> = Result<T, ISDEDError>;
// ここでstd::convert::Fromが使えればいいのだが
fn result_into_u64<T>(result: ISDEDResult<T>) -> u64 {
    use ISDEDError::*;
    match result {
        Ok(_) => 0,
        Err(error) => match error {
            PolicyError => 0x0000000100000001,
            RollbackError(_, _) => 0x0000000100000002,
            SGXError(e) => e as u64,
            _ => 0xffffffffffffffff,
        }
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
    let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Full); // TODO

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

    let filedata = file::ISDEDFileData {
        data: msg.iter().cloned().collect(),
        output_policy: policy.to_string(),
        mc_handle: key,
        mc_value: ctr,
    };
    let filename = CStr::from_ptr(filename).to_str().unwrap();
    filedata.write_to(&filename).unwrap();

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
pub extern "C" fn open_file(filename: *const c_char) -> u64 {
    let filename = unsafe { CStr::from_ptr(filename).to_str().unwrap() };

    result_into_u64(open_file_(&filename))
}

fn open_file_(filename: &str) -> ISDEDResult<()> {
    let filedata = file::ISDEDFileData::read_from(&filename)?;
    let real_mc_value = jwtmc::ctr_access(&MC_ADDR, filedata.mc_handle, 0.0)?;
    if real_mc_value != filedata.mc_value {
        return Err(ISDEDError::RollbackError(real_mc_value, filedata.mc_value));
    }

    if output_policy::evaluate(&filedata.output_policy) {
        stdout().write_all(&filedata.data).unwrap();

        let new_ctr = jwtmc::ctr_access(&MC_ADDR, filedata.mc_handle, 1.0).expect("ctr_access failed");

        file::ISDEDFileData {
            mc_value: new_ctr,
            ..filedata
        }.write_to(&filename).unwrap();
    } else {
        return Err(ISDEDError::PolicyError);
    }

    Ok(())
}

#[no_mangle]
pub unsafe extern "C" fn ecall_test() {
    backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Full).unwrap(); // TODO
    let time = jwtmc::query_time(&("localhost", 7777)).unwrap();
    println!("{:#x?}", time);
}
