use crate::{file, jwtmc, output_policy, ecall_define, to_i64};
use crate::error::{Error, Result};
use lazy_static::lazy_static;
use libc::c_char;
use sgx_tcrypto::rsgx_rijndael128GCM_decrypt as decrypt;
use sgx_tcrypto::SgxEccHandle;
use sgx_types::*;
use std::backtrace::{self, PrintFormat};
use std::convert::TryInto;
use std::ffi::CStr;
use std::io::{stdout, Write};
use std::slice;
use std::string::ToString;
use std::sync::SgxMutex as Mutex;

const MC_ADDR: (&str, u16) = ("jwtmc", 7777);

lazy_static! {
    static ref QE_INFO: Mutex<Option<(sgx_target_info_t, sgx_epid_group_id_t)>> = Mutex::new(None);
    static ref KEY: Mutex<Option<(sgx_ec256_private_t, sgx_ec256_public_t)>> = Mutex::new(None);
    static ref DHKEY: Mutex<Option<sgx_ec256_dh_shared_t>> = Mutex::new(None);
    static ref NONCE: Mutex<Option<sgx_quote_nonce_t>> = Mutex::new(None);
}

ecall_define! {
    /// Set QE's measurement (target_info) and EPID group ID
    fn set_qe_info(
        target_info: *const sgx_target_info_t,
        epid_group_id: *const sgx_epid_group_id_t,
    ) {
        let mut qe_info = QE_INFO.lock().unwrap(); // TODO
        qe_info.replace((unsafe { *target_info }, unsafe { *epid_group_id }));
    }
}

ecall_define! {
    /// process start request from SP and create REPORT for QE
    /// DH key is calculated within this function
    fn start_request(
        ga: *const sgx_ec256_public_t,
        nonce: *const sgx_quote_nonce_t,
        report: *mut sgx_report_t,
    ) -> Result<()> {
        let ga = unsafe { &*ga };
        let nonce = unsafe { &*nonce };
        let report = unsafe { &mut *report };

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
        let status = unsafe { sgx_create_report(&target_info, &report_data, report) };
        if status != sgx_status_t::SGX_SUCCESS {
            return Err(status.into())
        }

        Ok(())
    }
}

ecall_define! {
    fn store_file(
        ciphertext: *const uint8_t,
        ciphertext_len: uint64_t,
        mac: *const sgx_aes_gcm_128bit_tag_t,
        filename: *const c_char,
    ) -> Result<()> {
        let ciphertext = unsafe { slice::from_raw_parts(ciphertext, ciphertext_len.try_into().unwrap()) };
        let mac = unsafe { mac.as_ref() }.unwrap();

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
        let policy = std::str::from_utf8(&plaintext[8..(8 + policy_len).try_into().unwrap()])?;
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

        let env = output_policy::init_env(policy).expect("init_env");

        let filedata = file::ISDEDFileData {
            data: msg.iter().cloned().collect(),
            output_policy: policy.to_string(),
            environment: env,
            mc_handle: key,
            mc_value: ctr,
        };
        let filename = unsafe { CStr::from_ptr(filename) }.to_str().unwrap();
        filedata.write_to(&filename).unwrap();

        Ok(())
    }
}

ecall_define! {
    /// ローカルのファイルを読み込み
    fn open_file(filename: *const c_char) -> Result<()> {
        let filename = unsafe { CStr::from_ptr(filename).to_str().unwrap() };
        let filedata = file::ISDEDFileData::read_from(&filename)?;
        let real_mc_value = jwtmc::ctr_access(&MC_ADDR, filedata.mc_handle, 0.0)?;
        if real_mc_value != filedata.mc_value {
            return Err(Error::RollbackError(real_mc_value, filedata.mc_value));
        }
        let env = filedata.environment.clone();

        let (output_allowed, newenv) = output_policy::evaluate(&filedata.output_policy, env)?;

        let newctr =
            jwtmc::ctr_access(&MC_ADDR, filedata.mc_handle, 1.0).expect("ctr_access failed");

        let filedata = file::ISDEDFileData {
            mc_value: newctr,
            environment: newenv,
            ..filedata
        };
        filedata.write_to(&filename).unwrap();

        if output_allowed {
            stdout().write_all(&filedata.data).unwrap();
        } else {
            return Err(Error::PolicyError);
        }

        Ok(())
    }
}

ecall_define! {
    fn test_policy(policy: *const c_char, times: u64) -> Result<()> {
        let policy = unsafe { CStr::from_ptr(policy).to_str().unwrap() };
        let _ = backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Short); // TODO
        output_policy::validate(policy)?;
        println!("validation passed!");

        let mut env = output_policy::init_env(policy)?;
        println!("initial env: {:#x?}", &env);
        for i in 0..times {
            let (res, newenv) = output_policy::evaluate(policy, env)?;
            println!("[{}]: {}, env := {:#x?}", i, res, &newenv);
            env = newenv;
        }

        Ok(())
    }
}

ecall_define! {
    fn ecall_test() {
        backtrace::enable_backtrace("enclave.signed.so", PrintFormat::Full).unwrap(); // TODO
        let time = jwtmc::query_time(&("localhost", 7777)).unwrap();
        println!("{:#x?}", time);
    }
}

