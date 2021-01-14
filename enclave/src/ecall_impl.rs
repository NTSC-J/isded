ecall_define! {
    /// Set QE's measurement (target_info) and EPID group ID
    fn set_qe_info(
        #[edl("in")] target_info: *const sgx_target_info_t,
        #[edl("in")] epid_group_id: *const sgx_epid_group_id_t
    ) -> Result<()> {
        let mut qe_info = QE_INFO.lock().unwrap(); // TODO
        qe_info.replace((unsafe { *target_info }, unsafe { *epid_group_id }));
        Ok(())
    }
}

ecall_define! {
    /// process start request from SP and create REPORT for QE
    /// DH key is calculated within this function
    fn start_request(
        #[edl("in")] ga: *const sgx_ec256_public_t,
        #[edl("out")] report: *mut sgx_report_t,
        #[edl("out, size=128")] pubkeys: *mut u8
    ) -> Result<()> {
        let ga = unsafe { &*ga };
        let report = unsafe { &mut *report };
        let pubkeys = unsafe { std::slice::from_raw_parts_mut(pubkeys, 128) };

        let handle = SgxEccHandle::new();
        handle.open()?;

        let mut key = KEY.lock().unwrap();
        let (private_key, public_key) = handle.create_key_pair()?;
        key.replace((private_key, public_key));

        let mut dhkey = DHKEY.lock().unwrap();
        dhkey.replace(handle.compute_shared_dhkey(&private_key, ga)?);

        pubkeys[..32].clone_from_slice(&ga.gx);
        pubkeys[32..64].clone_from_slice(&ga.gy);
        pubkeys[64..96].clone_from_slice(&public_key.gx);
        pubkeys[96..].clone_from_slice(&public_key.gy);

        let pubkey_hash = rsgx_sha256_slice(&pubkeys)?;

        let report_data = {
            let mut r = sgx_report_data_t::default();
            r.d[..32].clone_from_slice(&pubkey_hash);
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
    /// ローカルのファイルを読み込み
    fn isded_open(
        #[edl("in, string")] filename: *const c_char
    ) -> Result<i64> {
        let filename = unsafe { CStr::from_ptr(filename).to_str().unwrap() };
        let file = file::ISDEDFile::open_read(&filename)?;
        let real_mc_value = jwtmc::ctr_peek(&MC_ADDR, file.mc_handle)?;
        if real_mc_value != file.mc_value {
            return Err(Error::RollbackError(real_mc_value, file.mc_value));
        }
        let env = file.environment.clone();

        let (output_allowed, newenv) = output_policy::evaluate(&file.output_policy, env)?;

        let newctr =
            jwtmc::ctr_access(&MC_ADDR, file.mc_handle, 1.0).expect("ctr_access failed");

        let file = file::ISDEDFile {
            mc_value: newctr,
            environment: newenv,
            ..file
        };
        file.write_metadata(&filename).unwrap();

        if output_allowed {
            let mut rng = rand::thread_rng();
            let mut open_handles = OPEN_HANDLES.lock().unwrap();
            let mut handle = Uniform::from(1..i64::MAX).sample(&mut rng);
            while open_handles.get(&handle).is_some() {
                handle = Uniform::from(1..i64::MAX).sample(&mut rng);
            }
            open_handles.insert(handle, file);
            Ok(handle)
        } else {
            Err(Error::PolicyError)
        }
    }
}

ecall_define! {
    fn isded_open_new(
        #[edl("in, string")] filename: *const c_char,
        #[edl("in, size=epolicy_len")] epolicy: *const u8,
        epolicy_len: usize) -> Result<i64> {
        let filename = unsafe { CStr::from_ptr(filename) }.to_str().unwrap();
        let epolicy = unsafe { std::slice::from_raw_parts(epolicy, epolicy_len) };

        let policy = crypto::decrypt(&dh_aes_key(), &epolicy);
        let policy = String::from_utf8_lossy(&policy);

        // TODO: error
        let (key, ctr) = jwtmc::ctr_init(&MC_ADDR).expect("ctr_init failed");

        let env = output_policy::init_env(&policy).expect("init_env");

        let file = file::ISDEDFile::open_create(filename, &policy, key, ctr, env)?;

        let mut rng = rand::thread_rng();
        let mut open_handles = OPEN_HANDLES.lock().unwrap();
        let mut handle = Uniform::from(1..i64::MAX).sample(&mut rng);
        while open_handles.get(&handle).is_some() {
            handle = Uniform::from(1..i64::MAX).sample(&mut rng);
        }
        open_handles.insert(handle, file);

        Ok(handle)
    }
}

ecall_define! {
    /// openしたファイルを出力
    fn isded_read(
        handle: i64,
        #[edl("out, size=count")] buf: *mut u8,
        count: usize
    ) -> Result<i64> {
        let buf = unsafe { std::slice::from_raw_parts_mut(buf, count) };
        let mut open_handles = OPEN_HANDLES.lock().unwrap();
        if let Some(ref mut file) = open_handles.get_mut(&handle) {
            if let ISDEDFileStream::Reader(ref mut reader) = file.stream {
                let nread = reader.read(buf)?;
                Ok(nread.try_into().unwrap())
            } else {
                Err(Error::UnsupportedOperationError)
            }
        } else {
            Err(Error::InvalidHandleError)
        }
    }
}

ecall_define! {
    /// データの大きさ
    fn isded_stat_size(
        handle: i64
    ) -> Result<i64> {
        let mut open_handles = OPEN_HANDLES.lock().unwrap();
        if let Some(ref mut file) = open_handles.get_mut(&handle) {
            if let ISDEDFileStream::Reader(ref mut reader) = file.stream {
                Ok(reader.stream_len()?.try_into()?)
            } else {
                Err(Error::UnsupportedOperationError)
            }
        } else {
            Err(Error::InvalidHandleError)
        }
    }
}

ecall_define! {
    /// データを DH 鍵で復号してから seal し、open_new したファイルに追記
    fn isded_write(
        handle: i64,
        #[edl("in, size=echunk_len")] echunk: *const u8,
        echunk_len: usize
    ) -> Result<()> {
        let echunk = unsafe { std::slice::from_raw_parts(echunk, echunk_len) };
        let mut open_handles = OPEN_HANDLES.lock().unwrap();
        if let Some(ref mut file) = open_handles.get_mut(&handle) {
            if let ISDEDFileStream::Writer(ref mut writer) = file.stream {
                let dhkey = DHKEY.lock().unwrap().unwrap();
                let mut key = sgx_aes_gcm_128bit_key_t::default();
                key.clone_from_slice(&dhkey.s[..16]);
                let chunk = crypto::decrypt(&key, &echunk);
                writer.write_all(&chunk)?;
                Ok(())
            } else {
                Err(Error::UnsupportedOperationError)
            }
        } else {
            Err(Error::InvalidHandleError)
        }
    }
}

ecall_define! {
    fn isded_seek(handle: i64, offset: i64, whence: i64) -> Result<i64> {
        use std::io::SeekFrom::*;
        let mut open_handles = OPEN_HANDLES.lock().unwrap();
        if let Some(ref mut file) = open_handles.get_mut(&handle) {
            let pos = match whence {
                0 => Start(offset.try_into().unwrap()),
                1 => End(offset),
                2 => Current(offset),
                _ => return Err(Error::InvalidParameterError),
            };
            if let ISDEDFileStream::Reader(ref mut reader) = file.stream {
                let newpos = reader.seek(pos)?;
                Ok(newpos.try_into().unwrap())
            } else {
                Err(Error::UnsupportedOperationError)
            }
        } else {
            Err(Error::InvalidHandleError)
        }
    }
}

ecall_define! {
    fn isded_close(
        handle: int64_t
    ) -> Result<()> {
        let mut open_handles = OPEN_HANDLES.lock().unwrap();
        if let Some(file) = open_handles.remove(&handle) {
            if let ISDEDFileStream::Writer(mut writer) = file.stream {
                writer.flush()?;
            }
            Ok(())
        } else {
            Err(Error::InvalidHandleError)
        }
    }
}

ecall_define! {
    fn test_policy(
        #[edl("in, string")] policy: *const c_char,
        times: u64
    ) -> Result<()> {
        let policy = unsafe { CStr::from_ptr(policy).to_str().unwrap() };
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
    fn ecall_test() -> Result<()> {
        let time = jwtmc::query_time(&("localhost", 7777)).unwrap();
        println!("{:#x?}", time);
        Ok(())
    }
}
