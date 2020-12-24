#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

use crate::crypto::*;
use crate::ecalls::*;
use crate::ecall;
use crate::enclave::*;
use crate::ias;
use crate::msg_stream::*;
use sgx_types::*;
use std::io::{self, Read, Write};
use std::fs::File;
use std::ffi::CString;
use clap::*;
use failure::{bail, Error};
use std::result::Result;
use sgx_ucrypto::SgxEccHandle;
use rand::random as rand_random; // FIXME
use std::convert::TryInto;
use std::mem;
use std::net::{TcpStream, TcpListener, Ipv4Addr};
use std::ptr;
use std::slice;
use std::time::Instant;

const ISDED_PORT: u16 = 5555;

macro_rules! as_bytes {
    ($e:expr, $t:ty) => {
        slice::from_raw_parts($e as *const $t as *const u8, mem::size_of::<$t>())
    };
}

macro_rules! as_hex {
    ($e: expr, $t:ty) => {
        hex::encode(as_bytes!($e, $t))
    };
}

macro_rules! check_status {
    ($e:expr) => {
        {
            let s = $e;
            if $e != sgx_status_t::SGX_SUCCESS {
                panic!("{}: {}: {}", stringify!($e), s.as_str(), s.__description());
            }
        }
    };
}


/// send a self-destructing/emerging file to remote host
///
/// start request: (nonce, public_key)
pub fn subcommand_send(matches: &ArgMatches) -> Result<(), Error> {
    let benchmark_start = Instant::now();

    let mut input: Box<dyn Read> = if let Some(name) = matches.value_of("input") {
        Box::new(File::open(name)?)
    } else {
        Box::new(io::stdin())
    };
    let policy = matches.value_of("policy").expect("specify the policy!");
    let host = matches.value_of("to").expect("specify the host!");
    let port = value_t!(matches.value_of("port"), u16).unwrap_or(ISDED_PORT);

    info!("Creating RA start request...");
    let ecc = SgxEccHandle::new();
    ecc.open().unwrap();
    let (private_key, public_key) = ecc.create_key_pair().unwrap();
    let nonce = sgx_quote_nonce_t {
        rand: rand_random::<u128>().to_be_bytes()
    };
    let start_request = {
        let mut start_request = Vec::new();
        start_request.extend(unsafe { as_bytes!(&nonce, sgx_quote_nonce_t) });
        start_request.extend(unsafe { as_bytes!(&public_key, sgx_ec256_public_t) });
        start_request
    };

    info!("Opening socket to {}:{}", host, port);
    let stream = TcpStream::connect(format!("{}:{}", host, port))?;
    let mut stream = MsgStream::new(stream);

    info!("Sending RA start request...");
    stream.write_msg(MsgType::StartRequest, &start_request)?;

    info!("Fetching QUOTE...");
    let quote = stream.read_msg_that_is(MsgType::Quote)?;
    info!("Received QUOTE size: {}", quote.len());

    info!("Verifying QUOTE...");
    if let Err(e) = ias::verify_quote(&quote) {
        error!("QUOTE invalid!");
        error!("{:?}", &e);
        return Err(e);
    }

    info!("QUOTE verified OK! Reading QUOTE...");
    let quote = unsafe {
        (quote.as_ptr() as *const sgx_quote_t).as_ref().unwrap()
    };

    info!("MRENCLAVE: {}", hex::encode(&quote.report_body.mr_enclave.m));
    info!("MRSIGNER: {}", hex::encode(&quote.report_body.mr_signer.m));
    // TODO: nonceはどこ？

    let mut isv_public_key = sgx_ec256_public_t::default();
    isv_public_key.gx.clone_from_slice(&quote.report_body.report_data.d[..32]);
    isv_public_key.gy.clone_from_slice(&quote.report_body.report_data.d[32..]);

    info!("Computing shared key...");
    // 256-bit shared key (x-coordinate)
    let dhkey = ecc.compute_shared_dhkey(&private_key, &isv_public_key).unwrap();
    // TODO: better KDF
    let mut aes_key = sgx_aes_gcm_128bit_key_t::default();
    aes_key.clone_from_slice(&dhkey.s[..16]);

    info!("Sending policy...");
    stream.write_msg(MsgType::EncryptedPolicy, &encrypt(&aes_key, policy.as_bytes()))?;

    info!("Sending chunked data...");
    while {
        let mut buf = vec![0u8; 1048576];
        let nread = input.read(&mut buf)?;
        stream.write_msg(MsgType::EncryptedDataChunk, &encrypt(&aes_key, &buf[..nread]))?;
        nread != 0
    } {}

    info!("Sending finish request...");
    stream.write_msg(MsgType::Finished, &[0u8; 0])?;

    info!("Waiting for receiver finish response...");
    let (t, _) = stream.read_msg()?;
    if t != MsgType::Finished {
        bail!("Error! receiver couldn't finish");
    }

    info!("Sent data");
    println!("{}", benchmark_start.elapsed().as_secs_f64());
    Ok(())
}

pub fn subcommand_recv(matches: &ArgMatches) -> Result<(), Error> {
//    let mut output: Box<dyn Write> = if let Some(name) = matches.value_of("output") {
//        Box::new(File::create(name)?)
//    } else {
//        Box::new(io::stdout())
//    };
    let output_filename = matches.value_of("output").expect("specify output!");
    let port = value_t!(matches.value_of("port"), u16).unwrap_or(ISDED_PORT);

    // TODO: parallelism
    info!("Initializing RE...");
    let enclave = init_enclave().expect("Failed to initialize enclave");

    info!("Teaching RE about QE...");
    let mut target_info = sgx_target_info_t::default();
    let mut epid_group_id = sgx_epid_group_id_t::default();
    unsafe {
        check_status!(sgx_init_quote(&mut target_info, &mut epid_group_id));
        ecall!(enclave, set_qe_info(&target_info, &epid_group_id));
    }
    info!("mr_enclave: {}", unsafe { as_hex!(&target_info.mr_enclave, sgx_measurement_t) });
    info!("epid_group_id: {}", unsafe { as_hex!(&epid_group_id, sgx_epid_group_id_t) });

    info!("Retrieving SigRL...");
    let sigrl = ias::get_sigrl(&epid_group_id)?;

    let bind_addr = (Ipv4Addr::new(0, 0, 0, 0), port);
    info!("Listening at {:?}...", &bind_addr);
    let listener = TcpListener::bind(bind_addr)?;
    let (stream, addr) = listener.accept()?;
    let mut stream = MsgStream::new(stream);
    info!("Accepted connection: {:?}", &addr);

    info!("Reading start request...");
    let req = stream.read_msg_that_is(MsgType::StartRequest)?;
    let nonce_len = mem::size_of::<sgx_quote_nonce_t>();
    let ga_len = mem::size_of::<sgx_ec256_public_t>();
    assert_eq!(req.len(), nonce_len + ga_len);
    let p_nonce = req[0..nonce_len].as_ptr() as *const sgx_quote_nonce_t;
    let p_ga = req[nonce_len..nonce_len + ga_len].as_ptr() as *const sgx_ec256_public_t;

    info!("Creating REPORT for QE...");
    let mut report = sgx_report_t::default();
    unsafe { ecall!(enclave, start_request(p_ga, p_nonce, &mut report)); }

    info!("Getting QUOTE...");
    let sign_type = sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE;
    let spid = {
        let spid = include_str!("spid.txt");
        let spid = hex::decode(&spid[..32])?;
        let mut r = sgx_spid_t::default();
        r.id.clone_from_slice(&spid);
        r
    };

    let mut quote;
    let mut qe_report = sgx_report_t::default();
    unsafe {
        let mut quote_size = 0;
        let p_sigrl = if sigrl.len() == 0 { ptr::null() } else { sigrl.as_ptr() };
        check_status!(sgx_calc_quote_size(p_sigrl, sigrl.len().try_into()?, &mut quote_size as *mut uint32_t));
        quote = vec![0u8; quote_size as usize];
        let p_quote = quote.as_mut_ptr() as *mut sgx_quote_t;
        check_status!(sgx_get_quote(&report, sign_type, &spid, p_nonce, p_sigrl, sigrl.len().try_into()?, &mut qe_report, p_quote, quote_size));
        // TODO: verify QE's REPORT
    }
    info!("Sending back QUOTE...");
    stream.write_msg(MsgType::Quote, &quote)?;

    info!("Reading encrypted output policy...");
    let policy = stream.read_msg_that_is(MsgType::EncryptedPolicy)?;
    let handle = unsafe {
        ecall!(enclave, isded_open_new(
                CString::new(output_filename)?.as_ptr(),
                policy.as_ptr(),
                policy.len()))
    };

    info!("Reading encrypted chunks of data...");
    loop {
        let (t, data) = stream.read_msg()?;
        match t {
            MsgType::Finished => {
                info!("Got finish request");
                unsafe {
                    ecall!(enclave, isded_close(handle));
                }
                break;
            }
            MsgType::EncryptedDataChunk => {
                unsafe {
                    ecall!(enclave, isded_write(handle, data.as_ptr(), data.len()));
                }
            }
            _ => bail!("gah")
        }
    }

    info!("Sending finish response...");
    stream.write_msg(MsgType::Finished, &[0u8; 0])?;

    Ok(())
}

pub fn subcommand_open(matches: &ArgMatches) -> Result<(), Error> {
    let benchmark_start = Instant::now();
    let enclave = init_enclave().expect("init_enclave failed!");

    // TODO: support stdin
    let filename = matches.value_of("input").expect("specify the filename!");

    let filename = CString::new(filename)?;
    let handle = unsafe { ecall!(enclave, isded_open(filename.as_ptr())) };
    info!("Opened file handle: {}", handle);

    let mut buf = vec![0u8; 4096];
    while {
        let nread = unsafe { ecall!(enclave, isded_read(handle, buf.as_mut_ptr(), buf.len().try_into().unwrap())) };
        if nread < 0 {
            warn!("read_file() returned {}", nread);
        }
        std::io::stdout().write_all(&buf[..nread.try_into().unwrap()])?;

        0 < nread
    } {}

    eprintln!("{}", benchmark_start.elapsed().as_secs_f64());

    enclave.destroy();

    Ok(())
}

pub fn subcommand_test(_matches: &ArgMatches) -> Result<(), Error> {
    let enclave = init_enclave().unwrap();
    let eid = enclave.geteid();

    unsafe {
        ecall_test(eid);
    }

    Ok(())
}

pub fn subcommand_eval(matches: &ArgMatches) -> Result<(), Error> {
    let enclave = init_enclave().unwrap();

    let policy = matches.value_of("policy").unwrap();
    let times = matches.value_of("times").unwrap_or("10").parse().unwrap();

    unsafe {
        let policy = CString::new(policy)?;
        let mut r = 0;
        test_policy(enclave.geteid(), &mut r, policy.as_ptr(), times);
    }

    Ok(())
}

