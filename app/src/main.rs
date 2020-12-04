// Copyright (C) 2019-2020 Fuga Kato

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::io::{self, Read, Write};
use std::fs::File;
use std::ffi::CString;
use std::path;
use clap::*;
use failure::{bail, Error};
use std::result::Result;
use sgx_ucrypto::SgxEccHandle;
use sgx_ucrypto::rsgx_rijndael128GCM_encrypt as encrypt;
use rand::random as rand_random; // FIXME
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use std::convert::TryInto;
use std::mem;
use std::net::{TcpStream, TcpListener, Ipv4Addr};
use std::ptr;
use std::slice;
use std::time::Instant;
use chrono::prelude::*;
use once_cell::sync::Lazy;

#[macro_use]
extern crate log;

// TODO: bindgenに任せる
mod ecall;
use ecall::*;
mod ias;

const ENCLAVE_FILE: &'static str = "enclave.signed.so";
const ENCLAVE_TOKEN: &'static str = "enclave.token";
const ISDED_PORT: u16 = 5555;
static APP_YAML: Lazy<yaml_rust::Yaml> = Lazy::new(|| load_yaml!("cli.yaml").clone());

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

fn main() -> Result<(), Error> {
    env_logger::builder()
        .format(|buf, record| {
            writeln!(buf, "[{} {} {}] {}",
                Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                record.level(),
                crate_name!(),
                record.args())
        })
        .init();

    let matches = get_clap_app().get_matches();

    let subcommand_result = match matches.subcommand() {
        ("send", Some(sub_m)) => subcommand_send(&sub_m),
        ("recv", Some(sub_m)) => subcommand_recv(&sub_m),
        ("open", Some(sub_m)) => subcommand_open(&sub_m),
        ("eval", Some(sub_m)) => subcommand_eval(&sub_m),
        ("test", Some(sub_m)) => subcommand_test(&sub_m),
        _ => if matches.is_present("version") {
            get_clap_app().write_long_version(&mut io::stdout())?;
            println!();
            Ok(())
        } else {
            eprintln_help();
            Ok(())
        }
    };

    // TODO: 細分化
    match subcommand_result {
        Err(e) => {
            eprintln_help();
            Err(e)
        },
        Ok(o) => Ok(o)
    }
}

fn get_clap_app() -> App<'static, 'static> {
    App::from_yaml(&*APP_YAML)
        .name(crate_name!())
        .author(crate_authors!())
        .about(crate_description!())
        .version(crate_version!())
}

fn eprintln_help() {
    get_clap_app().write_long_help(&mut io::stderr()).unwrap();
    writeln!(&mut io::stderr()).unwrap();
}

/// send a self-destructing/emerging file to remote host
///
/// start request: (nonce, public_key)
fn subcommand_send(matches: &ArgMatches) -> Result<(), Error> {
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
    let mut stream = TcpStream::connect(format!("{}:{}", host, port))?;

    info!("Sending RA start request...");
    write_msg(&mut stream, MSGType::StartRequest, &start_request)?;

    info!("Fetching QUOTE...");
    let (t, quote) = read_msg(&mut stream)?;
    if t != MSGType::Quote {
        bail!("not QUOTE");
    }
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
    // TODO: better key/IV derivation
    let mut aes_key = sgx_aes_gcm_128bit_key_t::default();
    aes_key.clone_from_slice(&dhkey.s[..16]);
    let mut iv = [0u8; 12];
    iv.clone_from_slice(&nonce.rand[..12]);
    let aad = [0u8; 0]; // additional authentication data (unused)

    // TODO: parallel to RA
    info!("Loading data...");
    let mut plaintext = Vec::new();
    let policy_bytes = policy.as_bytes();
    let policy_len: u64 = policy_bytes.len().try_into()?;
    plaintext.extend_from_slice(&policy_len.to_be_bytes());
    plaintext.extend_from_slice(policy_bytes);
    let mut msg = Vec::new();
    let msg_len:u64 = input.read_to_end(&mut msg)?.try_into()?;
    plaintext.extend_from_slice(&msg_len.to_be_bytes());
    plaintext.append(&mut msg);

    // TODO: buffered input
    info!("Encrypting data with shared key...");
    let mut ciphertext = vec![0u8; plaintext.len()];
    let mut mac = vec![0u8; mem::size_of::<sgx_aes_gcm_128bit_tag_t>()];
    let mac_ref = unsafe {
        (mac.as_mut_ptr() as *mut sgx_aes_gcm_128bit_tag_t).as_mut().unwrap()
    };
    encrypt(&aes_key, &plaintext, &iv, &aad, &mut ciphertext, mac_ref).unwrap();

    info!("Sending encrypted data...");
    write_msg(&mut stream, MSGType::EncryptedData, &ciphertext)?;
    write_msg(&mut stream, MSGType::EncryptedDataMac, &mac)?;

    info!("Waiting for receiver finish response...");
    let (t, _) = read_msg(&mut stream)?;
    if t != MSGType::Finished {
        bail!("Error! receiver couldn't finish");
    }

    info!("Sent data");
    println!("{}", benchmark_start.elapsed().as_secs_f64());
    Ok(())
}

fn subcommand_recv(matches: &ArgMatches) -> Result<(), Error> {
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
    macro_rules! ec {
        ($name:ident, $($arg:expr),*) => {
            ecall!(enclave, $name, $($arg),*)
            .unwrap_or_else(|x| { panic!("{} failed: {}", stringify!($name), x.as_str()); })
        }
    }

    info!("Teaching RE about QE...");
    let mut target_info = sgx_target_info_t::default();
    let mut epid_group_id = sgx_epid_group_id_t::default();
    unsafe {
        check_status!(sgx_init_quote(&mut target_info, &mut epid_group_id));
        ec!(set_qe_info, &target_info, &epid_group_id);
    }
    info!("mr_enclave: {}", unsafe { as_hex!(&target_info.mr_enclave, sgx_measurement_t) });
    info!("epid_group_id: {}", unsafe { as_hex!(&epid_group_id, sgx_epid_group_id_t) });

    info!("Retrieving SigRL...");
    let sigrl = ias::get_sigrl(&epid_group_id)?;

    let bind_addr = (Ipv4Addr::new(0, 0, 0, 0), port);
    info!("Listening at {:?}...", &bind_addr);
    let listener = TcpListener::bind(bind_addr)?;
    let (mut stream, addr) = listener.accept()?;
    info!("Accepted connection: {:?}", &addr);

    info!("Reading start request...");
    let req = read_msg_that_is(&mut stream, MSGType::StartRequest)?;
    let nonce_len = mem::size_of::<sgx_quote_nonce_t>();
    let ga_len = mem::size_of::<sgx_ec256_public_t>();
    assert_eq!(req.len(), nonce_len + ga_len);
    let p_nonce = req[0..nonce_len].as_ptr() as *const sgx_quote_nonce_t;
    let p_ga = req[nonce_len..nonce_len + ga_len].as_ptr() as *const sgx_ec256_public_t;

    info!("Creating REPORT for QE...");
    let mut report = sgx_report_t::default();
    unsafe { ec!(start_request, p_ga, p_nonce, &mut report); }

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
    write_msg(&mut stream, MSGType::Quote, &quote)?;

    info!("Reading Encrypted data...");
    let ciphertext = read_msg_that_is(&mut stream, MSGType::EncryptedData)?;
    let mac = read_msg_that_is(&mut stream, MSGType::EncryptedDataMac)?;
    assert_eq!(mac.len(), mem::size_of::<sgx_aes_gcm_128bit_tag_t>());

    info!("Letting RE store sealed data to file...");
    unsafe { ec!(store_file, ciphertext.as_ptr(), ciphertext.len().try_into()?, mac.as_ptr() as *const sgx_aes_gcm_128bit_tag_t, CString::new(output_filename)?.as_ptr()); }

    info!("Sending finish response...");
    write_msg(&mut stream, MSGType::Finished, &[0u8; 0])?;

    Ok(())
}

fn subcommand_open(matches: &ArgMatches) -> Result<(), Error> {
    let benchmark_start = Instant::now();
    let enclave = init_enclave().expect("init_enclave failed!");
    macro_rules! ec {
        ($name:ident, $($arg:expr),*) => {
            ecall!(enclave, $name, $($arg),*)
            .unwrap_or_else(|x| { panic!("{} failed: {}", stringify!($name), x.as_str()); })
        }
    }

    // TODO: support stdin
    let filename = matches.value_of("input").expect("specify the filename!");

    unsafe {
        let filename = CString::new(filename)?;
        ec!(open_file, filename.as_ptr());
    }
    eprintln!("{}", benchmark_start.elapsed().as_secs_f64());

    enclave.destroy();

    Ok(())
}

fn subcommand_test(_matches: &ArgMatches) -> Result<(), Error> {
    let enclave = init_enclave().unwrap();
    let eid = enclave.geteid();

    unsafe {
        ecall_test(eid);
    }

    Ok(())
}

fn subcommand_eval(matches: &ArgMatches) -> Result<(), Error> {
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

#[derive(Debug, PartialEq, FromPrimitive)]
enum MSGType {
    StartRequest = 0x15636010,
    Quote = 0x15636020,
    EncryptedData = 0x15636030,
    EncryptedDataMac = 0x1536031,
    Finished = 0x156360ff,
}

/// read size and data from TCP stream
fn read_msg(stream: &mut TcpStream) -> Result<(MSGType, Vec<u8>), Error> {
    let mut msgtype = [0u8; 4];
    stream.read_exact(&mut msgtype)?;
    let msgtype = if let Some(t) = FromPrimitive::from_u32(u32::from_be_bytes(msgtype)) { t } else { bail!("invalid message type") };
    let mut len = [0u8; 8];
    stream.read_exact(&mut len)?;
    let len = u64::from_be_bytes(len).try_into()?;
    let mut msg = vec![0; len];
    stream.read_exact(&mut msg)?;
    Ok((msgtype, msg))
}

/// read msg and the type should be this
fn read_msg_that_is(stream: &mut TcpStream, msgtype: MSGType) -> Result<Vec<u8>, Error> {
    let (t, m) = read_msg(stream)?;
    if t != msgtype {
        bail!("msgtype {:?} expected but got {:?}", msgtype, t);
    }
    Ok(m)
}

/// write size and data into TCP stream
fn write_msg(stream: &mut TcpStream, msgtype: MSGType, msg: &[u8]) -> Result<(), Error> {
    let msgtype = (msgtype as u32).to_be_bytes();
    let len: u64 = msg.len().try_into()?;
    let len = len.to_be_bytes();
    stream.write_all(&msgtype)?;
    stream.write_all(&len)?;
    stream.write_all(&msg)?;
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
            home_dir = path;
            true
        },
        None => {
            println!("Cannot get home dir");
            false
        }
    };

    let token_file: path::PathBuf = home_dir.join(ENCLAVE_TOKEN);
    if use_token {
        match File::open(&token_file) {
            Err(_) => {
                println!("[-] Open token file {} error! Will create one.", token_file.as_path().to_str().unwrap());
            },
            Ok(mut f) => {
                match f.read(&mut launch_token) {
                    Ok(1024) => {},
                    _ => println!("[+] Token file invalid, will create new token file"),
                }
            }
        }
    }

    // Step 2: call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    let enclave = SgxEnclave::create(ENCLAVE_FILE,
                                     debug,
                                     &mut launch_token,
                                     &mut launch_token_updated,
                                     &mut misc_attr)?;

    // Step 3: save the launch token if it is updated
    if use_token && launch_token_updated != 0 {
        // reopen the file with write capablity
        match File::create(&token_file) {
            Ok(mut f) => {
                if f.write_all(&launch_token).is_err() {
                    println!("[-] Failed to save updated launch token!");
                }
            },
            Err(_) => {
                println!("[-] Failed to save updated enclave token, but doesn't matter");
            },
        }
    }

    Ok(enclave)
}

