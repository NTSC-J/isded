#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

use crate::crypto::*;
use crate::enclave::*;
use crate::ias;
use crate::msg_stream::*;
use sgx_types::*;
use std::io::{self, Read, Write};
use std::fs::File;
use std::ffi::CString;
use std::time::Duration;
use clap::*;
use sgx_ucrypto::{SgxEccHandle, rsgx_sha256_slice};
use std::convert::TryInto;
use std::mem;
use std::net::{TcpStream, TcpListener, Ipv4Addr};
use std::ptr;
use std::slice;
use std::time::Instant;
use once_cell::sync::OnceCell;
use warp::{Filter, http::Response};
use if_chain::if_chain;
use thiserror::Error;

const ISDED_PORT: u16 = 5555;
const ENCLAVE_FILE: &str = "enclave.signed.so";
const TOKEN_FILE: &str = "enclave.token";

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

#[derive(Debug, Error)]
pub enum Error {
    #[error("Bad message")]
    BadMessageError,
    #[error("SGX error {0:?}")]
    SgxError(sgx_status_t),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    MsgStreamError(#[from] MsgStreamError),
    #[error(transparent)]
    IASError(#[from] ias::IASError),
    #[error(transparent)]
    ClapError(#[from] clap::Error),
    #[error(transparent)]
    EnclaveError(#[from] EnclaveError),
}
impl From<sgx_status_t> for Error {
    fn from(s: sgx_status_t) -> Self {
        Self::SgxError(s)
    }
}
pub type Result<T> = std::result::Result<T, Error>;

fn create_enclave() -> EnclaveResult<Enclave> {
    info!("Creating enclave");
    let token_path = dirs::home_dir().unwrap().join(&TOKEN_FILE);
    Enclave::create(&ENCLAVE_FILE, &token_path, true)
}

/// send a self-destructing/emerging file to remote host
///
/// start request: (nonce, public_key)
pub async fn subcommand_send<'a>(matches: &ArgMatches<'a>) -> Result<()> {
    let benchmark_start = Instant::now();

    let mut input: Box<dyn Read> = if let Some(name) = matches.value_of("input") {
        Box::new(File::open(name)?)
    } else {
        Box::new(io::stdin())
    };
    let policy = matches.value_of("policy").expect("specify the policy!");
    let host = matches.value_of("to").expect("specify the host!");
    let port = value_t!(matches.value_of("port"), u16).unwrap_or(ISDED_PORT);
    let bufsize = value_t!(matches.value_of("bufsize"), usize).unwrap_or(1048576);
    let retry_sec = Duration::from_secs_f64(value_t!(matches.value_of("retry-sec"), f64).unwrap_or(5.0));

    info!("Creating EC key pair...");
    let ecc = SgxEccHandle::new();
    ecc.open().unwrap();
    let (private_key, public_key) = ecc.create_key_pair().unwrap();

    info!("Opening socket to {}:{}", host, port);
    let stream = loop {
        if let Ok(s) = TcpStream::connect(format!("{}:{}", host, port)) {
            break s;
        }
        info!("Failed to open socket, retrying in {:?}...", retry_sec);
        std::thread::sleep(retry_sec);
    };
    let mut stream = MsgStream::new(stream);

    info!("Sending EC public key...");
    stream.write_msg(MsgType::StartRequest, unsafe { as_bytes!(&public_key, sgx_ec256_public_t) })?;

    info!("Fetching QUOTE...");
    let quote = stream.read_msg_of_type(MsgType::Quote)?;
    info!("Received QUOTE filesize: {}", quote.len());

    // (SApp key, RE(isv) key)
    info!("Fetching ECDH public keys...");
    let pubkeys = stream.read_msg_of_type(MsgType::ECDHPubKeys)?;
    if pubkeys.len() != 128 { // 2 * sgx_ec256_public_t
        return Err(Error::BadMessageError);
    }
    let isv_public_key = {
        let mut k = sgx_ec256_public_t::default();
        k.gx.clone_from_slice(&pubkeys[64..96]);
        k.gy.clone_from_slice(&pubkeys[96..128]);
        k
    };

    info!("Verifying QUOTE...");
    ias::verify_quote(&quote).await?;

    info!("QUOTE verified OK! Reading QUOTE...");
    let quote = unsafe {
        (quote.as_ptr() as *const sgx_quote_t).as_ref().unwrap()
    };

    info!("MRENCLAVE: {}", hex::encode(&quote.report_body.mr_enclave.m));
    info!("MRSIGNER: {}", hex::encode(&quote.report_body.mr_signer.m));

    info!("Verifying validity of public keys...");
    info!("Public key sent:   {}", unsafe { as_hex!(&public_key, sgx_ec256_public_t) });
    info!("Public key recv'd: {}", hex::encode(&pubkeys[..64]));
    if unsafe { as_bytes!(&public_key, sgx_ec256_public_t) } != &pubkeys[..64] {
        return Err(Error::BadMessageError);
    }
    info!("Public keys match OK!");
    let hash_computed = rsgx_sha256_slice(&pubkeys).unwrap();
    let hash_reported = &quote.report_body.report_data.d[..32];
    info!("Computed hash: {}", hex::encode(&hash_computed));
    info!("Reported hash: {}", hex::encode(&hash_reported));
    if hash_computed != hash_reported {
        return Err(Error::BadMessageError);
    }
    info!("Public keys' hash OK!");

    info!("Computing shared key...");
    // 256-bit shared key (x-coordinate)
    let dhkey = ecc.compute_shared_dhkey(&private_key, &isv_public_key).unwrap();
    let mut aes_key = sgx_aes_gcm_128bit_key_t::default();
    aes_key.clone_from_slice(&dhkey.s[..16]);

    info!("Sending policy...");
    info!("Policy: {}", &policy);
    stream.write_msg(MsgType::EncryptedPolicy, &encrypt(&aes_key, policy.as_bytes()))?;

    info!("Sending chunked data...");
    loop {
        let mut buf = vec![0u8; bufsize];
        let nread = input.read(&mut buf)?;
        if nread == 0 {
            break;
        }
        stream.write_msg(MsgType::EncryptedDataChunk, &encrypt(&aes_key, &buf[..nread]))?;
    }

    info!("Sending finish request...");
    stream.write_msg(MsgType::Finished, &[0u8; 0])?;

    info!("Waiting for receiver finish response...");
    let (t, _) = stream.read_msg()?;
    if t != MsgType::Finished {
        return Err(Error::BadMessageError);
    }
    info!("Got receiver finish response");

    println!("{}", benchmark_start.elapsed().as_secs_f64());
    Ok(())
}

pub async fn subcommand_recv<'a>(matches: &ArgMatches<'a>) -> Result<()> {
//    let mut output: Box<dyn Write> = if let Some(name) = matches.value_of("output") {
//        Box::new(File::create(name)?)
//    } else {
//        Box::new(io::stdout())
//    };
    let output_filename = matches.value_of("output").expect("specify output!");
    let port = value_t!(matches.value_of("port"), u16).unwrap_or(ISDED_PORT);

    // TODO: parallelism
    let enclave = create_enclave()?;

    info!("Teaching RE about QE...");
    let mut target_info = sgx_target_info_t::default();
    let mut epid_group_id = sgx_epid_group_id_t::default();
    unsafe {
        check_status!(sgx_init_quote(&mut target_info, &mut epid_group_id));
        enclave.set_qe_info(&target_info, &epid_group_id)?;
    }
    info!("mr_enclave: {}", unsafe { as_hex!(&target_info.mr_enclave, sgx_measurement_t) });
    info!("epid_group_id: {}", unsafe { as_hex!(&epid_group_id, sgx_epid_group_id_t) });

    info!("Retrieving SigRL...");
    let sigrl = ias::get_sigrl(&epid_group_id).await?;

    let bind_addr = (Ipv4Addr::new(0, 0, 0, 0), port);
    info!("Listening at {:?}...", &bind_addr);
    let listener = TcpListener::bind(bind_addr)?;
    let (stream, addr) = listener.accept()?;
    let mut stream = MsgStream::new(stream);
    info!("Accepted connection: {:?}", &addr);

    info!("Reading sender's public key...");
    let req = stream.read_msg_of_type(MsgType::StartRequest)?;
    assert_eq!(req.len(), mem::size_of::<sgx_ec256_public_t>());
    let p_ga = req.as_ptr() as *const sgx_ec256_public_t;

    info!("Creating REPORT for QE...");
    let mut report = sgx_report_t::default();
    let mut pubkeys = vec![0u8; 128];
    unsafe { enclave.start_request(p_ga, &mut report, pubkeys.as_mut_ptr())?; }

    info!("Getting QUOTE...");
    let sign_type = sgx_quote_sign_type_t::SGX_UNLINKABLE_SIGNATURE;
    let spid = {
        let spid = include_str!("spid.txt");
        let spid = hex::decode(&spid[..32]).unwrap();
        let mut r = sgx_spid_t::default();
        r.id.clone_from_slice(&spid);
        r
    };

    let mut quote;
    let mut qe_report = sgx_report_t::default();
    let quote_nonce = sgx_quote_nonce_t::default(); // unused
    unsafe {
        let mut quote_size = 0;
        let p_sigrl = if sigrl.is_empty() { ptr::null() } else { sigrl.as_ptr() };
        check_status!(sgx_calc_quote_size(p_sigrl, sigrl.len().try_into().unwrap(), &mut quote_size as *mut uint32_t));
        quote = vec![0u8; quote_size as usize];
        let p_quote = quote.as_mut_ptr() as *mut sgx_quote_t;
        check_status!(sgx_get_quote(&report, sign_type, &spid, &quote_nonce, p_sigrl, sigrl.len().try_into().unwrap(), &mut qe_report, p_quote, quote_size));
        // TODO: verify QE's REPORT
    }

    info!("Sending back QUOTE...");
    stream.write_msg(MsgType::Quote, &quote)?;
    info!("Sending back public keys...");
    stream.write_msg(MsgType::ECDHPubKeys, &pubkeys)?;

    info!("Reading encrypted output policy...");
    let policy = stream.read_msg_of_type(MsgType::EncryptedPolicy)?;
    let handle = unsafe {
        enclave.isded_open_new(
            CString::new(output_filename).unwrap().as_ptr(),
            policy.as_ptr(),
            policy.len())
    }?;

    info!("Reading encrypted chunks of data...");
    loop {
        let (t, data) = stream.read_msg()?;
        match t {
            MsgType::Finished => {
                info!("Got finish request");
                unsafe { enclave.isded_close(handle) }?;
                break;
            }
            MsgType::EncryptedDataChunk => {
                unsafe { enclave.isded_write(handle, data.as_ptr(), data.len()) }?;
            }
            _ => return Err(Error::BadMessageError)
        }
    }

    info!("Sending finish response...");
    stream.write_msg(MsgType::Finished, &[0u8; 0])?;

    Ok(())
}

pub fn subcommand_open(matches: &ArgMatches) -> Result<()> {
    let benchmark_start = Instant::now();
    let enclave = create_enclave()?;

    // TODO: support stdin
    let filename = matches.value_of("input").expect("specify the filename!");
    let bufsize = value_t!(matches.value_of("bufsize"), usize).unwrap_or(1048576);

    let filename = CString::new(filename).unwrap();
    let handle = unsafe { enclave.isded_open(filename.as_ptr()) }?;
    info!("Opened file handle: {}", handle);

    let mut buf = vec![0u8; bufsize];
    while {
        let nread = unsafe { enclave.isded_read(handle, buf.as_mut_ptr(), buf.len()) }?;
        if nread < 0 {
            warn!("isded_read() returned {}", nread);
        }
        std::io::stdout().write_all(&buf[..nread.try_into().unwrap()])?;

        0 < nread
    } {}

    eprintln!("{}", benchmark_start.elapsed().as_secs_f64());

    Ok(())
}

// enclave, handle, filesize, bufsize
static SERVE_CONTEXT: OnceCell<(Enclave, i64, usize, usize)> = OnceCell::new();
fn parse_range(range: &str) -> Option<Vec<(usize, usize)>> {
    let filesize = SERVE_CONTEXT.get().unwrap().2;
    if let Some(range) = range.strip_prefix("bytes=") {
        let mut ret = Vec::new();
        for range in range.split(", ") {
            match range.split("-").collect::<Vec<&str>>().as_slice() {
                ["", ""] => return None,
                [start, ""] => 
                    if let Ok(start) = start.parse() {
                        let len = filesize - start;
                        ret.push((start, len));
                    } else {
                        return None;
                    },
                ["", sufflen] =>
                    if let Ok(sufflen) = sufflen.parse() {
                        let start = filesize - sufflen;
                        ret.push((start, sufflen));
                    } else {
                        return None;
                    },
                [start, end] =>
                    if let (Ok(start), Ok(end)) = (start.parse(), end.parse::<usize>()) {
                        ret.push((start, end + 1 - start));
                    } else {
                        return None;
                    },
                _ => return None,
            }
        }
        Some(ret)
    } else {
        None
    }
}
fn path_to_mime(p: &str) -> String {
    mime_guess::from_path(&p)
        .first()
        .map(|m| m.to_string())
        .unwrap_or("application/octet-stream".to_string())
}
fn serve(path: String, range: Option<String>) -> Response<Vec<u8>> {
    info!("got request: {}", &path);
    let (enclave, handle, filesize, bufsize) = SERVE_CONTEXT.get().unwrap();
    let res = Response::builder()
        .header("content-type", &path_to_mime(&path))
        .header("accept-ranges", "bytes");
    // TODO: ECall error handling
    if_chain! {
        if let Some(r) = range;
        if let Some(rs) = parse_range(&r);
        if let [(start, len)] = rs.as_slice();
        then {
            info!("got request range: {}", &r);
            unsafe { enclave.isded_seek(*handle, (*start).try_into().unwrap(), 0) }.unwrap();
            let mut buf = vec![0u8; *len];
            let mut wpos = 0;
            loop {
                let nread = *std::cmp::min(bufsize, &(*len - wpos));
                let wbuf = &mut buf[wpos..wpos + nread];
                let nread: usize = unsafe { enclave.isded_read(*handle, wbuf.as_mut_ptr(), nread) }.unwrap().try_into().unwrap();
                wpos += nread;
                if nread == 0 {
                    break;
                }
            }
            buf.resize(wpos, 0);
            debug!("read {} bytes", buf.len());
            res
            .status(206)
            .header("content-range", format!("bytes {}-{}/{}", start, start + len, filesize))
            .header("content-length", format!("{}", len))
            .body(buf).unwrap()
        } else { // 全部送る
            unsafe { enclave.isded_seek(*handle, 0, 0) }.unwrap();
            let mut data = Vec::new();
            loop {
                let mut buf = vec![0u8; *bufsize];
                let nread = unsafe { enclave.isded_read(*handle, buf.as_mut_ptr(), buf.len()) }.unwrap();
                if nread <= 0 {
                    break;
                }
                buf.resize(nread.try_into().unwrap(), 0);
                data.append(&mut buf);
            }
            debug!("read {} bytes", data.len());
            res
            .status(200)
            .header("content-length", format!("{}", data.len()))
            .body(data).unwrap()
        }
    }
}
pub async fn subcommand_serve<'a>(matches: &ArgMatches<'a>) -> Result<()> {
    let enclave = create_enclave()?;

    let filename = matches.value_of("input").expect("specify the filename!");
    let bufsize = value_t!(matches.value_of("bufsize"), usize).unwrap_or(1048576);
    let port = value_t!(matches.value_of("port"), u16).unwrap_or(8080);
    let filename = CString::new(filename).unwrap();
    let handle = unsafe { enclave.isded_open(filename.as_ptr()) }?;
    info!("Opened file handle: {}", handle);
    let filesize: usize = unsafe { enclave.isded_stat_size(handle) }?.try_into().unwrap();
    info!("File filesize: {}", filesize);
    let _ = SERVE_CONTEXT.set((enclave, handle, filesize, bufsize));
    
    let hi = warp::path!(String)
        .and(warp::header::optional::<String>("range"))
        .map(serve);
    warp::serve(hi).run(([127, 0, 0, 1], port)).await;

    Ok(())
}

pub fn subcommand_test(_matches: &ArgMatches) -> Result<()> {
    let enclave = create_enclave()?;

    unsafe { enclave.ecall_test() }?;

    Ok(())
}

pub fn subcommand_eval(matches: &ArgMatches) -> Result<()> {
    let enclave = create_enclave()?;

    let policy = matches.value_of("policy").unwrap();
    let times = matches.value_of("times").unwrap_or("10").parse().unwrap();

    unsafe {
        let policy = CString::new(policy).unwrap();
        enclave.test_policy(policy.as_ptr(), times)?;
    }

    Ok(())
}

