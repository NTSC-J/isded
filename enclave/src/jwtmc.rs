use serde::{Serialize, Deserialize};
use jsonwebtoken::{Header, Validation, Algorithm, DecodingKey, EncodingKey, TokenData};
use thiserror::Error;
use chrono::prelude::*;
use bufstream::BufStream;
use lazy_static::lazy_static;

use std::net::{ToSocketAddrs, TcpStream}; // sgx_libc 経由でOCallする
use std::prelude::v1::*;
use std::io::prelude::*;

lazy_static! {
    static ref ENCODING_KEY: EncodingKey = EncodingKey::from_rsa_pem(include_bytes!("client_private.pem")).unwrap();
    static ref DECODING_KEY: DecodingKey<'static> = DecodingKey::from_rsa_pem(include_bytes!("server_public.pem")).unwrap();
}

#[derive(Error, Debug)]
pub enum JWTMCError {
    #[error("Server returned an error: {0}")]
    ServerError(String),
    #[error("Nonce mismatch (client side)")]
    ClientNonceMismatchError,
    #[error("Invalid signature (client side)")]
    ClientInvalidSignatureError,
    #[error("Server returned an invalid response")]
    InvalidResponseError,
    #[error("Nonce mismatch (server side)")]
    ServerNonceMismatchError,
    #[error("Invalid signature (server side)")]
    ServerInvalidSignatureError,
    #[error("The server doesn't understand the request")]
    InvalidRequestError,
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    JWTError(#[from] jsonwebtoken::errors::Error),
}
impl JWTMCError {
    fn from_res(res: &ResError) -> Self {
        match res.info.as_str() {
            "nonce_mismatch" => JWTMCError::ServerNonceMismatchError,
            "invalid_signature" => JWTMCError::ServerInvalidSignatureError,
            "invalid_request" => JWTMCError::InvalidRequestError,
            x => JWTMCError::ServerError(x.to_owned()),
        }
    }
}

pub type JWTMCResult<T> = Result<T, JWTMCError>;

// TODO: f64ではなくu64を使えるようにする
pub type Nonce = f64;
pub type Key = f64;
pub type Ctr = f64;

#[derive(Debug, Serialize, Deserialize)]
struct Res {
    msgtype: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ResError {
    msgtype: String, // "error"
    info: String, // "invalid_signature" | "invalid_request" | "nonce_mismatch"
}

#[derive(Debug, Serialize, Deserialize)]
struct ReqCtrInit {
    msgtype: String,
    nonce: Nonce,
}
impl ReqCtrInit {
    fn new(nonce: Nonce) -> Self {
        ReqCtrInit {
            msgtype: "ctr_init".to_owned(),
            nonce: nonce
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ResCtrInitOk {
    msgtype: String, // "ctr_init_ok"
    key: Key,
    nonce: Nonce,
    v: Ctr,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReqCtrAccess {
    msgtype: String,
    nonce0: Nonce,
    key: Key,
    inc: Ctr,
}
impl ReqCtrAccess {
    fn new(nonce0: Nonce, key: Key, inc: Ctr) -> Self {
        ReqCtrAccess {
            msgtype: "ctr_access".to_owned(),
            nonce0: nonce0,
            key: key,
            inc: inc
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ResCtrAccessAck0 {
    msgtype: String,
    nonce0: Nonce,
    nonce1: Nonce,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReqCtrAccessAck1 {
    msgtype: String,
    nonce0: Nonce,
    nonce1: Nonce,
}
impl ReqCtrAccessAck1 {
    fn new(nonce0: Nonce, nonce1: Nonce) -> Self {
        ReqCtrAccessAck1 {
            msgtype: "ctr_access_ack1".to_owned(),
            nonce0: nonce0,
            nonce1: nonce1
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ResCtrAccessOk {
    msgtype: String,
    nonce0: Nonce,
    nonce1: Nonce,
    v: Ctr,
}

#[derive(Debug, Serialize, Deserialize)]
struct ReqTimeQuery {
    msgtype: String,
    nonce: Nonce,
}
impl ReqTimeQuery {
    fn new(nonce: Nonce) -> Self {
        ReqTimeQuery {
            msgtype: "time_query".to_owned(),
            nonce: nonce
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ResTimeAnswer {
    msgtype: String,
    nonce: Nonce,
    time: f64,
}

fn encode<T: Serialize>(claims: &T) -> JWTMCResult<Vec<u8>> {
    //let line: String = jsonwebtoken::encode(&Header::new(Algorithm::RS256), claims, &ENCODING_KEY)? + "\n";
    let encoding_key = EncodingKey::from_rsa_pem(include_bytes!("client_private.pem")).unwrap();
    let line: String = jsonwebtoken::encode(&Header::new(Algorithm::RS256), claims, &encoding_key)? + "\n";
    println!("encode: {}", line);
    Ok(line.into_bytes())
}

fn decode<T: serde::de::DeserializeOwned>(token: &str) -> JWTMCResult<TokenData<T>> {
    let validation = Validation {
        validate_exp: false,
        algorithms: vec![Algorithm::RS256],
        ..Default::default()
    };
    Ok(jsonwebtoken::decode::<T>(token, &DECODING_KEY, &validation)?)
}

// TODO: 共通する処理はマクロにしても良いかもしれない

pub fn ctr_init<A: ToSocketAddrs>(addr: A) -> JWTMCResult<(Key, Ctr)> {
    let stream = TcpStream::connect(addr)?;
    let mut stream = BufStream::new(stream);

    let nonce = rand::random();
    println!("nonce: {}", nonce);
    let req = ReqCtrInit::new(nonce);
    println!("req: {:?}", &req);
    let req = encode(&req)?;
    //let req = encode(&ReqCtrInit::new(nonce))?;
    println!("req: {}", String::from_utf8(req.clone()).unwrap());
    stream.write(&req)?;

    let mut res = String::new();
    stream.read_line(&mut res)?;
    println!("res: {}", &res);

    let restype = decode::<Res>(&res)?.claims.msgtype;
    let res_ok = match restype.as_str() {
        "ctr_init_ok" => decode::<ResCtrInitOk>(&res)?,
        "error" => return Err(JWTMCError::from_res(&decode::<ResError>(&res)?.claims)),
        _ => return Err(JWTMCError::InvalidResponseError),
    };
    if nonce != res_ok.claims.nonce {
        return Err(JWTMCError::ClientNonceMismatchError);
    }

    Ok((res_ok.claims.key, res_ok.claims.v))
}

pub fn ctr_access<A: ToSocketAddrs>(addr: A, key: Key, inc: Ctr) -> JWTMCResult<Ctr> {
    let stream = TcpStream::connect(addr)?;
    let mut stream = BufStream::new(stream);

    let nonce0 = rand::random();
    let req = encode(&ReqCtrAccess::new(nonce0, key, inc))?;
    stream.write(&req)?;

    let mut res = String::new();
    stream.read_line(&mut res)?;

    let restype = decode::<Res>(&res)?.claims.msgtype;
    let res_ack0 = match restype.as_str() {
        "ctr_access_ack0" => decode::<ResCtrAccessAck0>(&res)?,
        "error" => return Err(JWTMCError::from_res(&decode::<ResError>(&res)?.claims)),
        _ => return Err(JWTMCError::InvalidResponseError),
    };
    if nonce0 != res_ack0.claims.nonce0 {
        return Err(JWTMCError::ClientNonceMismatchError);
    }
    let nonce1 = res_ack0.claims.nonce1;

    let req_ack1 = encode(&ReqCtrAccessAck1::new(nonce0, nonce1))?;
    stream.write(&req_ack1)?;

    let mut res = String::new();
    stream.read_line(&mut res)?;

    let restype = decode::<Res>(&res)?.claims.msgtype;
    let res_ok = match restype.as_str() {
        "ctr_access_ok" => decode::<ResCtrAccessOk>(&res)?,
        "error" => return Err(JWTMCError::from_res(&decode::<ResError>(&res)?.claims)),
        _ => return Err(JWTMCError::InvalidResponseError),
    };
    if nonce0 != res_ok.claims.nonce0 || nonce1 != res_ok.claims.nonce1 {
        return Err(JWTMCError::ClientNonceMismatchError);
    }

    Ok(res_ok.claims.v)
}

pub fn query_time<A: ToSocketAddrs>(addr: A) -> JWTMCResult<DateTime<Utc>> {
    let stream = TcpStream::connect(addr)?;
    let mut stream = BufStream::new(stream);

    let nonce = rand::random();
    let req = encode(&ReqTimeQuery::new(nonce))?;
    stream.write(&req)?;

    let mut res = String::new();
    stream.read_line(&mut res)?;

    let restype = decode::<Res>(&res)?.claims.msgtype;
    let res_answer = match restype.as_str() {
        "time_answer" => decode::<ResTimeAnswer>(&res)?,
        "error" => return Err(JWTMCError::from_res(&decode::<ResError>(&res)?.claims)),
        _ => return Err(JWTMCError::InvalidResponseError),
    };
    if nonce != res_answer.claims.nonce {
        return Err(JWTMCError::ClientNonceMismatchError);
    }

    let s = res_answer.claims.time.floor() as i64;
    let ns = ((res_answer.claims.time - s as f64) * 1e9) as u32;
    Ok(Utc.timestamp(s, ns))
}

