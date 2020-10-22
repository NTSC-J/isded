use bufstream::BufStream;
use chrono::prelude::*;
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use std::io::prelude::*;
use std::net::{TcpStream, ToSocketAddrs}; // sgx_libc 経由でOCallする
use std::prelude::v1::*;

lazy_static! {
    static ref ENCODING_KEY: EncodingKey = EncodingKey::from_rsa_der(include_bytes!("client_private.der"));
    static ref DECODING_KEY: DecodingKey<'static> = DecodingKey::from_rsa_der(include_bytes!("server_public.der"));
    //static ref ENCODING_KEY: EncodingKey = EncodingKey::from_rsa_pem(include_bytes!("client_private.der")).unwrap();
    //static ref DECODING_KEY: DecodingKey<'static> = DecodingKey::from_rsa_pem(include_bytes!("server_public.der")).unwrap();
}

#[derive(Error, Debug)]
pub enum JWTMCError {
    #[error("Server returned an error: {0}")]
    ServerError(String),
    #[error("Nonce mismatch (client side)")]
    ClientNonceMismatchError,
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
    info: String,    // "invalid_signature" | "invalid_request" | "nonce_mismatch"
}

#[derive(Debug, Serialize, Deserialize)]
struct ReqCtrInit {
    msgtype: String,
    nonce: Nonce,
    pubkey: String,
}
impl ReqCtrInit {
    fn new(nonce: Nonce) -> Self {
        ReqCtrInit {
            msgtype: "ctr_init".to_owned(),
            nonce: nonce,
            // FIXME: !!!!!
            pubkey: r#"{"e":"AQAB","kid":"oi4yXRRUW2nbIimn_P0dLfVgnO2TMUuIze0Qx5vM9jU","kty":"RSA","n":"wuxmKcJMeIH1XqPpp9RpTKe0wjcDzYu_45SvMzU55imGr7qZaiY1lqRiGXlL4_yIT0QdIFBkG3FKn6V-7bvwN5tAOePBVy832ACHyPhDuGg97rijLchRoE4vu9L8TIXD-5lgRRpzb2X7_9D_5Nis_G-7rRRtx5Itk8rKEtHfj3z7Kqes7CkCBvXgASSUq1RYU0XOg8MzKaILFE65ULX4-DDzRcDcM0e0ky25nbGqBXFFFVyRsTSVRKXdELGAfHBmyR79_ryYub9cGwlEstDGRiCfsihQWuaAS1323Bo-ZvjMvx9OmiGsMoQURFEQ9K_wt3I3OO9vbpGTaxuKJx8L-w"}"#.to_owned(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ResCtrInitOk {
    msgtype: String, // "ctr_init_ok"
    key: Key,
    nonce: Nonce,
    ctr: Ctr,
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
            inc: inc,
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
            nonce1: nonce1,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct ResCtrAccessOk {
    msgtype: String,
    nonce0: Nonce,
    nonce1: Nonce,
    ctr: Ctr,
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
            nonce: nonce,
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
    let line: String = jsonwebtoken::encode(&Header::new(Algorithm::RS256), claims, &*ENCODING_KEY)? + "\n";
    Ok(line.into_bytes())
}

fn decode<T: serde::de::DeserializeOwned>(token: &str) -> JWTMCResult<TokenData<T>> {
    let validation = Validation {
        validate_exp: false,
        algorithms: vec![Algorithm::RS256],
        ..Default::default()
    };
    let token = token.trim_end_matches(&['\r', '\n'][..]);

    // FIXME: 署名検証
    //jsonwebtoken::decode(token, &*DECODING_KEY, &validation).map_err(|e| e.into())
    jsonwebtoken::dangerous_insecure_decode_with_validation(token, &validation).map_err(|e| e.into())
}

// TODO: 共通する処理はマクロにしても良いかもしれない

pub fn ctr_init<A: ToSocketAddrs>(addr: A) -> JWTMCResult<(Key, Ctr)> {
    let stream = TcpStream::connect(addr)?;
    let mut stream = BufStream::new(stream);

    let nonce = rand::random::<u32>().into();
    let req = encode(&ReqCtrInit::new(nonce))?;
    stream.write_all(&req)?;
    stream.flush()?;

    let mut res = String::new();
    stream.read_line(&mut res)?;

    let restype = decode::<Res>(&res)?.claims.msgtype;
    let res_ok = match restype.as_str() {
        "ctr_init_ok" => decode::<ResCtrInitOk>(&res)?,
        "error" => return Err(JWTMCError::from_res(&decode::<ResError>(&res)?.claims)),
        _ => return Err(JWTMCError::InvalidResponseError),
    };
    if nonce != res_ok.claims.nonce {
        return Err(JWTMCError::ClientNonceMismatchError);
    }

    Ok((res_ok.claims.key, res_ok.claims.ctr))
}

pub fn ctr_access<A: ToSocketAddrs>(addr: A, key: Key, inc: Ctr) -> JWTMCResult<Ctr> {
    let stream = TcpStream::connect(addr)?;
    let mut stream = BufStream::new(stream);

    let nonce0 = rand::random::<u32>().into();
    let req = encode(&ReqCtrAccess::new(nonce0, key, inc))?;
    stream.write_all(&req)?;
    stream.flush()?;

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
    stream.write_all(&req_ack1)?;
    stream.flush()?;

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

    Ok(res_ok.claims.ctr)
}

pub fn query_time<A: ToSocketAddrs>(addr: A) -> JWTMCResult<DateTime<Utc>> {
    let stream = TcpStream::connect(addr)?;
    let mut stream = BufStream::new(stream);

    let nonce = rand::random::<u32>().into();
    let req = encode(&ReqTimeQuery::new(nonce))?;
    stream.write_all(&req)?;
    stream.flush()?;

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
