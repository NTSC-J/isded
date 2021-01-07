// Copyright (C) 2019-2020 Fuga Kato

use std::net::TcpStream;
use num_derive::FromPrimitive;
use num_traits::FromPrimitive;
use thiserror::Error;
use std::convert::TryInto;
use std::io::{Read, Write};
use std::fmt::Display;

#[derive(Debug, PartialEq, FromPrimitive)]
pub enum MsgType {
    StartRequest = 0x15636010,
    Quote = 0x15636020,
    ECDHPubKeys = 0x15636021,
    EncryptedPolicy = 0x15636030,
    EncryptedDataChunk = 0x15636040,
    Finished = 0x156360ff,
}
impl Display for MsgType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", stringify!(self))
    }
}

#[derive(Debug, Error)]
pub enum MsgStreamError {
    #[error("Invalid message type")]
    InvalidMsgTypeError,
    #[error("Expected {0} but got {1}")]
    UnexpectedMsgTypeError(MsgType, MsgType),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

pub struct MsgStream(TcpStream);

impl MsgStream {
    pub fn new(stream: TcpStream) -> Self {
        Self(stream)
    }
    /// read size and data from TCP stream
    pub fn read_msg(&mut self) -> Result<(MsgType, Vec<u8>), MsgStreamError> {
        let mut msgtype = [0u8; 4];
        self.0.read_exact(&mut msgtype)?;
        let msgtype = if let Some(t) = FromPrimitive::from_u32(u32::from_be_bytes(msgtype)) {
            t
        } else {
            return Err(MsgStreamError::InvalidMsgTypeError)
        };
        let mut len = [0u8; 8];
        self.0.read_exact(&mut len)?;
        let len = u64::from_be_bytes(len).try_into().unwrap();
        let mut msg = vec![0; len];
        self.0.read_exact(&mut msg)?;
        Ok((msgtype, msg))
    }

    /// read msg and the type should be this
    pub fn read_msg_of_type(&mut self, msgtype: MsgType) -> Result<Vec<u8>, MsgStreamError> {
        let (t, m) = self.read_msg()?;
        if t != msgtype {
            return Err(MsgStreamError::UnexpectedMsgTypeError(msgtype, t));
        }
        Ok(m)
    }

    /// write size and data into TCP stream
    pub fn write_msg(&mut self, msgtype: MsgType, msg: &[u8]) -> Result<(), MsgStreamError> {
        let msgtype = (msgtype as u32).to_be_bytes();
        let len: u64 = msg.len().try_into().unwrap();
        let len = len.to_be_bytes();
        self.0.write_all(&msgtype)?;
        self.0.write_all(&len)?;
        self.0.write_all(&msg)?;
        Ok(())
    }
}
