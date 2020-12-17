use thiserror::Error as ThisError;
use std::result::Result as StdResult;
use crate::{file, jwtmc, output_policy};
use sgx_types::sgx_status_t;

#[derive(Debug, ThisError)]
pub enum Error {
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
    #[error(transparent)]
    OutputPolicyError(#[from] output_policy::OutputPolicyError),
    #[error(transparent)]
    Utf8Error(#[from] std::str::Utf8Error),
}

pub type Result<T> = StdResult<T, Error>;

impl From<Error> for i64 {
    fn from(error: Error) -> Self {
        use Error::*;
        match error {
            PolicyError => -0x0000000100000001,
            RollbackError(_, _) => -0x0000000100000002,
            SGXError(e) => -(e as i64),
            _ => -0x00000001ffffffff,
        }
    }
}

