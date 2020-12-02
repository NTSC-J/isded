use crate::{jwtmc, output_policy};
use sgx_tprotected_fs::SgxFileStream;
use sgx_types::*;
use std::ffi::CString;
use std::io::prelude::*;
use std::prelude::v1::*;
use thiserror::Error;
use serde::{Serialize, Deserialize};

#[derive(Debug, Error)]
pub enum FileError {
    #[error("SysError({0})")]
    SysError(sys_error_t),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    FileNameError(#[from] std::ffi::NulError),
    #[error(transparent)]
    BincodeError(#[from] bincode::Error),
}
impl From<sys_error_t> for FileError {
    fn from(error: sys_error_t) -> Self {
        Self::SysError(error)
    }
}

type FileResult<T> = Result<T, FileError>;

struct MySgxFileStream {
    file: SgxFileStream,
}
impl MySgxFileStream {
    fn open(filename: &str, mode: &str) -> FileResult<Self> {
        let filename = CString::new(filename)?;
        let mode = CString::new(mode)?;

        Ok(MySgxFileStream {
            // FIXME: 鍵をMRSIGNERからderiveしている
            file: SgxFileStream::open_auto_key(&filename, &mode)?,
        })
    }
}
impl Read for MySgxFileStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.file
            .read(buf)
            .map_err(|x| std::io::Error::from_raw_os_error(x))
    }
}
impl Write for MySgxFileStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file
            .write(buf)
            .map_err(|x| std::io::Error::from_raw_os_error(x))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.file
            .flush()
            .map_err(|x| std::io::Error::from_raw_os_error(x))
    }
}
impl From<SgxFileStream> for MySgxFileStream {
    fn from(file: SgxFileStream) -> Self {
        MySgxFileStream { file: file }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ISDEDFileData {
    pub data: Vec<u8>, // TODO: ファイルへの参照にする
    pub output_policy: String,
    pub mc_handle: jwtmc::Key,
    pub mc_value: jwtmc::Ctr,
    pub environment: output_policy::Environment,
}
impl ISDEDFileData {
    pub fn read_from(filename: &str) -> FileResult<Self> {
        let dataname = format!("{}.isded_data", &filename);
        let mut datafile = MySgxFileStream::open(&dataname, "r")?;
        let mut data = Vec::new();
        datafile.read_to_end(&mut data)?;

        let policyname = format!("{}.isded_policy", &filename);
        let mut policyfile = MySgxFileStream::open(&policyname, "r")?;
        let mut policy = String::new();
        policyfile.read_to_string(&mut policy)?;

        let mcname = format!("{}.isded_mc", &filename);
        let mut mcfile = MySgxFileStream::open(&mcname, "r")?;
        let mut mc_handle = [0u8; std::mem::size_of::<jwtmc::Key>()];
        let mut mc_value = [0u8; std::mem::size_of::<jwtmc::Ctr>()];
        mcfile.read_exact(&mut mc_handle)?;
        let mc_handle = jwtmc::Key::from_le_bytes(mc_handle);
        mcfile.read_exact(&mut mc_value)?;
        let mc_value = jwtmc::Key::from_le_bytes(mc_value);

        let envname = format!("{}.isded_env", &filename);
        let mut envfile = MySgxFileStream::open(&envname, "r")?;
        let env = bincode::deserialize_from(&mut envfile)?;

        Ok(ISDEDFileData {
            data: data,
            output_policy: policy,
            mc_handle: mc_handle,
            mc_value: mc_value,
            environment: env,
        })
    }

    pub fn write_to(&self, filename: &str) -> FileResult<()> {
        let dataname = format!("{}.isded_data", &filename);
        let mut datafile = MySgxFileStream::open(&dataname, "w")?;
        datafile.write_all(&self.data)?;

        let policyname = format!("{}.isded_policy", &filename);
        let mut policyfile = MySgxFileStream::open(&policyname, "w")?;
        policyfile.write_all(&self.output_policy.as_bytes())?;

        let mcname = format!("{}.isded_mc", &filename);
        let mut mcfile = MySgxFileStream::open(&mcname, "w")?;
        mcfile.write_all(&self.mc_handle.to_le_bytes())?;
        mcfile.write_all(&self.mc_value.to_le_bytes())?;

        let envname = format!("{}.isded_env", &filename);
        let envfile = MySgxFileStream::open(&envname, "w")?;
        bincode::serialize_into(envfile, &self.environment)?;

        Ok(())
    }
}
