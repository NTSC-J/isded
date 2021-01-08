use crate::{jwtmc, output_policy};
use sgx_tprotected_fs::SgxFileStream;
use sgx_types::*;
use std::ffi::CString;
use std::io::prelude::*;
use std::prelude::v1::*;
use thiserror::Error;
use std::io::SeekFrom;
use std::fmt::Debug;
use std::convert::TryInto;

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

struct MySgxFileStream(SgxFileStream);
impl MySgxFileStream {
    fn open(filename: &str, mode: &str) -> FileResult<Self> {
        let filename = CString::new(filename)?;
        let mode = CString::new(mode)?;
        // FIXME: 鍵をMRSIGNERからderiveしている
        let file = SgxFileStream::open_auto_key(&filename, &mode)?;

        Ok(Self(file))
    }
}
impl Debug for MySgxFileStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MySgxFileStream")
            .finish() // TODO
    }
}
impl Read for MySgxFileStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0
            .read(buf)
            .map_err(std::io::Error::from_raw_os_error)
    }
}
impl Write for MySgxFileStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .write(buf)
            .map_err(std::io::Error::from_raw_os_error)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0
            .flush()
            .map_err(std::io::Error::from_raw_os_error)
    }
}
impl Seek for MySgxFileStream {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        use sgx_tprotected_fs::SeekFrom as SgxSeekFrom;
        match pos {
            SeekFrom::Start(x) => self.0.seek(x.try_into().unwrap(), SgxSeekFrom::Start),
            SeekFrom::End(x) => self.0.seek(x, SgxSeekFrom::End),
            SeekFrom::Current(x) => self.0.seek(x, SgxSeekFrom::Current),
        }
        .and_then(|_| self.0.tell())
        .map_err(std::io::Error::from_raw_os_error)
        .map(|x| x.try_into().unwrap()) // i64 into u64
    }
}
impl From<SgxFileStream> for MySgxFileStream {
    fn from(file: SgxFileStream) -> Self {
        MySgxFileStream(file)
    }
}
unsafe impl Send for MySgxFileStream {} // TODO: ok?

pub trait ReadSeek: Send + Read + Seek + Debug {}
impl ReadSeek for MySgxFileStream {}

pub trait WriteSeek: Send + Write + Seek + Debug {}
impl WriteSeek for MySgxFileStream {}

#[derive(Debug)]
pub enum ISDEDFileStream {
    Reader(Box<dyn ReadSeek>),
    Writer(Box<dyn WriteSeek>),
}
#[derive(Debug)]
pub struct ISDEDFile {
    // データ本体へのアクセス方法
    pub stream: ISDEDFileStream,
    pub output_policy: String,
    pub mc_handle: jwtmc::Key,
    pub mc_value: jwtmc::Ctr,
    pub environment: output_policy::Environment,
}
impl ISDEDFile{
    pub fn open_read(filename: &str) -> FileResult<Self> {
        let dataname = format!("{}.isded_data", &filename);
        let reader = MySgxFileStream::open(&dataname, "r")?;

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

        Ok(ISDEDFile {
            stream: ISDEDFileStream::Reader(Box::new(reader)),
            output_policy: policy,
            mc_handle,
            mc_value,
            environment: env,
        })
    }

    /// これでファイルをつくったあと、writerを使ってデータ本体を書き込む
    pub fn open_create(filename: &str, output_policy: &str, mc_handle: jwtmc::Key, mc_value: jwtmc::Ctr, environment: output_policy::Environment) -> FileResult<Self> {
        let dataname = format!("{}.isded_data", &filename);
        let datafile = MySgxFileStream::open(&dataname, "w")?;

        let policyname = format!("{}.isded_policy", &filename);
        let mut policyfile = MySgxFileStream::open(&policyname, "w")?;
        policyfile.write_all(output_policy.as_bytes())?;

        let mcname = format!("{}.isded_mc", &filename);
        let mut mcfile = MySgxFileStream::open(&mcname, "w")?;
        mcfile.write_all(&mc_handle.to_le_bytes())?;
        mcfile.write_all(&mc_value.to_le_bytes())?;

        let envname = format!("{}.isded_env", &filename);
        let envfile = MySgxFileStream::open(&envname, "w")?;
        bincode::serialize_into(envfile, &environment)?;

        Ok(ISDEDFile {
            stream: ISDEDFileStream::Writer(Box::new(datafile)),
            output_policy: output_policy.to_owned(),
            mc_handle,
            mc_value,
            environment,
        })
    }

    // TODO: remove this
    pub fn write_metadata(&self, filename: &str) -> FileResult<()> {
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
