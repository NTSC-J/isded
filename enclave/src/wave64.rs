use std::prelude::v1::*;
use std::io::Read;
use crate::guid::GUID;
use crate::jwtmc;
use crate::output_policy;
use lazy_static::lazy_static;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Wave64Error {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    FromUtf8Error(#[from] std::string::FromUtf8Error),
}
pub type Wave64Result<T> = Result<T, Wave64Error>;

// SDEData: データ本体、必須
// SDEMetadata: 出力条件、モノトニックカウンタのハンドル、モノトニックカウンタの値、必須
// SDEFileName: もとのファイル名、オプション
// SDEMimeType: データのMIMEタイプ、オプション

lazy_static! {
    static ref GUID_RIFF: GUID = GUID::from_str("66666972-912E-11CF-A5D6-28DB04C10000").unwrap();
    static ref GUID_ISDED: GUID = GUID::from_str("26C3E482-E6BF-43C1-9337-5834F5A74762").unwrap();
    static ref GUID_SDE_DATA: GUID = GUID::from_str("49CF7F30-9668-4612-BDDA-F47412596314").unwrap();
    static ref GUID_SDE_METADATA: GUID = GUID::from_str("E447E6E6-DBE4-4BF2-A438-A5D11CA21414").unwrap();
    static ref GUID_SDE_FILE_NAME: GUID = GUID::from_str("E79088B7-7775-45DC-83B2-B9E4AC4D2573").unwrap();
    static ref GUID_SDE_MIME_TYPE: GUID = GUID::from_str("6BA5B737-90A3-4A49-8717-BB59D2393EAA").unwrap();
}

pub enum RIFFChunk {
    RIFF(GUID, Vec<RIFFChunk>), // form type, subchunks
    SDEData(Vec<u8>), // file data
    SDEMetadata(String, jwtmc::Key, jwtmc::Ctr),
    //SDEEnvironment(output_policy::Environment),
    SDEFileName(String),
    SDEMimeType(String),
    Unknown(GUID, Vec<u8>),
}
impl RIFFChunk {
    pub fn from_read<R: Read>(buf: &mut R) -> Wave64Result<Self> {
        let mut guid = [0u8; 16];
        buf.read_exact(&mut guid)?;
        let guid = GUID::from_bytes(guid);

        let mut size = [0u8; 8];
        buf.read_exact(&mut size)?;
        let size = u64::from_le_bytes(size) as usize;

        // matchにしたいが……
        if guid == *GUID_RIFF {
            let mut formtype = [0u8; 16];
            buf.read_exact(&mut formtype)?;
            let formtype = GUID::from_bytes(formtype); // なんでもいい
            let mut buf = buf.take(size as u64 - 16); // RIFFチャンクの残りのサイズ
            let mut subchunks = Vec::new();
            loop {
                match RIFFChunk::from_read(&mut buf) {
                    Ok(chunk) => subchunks.push(chunk),
                    Err(e) => {
                        if let Wave64Error::IOError(ioe) = e {
                            if ioe.kind() == std::io::ErrorKind::UnexpectedEof {
                                break; // read_exact() failed
                            }
                        } else {
                            return Err(e);
                        }
                    }
                }
            }

            Ok(RIFFChunk::RIFF(formtype, subchunks))
        } else if guid == *GUID_SDE_DATA {
            let mut data = vec![0u8; size];
            buf.read_exact(&mut data)?;

            Ok(RIFFChunk::SDEData(data))
        } else if guid == *GUID_SDE_METADATA {
            let mut buf = buf.take(size as u64);

            // 出力条件
            let mut len = [0u8; 8];
            buf.read_exact(&mut len)?;
            let len = u64::from_le_bytes(len) as usize;
            let mut policy = vec![0u8; len];
            buf.read_exact(&mut policy)?;
            let policy = String::from_utf8(policy)?;

            // モノトニックカウンタのキー
            let mut key = [0u8; 8];
            buf.read_exact(&mut key)?;
            let key = jwtmc::Key::from_le_bytes(key);

            // モノトニックカウンタの値
            let mut ctr = [0u8; 8];
            buf.read_exact(&mut ctr)?;
            let ctr = jwtmc::Ctr::from_le_bytes(ctr);

            Ok(RIFFChunk::SDEMetadata(policy, key, ctr))
        } else { // unknown GUID
            let mut data = vec![0u8; size];
            buf.read_exact(&mut data)?;

            Ok(RIFFChunk::Unknown(guid, data))
        }
    }
}