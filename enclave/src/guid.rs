use std::prelude::v1::*;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GUIDError {
    #[error("Parse failed")]
    ParseError,
}
pub type GUIDResult<T> = Result<T, GUIDError>;

#[derive(Debug, PartialEq)]
pub struct GUID {
    data: [u8; 16],
}
impl GUID {
    pub fn from_str(s: &str) -> GUIDResult<Self> {
        let s = s.replace(&['{', '}'][..], "");
        let ss: Vec<&str> = s.split('-').collect();
        if ss.iter().map(|s| s.len()).collect::<Vec<usize>>() != [8, 4, 4, 4, 12] {
            return Err(GUIDError::ParseError);
        }
        let mut data = Vec::new();
        // Data1~3はリトルエンディアン
        for s in ss.iter().take(3) {
            let mut d = hex::decode(s).map_err(|_| GUIDError::ParseError)?;
            d.reverse();
            data.append(&mut d);
        }
        // Data4はビッグエンディアン
        for s in ss.iter().skip(3) {
            data.append(&mut hex::decode(s).map_err(|_| GUIDError::ParseError)?);
        }
        let mut d = [0u8; 16];
        d.copy_from_slice(&data);

        Ok(GUID { data: d })
    }
    // constな代わりにpanicする
    /*
    pub const fn from_str_const(s: &str) -> Self {
        let s = s.replace(&['{', '}'][..], "");
        let ss: Vec<&str> = s.split('-').collect();
        if ss.iter().map(|s| s.len()).collect::<Vec<usize>>() != [8, 4, 4, 4, 12] {
            panic!("invalid");
        }
        let mut data = Vec::new();

        // Data1~3はリトルエンディアン
        ss.iter().take(3).map(|s| {
            let mut d = hex::decode(&s).unwrap();
            d.reverse();
            data.append(&mut d);
        });

        // Data4はビッグエンディアン
        ss.iter().skip(3).map(|s| {
            let mut d = hex::decode(&s).unwrap();
            data.append(&mut d);
        });

        let mut d = [0u8; 16];
        d.copy_from_slice(&data);

        GUID {
            data: d
        }
    }*/
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        GUID { data: bytes }
    }
    pub fn as_bytes(self) -> [u8; 16] {
        self.data
    }
}
/*
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn it_works() {
        assert_eq!(
            GUID::from_str("{66666972-912E-11CF-A5D6-28DB04C10000}")
                .unwrap()
                .as_bytes(),
            [
                0x72, 0x69, 0x66, 0x66, 0x2e, 0x91, 0xcf, 0x11, 0xa5, 0xd6, 0x28, 0xdb, 0x04, 0xc1,
                0x00, 0x00
            ]
        );
    }
}
*/
