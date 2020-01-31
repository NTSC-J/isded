extern crate chrono;
extern crate serde;
extern crate serde_json;
use chrono::prelude::*;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct OutputTime {
    #[serde(with = "option_ts_milliseconds")]
    pub after: Option<DateTime<Utc>>,
    #[serde(with = "option_ts_milliseconds")]
    pub before: Option<DateTime<Utc>>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct OutputCondition {
    pub time: Option<OutputTime>,
    pub access_count: Option<u64>
}
#[derive(Serialize, Deserialize, Debug)]
pub struct SecretMetadata<'a> {
    pub output_condition: OutputCondition,
    pub access_count: u64,
    pub name: &'a str
}
#[derive(Serialize, Deserialize, Debug)]
pub struct SecretData<'a> {
    #[serde(borrow)]
    pub metadata: SecretMetadata<'a>,
    pub data: &'a [u8]
}

mod option_ts_milliseconds {
    use serde_derive::*;
    use chrono::prelude::*;
    use serde::ser::{Serialize, Serializer};
    use serde::de::{Deserialize, Deserializer};

    pub fn serialize<S>(value: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct Helper<'a>(#[serde(with = "::chrono::serde::ts_milliseconds")] &'a DateTime<Utc>);
        value.as_ref().map(Helper).serialize(serializer)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper(#[serde(with = "::chrono::serde::ts_milliseconds")] DateTime<Utc>);
        let helper = Option::deserialize(deserializer)?;
        Ok(helper.map(|Helper(o)| o))
    }
}

