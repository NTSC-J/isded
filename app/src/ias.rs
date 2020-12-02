use failure::{bail, Error};
use serde::Deserialize;
use reqwest::StatusCode;
use std::collections::HashMap;
use sgx_types::*;

const IAS_HOST: &str = "api.trustedservices.intel.com";
const REPORT_SUFFIX: &str = "/sgx/dev/attestation/v4/report";
const SIGRL_SUFFIX: &str = "/sgx/dev/attestation/v4/sigrl/";

#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct IASResponse {
    id: String,
    timestamp: String,
    version: i64,
    isvEnclaveQuoteStatus: String,
    isvEnclaveQuoteBody: String,
    revocationReason: Option<i64>,
    pseManifestStatus: Option<String>,
    pseManifestHash: Option<String>,
    platformInfoBlob: Option<String>,
    nonce: Option<String>,
    epidPseudonym: Option<String>,
    advisoryURL: Option<String>,
    advisoryIDs: Option<Vec<String>>,
}

/// let IAS verify QUOTE
pub fn verify_quote(quote: &Vec<u8>) -> Result<(), Error> {
    let mut req = HashMap::new();
    req.insert("isvEnclaveQuote", base64::encode(&quote[..]));
    let client = reqwest::blocking::Client::new();
    let ias_uri = format!("https://{}{}", IAS_HOST, REPORT_SUFFIX);
    let res = client.post(&ias_uri)
            .header("Ocp-Apim-Subscription-Key", include_str!("api_key.txt"))
            .json(&req)
            .send()?;

    if res.status() != StatusCode::OK {
        bail!("IAS returned error: {:?}", &res);
    }

    let _sig = res.headers().get("X-IASReport-Signature").unwrap();
    let _cert = res.headers().get("X-IASReport-Signing-Certificate").unwrap();

    let resbody = res.json::<IASResponse>()?;
    match resbody.isvEnclaveQuoteStatus.as_str() {
        "OK" => return Ok(()),
        "SIGNATURE_INVALID" => bail!("EPID signature of the ISV enclave QUOTE was invalid."),
        "GROUP_REVOKED" => bail!("EPID group has been revoked (reason: {}).", &resbody.revocationReason.unwrap()),
        "SIGNATURE_REVOKED" => bail!("The EPID private key used to sign the QUOTE has been revoked by signature."),
        "KEY_REVOKED" => bail!("The EPID private key used to sign the QUOTE has been directry revoked."),
        "SIGRL_VERSION_MISMATCH" => bail!("QUOTE's SigRL version is old."),
        "GROUP_OUT_OF_DATE" | "CONFIGURATION_NEEDED" | "SW_HARDENING_NEEDED" | "CONFIGURATION_AND_SW_HARDENING_NEEDED" => {
            warn!("{}",
                match resbody.isvEnclaveQuoteStatus.as_str() {
                    "GROUP_OUT_OF_DATE" => "The TCB level of SGX platform is outdated.",
                    "CONFIGURATION_NEEDED" => "Additional configuration of SGX platform may be needed.",
                    "SW_HARDENING_NEEDED" => "Additional SW hardening in the enclave may be needed.",
                    "CONFIGURATION_AND_SW_HARDENING_NEEDED" => "Additional configuration of SGX platform and SW hardening in the enclave may be needed.",
                    _ => unreachable!()
                });
            if let Some(url) = &resbody.advisoryURL {
                warn!("See advisory: {}", &url);
            }
            if let Some(ids) = &resbody.advisoryIDs {
                warn!("Advisory IDs: {}", &ids.join(", "));
            }
            return Ok(()); // NOTE: maybe should return error
        },
        _ => bail!("{}: unknown QUOTE status", &resbody.isvEnclaveQuoteStatus)
    };
}

/// Get SigRL from IAS
pub fn get_sigrl(epid_group_id: &sgx_epid_group_id_t) -> Result<Vec<u8>, Error> {
    let mut epid_group_id = epid_group_id.clone();
    epid_group_id.reverse();
    let ias_uri = format!("https://{}{}{}", IAS_HOST, SIGRL_SUFFIX, hex::encode(&epid_group_id));
    let client = reqwest::blocking::Client::new();
    let res = client.get(&ias_uri)
        .header("Ocp-Apim-Subscription-Key", include_str!("api_key.txt"))
        .send()?;
    if res.status() != StatusCode::OK {
        bail!("IAS returned error: {:?}", &res);
    }
    Ok(base64::decode(res.text()?).expect("decode failed"))
}


