use thiserror::Error;
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

#[derive(Debug, Error)]
pub enum IASError {
    #[error("HTTP error {0}")]
    HTTPError(StatusCode),
    #[error("EPID signature of the ISV enclave QUOTE was invalid.")]
    EPIDSignatureInvalidError,
    #[error("EPID group has been revoked (reason: {0}).")]
    EPIDGroupRevokedError(i64),
    #[error("The EPID private key used to sign the QUOTE has been revoked by signature.")]
    EPIDSignatureRevokedError,
    #[error("The EPID private key used to sign the QUOTE has been directry revoked.")]
    EPIDKeyRevokedError,
    #[error("QUOTE's SigRL version is old.")]
    SigRLVersionMismatchError,
    #[error("{0}: unknown QUOTE status.")]
    UnknownError(String),
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),
}
pub type IASResult<T> = std::result::Result<T, IASError>;

/// let IAS verify QUOTE
pub async fn verify_quote(quote: &[u8]) -> IASResult<()> {
    use IASError::*;

    let mut req = HashMap::new();
    req.insert("isvEnclaveQuote", base64::encode(&quote[..]));
    let client = reqwest::Client::new();
    let ias_uri = format!("https://{}{}", IAS_HOST, REPORT_SUFFIX);
    let res = client.post(&ias_uri)
            .header("Ocp-Apim-Subscription-Key", include_str!("api_key.txt"))
            .json(&req)
            .send()
            .await?;

    if res.status() != StatusCode::OK {
        return Err(HTTPError(res.status()));
    }

    let _sig = res.headers().get("X-IASReport-Signature").unwrap();
    let _cert = res.headers().get("X-IASReport-Signing-Certificate").unwrap();

    let resbody = res.json::<IASResponse>().await?;
    match resbody.isvEnclaveQuoteStatus.as_str() {
        "OK" => Ok(()),
        "SIGNATURE_INVALID" => Err(EPIDSignatureInvalidError),
        "GROUP_REVOKED" => Err(EPIDGroupRevokedError(resbody.revocationReason.unwrap())),
        "SIGNATURE_REVOKED" => Err(EPIDSignatureRevokedError),
        "KEY_REVOKED" => Err(EPIDKeyRevokedError),
        "SIGRL_VERSION_MISMATCH" => Err(SigRLVersionMismatchError),
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
            Ok(()) // NOTE: maybe should return error
        },
        _ => Err(UnknownError(resbody.isvEnclaveQuoteStatus))
    }
}

/// Get SigRL from IAS
pub async fn get_sigrl(epid_group_id: &sgx_epid_group_id_t) -> IASResult<Vec<u8>> {
    let mut epid_group_id = *epid_group_id;
    epid_group_id.reverse();
    let ias_uri = format!("https://{}{}{}", IAS_HOST, SIGRL_SUFFIX, hex::encode(&epid_group_id));
    let client = reqwest::Client::new();
    let res = client.get(&ias_uri)
        .header("Ocp-Apim-Subscription-Key", include_str!("api_key.txt"))
        .send()
        .await?;
    if res.status() != StatusCode::OK {
        return Err(IASError::HTTPError(res.status()));
    }
    Ok(base64::decode(res.text().await?).expect("decode failed"))
}
