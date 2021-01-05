use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::path::PathBuf;
use std::fs::File;
use std::io::{Read, Write};

const ENCLAVE_FILE: &'static str = "enclave.signed.so";
const ENCLAVE_TOKEN: &'static str = "enclave.token";

pub fn init_enclave() -> SgxResult<SgxEnclave> {
    info!("init_enclave()");
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // Step 1: try to retrieve the launch token saved by last transaction
    //         if there is no token, then create a new one.
    //
    // try to get the token saved in $HOME */
    let mut home_dir = PathBuf::new();
    let use_token = match dirs::home_dir() {
        Some(path) => {
            home_dir = path;
            true
        },
        None => {
            info!("Cannot get home dir");
            false
        }
    };

    let token_file: PathBuf = home_dir.join(ENCLAVE_TOKEN);
    if use_token {
        match File::open(&token_file) {
            Err(_) => {
                info!("Open token file {} error! Will create one.", token_file.as_path().to_str().unwrap());
            },
            Ok(mut f) => {
                match f.read(&mut launch_token) {
                    Ok(1024) => {},
                    _ => info!("Token file invalid, will create new token file"),
                }
            }
        }
    }

    // Step 2: call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    let enclave = SgxEnclave::create(ENCLAVE_FILE,
                                     debug,
                                     &mut launch_token,
                                     &mut launch_token_updated,
                                     &mut misc_attr)?;

    // Step 3: save the launch token if it is updated
    if use_token && launch_token_updated != 0 {
        // reopen the file with write capablity
        match File::create(&token_file) {
            Ok(mut f) => {
                if f.write_all(&launch_token).is_err() {
                    info!("Failed to save updated launch token!");
                }
            },
            Err(_) => {
                info!("Failed to save updated enclave token, but doesn't matter");
            },
        }
    }

    Ok(enclave)
}
