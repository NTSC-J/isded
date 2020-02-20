// Copyright (C) 2019 Fuga Kato

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
include!(concat!(env!("OUT_DIR"), "/Enclave_u.rs"));

use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::io::{Read, Write};
use std::fs;
use std::fs::OpenOptions;
use std::ffi::CString;
use std::path;
use memmap::{MmapOptions, MmapMut};
use std::convert::TryInto;
use clap::*;
use failure::Error;
use std::result::Result;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";
static ENCLAVE_TOKEN: &'static str = "enclave.token";

fn main() -> Result<(), Error> {
    let app = app_from_crate!()
        .subcommand(SubCommand::with_name("open")
                    .about("open a self-destructing file")
                    .arg(Arg::with_name("input")
                         .help("the name of the input file")
                         .index(1)
                         .required(true)))
        .subcommand(SubCommand::with_name("create")
                    .about("create a self-destructing file locally")
                    .arg(Arg::with_name("input")
                         .help("the name of the input file")
                         .short("i")
                         .long("input")
                         .takes_value(true)
                         .required(true))
                    .arg(Arg::with_name("output")
                         .help("the name of the output file (default: <input file name>.sd)")
                         .short("o")
                         .long("output")
                         .takes_value(true)
                         .required(false))
                    .arg(Arg::with_name("policy")
                         .help("the policy")
                         .short("p")
                         .long("policy")
                         .takes_value(true)
                         .required(true)))
        .arg(Arg::with_name("version")
             .help("display app version")
             .long("version"));
    let matches = app.get_matches();

    if let Some(matches) = matches.subcommand_matches("open") {
        return subcommand_open(matches);
    }

    if let Some(matches) = matches.subcommand_matches("create") {
        return subcommand_create(matches);
    }

    if let Some(_) = matches.value_of("version") {
        println!("{} version {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    }

    Ok(())
}

fn subcommand_open(matches: &ArgMatches) -> Result<(), Error> {
    let filename = matches.value_of("input").unwrap();
    let enclave = init_enclave().expect("init_enclave failed!");
    let file = OpenOptions::new().read(true).write(true).append(false).open(filename)?;

    unsafe {
        let mut r = 0;
        let mmap = MmapOptions::new().map(&file)?;
        load_file(enclave.geteid(), &mut r, mmap.as_ptr(), file.metadata()?.len().try_into().unwrap());
    }

    enclave.destroy();

    Ok(())
}

fn subcommand_create(matches: &ArgMatches) -> Result<(), Error> {
    let enclave = init_enclave().expect("init_enclave failed!");
    let input_name = matches.value_of("input").unwrap();
    let default_output = format!("{}.sd", input_name);
    let output_name = matches.value_of("output").unwrap_or(default_output.as_str());
    let policy = matches.value_of("policy").unwrap();

    let input_file = OpenOptions::new().read(true).open(input_name)?;

    unsafe {
        let policy = CString::new(policy)?;
        let input_map = MmapOptions::new().map(&input_file)?.as_ptr();
        let input_size = input_file.metadata()?.len();
        let mut output_size = 0;
        create_file(enclave.geteid(), &mut output_size, policy.as_ptr(), input_map, input_size);

        let output_file = OpenOptions::new().read(true).write(true).create(true).open(output_name)?;
        output_file.set_len(output_size)?;
        let output_map = MmapMut::map_mut(&output_file)?.as_mut_ptr();
        let mut r = 0;
        save_file(enclave.geteid(), &mut r, output_map);
    }
    Ok(())
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // Step 1: try to retrieve the launch token saved by last transaction
    //         if there is no token, then create a new one.
    //
    // try to get the token saved in $HOME */
    let mut home_dir = path::PathBuf::new();
    let use_token = match dirs::home_dir() {
        Some(path) => {
            println!("[+] Home dir is {}", path.display());
            home_dir = path;
            true
        },
        None => {
            println!("[-] Cannot get home dir");
            false
        }
    };

    let token_file: path::PathBuf = home_dir.join(ENCLAVE_TOKEN);
    if use_token == true {
        match fs::File::open(&token_file) {
            Err(_) => {
                println!("[-] Open token file {} error! Will create one.", token_file.as_path().to_str().unwrap());
            },
            Ok(mut f) => {
                println!("[+] Open token file success! ");
                match f.read(&mut launch_token) {
                    Ok(1024) => {
                        println!("[+] Token file valid!");
                    },
                    _ => println!("[+] Token file invalid, will create new token file"),
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
    if use_token == true && launch_token_updated != 0 {
        // reopen the file with write capablity
        match fs::File::create(&token_file) {
            Ok(mut f) => {
                match f.write_all(&launch_token) {
                    Ok(()) => println!("[+] Saved updated launch token!"),
                    Err(_) => println!("[-] Failed to save updated launch token!"),
                }
            },
            Err(_) => {
                println!("[-] Failed to save updated enclave token, but doesn't matter");
            },
        }
    }

    Ok(enclave)
}

