// Copyright (C) 2019-2020 Fuga Kato

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]

use std::io::{self, Write};
use clap::*;
use failure::Error;
use std::result::Result;
use chrono::prelude::*;
use once_cell::sync::Lazy;

#[macro_use]
extern crate log;

mod ecalls;
mod ias;
mod enclave;
mod msg_stream;
mod crypto;
mod subcommands;
use subcommands::*;

static APP_YAML: Lazy<yaml_rust::Yaml> = Lazy::new(|| load_yaml!("cli.yaml").clone());

#[tokio::main]
async fn main() -> Result<(), Error> {
    env_logger::builder()
        .format(|buf, record| {
            writeln!(buf, "[{} {} {}] {}",
                Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
                record.level(),
                crate_name!(),
                record.args())
        })
        .init();

    let matches = get_clap_app().get_matches();

    let subcommand_result = match matches.subcommand() {
        ("send", Some(sub_m)) => subcommand_send(&sub_m).await,
        ("recv", Some(sub_m)) => subcommand_recv(&sub_m).await,
        ("open", Some(sub_m)) => subcommand_open(&sub_m),
        ("serve", Some(sub_m)) => subcommand_serve(&sub_m).await,
        ("eval", Some(sub_m)) => subcommand_eval(&sub_m),
        ("test", Some(sub_m)) => subcommand_test(&sub_m),
        _ => if matches.is_present("version") {
            get_clap_app().write_long_version(&mut io::stdout())?;
            println!();
            Ok(())
        } else {
            eprintln_help();
            Ok(())
        }
    };

    // TODO: 細分化
    match subcommand_result {
        Err(e) => {
            eprintln_help();
            Err(e)
        },
        Ok(_) => Ok(())
    }
}

fn get_clap_app() -> App<'static, 'static> {
    App::from_yaml(&*APP_YAML)
        .name(crate_name!())
        .author(crate_authors!())
        .about(crate_description!())
        .version(crate_version!())
}

fn eprintln_help() {
    get_clap_app().write_long_help(&mut io::stderr()).unwrap();
    writeln!(&mut io::stderr()).unwrap();
}

