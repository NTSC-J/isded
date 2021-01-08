use std::fs;
use std::io::{self, Write, Result};

const SRC: &str = "../enclave/src/ecall_impl.rs";
const DST: &str = "obj/ecall_impl_.rs";

fn main() -> Result<()>  {
    fs::create_dir_all("obj")?;
    let mut src = fs::File::open(&SRC)?;
    let mut dst = fs::File::create(&DST)?;
    dst.write_all(b"{{")?;
    io::copy(&mut src, &mut dst)?;
    dst.write_all(b"}}")?;
    Ok(())
}
