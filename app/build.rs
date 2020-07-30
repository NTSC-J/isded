use std::env;
use std::path::PathBuf;

fn main () {
    let sdk_dir = env::var("SGX_SDK")
                    .unwrap_or_else(|_| "/opt/intel/sgxsdk".to_string());
    let is_sim = env::var("SGX_MODE")
                    .unwrap_or_else(|_| "HW".to_string());

    println!("cargo:rustc-link-search=native=obj/");
    println!("cargo:rustc-link-lib=static=Enclave_u");

    println!("cargo:rustc-link-search=native={}/lib64", sdk_dir);
    println!("cargo:rustc-link-lib=sgx_uprotected_fs");

    match is_sim.as_ref() {
        "SW" => {
            println!("cargo:rustc-link-lib=dylib=sgx_urts_sim");
            println!("cargo:rustc-link-lib=dylib=sgx_uae_service_sim");
        },
        _    => { // Treat undefined as HW
            println!("cargo:rustc-link-lib=dylib=sgx_urts");
            println!("cargo:rustc-link-lib=dylib=sgx_uae_service");
        },
    }

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    println!("cargo:rerun-if-changed=obj/Enclave_u.h");
    bindgen::Builder::default()
        .header("obj/Enclave_u.h")
        .clang_arg(format!("-I{}/include", sdk_dir))
        .clang_arg("-I../../../edl")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(out_path.join("Enclave_u.rs")).expect("Couldn't write bindings!");
}
