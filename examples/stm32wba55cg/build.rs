use std::{env, fs, path::PathBuf};

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());

    fs::copy("memory.x", out.join("memory.x")).expect("could not copy memory.x");
    fs::copy("device.x", out.join("device.x")).expect("could not copy device.x");

    println!("cargo:rustc-link-search={}", out.display());

    println!("cargo:rerun-if-changed=memory.x");
    println!("cargo:rerun-if-changed=device.x");
}
