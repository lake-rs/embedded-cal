use std::{env, fs, path::PathBuf};

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());

    // copy memory.x into OUT_DIR, so we can have a different memory.x for each chip
    fs::copy("memory.x", out.join("memory.x")).expect("could not copy memory.x");

    println!("cargo:rustc-link-search={}", out.display());
    println!("cargo:rerun-if-changed=memory.x");
}
