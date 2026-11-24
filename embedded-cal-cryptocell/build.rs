// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

use std::{env, fs, path::PathBuf};

/// Memory layout of each supported chip, selected by the chip feature.
const CHIPS: &[(&str, &str)] = &[("CARGO_FEATURE_NRF5340", "memory-nrf5340.x")];

fn main() {
    let out = PathBuf::from(env::var("OUT_DIR").unwrap());

    for (feature, memory) in CHIPS {
        println!("cargo:rerun-if-changed={memory}");
        if env::var_os(feature).is_some() {
            // Provide the chip's layout as memory.x, as cortex-m-rt's link.x expects.
            fs::copy(memory, out.join("memory.x")).expect("could not copy memory layout");
        }
    }

    println!("cargo:rustc-link-search={}", out.display());
}
