// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

fn main() {
    colog::init();

    let mut cal = cfg_select! {
        feature = "backend-rustcrypto" => {
            embedded_cal_rustcrypto::Standalone::standalone()
        }
        feature = "backend-libcrux" => {
            embedded_cal_libcrux::Standalone::standalone()
        }
        feature = "backend-empty" => {
            embedded_cal::empty::EmptyCal
        }
        _ => const { panic!("No --features=backend-… option selected") },
    };

    embedded_cal_examples::show_examples(&mut cal);
}
