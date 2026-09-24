// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss

fn main() {
    colog::init();

    let mut cal = cfg_select! {
        all(feature = "backend-libcrux", feature = "backend-rustcrypto") => {{
            // When all backends are selected, we have to build the stack manually -- as we do with
            // custom hardware configurations.

            struct LibcruxConfig;
            impl embedded_cal_libcrux::ExtenderConfig for LibcruxConfig {
                type Base = embedded_cal_rustcrypto::Standalone;
            }

            embedded_cal_libcrux::Extender::<LibcruxConfig>::new(
                // Using the immediate constructor here, but really this too is a composition:
                // It takes the empty Cal (a ZST that supports no algorithms at all), layers the
                // system RNG on top of it, and then wraps it in an embedded_cal_rustcrypto
                // extender.
                embedded_cal_rustcrypto::Standalone::standalone()
            )
        }}
        // For the simple cases, immediate constructors are provided.
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
