// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: Inria-AIO, Cryspen, and Christian Amsüss
//! Managing CRACEN microcode.
//!
//! The microcode, which is a program proprietory to the CRACEN engine and propritory in license,
//! needs to be loaded before any PKE operation can be performed.

mod data;

pub(crate) const BASE: u32 = 0x5180_C000;

pub(super) unsafe fn load() {
    let mut p = BASE as *mut u32;
    for word in &data::DATA {
        unsafe { core::ptr::write_volatile(p, *word) };
        p = unsafe { p.add(1) };
    }
}
