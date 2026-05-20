pub mod hash;

/// Sum of all traits that a hardware accelerator can provide.
///
/// To avoid that users need to do type-level configuration depending on what the back-end
/// provides, all these traits have a `const SUPPORTED: bool`: If this is false (which will be
/// default once the `associated_type_defaults` feature lands), all other values are ignored, and
/// all functions can use the provided panicking implementations.
pub trait Plumbing: hash::Hash {}
