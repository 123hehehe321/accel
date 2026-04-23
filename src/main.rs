mod cli;
mod config;
mod mode;
mod ports;
mod socket;
mod status;

use std::process::ExitCode;

// include_bytes! returns byte-aligned data, but the `object` crate used by
// aya to parse ELF requires 8-byte alignment for section headers. Wrap the
// bytes in a repr-aligned struct so the embedded blob is safely parseable.
#[repr(C, align(8))]
pub(crate) struct Aligned<T: ?Sized>(pub T);
pub(crate) static CLASSIFIER_OBJ: &Aligned<[u8]> =
    &Aligned(*include_bytes!(concat!(env!("OUT_DIR"), "/classifier.o")));

fn main() -> ExitCode {
    cli::dispatch()
}
