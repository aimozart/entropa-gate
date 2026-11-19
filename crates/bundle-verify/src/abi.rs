//! The plain C interface for WebAssembly (no wasm-bindgen, no JavaScript glue). The page calls, in this order: `input_reserve(n)` (returns the address of an n-byte buffer the module owns), writes the bundle there,
//! `verify()` (returns the closed code), then reads `output_len()` bytes at `output_ptr()` (a small JSON text). Addresses are only valid until the next call of `input_reserve`.
//! The only unsafe-flagged items are the export attributes; there is no unsafe block.
#![allow(unsafe_code)]
use std::cell::RefCell;

thread_local! {
    static INPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
    static OUTPUT: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

/// Make the input buffer exactly `n` bytes (zeroed) and return its address.
#[no_mangle]
pub extern "C" fn input_reserve(n: usize) -> usize {
    INPUT.with(|b| {
        let mut b = b.borrow_mut();
        b.clear();
        b.resize(n, 0);
        b.as_ptr() as usize
    })
}

/// Verify the bytes in the input buffer; returns the closed code (0 ok, 1 invalid, 2 verify, 3 limit, 4 other) and stores the JSON verdict for `output_ptr`/`output_len`.
#[no_mangle]
pub extern "C" fn verify() -> i32 {
    let (code, json) = INPUT.with(|b| crate::verify_bytes(&b.borrow()));
    OUTPUT.with(|o| *o.borrow_mut() = json.into_bytes());
    code
}

/// Address of the verdict text.
#[no_mangle]
pub extern "C" fn output_ptr() -> usize {
    OUTPUT.with(|o| o.borrow().as_ptr() as usize)
}

/// Length of the verdict text in bytes.
#[no_mangle]
pub extern "C" fn output_len() -> usize {
    OUTPUT.with(|o| o.borrow().len())
}
