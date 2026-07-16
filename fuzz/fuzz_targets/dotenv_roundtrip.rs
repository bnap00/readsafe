#![no_main]
//! The dotenv parser's central invariant: parsing then rendering reproduces
//! the input byte-for-byte. A counterexample means the model dropped, added,
//! or mutated bytes — the class of bug that could silently corrupt a secret
//! file on write. Runs over arbitrary UTF-8 input.

use libfuzzer_sys::fuzz_target;
use readsafe_core::dotenv::Document;

fuzz_target!(|input: String| {
    let doc = Document::parse(&input);
    let rendered = doc.render();
    assert_eq!(
        rendered, input,
        "dotenv round-trip changed the byte stream"
    );
});
