#![no_main]
mod common;
use entropa_standards::records::NullSink;
use entropa_standards::tools::{Server, TOOL_NAMES};
use libfuzzer_sys::fuzz_target;
use std::cell::RefCell;

thread_local! { static S: RefCell<Option<Server>> = const { RefCell::new(None) }; }

// Arbitrary bytes parsed as JSON arguments (or as a tool name plus arguments) go to every tool: the server never panics and the body is an
// object or null.
fuzz_target!(|data: &[u8]| {
    let Ok(args) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    S.with(|c| {
        let mut slot = c.borrow_mut();
        let srv = slot.get_or_insert_with(|| {
            Server::new(
                entropa_standards::retrieve::Retriever::from_clauses("fz", &"0".repeat(64), common::clauses()),
                Box::new(NullSink),
                "fz",
            )
        });
        for t in TOOL_NAMES {
            let out = srv.call(t, &args);
            assert!(out.body.is_object() || out.body.is_null());
        }
        let name = String::from_utf8_lossy(data).into_owned();
        let _ = srv.call(&name, &args);
    });
});
