//! With the `aws` feature, compile a small C shim so the binary needs only glibc 2.34 (see src/glibc_compat.c).
fn main() {
    println!("cargo:rerun-if-changed=src/glibc_compat.c");
    if std::env::var_os("CARGO_FEATURE_AWS").is_some() && cfg!(target_os = "linux") {
        let objs = cc::Build::new()
            .file("src/glibc_compat.c")
            .flag("-std=gnu17")
            .flag("-U_GNU_SOURCE")
            .opt_level(2)
            .try_compile_intermediates()
            .unwrap_or_default();
        for o in objs {
            println!("cargo:rustc-link-arg-bins={}", o.display());
        }
    }
}
