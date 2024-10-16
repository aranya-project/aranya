use std::env;

fn main() {
    println!("cargo:rerun-if-changed=src/policy.md");
    // docs.rs build sets the source as readonly.
    if env::var("DOCS_RS").as_deref() != Ok("1") {
        aranya_policy_ifgen_build::generate("src/policy.md", "src/policy.rs")
            .expect("expected policy-ifgen to generate policy.rs");
    }
}
