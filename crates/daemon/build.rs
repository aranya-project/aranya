fn main() {
    println!("cargo:rerun-if-changed=src/policy.md");
    policy_ifgen_build::generate("src/policy.md", "src/policy.rs")
        .expect("expected policy-ifgen to generate policy.rs");
}
