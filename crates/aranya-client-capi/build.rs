use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::Context;
use aranya_capi_codegen::Config;
use quote::format_ident;
use syn::parse_quote;

fn main() -> anyhow::Result<()> {
    println!("cargo::rustc-check-cfg=cfg(cbindgen)");
    if env::var("_CBINDGEN_IS_RUNNING").is_ok() {
        println!("cargo::rustc-cfg=cbindgen");
    }

    let in_path = Path::new("src/api/defs.rs");
    let source = fs::read_to_string("src/api/defs.rs")
        .with_context(|| format!("unable to read file `{}`", in_path.display()))?;
    let cfg = Config {
        err_ty: parse_quote!(Error),
        ext_err_ty: parse_quote!(ExtError),
        ty_prefix: format_ident!("Aranya"),
        fn_prefix: format_ident!("aranya_"),
        defs: parse_quote!(crate::api::defs),
        target: env::var("TARGET")?,
    };
    let tokens = cfg
        .generate(&source)
        .inspect_err(|err| err.display(in_path, &source))?;
    let data = aranya_capi_codegen::format(&tokens);
    let out_path = PathBuf::from(env::var("OUT_DIR")?).join("generated.rs");
    fs::write(out_path, &data)?;
    Ok(())
}
