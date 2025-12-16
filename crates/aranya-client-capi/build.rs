use std::{
    env, fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context};
use aranya_capi_codegen::Config;
use quote::format_ident;
use syn::parse_quote;

fn main() -> anyhow::Result<()> {
    println!("cargo::rustc-check-cfg=cfg(cbindgen)");

    let in_path = Path::new("src/api/defs.rs");
    println!("cargo::rerun-if-changed={}", in_path.display());

    let out_path = PathBuf::from(env::var("OUT_DIR")?).join("generated.rs");
    let source = fs::read_to_string(in_path)
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
    fs::write(&out_path, &data)?;

    cbindgen::Builder::new()
        .with_config(cbindgen::Config::from_file("cbindgen.toml").map_err(|e| anyhow!("{e}"))?)
        .with_src(out_path)
        .generate()?
        .write_to_file("output/aranya-client.h");

    Ok(())
}
