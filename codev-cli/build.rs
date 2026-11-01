use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let source = manifest.join("assets/fields-1.24.0.2911.json");
    println!("cargo:rerun-if-changed={}", source.display());
    let encoded: Vec<u8> = fs::read(&source)
        .expect("field dictionary must exist")
        .into_iter()
        .map(|byte| byte ^ 0xA7)
        .collect();
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("fields.bin");
    fs::write(out, encoded).expect("write xor-wrapped field dictionary");
}
