use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    // 与 codev-cli 共用同一份字典源文件（不复制），保证两侧编码结果逐字节一致。
    let source = manifest.join("../codev-cli/assets/fields-1.24.0.2911.json");
    println!("cargo:rerun-if-changed={}", source.display());
    let encoded: Vec<u8> = fs::read(&source)
        .expect("field dictionary must exist")
        .into_iter()
        .map(|byte| byte ^ 0xA7)
        .collect();
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("fields.bin");
    fs::write(out, encoded).expect("write xor-wrapped field dictionary");
}
