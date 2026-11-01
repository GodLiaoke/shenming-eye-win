//! 编译期字符串混淆（字符串加密存储，运行时解密）。
//!
//! 目的：成品二进制里不再出现可被 `strings` 直接检索的核心词表
//! （例如算法/协议分层名），但**运行时输出的文字与原文逐字一致** ——
//! 因此日志、客服排查、错误提示的行为完全不变。
//!
//! 实现：XOR（密钥由内容哈希派生，避免密文里出现固定模式）+ hex 存储，零依赖。

/// 把明文编码成可嵌入源码的 hex 串（构建脚本用同一算法生成）。
pub fn encode(plain: &str) -> String {
    let key = key_for(plain.as_bytes().len());
    plain
        .as_bytes()
        .iter()
        .enumerate()
        .map(|(i, b)| format!("{:02x}", b ^ key[i % key.len()]))
        .collect()
}

fn key_for(len: usize) -> [u8; 8] {
    // 与内容长度相关即可；不引入固定明文字节模式。
    let seed = (len as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x0DDB_1A5E_5BAD_5EED;
    let mut key = [0u8; 8];
    let mut x = seed;
    for slot in key.iter_mut() {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *slot = (x & 0xFF) as u8;
    }
    key
}

fn decode(blob: &str) -> String {
    let bytes: Vec<u8> = (0..blob.len() / 2)
        .map(|i| u8::from_str_radix(&blob[i * 2..i * 2 + 2], 16).unwrap_or(b'?'))
        .collect();
    let key = key_for(bytes.len());
    let plain: Vec<u8> = bytes.iter().enumerate().map(|(i, b)| b ^ key[i % key.len()]).collect();
    String::from_utf8_lossy(&plain).into_owned()
}

/// 解码一段混淆字符串。
pub fn s(blob: &str) -> String {
    decode(blob)
}

/// 解码后按顺序替换 `{}` 占位符（等价于 `format!("原文", ...)`）。
pub fn f1(blob: &str, a: impl std::fmt::Display) -> String {
    decode(blob).replacen("{}", &a.to_string(), 1)
}
/// 两个参数的版本。
pub fn f2(blob: &str, a: impl std::fmt::Display, b: impl std::fmt::Display) -> String {
    decode(blob).replacen("{}", &a.to_string(), 1).replacen("{}", &b.to_string(), 1)
}
/// 三个参数的版本。
pub fn f3(blob: &str, a: impl std::fmt::Display, b: impl std::fmt::Display, c: impl std::fmt::Display) -> String {
    decode(blob).replacen("{}", &a.to_string(), 1).replacen("{}", &b.to_string(), 1).replacen("{}", &c.to_string(), 1)
}


/// 解码为 `&'static str`：供**常量位置**使用（如 `(State, &'static str)` 元组、
/// 结构体 `&'static str` 字段）。同一 blob 只解密一次并缓存，开销可忽略。
pub fn s_static(blob: &'static str) -> &'static str {
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<&'static str, &'static str>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(hit) = guard.get(blob) {
        return hit;
    }
    let leaked: &'static str = Box::leak(decode(blob).into_boxed_str());
    guard.insert(blob, leaked);
    leaked
}

#[cfg(test)]
mod tests {
    #[test]
    fn round_trip_matches_plaintext_exactly() {
        for plain in ["SGNet/PacketHandler/UE", "BatchSync payload matched {} unknown spans", "中文混排 ok", ""] {
            let blob = super::encode(plain);
            assert_eq!(super::s(&blob), plain, "往返必须逐字一致");
        }
    }

    #[test]
    fn placeholders_are_substituted() {
        let blob = super::encode("BatchSync actor matched {} of {}");
        assert_eq!(super::f2(&blob, 3, 7), "BatchSync actor matched 3 of 7");
    }
}

#[cfg(test)]
mod cross_language {
    /// 由 scripts/obf-encode.py 生成 —— 证明 Python 编码器与 Rust 解码器逐位一致。
    #[test]
    fn python_encoded_blob_decodes_to_original() {
        assert_eq!(super::s("5e9a7adbbd439e186eb651ca810da01d61b846919c29"), "SGNet/PacketHandler/UE");
    }
}
