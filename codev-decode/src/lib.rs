//! S3：引擎解密/解析管线的可复用封装。
//!
//! 源文件与 `codev-cli` 共用同一批文件（见下方 `#[path]`），
//! 因此引擎与客户端**不可能出现实现漂移**。

/// 与 `codev-cli` 的常量保持一致；解码产物里会记录它。
pub const SUPPORTED_BUILD: &str = "1.24.0.2911";

// 与服务端**共用同一份**会话密钥/字典加解密实现（不是复制）。
// 这保证客户端解出的字典与服务端加密时用的算法逐比特一致。
#[path = "../../codev-web/src/session_key.rs"]
pub mod session_key;
#[path = "../../codev-cli/src/artifacts.rs"]
pub mod artifacts;
#[path = "../../codev-cli/src/compat_auxiliary.rs"]
pub mod compat_auxiliary;
#[path = "../../codev-cli/src/compat_batch.rs"]
pub mod compat_batch;
#[path = "../../codev-cli/src/compat_documents.rs"]
pub mod compat_documents;
#[path = "../../codev-cli/src/compat_gate.rs"]
pub mod compat_gate;
#[path = "../../codev-cli/src/compat_netguid.rs"]
pub mod compat_netguid;
#[path = "../../codev-cli/src/compat_network.rs"]
pub mod compat_network;
#[path = "../../codev-cli/src/compat_packets.rs"]
pub mod compat_packets;
#[path = "../../codev-cli/src/compat_report.rs"]
pub mod compat_report;
#[path = "../../codev-cli/src/compat_session.rs"]
pub mod compat_session;
#[path = "../../codev-cli/src/dump_coordinates.rs"]
pub mod dump_coordinates;
#[path = "../../codev-cli/src/record.rs"]
pub mod record;

#[cfg(test)]
mod regression {
    use std::path::Path;

    /// S3 的回归闸门：新 crate 跑出来的解码结果，必须与引擎二进制逐项一致。
    /// 参考值来自 2026-09-30 那次成功解码（已存档）。
    #[test]
    fn reproduces_reference_decode_exactly() {
        let pcap = Path::new(
            "/Users/Admin/Desktop/Phoenix采集-20260930-122104/proxy-1790741740-21707-0.pcap",
        );
        if !pcap.is_file() {
            eprintln!("参考 pcap 不存在，跳过（不静默通过：会打印这行）");
            return;
        }
        let out = std::env::temp_dir().join("codev-decode-regression");
        std::fs::create_dir_all(&out).unwrap();
        let summary =
            crate::dump_coordinates::dump_coordinates(pcap, &out.join("coordinates.jsonl"), true)
                .expect("解码必须成功");

        assert_eq!(summary.coordinate_records, 31863, "坐标条数必须与参考一致");
        assert_eq!(summary.map_id, 2, "地图必须是 Bind(map_id=2)");
        assert_eq!(summary.pipeline_datagrams, 16757, "数据包数必须一致");
    }
}
