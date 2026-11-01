//! Rust-native `netguid.json` projection from typed PackageMap exports.

use std::collections::BTreeMap;
use std::path::Path;

use codev_stream::{
    C0Cipher, NetGuidExport, PacketSource, S0PcapSource, SelectedUdpFlow, SourceError,
    TransportKind, WireError, parse_transport, prove_packet_handler_wire,
};
use serde::Serialize;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NetGuidArtifact {
    pub binding_count: usize,
    pub conflicts: Vec<NetGuidConflict>,
    pub bindings: Vec<NetGuidBinding>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NetGuidBinding {
    pub netguid: u32,
    pub outer_netguid: Option<u32>,
    pub path: String,
    pub network_checksum: Option<u32>,
    pub flags: u8,
    pub bunch_index: usize,
    pub channel_index: u32,
    pub source_frame: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NetGuidConflict {
    pub existing: NetGuidBinding,
    pub observed: NetGuidBinding,
}

#[derive(Debug, Error)]
pub enum NetGuidArtifactError {
    #[error("capture source error: {0}")]
    Source(#[from] SourceError),
    #[error("S0 session error: {0}")]
    Session(#[from] codev_stream::SessionError),
    #[error("typed wire error: {0}")]
    Wire(#[from] WireError),
}

pub fn build_netguid_artifact(
    pcap: &Path,
    cipher: &C0Cipher,
    flow: SelectedUdpFlow,
) -> Result<NetGuidArtifact, NetGuidArtifactError> {
    let mut bindings = BTreeMap::<u32, NetGuidBinding>::new();
    let mut conflicts = Vec::new();
    let mut source = S0PcapSource::open(pcap)?;
    while let Some(packet) = source.next_packet()? {
        let Ok(transport) = parse_transport(&packet) else {
            continue;
        };
        if transport.kind != TransportKind::Udp
            || !flow.key.contains(transport.source, transport.destination)
        {
            continue;
        }
        let logical = if transport.source == flow.client {
            cipher.crypt_client_datagram(transport.payload)?
        } else {
            cipher.crypt_server_datagram(transport.payload)
        };
        let inner = if transport.source == flow.client {
            &logical[codev_stream::SGNET_CLIENT_PREFIX_BYTES..]
        } else {
            &logical
        };
        let proof = prove_packet_handler_wire(inner)?;
        let Some(unreal) = proof.unreal.as_ref() else {
            continue;
        };
        for package_map in &proof.package_map_exports {
            let bunch = &unreal.bunches[package_map.bunch_index];
            for export in &package_map.prefix.exports {
                collect_export_chain(
                    export,
                    package_map.bunch_index,
                    bunch.channel_index,
                    packet.index + 1,
                    &mut bindings,
                    &mut conflicts,
                );
            }
        }
    }
    Ok(NetGuidArtifact {
        binding_count: bindings.len(),
        conflicts,
        bindings: bindings.into_values().collect(),
    })
}

fn collect_export_chain(
    export: &NetGuidExport,
    bunch_index: usize,
    channel_index: u32,
    source_frame: u64,
    bindings: &mut BTreeMap<u32, NetGuidBinding>,
    conflicts: &mut Vec<NetGuidConflict>,
) {
    if let (Some(flags), Some(path)) = (export.flags, export.path.as_ref()) {
        let observed = NetGuidBinding {
            netguid: export.netguid,
            outer_netguid: export.outer.as_deref().map(|outer| outer.netguid),
            path: path.value.clone(),
            network_checksum: export.network_checksum,
            flags,
            bunch_index,
            channel_index,
            source_frame,
        };
        match bindings.get(&observed.netguid) {
            None => {
                bindings.insert(observed.netguid, observed);
            }
            Some(existing)
                if existing.outer_netguid != observed.outer_netguid
                    || existing.path != observed.path
                    || existing.network_checksum != observed.network_checksum =>
            {
                conflicts.push(NetGuidConflict {
                    existing: existing.clone(),
                    observed,
                });
            }
            Some(_) => {}
        }
    }
    if let Some(outer) = export.outer.as_deref() {
        collect_export_chain(
            outer,
            bunch_index,
            channel_index,
            source_frame,
            bindings,
            conflicts,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use codev_stream::{discover_primary_udp_flow, recover_enter_game_session_from_classic_pcap};
    use sha2::{Digest, Sha256};
    use std::io::Write;

    #[test]
    fn private_full_capture_matches_corrected_v2_netguid_artifact() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let pcap = root.join("input-20260806/game-capture-20260806-082804-CST-full.pcap");
        if !pcap.is_file() {
            return;
        }
        let recovered = recover_enter_game_session_from_classic_pcap(&pcap).unwrap();
        let cipher =
            C0Cipher::from_packet_key(&recovered.session.packet_key, recovered.session.g0_id);
        let mut source = S0PcapSource::open(&pcap).unwrap();
        let flow = discover_primary_udp_flow(&mut source).unwrap();
        let artifact = build_netguid_artifact(&pcap, &cipher, flow).unwrap();
        assert_eq!(artifact.binding_count, 1_048);
        assert!(artifact.conflicts.is_empty());
        assert!(
            artifact
                .bindings
                .iter()
                .any(|binding| { binding.path == "/Game/Maps/Icebox/Levels/MAP_IceBox_Main" })
        );

        let mut actual = Vec::new();
        serde_json::to_writer_pretty(&mut actual, &artifact).unwrap();
        actual.write_all(b"\n").unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&actual)),
            "b44f7c97202acb0ea3bd26836150933e1b428bcab8d730ac448916b939cad423"
        );
        let oracle = root.join("work/oracle-v2-full-20260815-session/netguid.json");
        if oracle.is_file() {
            assert_eq!(actual, std::fs::read(oracle).unwrap());
        }
    }
}
