// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! A2 roster-derived config generator: derive each node's config from the ONE operator-signed roster
//! (DRY — a node distributes config but never authors its own authority). This crate is a READ-ONLY
//! consumer of the signed roster; it never writes the roster and holds no head-mutation authority.
//!
//! It derives two files from ONE verified active roster (single-sourced so the fail-closed join can't
//! diverge): the NON-SECRET elector config (mesh IPs + raft ids + ports), and the SECRET WireGuard
//! config, whose `[Interface]` carries the node's WG PRIVATE key (bound to the node's operator-signed WG
//! public key, mode-600 on disk, never in evidence).
//!
//! **Trust order (A2 slice-2 constraint):** trust network records ONLY after WHOLE-LOG integrity — the
//! head length-witness (exact count + prefix-digest over ALL lines, network bytes included) and the
//! per-record operator signatures — over the SAME lines, before deriving anything.

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_CHIRHO, Engine as _};
use cairn_replication_chirho::membership_chirho::{
    verify_membership_roster_with_head_chirho, verify_node_network_records_chirho,
    verify_preferred_leader_records_chirho, VerifiedMembershipChirho, VerifiedNodeNetworkChirho,
};
use cairn_tenant_placement_authority_chirho::{
    TenantPlacementNodeBindingChirho, VerifiedTenantPlacementChirho,
};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::Read;
use std::net::IpAddr;
use std::process::{Command, Stdio};
use x25519_dalek::{x25519, X25519_BASEPOINT_BYTES};
use zeroize::Zeroizing;

/// The elector wire port every node binds/dials on the mesh (named, not a literal — A2-R6).
pub const ELECTOR_PORT_CHIRHO: u16 = 8300;
/// The reviewed fleet WireGuard interface carrying election and relay traffic.
pub const RELAY_WIREGUARD_INTERFACE_CHIRHO: &str = "wg0";
/// The fixed label that replaces a public endpoint in shareable evidence (A2-R6, M206 pattern).
pub const REDACTED_ENDPOINT_LABEL_CHIRHO: &str = "[redacted-endpoint-chirho]";
/// PersistentKeepalive (seconds) set on every WireGuard peer — keeps NAT'd / idle tunnels alive and is
/// harmless on directly-routable links. Named, not a literal (A2-R6).
pub const WG_KEEPALIVE_SECS_CHIRHO: u16 = 25;
/// The fixed label that replaces the WG private key / secret config text in a redacted Debug (A2-R3).
pub const REDACTED_SECRET_LABEL_CHIRHO: &str = "[redacted-secret-chirho]";
const ACTIVE_INTERFACE_COMMAND_OUTPUT_MAX_BYTES_CHIRHO: usize = 64 * 1024;
const ACTIVE_RELAY_MESH_MAX_MEMBERS_CHIRHO: usize = 64;
const WIREGUARD_INTERFACE_NAME_MAX_BYTES_CHIRHO: usize = 15;

/// One derived elector member (config.json `members_chirho` shape).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ElectorMemberChirho {
    pub raft_id_chirho: u64,
    pub pubkey_chirho: String,
    pub url_chirho: String,
    pub learner_chirho: bool,
}

/// The mesh-derived portion of a node's elector config (the roster-derived fields). The caller supplies
/// the local-only fields (group, durable dir, sign root, tick) to assemble the full `config.json`; those
/// are not roster-derived and carry no authority.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DerivedElectorConfigChirho {
    /// This node's raft id (from its verified network record).
    pub local_raft_id_chirho: u64,
    /// All active members, SORTED by raft id ascending (A2-R4 determinism), each dialled on the mesh.
    pub members_chirho: Vec<ElectorMemberChirho>,
    /// This node's mesh listen address, `<mesh_ip>:<ELECTOR_PORT_CHIRHO>`.
    pub listen_addr_chirho: String,
}

/// NON-SECRET shareable evidence about a derived config: counts, raft ids, and mesh IPs only. Public
/// endpoints (fleet topology) are NOT included — they are replaced by a fixed redaction label (A2-R6).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RosterConfigEvidenceChirho {
    pub member_count_chirho: usize,
    pub raft_ids_chirho: Vec<u64>,
    pub mesh_ips_chirho: Vec<String>,
    pub endpoints_chirho: &'static str,
}

/// This node's WireGuard PRIVATE key (standard WireGuard base64 — what `wg genkey` emits, 32 bytes).
/// SECRET. It deliberately has NO `Serialize`/`Deserialize` (so it can never be dumped to JSON or
/// evidence) and a REDACTED `Debug`; its bytes are zeroized on drop (`Zeroizing`, so a freed copy does
/// not linger in the heap / swap / a core dump); the only place they travel is into the `[Interface]` of
/// a SECRET config the caller must write mode-600 (A2-R3).
pub struct WgLocalPrivateKeyChirho {
    base64_chirho: Zeroizing<String>,
}

impl WgLocalPrivateKeyChirho {
    /// Wrap a standard-WireGuard-base64 private key, validating it decodes to exactly 32 bytes.
    pub fn from_base64_chirho(base64_chirho: &str) -> Result<Self> {
        let trimmed_chirho = base64_chirho.trim();
        let raw_chirho = BASE64_CHIRHO
            .decode(trimmed_chirho)
            .map_err(|_| anyhow!("WireGuard private key is not valid base64"))?;
        if raw_chirho.len() != 32 {
            bail!(
                "WireGuard private key must decode to 32 bytes, got {}",
                raw_chirho.len()
            );
        }
        Ok(Self {
            base64_chirho: Zeroizing::new(trimmed_chirho.to_string()),
        })
    }

    /// Derive the WireGuard PUBLIC key (standard base64) — the same value `wg pubkey` produces: the
    /// clamped private scalar times the Curve25519 basepoint. Non-secret (a public key); used for the
    /// A2-R2 binding check and available as an operator preflight.
    pub fn derive_wg_pubkey_base64_chirho(&self) -> Result<String> {
        let raw_chirho = BASE64_CHIRHO
            .decode(self.base64_chirho.as_bytes())
            .map_err(|_| anyhow!("WireGuard private key is not valid base64"))?;
        let secret_bytes_chirho: [u8; 32] = raw_chirho
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("WireGuard private key must be 32 bytes"))?;
        let public_bytes_chirho = x25519(secret_bytes_chirho, X25519_BASEPOINT_BYTES);
        Ok(BASE64_CHIRHO.encode(public_bytes_chirho))
    }
}

impl fmt::Debug for WgLocalPrivateKeyChirho {
    fn fmt(&self, f_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        // NEVER print the key material (A2-R3).
        write!(
            f_chirho,
            "WgLocalPrivateKeyChirho({REDACTED_SECRET_LABEL_CHIRHO})"
        )
    }
}

/// A rendered WireGuard config for THIS node — the `[Interface]` (this node's WG private key + mesh IP)
/// plus one `[Peer]` per OTHER active member. SECRET: the text carries the private key. It has NO
/// `Serialize` (cannot be dumped to JSON) and a REDACTED `Debug`; the text is zeroized on drop
/// (`Zeroizing`); the only secret accessor is the explicitly-named
/// [`WireguardConfigChirho::secret_config_text_chirho`], and [`WireguardConfigChirho::evidence_chirho`]
/// returns non-secret fields only (A2-R3).
pub struct WireguardConfigChirho {
    secret_text_chirho: Zeroizing<String>,
    interface_pubkey_chirho: String,
    mesh_ip_chirho: String,
    listen_port_chirho: u16,
    peer_count_chirho: usize,
}

impl WireguardConfigChirho {
    /// The full `[Interface]`+`[Peer]` config text. SECRET (contains the WG private key): write it only
    /// to a mode-600 file via [`write_secret_wireguard_config_chirho`]; never log it, print it, put it in
    /// CAS, a signed log, or shareable evidence.
    pub fn secret_config_text_chirho(&self) -> &str {
        self.secret_text_chirho.as_str()
    }

    /// This node's WireGuard PUBLIC key (non-secret).
    pub fn interface_pubkey_chirho(&self) -> &str {
        &self.interface_pubkey_chirho
    }

    /// Non-secret evidence about this config: this node's PUBLIC key, mesh IP, listen port, and peer
    /// count — NO private key, NO peer endpoints (endpoints are the fixed redaction label; A2-R3 + A2-R6).
    pub fn evidence_chirho(&self) -> WireguardEvidenceChirho {
        WireguardEvidenceChirho {
            interface_pubkey_chirho: self.interface_pubkey_chirho.clone(),
            mesh_ip_chirho: self.mesh_ip_chirho.clone(),
            listen_port_chirho: self.listen_port_chirho,
            peer_count_chirho: self.peer_count_chirho,
            endpoints_chirho: REDACTED_ENDPOINT_LABEL_CHIRHO,
        }
    }
}

impl fmt::Debug for WireguardConfigChirho {
    fn fmt(&self, f_chirho: &mut fmt::Formatter<'_>) -> fmt::Result {
        // NEVER print the config text (it holds the private key) — evidence-shaped Debug only (A2-R3).
        f_chirho
            .debug_struct("WireguardConfigChirho")
            .field("interface_pubkey_chirho", &self.interface_pubkey_chirho)
            .field("mesh_ip_chirho", &self.mesh_ip_chirho)
            .field("listen_port_chirho", &self.listen_port_chirho)
            .field("peer_count_chirho", &self.peer_count_chirho)
            .field("secret_text_chirho", &REDACTED_SECRET_LABEL_CHIRHO)
            .finish()
    }
}

/// NON-SECRET evidence about a derived WireGuard config: this node's PUBLIC key, mesh IP, listen port,
/// and peer count. Carries NO private key and NO peer endpoints (endpoints are the fixed redaction
/// label). Safe to serialize into a shareable report.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WireguardEvidenceChirho {
    pub interface_pubkey_chirho: String,
    pub mesh_ip_chirho: String,
    pub listen_port_chirho: u16,
    pub peer_count_chirho: usize,
    pub endpoints_chirho: &'static str,
}

/// The verified, collision-checked, deterministically-ordered active roster that BOTH the elector and
/// WireGuard derivations build on — single-sourced so the fail-closed join can never diverge between the
/// two consumers (duplicated security logic is exactly the divergence hazard the Direction-2 fix showed).
/// Owned (clones the small coord structs) so callers iterate without lifetime juggling.
struct VerifiedActiveRosterChirho {
    /// Every active member's verified network coords, SORTED by raft id ascending (A2-R4). Guaranteed:
    /// each is an active member with coords (A2-R5 Direction 1), no four-field collision / zero raft id
    /// (A2-R1), and the local node is among them.
    sorted_active_chirho: Vec<VerifiedNodeNetworkChirho>,
    membership_chirho: VerifiedMembershipChirho,
}

impl VerifiedActiveRosterChirho {
    /// This node's own verified coords — presence is guaranteed by construction.
    fn local_coords_chirho(
        &self,
        local_node_pubkey_hex_chirho: &str,
    ) -> &VerifiedNodeNetworkChirho {
        self.sorted_active_chirho
            .iter()
            .find(|coords_chirho| {
                coords_chirho.node_pubkey_hex_chirho == local_node_pubkey_hex_chirho
            })
            .expect("local node presence is guaranteed by verify_and_order_active_roster_chirho")
    }
}

/// One member of an operator-signed active relay mesh.
///
/// Fields stay private and this type has no public constructor or serde implementation. Callers may
/// read the verified node id and mesh address but cannot turn an ambient endpoint map into this
/// evidence.
pub struct VerifiedRelayMeshMemberChirho {
    node_id_chirho: String,
    mesh_ip_chirho: IpAddr,
    wg_pubkey_chirho: String,
}

impl VerifiedRelayMeshMemberChirho {
    pub fn node_id_chirho(&self) -> &str {
        &self.node_id_chirho
    }

    pub fn mesh_ip_chirho(&self) -> IpAddr {
        self.mesh_ip_chirho
    }
}

/// Opaque result of the complete signed-roster/network join for relay transport.
///
/// This proves roster membership and operator-assigned network coordinates. It does not yet prove
/// that the local host has brought up the matching WireGuard interface; only
/// [`VerifiedActiveRelayMeshChirho`] is accepted by the production relay adapter.
pub struct VerifiedRelayMeshChirho {
    local_node_id_chirho: String,
    local_mesh_ip_chirho: IpAddr,
    local_wg_pubkey_chirho: String,
    members_chirho: Vec<VerifiedRelayMeshMemberChirho>,
}

impl VerifiedRelayMeshChirho {
    pub fn local_node_id_chirho(&self) -> &str {
        &self.local_node_id_chirho
    }

    pub fn local_mesh_ip_chirho(&self) -> IpAddr {
        self.local_mesh_ip_chirho
    }

    pub fn members_chirho(&self) -> &[VerifiedRelayMeshMemberChirho] {
        &self.members_chirho
    }
}

/// Opaque composition evidence that the signed local WireGuard identity is active on this host.
///
/// No public constructor, serde implementation, or unchecked conversion exists. The only mint runs
/// the bounded host preflight below against the exact signed local public key and mesh address.
pub struct VerifiedActiveRelayMeshChirho {
    verified_chirho: VerifiedRelayMeshChirho,
    interface_name_chirho: String,
}

impl VerifiedActiveRelayMeshChirho {
    pub fn local_node_id_chirho(&self) -> &str {
        self.verified_chirho.local_node_id_chirho()
    }

    pub fn local_mesh_ip_chirho(&self) -> IpAddr {
        self.verified_chirho.local_mesh_ip_chirho()
    }

    pub fn members_chirho(&self) -> &[VerifiedRelayMeshMemberChirho] {
        self.verified_chirho.members_chirho()
    }

    pub fn interface_name_chirho(&self) -> &str {
        &self.interface_name_chirho
    }
}

/// Derive the exact active relay-mesh population from the same whole-log-first verifier that owns
/// elector and WireGuard config generation.
pub fn derive_verified_relay_mesh_chirho(
    roster_lines_chirho: &[Vec<u8>],
    roster_head_bytes_chirho: &[u8],
    operator_pubkey_hex_chirho: &str,
    local_node_pubkey_hex_chirho: &str,
) -> Result<VerifiedRelayMeshChirho> {
    let roster_chirho = verify_and_order_active_roster_chirho(
        roster_lines_chirho,
        roster_head_bytes_chirho,
        operator_pubkey_hex_chirho,
        local_node_pubkey_hex_chirho,
    )?;
    let local_chirho = roster_chirho.local_coords_chirho(local_node_pubkey_hex_chirho);
    let local_mesh_ip_chirho = parse_mesh_ip_chirho(&local_chirho.mesh_ip_chirho)?;
    if roster_chirho.sorted_active_chirho.len() > ACTIVE_RELAY_MESH_MAX_MEMBERS_CHIRHO {
        bail!("roster-config: relay mesh exceeds its fixed member bound");
    }
    let members_chirho = roster_chirho
        .sorted_active_chirho
        .iter()
        .map(|member_chirho| {
            Ok(VerifiedRelayMeshMemberChirho {
                node_id_chirho: member_chirho.node_pubkey_hex_chirho.clone(),
                mesh_ip_chirho: parse_mesh_ip_chirho(&member_chirho.mesh_ip_chirho)?,
                wg_pubkey_chirho: member_chirho.wg_pubkey_chirho.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(VerifiedRelayMeshChirho {
        local_node_id_chirho: local_chirho.node_pubkey_hex_chirho.clone(),
        local_mesh_ip_chirho,
        local_wg_pubkey_chirho: local_chirho.wg_pubkey_chirho.clone(),
        members_chirho,
    })
}

/// Verify the exact operator-signed WireGuard identity and mesh address against a live host
/// interface before relay request secrets may enter the adapter.
pub fn verify_active_relay_mesh_interface_chirho(
    verified_chirho: VerifiedRelayMeshChirho,
    interface_name_chirho: &str,
) -> Result<VerifiedActiveRelayMeshChirho> {
    validate_wireguard_interface_name_chirho(interface_name_chirho)?;
    let public_key_output_chirho =
        bounded_command_output_chirho("wg", &["show", interface_name_chirho, "public-key"])?;
    let link_output_chirho =
        bounded_command_output_chirho("ip", &["-o", "link", "show", "dev", interface_name_chirho])?;
    let address_output_chirho =
        bounded_command_output_chirho("ip", &["-o", "addr", "show", "dev", interface_name_chirho])?;
    let allowed_ips_output_chirho =
        bounded_command_output_chirho("wg", &["show", interface_name_chirho, "allowed-ips"])?;
    verify_active_relay_mesh_observation_chirho(
        &verified_chirho,
        public_key_output_chirho.trim(),
        &link_output_chirho,
        &address_output_chirho,
    )?;
    let mut route_outputs_chirho = Vec::new();
    for member_chirho in verified_chirho
        .members_chirho
        .iter()
        .filter(|member_chirho| {
            member_chirho.node_id_chirho != verified_chirho.local_node_id_chirho
        })
    {
        let mesh_ip_chirho = member_chirho.mesh_ip_chirho.to_string();
        let route_output_chirho =
            bounded_command_output_chirho("ip", &["-o", "route", "get", &mesh_ip_chirho])?;
        route_outputs_chirho.push((member_chirho.mesh_ip_chirho, route_output_chirho));
    }
    verify_active_relay_mesh_peer_routes_chirho(
        &verified_chirho,
        interface_name_chirho,
        &allowed_ips_output_chirho,
        &route_outputs_chirho,
    )?;
    Ok(VerifiedActiveRelayMeshChirho {
        verified_chirho,
        interface_name_chirho: interface_name_chirho.to_string(),
    })
}

fn parse_mesh_ip_chirho(value_chirho: &str) -> Result<IpAddr> {
    let parsed_chirho = value_chirho
        .parse::<IpAddr>()
        .map_err(|_| anyhow!("roster-config: relay mesh IP is not a literal IP address"))?;
    let private_mesh_chirho = match parsed_chirho {
        IpAddr::V4(address_chirho) => address_chirho.is_loopback() || address_chirho.is_private(),
        IpAddr::V6(address_chirho) => {
            address_chirho.is_loopback() || (address_chirho.segments()[0] & 0xfe00) == 0xfc00
        }
    };
    if !private_mesh_chirho {
        bail!("roster-config: relay mesh IP must be loopback or private-mesh scoped");
    }
    Ok(parsed_chirho)
}

fn validate_wireguard_interface_name_chirho(interface_name_chirho: &str) -> Result<()> {
    if interface_name_chirho.is_empty()
        || interface_name_chirho.len() > WIREGUARD_INTERFACE_NAME_MAX_BYTES_CHIRHO
        || !interface_name_chirho.bytes().all(|byte_chirho| {
            byte_chirho.is_ascii_alphanumeric() || matches!(byte_chirho, b'_' | b'-' | b'.')
        })
    {
        bail!("roster-config: WireGuard interface name is invalid");
    }
    Ok(())
}

fn bounded_command_output_chirho(program_chirho: &str, args_chirho: &[&str]) -> Result<String> {
    let mut child_chirho = Command::new(program_chirho)
        .args(args_chirho)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("run {program_chirho} relay-interface preflight"))?;
    let stdout_chirho = child_chirho
        .stdout
        .take()
        .ok_or_else(|| anyhow!("roster-config: relay-interface preflight stdout is unavailable"))?;
    let mut output_chirho = Vec::new();
    stdout_chirho
        .take((ACTIVE_INTERFACE_COMMAND_OUTPUT_MAX_BYTES_CHIRHO + 1) as u64)
        .read_to_end(&mut output_chirho)
        .context("read relay-interface preflight output")?;
    if output_chirho.len() > ACTIVE_INTERFACE_COMMAND_OUTPUT_MAX_BYTES_CHIRHO {
        let _ = child_chirho.kill();
        let _ = child_chirho.wait();
        bail!("roster-config: active WireGuard interface preflight output exceeds its bound");
    }
    let status_chirho = child_chirho
        .wait()
        .context("wait for relay-interface preflight")?;
    if !status_chirho.success() {
        bail!("roster-config: active WireGuard interface preflight command refused");
    }
    String::from_utf8(output_chirho)
        .map_err(|_| anyhow!("roster-config: active WireGuard interface output is not UTF-8"))
}

fn verify_active_relay_mesh_observation_chirho(
    verified_chirho: &VerifiedRelayMeshChirho,
    observed_wg_pubkey_chirho: &str,
    link_output_chirho: &str,
    address_output_chirho: &str,
) -> Result<()> {
    if observed_wg_pubkey_chirho != verified_chirho.local_wg_pubkey_chirho {
        bail!("roster-config: active WireGuard interface public key differs from signed roster");
    }
    let flags_chirho = link_output_chirho
        .split_once('<')
        .and_then(|(_prefix_chirho, rest_chirho)| rest_chirho.split_once('>'))
        .map(|(flags_chirho, _suffix_chirho)| flags_chirho)
        .ok_or_else(|| anyhow!("roster-config: active WireGuard link flags are unavailable"))?;
    if !flags_chirho
        .split(',')
        .any(|flag_chirho| flag_chirho == "UP")
    {
        bail!("roster-config: signed WireGuard interface is not UP");
    }
    let observed_address_chirho = address_output_chirho
        .split_ascii_whitespace()
        .collect::<Vec<_>>()
        .windows(2)
        .filter(|pair_chirho| matches!(pair_chirho[0], "inet" | "inet6"))
        .filter_map(|pair_chirho| pair_chirho[1].split('/').next())
        .filter_map(|value_chirho| value_chirho.parse::<IpAddr>().ok())
        .any(|address_chirho| address_chirho == verified_chirho.local_mesh_ip_chirho);
    if !observed_address_chirho {
        bail!("roster-config: active WireGuard interface lacks the signed local mesh address");
    }
    Ok(())
}

fn verify_active_relay_mesh_peer_routes_chirho(
    verified_chirho: &VerifiedRelayMeshChirho,
    interface_name_chirho: &str,
    allowed_ips_output_chirho: &str,
    route_outputs_chirho: &[(IpAddr, String)],
) -> Result<()> {
    let expected_peer_routes_chirho = verified_chirho
        .members_chirho
        .iter()
        .filter(|member_chirho| {
            member_chirho.node_id_chirho != verified_chirho.local_node_id_chirho
        })
        .map(|member_chirho| {
            let prefix_chirho = match member_chirho.mesh_ip_chirho {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            (
                member_chirho.wg_pubkey_chirho.as_str(),
                format!("{}/{prefix_chirho}", member_chirho.mesh_ip_chirho),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut observed_peer_routes_chirho = BTreeMap::new();
    for line_chirho in allowed_ips_output_chirho
        .lines()
        .filter(|line_chirho| !line_chirho.trim().is_empty())
    {
        let fields_chirho = line_chirho.split_ascii_whitespace().collect::<Vec<_>>();
        if fields_chirho.len() != 2
            || fields_chirho[1].split(',').count() != 1
            || observed_peer_routes_chirho
                .insert(fields_chirho[0], fields_chirho[1].to_string())
                .is_some()
        {
            bail!("roster-config: active WireGuard peer-to-address mapping is not canonical");
        }
    }
    if expected_peer_routes_chirho != observed_peer_routes_chirho {
        bail!("roster-config: active WireGuard peer-to-address mapping differs from signed roster");
    }

    let expected_routes_chirho = verified_chirho
        .members_chirho
        .iter()
        .filter(|member_chirho| {
            member_chirho.node_id_chirho != verified_chirho.local_node_id_chirho
        })
        .map(|member_chirho| member_chirho.mesh_ip_chirho)
        .collect::<BTreeSet<_>>();
    let observed_routes_chirho = route_outputs_chirho
        .iter()
        .map(|(mesh_ip_chirho, _output_chirho)| *mesh_ip_chirho)
        .collect::<BTreeSet<_>>();
    if expected_routes_chirho.len() != route_outputs_chirho.len()
        || expected_routes_chirho != observed_routes_chirho
    {
        bail!("roster-config: active WireGuard route population differs from signed roster");
    }
    for (mesh_ip_chirho, output_chirho) in route_outputs_chirho {
        let fields_chirho = output_chirho.split_ascii_whitespace().collect::<Vec<_>>();
        let route_target_chirho = fields_chirho
            .first()
            .and_then(|value_chirho| value_chirho.parse::<IpAddr>().ok());
        let route_device_chirho = route_field_chirho(&fields_chirho, "dev");
        let route_source_chirho = route_field_chirho(&fields_chirho, "src")
            .and_then(|value_chirho| value_chirho.parse::<IpAddr>().ok());
        if route_target_chirho != Some(*mesh_ip_chirho)
            || route_device_chirho != Some(interface_name_chirho)
            || route_source_chirho != Some(verified_chirho.local_mesh_ip_chirho)
        {
            bail!(
                "roster-config: signed relay endpoint does not route through the exact WireGuard interface and source address"
            );
        }
    }
    Ok(())
}

fn route_field_chirho<'a>(fields_chirho: &'a [&str], key_chirho: &str) -> Option<&'a str> {
    fields_chirho
        .windows(2)
        .find(|pair_chirho| pair_chirho[0] == key_chirho)
        .map(|pair_chirho| pair_chirho[1])
}

/// Verify the roster whole-log-first, then produce the fail-closed, collision-checked, raft-id-ordered
/// active set both derivations consume.
///
/// `local_node_pubkey_hex_chirho` is this node's ed25519 identity (must be an active member). Refuses
/// (emits nothing) on: a tampered log / bad or wrong-operator head or record signature; an active member
/// with no network record (A2-R5 Direction 1 — never a partial config); a duplicate on any of the four
/// network-identity fields or a zero raft id (A2-R1); or the local node absent. Non-member network
/// records (a removed or pre-provisioned node) are intentionally IGNORED, not an error — they are still
/// operator-signed, and the derivation builds only from active members, so a lingering record from a
/// removed node can neither reappear as a peer nor false-collide on a reclaimed mesh ip / endpoint.
fn verify_and_order_active_roster_chirho(
    roster_lines_chirho: &[Vec<u8>],
    roster_head_bytes_chirho: &[u8],
    operator_pubkey_hex_chirho: &str,
    local_node_pubkey_hex_chirho: &str,
) -> Result<VerifiedActiveRosterChirho> {
    // 1. Whole-log integrity (slice-2 constraint): the head pins the exact count + prefix-digest over ALL
    //    lines and every membership record's operator signature is checked, over the SAME lines, BEFORE
    //    any network record is trusted.
    let membership_chirho = verify_membership_roster_with_head_chirho(
        roster_lines_chirho,
        roster_head_bytes_chirho,
        operator_pubkey_hex_chirho,
    )?;
    // 2. The network records from the same (now head-verified) lines, operator-signature-checked,
    //    latest-per-pubkey.
    let network_chirho =
        verify_node_network_records_chirho(roster_lines_chirho, operator_pubkey_hex_chirho)?;

    // 3. Fail-closed join (A2-R5): every active member MUST have a network record — else refuse the whole
    //    config, naming the node (a silently dropped member = an unreachable peer = a quorum/split
    //    hazard). Non-member network records are intentionally IGNORED (see the fn doc): append-only
    //    records with no remove primitive would otherwise brick derivation after any node removal.
    for member_pubkey_chirho in membership_chirho.active_pubkeys_chirho() {
        if !network_chirho.contains_key(member_pubkey_chirho) {
            bail!(
                "roster-config: active member {member_pubkey_chirho} has no network record; refusing to derive a partial config"
            );
        }
    }

    // 4. Gather the active members' verified coords (owned) and order by raft id ascending — the single
    //    deterministic ordering (A2-R4) used for BOTH the collision walk and every derived output.
    let mut sorted_active_chirho: Vec<VerifiedNodeNetworkChirho> = membership_chirho
        .active_pubkeys_chirho()
        .map(|pubkey_chirho| network_chirho[pubkey_chirho].clone())
        .collect();
    sorted_active_chirho.sort_by_key(|coords_chirho| coords_chirho.raft_id_chirho);

    // 5. Collision (A2-R1): across the active members, no duplicate on ANY of the four network-identity
    //    fields, and no zero raft id (raft-rs reserves 0). Any collision fails closed.
    let mut seen_raft_ids_chirho: BTreeSet<u64> = BTreeSet::new();
    let mut seen_mesh_ips_chirho: BTreeSet<&str> = BTreeSet::new();
    let mut seen_wg_pubkeys_chirho: BTreeSet<&str> = BTreeSet::new();
    let mut seen_endpoints_chirho: BTreeSet<&str> = BTreeSet::new();
    for coords_chirho in &sorted_active_chirho {
        if coords_chirho.raft_id_chirho == 0 {
            bail!(
                "roster-config: node {} has raft id 0 (reserved); refusing",
                coords_chirho.node_pubkey_hex_chirho
            );
        }
        if !seen_raft_ids_chirho.insert(coords_chirho.raft_id_chirho) {
            bail!(
                "roster-config: duplicate raft id {} across active members; refusing",
                coords_chirho.raft_id_chirho
            );
        }
        if !seen_mesh_ips_chirho.insert(coords_chirho.mesh_ip_chirho.as_str()) {
            bail!(
                "roster-config: duplicate mesh ip {} across active members; refusing",
                coords_chirho.mesh_ip_chirho
            );
        }
        if !seen_wg_pubkeys_chirho.insert(coords_chirho.wg_pubkey_chirho.as_str()) {
            bail!("roster-config: duplicate WireGuard public key across active members; refusing");
        }
        if !seen_endpoints_chirho.insert(coords_chirho.endpoint_chirho.as_str()) {
            bail!(
                "roster-config: duplicate endpoint {} across active members; refusing",
                coords_chirho.endpoint_chirho
            );
        }
    }

    // 6. The local node must be an active member (with coords, guaranteed by step 3).
    if !sorted_active_chirho
        .iter()
        .any(|coords_chirho| coords_chirho.node_pubkey_hex_chirho == local_node_pubkey_hex_chirho)
    {
        bail!(
            "roster-config: the local node {local_node_pubkey_hex_chirho} is not an active member; refusing"
        );
    }

    Ok(VerifiedActiveRosterChirho {
        sorted_active_chirho,
        membership_chirho,
    })
}

/// Derive this node's elector config from the operator-signed roster, fail-closed. See
/// `verify_and_order_active_roster_chirho` for the shared verification and refusal rules. Members are
/// emitted sorted by raft id (A2-R4), so two nodes derive byte-identical member lists.
pub fn derive_elector_config_chirho(
    roster_lines_chirho: &[Vec<u8>],
    roster_head_bytes_chirho: &[u8],
    operator_pubkey_hex_chirho: &str,
    local_node_pubkey_hex_chirho: &str,
) -> Result<(DerivedElectorConfigChirho, RosterConfigEvidenceChirho)> {
    let roster_chirho = verify_and_order_active_roster_chirho(
        roster_lines_chirho,
        roster_head_bytes_chirho,
        operator_pubkey_hex_chirho,
        local_node_pubkey_hex_chirho,
    )?;
    let active_chirho = &roster_chirho.sorted_active_chirho;
    let local_coords_chirho = roster_chirho.local_coords_chirho(local_node_pubkey_hex_chirho);

    // All active members are voters in the derived (steady-state) config; runtime voter/learner
    // transitions are A1.3's ConfChange domain.
    let members_chirho: Vec<ElectorMemberChirho> = active_chirho
        .iter()
        .map(|coords_chirho| ElectorMemberChirho {
            raft_id_chirho: coords_chirho.raft_id_chirho,
            pubkey_chirho: coords_chirho.node_pubkey_hex_chirho.clone(),
            url_chirho: format!(
                "http://{}:{}",
                coords_chirho.mesh_ip_chirho, ELECTOR_PORT_CHIRHO
            ),
            learner_chirho: false,
        })
        .collect();
    let config_chirho = DerivedElectorConfigChirho {
        local_raft_id_chirho: local_coords_chirho.raft_id_chirho,
        members_chirho,
        listen_addr_chirho: format!(
            "{}:{}",
            local_coords_chirho.mesh_ip_chirho, ELECTOR_PORT_CHIRHO
        ),
    };

    // Non-secret evidence: counts, raft ids, mesh ips; endpoints redacted (A2-R6).
    let evidence_chirho = RosterConfigEvidenceChirho {
        member_count_chirho: active_chirho.len(),
        raft_ids_chirho: active_chirho
            .iter()
            .map(|coords_chirho| coords_chirho.raft_id_chirho)
            .collect(),
        mesh_ips_chirho: active_chirho
            .iter()
            .map(|coords_chirho| coords_chirho.mesh_ip_chirho.clone())
            .collect(),
        endpoints_chirho: REDACTED_ENDPOINT_LABEL_CHIRHO,
    };

    Ok((config_chirho, evidence_chirho))
}

/// Non-secret proof that two separately signed authorities agreed on one exact tenant membership.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TenantPlacementRosterJoinEvidenceChirho {
    pub placement_assignment_digest_chirho: String,
    pub assigned_node_ids_chirho: Vec<String>,
    pub assigned_raft_ids_chirho: Vec<u64>,
    pub held_observer_node_id_chirho: String,
    pub held_observer_raft_id_chirho: u64,
    pub preferred_node_id_chirho: String,
    pub preferred_raft_id_chirho: u64,
    pub local_node_assigned_chirho: bool,
    pub local_node_held_observer_chirho: bool,
}

/// Join one independently verified placement with one independently verified roster.
///
/// Neither authority wins a disagreement. Every assigned node must be active, carry one unique
/// operator-signed network coordinate, and have the same region in both records. The returned target
/// is exactly three serving voters plus the separately signed held-evidence learner, sorted by raft
/// id. A local node outside the target may still derive it so the old leader can converge itself out
/// safely; it gains no target readiness claim by doing so.
pub fn derive_tenant_placement_elector_config_chirho(
    roster_lines_chirho: &[Vec<u8>],
    roster_head_bytes_chirho: &[u8],
    operator_pubkey_hex_chirho: &str,
    local_node_pubkey_hex_chirho: &str,
    placement_chirho: &VerifiedTenantPlacementChirho,
) -> Result<(
    DerivedElectorConfigChirho,
    TenantPlacementRosterJoinEvidenceChirho,
)> {
    let roster_chirho = verify_and_order_active_roster_chirho(
        roster_lines_chirho,
        roster_head_bytes_chirho,
        operator_pubkey_hex_chirho,
        local_node_pubkey_hex_chirho,
    )?;
    let local_coords_chirho = roster_chirho.local_coords_chirho(local_node_pubkey_hex_chirho);
    let mut assigned_chirho = placement_chirho
        .assigned_nodes_chirho()
        .iter()
        .map(|assigned_chirho| {
            let coords_chirho = join_tenant_placement_node_chirho(
                &roster_chirho,
                assigned_chirho,
                "TenantPlacementRosterAssignedNodeInactiveChirho",
            )?;
            Ok((assigned_chirho, coords_chirho))
        })
        .collect::<Result<Vec<_>>>()?;
    assigned_chirho.sort_by_key(|(_assigned_chirho, coords_chirho)| coords_chirho.raft_id_chirho);
    let held_observer_chirho = placement_chirho.held_observer_node_chirho();
    let held_observer_coords_chirho = join_tenant_placement_node_chirho(
        &roster_chirho,
        held_observer_chirho,
        "TenantPlacementRosterHeldObserverInactiveChirho",
    )?;

    let mut members_chirho = assigned_chirho
        .iter()
        .map(|(_assigned_chirho, coords_chirho)| ElectorMemberChirho {
            raft_id_chirho: coords_chirho.raft_id_chirho,
            pubkey_chirho: coords_chirho.node_pubkey_hex_chirho.clone(),
            url_chirho: format!(
                "http://{}:{}",
                coords_chirho.mesh_ip_chirho, ELECTOR_PORT_CHIRHO
            ),
            learner_chirho: false,
        })
        .collect::<Vec<_>>();
    members_chirho.push(ElectorMemberChirho {
        raft_id_chirho: held_observer_coords_chirho.raft_id_chirho,
        pubkey_chirho: held_observer_coords_chirho.node_pubkey_hex_chirho.clone(),
        url_chirho: format!(
            "http://{}:{}",
            held_observer_coords_chirho.mesh_ip_chirho, ELECTOR_PORT_CHIRHO
        ),
        learner_chirho: true,
    });
    members_chirho.sort_by_key(|member_chirho| member_chirho.raft_id_chirho);
    let preferred_chirho = assigned_chirho
        .iter()
        .find(|(assigned_chirho, _coords_chirho)| {
            assigned_chirho.node_id_chirho == placement_chirho.preferred_node_chirho()
        })
        .ok_or_else(|| anyhow!("TenantPlacementRosterPreferredNodeRefusedChirho"))?;
    let evidence_chirho = TenantPlacementRosterJoinEvidenceChirho {
        placement_assignment_digest_chirho: placement_chirho.assignment_digest_chirho().to_string(),
        assigned_node_ids_chirho: assigned_chirho
            .iter()
            .map(|(assigned_chirho, _coords_chirho)| assigned_chirho.node_id_chirho.clone())
            .collect(),
        assigned_raft_ids_chirho: assigned_chirho
            .iter()
            .map(|(_assigned_chirho, coords_chirho)| coords_chirho.raft_id_chirho)
            .collect(),
        held_observer_node_id_chirho: held_observer_chirho.node_id_chirho.clone(),
        held_observer_raft_id_chirho: held_observer_coords_chirho.raft_id_chirho,
        preferred_node_id_chirho: preferred_chirho.0.node_id_chirho.clone(),
        preferred_raft_id_chirho: preferred_chirho.1.raft_id_chirho,
        local_node_assigned_chirho: placement_chirho
            .assigned_node_chirho(local_node_pubkey_hex_chirho)
            .is_some(),
        local_node_held_observer_chirho: held_observer_chirho.node_id_chirho
            == local_node_pubkey_hex_chirho,
    };
    Ok((
        DerivedElectorConfigChirho {
            local_raft_id_chirho: local_coords_chirho.raft_id_chirho,
            members_chirho,
            listen_addr_chirho: format!(
                "{}:{}",
                local_coords_chirho.mesh_ip_chirho, ELECTOR_PORT_CHIRHO
            ),
        },
        evidence_chirho,
    ))
}

fn join_tenant_placement_node_chirho<'a>(
    roster_chirho: &'a VerifiedActiveRosterChirho,
    placement_node_chirho: &TenantPlacementNodeBindingChirho,
    inactive_refusal_chirho: &str,
) -> Result<&'a VerifiedNodeNetworkChirho> {
    let coords_chirho = roster_chirho
        .sorted_active_chirho
        .iter()
        .find(|coords_chirho| {
            coords_chirho.node_pubkey_hex_chirho == placement_node_chirho.node_id_chirho
        })
        .ok_or_else(|| {
            anyhow!(
                "{inactive_refusal_chirho}: {}",
                placement_node_chirho.node_id_chirho
            )
        })?;
    let roster_region_chirho = roster_chirho
        .membership_chirho
        .region_of_chirho(&placement_node_chirho.node_id_chirho)
        .ok_or_else(|| {
            anyhow!(
                "{inactive_refusal_chirho}: {}",
                placement_node_chirho.node_id_chirho
            )
        })?;
    if roster_region_chirho != placement_node_chirho.failure_domain_chirho.region_chirho {
        bail!(
            "TenantPlacementRosterRegionDisagreementChirho: {}",
            placement_node_chirho.node_id_chirho
        );
    }
    Ok(coords_chirho)
}

/// Derive this node's SECRET WireGuard config from the operator-signed roster, fail-closed. Shares the
/// exact verification/refusal path as the elector (`verify_and_order_active_roster_chirho`) and adds:
/// the A2-R2 local-key binding — the local private key's public half MUST equal this node's
/// operator-signed WG public key, else refuse (a mis-provisioned key whose peers would never handshake) —
/// and one `[Peer]` per OTHER active member in raft-id order (A2-R4). The returned config is SECRET (it
/// holds the private key): its only non-secret exhaust is [`WireguardConfigChirho::evidence_chirho`], and
/// it must be written only via [`write_secret_wireguard_config_chirho`] (mode 600).
pub fn derive_wireguard_config_chirho(
    roster_lines_chirho: &[Vec<u8>],
    roster_head_bytes_chirho: &[u8],
    operator_pubkey_hex_chirho: &str,
    local_node_pubkey_hex_chirho: &str,
    local_wg_private_key_chirho: &WgLocalPrivateKeyChirho,
) -> Result<WireguardConfigChirho> {
    let roster_chirho = verify_and_order_active_roster_chirho(
        roster_lines_chirho,
        roster_head_bytes_chirho,
        operator_pubkey_hex_chirho,
        local_node_pubkey_hex_chirho,
    )?;
    let local_coords_chirho = roster_chirho.local_coords_chirho(local_node_pubkey_hex_chirho);

    // A2-R2: bind the local private key to this node's operator-signed WG public key. A mismatch means a
    // mis-provisioned node whose [Interface] peers would never handshake — refuse (naming the node, never
    // printing any key material).
    let interface_pubkey_chirho = local_wg_private_key_chirho.derive_wg_pubkey_base64_chirho()?;
    if interface_pubkey_chirho != local_coords_chirho.wg_pubkey_chirho {
        bail!(
            "roster-config: the local WireGuard private key's public half does not match node {}'s operator-signed WireGuard public key; refusing (mis-provisioned key)",
            local_coords_chirho.node_pubkey_hex_chirho
        );
    }

    // The local [Interface] ListenPort is the port of this node's OWN operator-signed endpoint (the port
    // peers dial), so a signed custom port stays authoritative.
    let listen_port_chirho = parse_endpoint_port_chirho(&local_coords_chirho.endpoint_chirho)?;

    // Render [Interface] + one [Peer] per OTHER active member, peers in raft-id order (A2-R4) so two
    // derivations are byte-identical.
    let mut secret_text_chirho = String::new();
    secret_text_chirho.push_str("[Interface]\n");
    secret_text_chirho.push_str(&format!(
        "# cairn node raft id {} — DERIVED from the operator-signed roster; do not hand-edit\n",
        local_coords_chirho.raft_id_chirho
    ));
    secret_text_chirho.push_str(&format!(
        "PrivateKey = {}\n",
        local_wg_private_key_chirho.base64_chirho.as_str()
    ));
    secret_text_chirho.push_str(&format!(
        "Address = {}/32\n",
        local_coords_chirho.mesh_ip_chirho
    ));
    secret_text_chirho.push_str(&format!("ListenPort = {listen_port_chirho}\n"));

    let mut peer_count_chirho = 0usize;
    for coords_chirho in &roster_chirho.sorted_active_chirho {
        if coords_chirho.node_pubkey_hex_chirho == local_node_pubkey_hex_chirho {
            continue;
        }
        secret_text_chirho.push_str("\n[Peer]\n");
        secret_text_chirho.push_str(&format!("# raft id {}\n", coords_chirho.raft_id_chirho));
        secret_text_chirho.push_str(&format!("PublicKey = {}\n", coords_chirho.wg_pubkey_chirho));
        secret_text_chirho.push_str(&format!(
            "AllowedIPs = {}/32\n",
            coords_chirho.mesh_ip_chirho
        ));
        secret_text_chirho.push_str(&format!("Endpoint = {}\n", coords_chirho.endpoint_chirho));
        secret_text_chirho.push_str(&format!(
            "PersistentKeepalive = {WG_KEEPALIVE_SECS_CHIRHO}\n"
        ));
        peer_count_chirho += 1;
    }

    Ok(WireguardConfigChirho {
        secret_text_chirho: Zeroizing::new(secret_text_chirho),
        interface_pubkey_chirho,
        mesh_ip_chirho: local_coords_chirho.mesh_ip_chirho.clone(),
        listen_port_chirho,
        peer_count_chirho,
    })
}

/// Parse the UDP port from a WireGuard endpoint (`host:port` or `[v6]:port`). A signed endpoint without a
/// parseable port is a malformed roster row — fail closed.
fn parse_endpoint_port_chirho(endpoint_chirho: &str) -> Result<u16> {
    endpoint_chirho
        .rsplit_once(':')
        .and_then(|(_host_chirho, port_chirho)| port_chirho.parse::<u16>().ok())
        .ok_or_else(|| {
            anyhow!("roster-config: endpoint {endpoint_chirho} has no parseable UDP port; refusing")
        })
}

/// Write a rendered WireGuard config to `path_chirho` as a SECRET file, mode 0600 (owner read/write
/// only). The config holds the WG private key, so it must never be group/world readable (A2-R3).
#[cfg(unix)]
pub fn write_secret_wireguard_config_chirho(
    path_chirho: &std::path::Path,
    config_chirho: &WireguardConfigChirho,
) -> Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let mut file_chirho = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path_chirho)
        .map_err(|e_chirho| {
            anyhow!(
                "roster-config: open {} for secret write: {e_chirho}",
                path_chirho.display()
            )
        })?;
    file_chirho
        .write_all(config_chirho.secret_config_text_chirho().as_bytes())
        .map_err(|e_chirho| {
            anyhow!("roster-config: write {}: {e_chirho}", path_chirho.display())
        })?;
    // Enforce exactly 0600 regardless of the process umask (the create mode is masked by umask).
    std::fs::set_permissions(path_chirho, std::fs::Permissions::from_mode(0o600)).map_err(
        |e_chirho| {
            anyhow!(
                "roster-config: chmod 600 {}: {e_chirho}",
                path_chirho.display()
            )
        },
    )?;
    Ok(())
}

/// Derive the operator-chosen PREFERRED write leader for a consistency group, fail-closed. This is the
/// A1.4 re-home target: the transfer-back driver moves leadership to this node when it is a caught-up
/// healthy voter (L.J.'s "the write primary moves back to the primary audience's home on heal").
///
/// `group_id_chirho` is the group's canonical id string (from
/// `ConsistencyGroupIdChirho::canonical_id_chirho`, the ONE shared conversion). Trusts the
/// preferred-leader records ONLY after WHOLE-LOG integrity (the same head length-witness + operator-
/// signature path the elector config uses). Returns `Ok(None)` when the operator has signed no preference
/// for this group (the driver leaves leadership where it is), and FAILS CLOSED if a preference EXISTS but
/// names a raft id that is not an active member — a config error that must never drive a bad re-home.
pub fn derive_preferred_leader_chirho(
    roster_lines_chirho: &[Vec<u8>],
    roster_head_bytes_chirho: &[u8],
    operator_pubkey_hex_chirho: &str,
    local_node_pubkey_hex_chirho: &str,
    group_id_chirho: &str,
) -> Result<Option<u64>> {
    // Whole-log integrity FIRST (the A2 slice-2 constraint, extended to A1.4): the verified active set,
    // gated by the head length-witness + operator signatures over the SAME lines.
    let roster_chirho = verify_and_order_active_roster_chirho(
        roster_lines_chirho,
        roster_head_bytes_chirho,
        operator_pubkey_hex_chirho,
        local_node_pubkey_hex_chirho,
    )?;
    // The preferred-leader records from those same head-verified lines (operator-sig-checked,
    // latest-per-group).
    let preferred_chirho =
        verify_preferred_leader_records_chirho(roster_lines_chirho, operator_pubkey_hex_chirho)?;
    let Some(choice_chirho) = preferred_chirho.get(group_id_chirho) else {
        // No signed preference for this group — the driver leaves leadership where it is.
        return Ok(None);
    };
    // Fail-closed: a preference that names a non-member is a config error — never drive a re-home to a
    // node that is not an active, fully-provisioned member of the target.
    let preferred_is_active_chirho =
        roster_chirho
            .sorted_active_chirho
            .iter()
            .any(|coords_chirho| {
                coords_chirho.raft_id_chirho == choice_chirho.preferred_leader_raft_id_chirho
            });
    if !preferred_is_active_chirho {
        bail!(
            "preferred-leader for group '{group_id_chirho}' is raft id {} which is not an active member; refusing (operator config error)",
            choice_chirho.preferred_leader_raft_id_chirho
        );
    }
    Ok(Some(choice_chirho.preferred_leader_raft_id_chirho))
}

#[cfg(test)]
mod tests_chirho;

#[cfg(test)]
mod tenant_placement_tests_chirho;
