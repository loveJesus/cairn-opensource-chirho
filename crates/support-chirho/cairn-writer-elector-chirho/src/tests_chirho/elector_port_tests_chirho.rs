// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! The n=1 baseline satisfies the writer-election port: a one-voter group elects its sole member as
//! leader with a valid lease at term 1, for any consistency group, and reports the node's identity.

use crate::elector_port_chirho::{
    NodeIdChirho, SingleNodeWriterElectorChirho, WriterElectorChirho,
};
use cairn_writer_head_chirho::writer_head_chirho::ConsistencyGroupIdChirho;

#[test]
fn single_node_elector_is_leader_of_any_group_chirho() {
    let node_id_chirho = NodeIdChirho("a".repeat(64));
    let elector_chirho = SingleNodeWriterElectorChirho::new_chirho(node_id_chirho.clone());

    for group_chirho in [
        ConsistencyGroupIdChirho::RootPathChirho {
            canonical_root_chirho: "/var/lib/cairn-root-chirho".to_string(),
        },
        ConsistencyGroupIdChirho::TenantChirho {
            tenant_id_chirho: "tenant-alpha-chirho".to_string(),
        },
    ] {
        let leadership_chirho = elector_chirho.leadership_chirho(&group_chirho);
        assert!(
            leadership_chirho.is_leader_chirho,
            "the sole voter is the leader"
        );
        assert_eq!(
            leadership_chirho.leader_id_chirho.as_ref(),
            Some(&node_id_chirho)
        );
        assert_eq!(leadership_chirho.term_chirho, 1);
        assert!(
            leadership_chirho.lease_valid_chirho,
            "a one-voter group holds a trivially valid lease"
        );
    }
    assert_eq!(elector_chirho.node_id_chirho(), &node_id_chirho);
}
