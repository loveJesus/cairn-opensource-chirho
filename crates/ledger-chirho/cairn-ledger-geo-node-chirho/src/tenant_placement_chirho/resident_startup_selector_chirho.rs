// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Exhaustive production selection between resident and transport-only startup.
//!
//! The elector decides the role. This selector decides whether that role is allowed to invoke the
//! sole resident opener; it grants no election, journal, mirror, or effect authority itself.

use super::{GeoNonResidentVoterRoleChirho, GeoVoterStartupRoleChirho};
use anyhow::Result;

pub(super) enum GeoResidentStartupSelectionChirho<ResidentChirho> {
    LocalWarmOwnerChirho(ResidentChirho),
    NonResidentChirho(GeoNonResidentVoterRoleChirho),
}

pub(super) fn select_geo_resident_startup_chirho<ResidentChirho>(
    role_chirho: GeoVoterStartupRoleChirho,
    open_resident_chirho: impl FnOnce() -> Result<ResidentChirho>,
) -> Result<GeoResidentStartupSelectionChirho<ResidentChirho>> {
    match role_chirho {
        GeoVoterStartupRoleChirho::LocalWarmOwnerChirho => Ok(
            GeoResidentStartupSelectionChirho::LocalWarmOwnerChirho(open_resident_chirho()?),
        ),
        GeoVoterStartupRoleChirho::NonResidentChirho(role_chirho) => Ok(
            GeoResidentStartupSelectionChirho::NonResidentChirho(role_chirho),
        ),
    }
}

#[cfg(test)]
mod tests_chirho {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn production_selector_opens_only_the_local_warm_owner_chirho() {
        let local_open_count_chirho = Cell::new(0_u8);
        let local_chirho = select_geo_resident_startup_chirho(
            GeoVoterStartupRoleChirho::LocalWarmOwnerChirho,
            || {
                local_open_count_chirho.set(local_open_count_chirho.get() + 1);
                Ok(41_u8)
            },
        )
        .unwrap();
        let GeoResidentStartupSelectionChirho::LocalWarmOwnerChirho(value_chirho) = local_chirho
        else {
            panic!("production selector must preserve the local warm-owner role");
        };
        assert_eq!(value_chirho, 41);
        assert_eq!(local_open_count_chirho.get(), 1);

        for role_chirho in [
            GeoNonResidentVoterRoleChirho::RemoteOwnerChirho,
            GeoNonResidentVoterRoleChirho::RetiringTransportOnlyChirho,
        ] {
            let nonresident_open_count_chirho = Cell::new(0_u8);
            let selected_chirho = select_geo_resident_startup_chirho(
                GeoVoterStartupRoleChirho::NonResidentChirho(role_chirho),
                || {
                    nonresident_open_count_chirho.set(nonresident_open_count_chirho.get() + 1);
                    Ok(99_u8)
                },
            )
            .unwrap();
            let GeoResidentStartupSelectionChirho::NonResidentChirho(selected_role_chirho) =
                selected_chirho
            else {
                panic!("production selector must preserve the nonresident role");
            };
            assert_eq!(selected_role_chirho, role_chirho);
            assert_eq!(nonresident_open_count_chirho.get(), 0);
        }
    }
}
