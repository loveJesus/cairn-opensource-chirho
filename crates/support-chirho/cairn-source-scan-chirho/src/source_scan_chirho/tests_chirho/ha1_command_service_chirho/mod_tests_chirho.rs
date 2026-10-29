// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Subscription control-plane guards. The CLI-independence layering guards for the dag/report/
//! status command services were demoted to the advisory structure report (dependency-direction
//! shape, no authority/effect claim).

use super::*;

#[path = "subscription_view_review_guard_tests_chirho.rs"]
mod subscription_view_review_guard_tests_chirho;

#[path = "subscription_control_plane_guard_tests_chirho.rs"]
mod subscription_control_plane_guard_tests_chirho;

#[path = "subscription_cursor_guard_tests_chirho.rs"]
mod subscription_cursor_guard_tests_chirho;
