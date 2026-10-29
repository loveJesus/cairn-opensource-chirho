// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

use super::*;
use crate::tests_chirho::{elector_for_root_chirho, temp_root_chirho};
use cairn_writer_head_chirho::run_admission_authority_chirho::RunAdmissionCommitScopeChirho;
use cairn_writer_head_chirho::writer_head_chirho::issue_elected_writer_fence_for_root_chirho;

struct ProbeActionChirho<'probe_chirho> {
    root_chirho: &'probe_chirho Path,
    handle_chirho: &'probe_chirho LocalAppendAuthorityHandleChirho,
    calls_chirho: usize,
    refuse_chirho: bool,
}

impl RunAdmissionCommitActionChirho for ProbeActionChirho<'_> {
    fn call_chirho(&mut self, scope_chirho: RunAdmissionCommitScopeChirho<'_>) -> Result<()> {
        self.calls_chirho += 1;
        scope_chirho.validate_sink_chirho(self.root_chirho)?;
        assert!(
            matches!(
                self.handle_chirho.try_acquire_chirho(),
                Err(LocalAppendAuthorityRefusalChirho::GuardBusyChirho)
            ),
            "the generation must remain held through the durable sink"
        );
        if self.refuse_chirho {
            anyhow::bail!("ProbeSinkRefusedChirho");
        }
        Ok(())
    }
}

#[test]
fn admission_retains_the_real_generation_and_releases_it_after_refusal_chirho() {
    let root_chirho = temp_root_chirho("run-admission-held");
    let elector_chirho = elector_for_root_chirho(&root_chirho, true);
    issue_elected_writer_fence_for_root_chirho(&root_chirho, 1).unwrap();
    let handle_chirho = elector_chirho.local_append_authority_handle_chirho();
    let adapter_chirho =
        ElectedHeadTransitionAdapterChirho::new_chirho(&root_chirho, handle_chirho.clone())
            .unwrap();
    let mut action_chirho = ProbeActionChirho {
        root_chirho: &root_chirho,
        handle_chirho: &handle_chirho,
        calls_chirho: 0,
        refuse_chirho: true,
    };
    assert!(adapter_chirho
        .with_elected_run_admission_scope_chirho(&root_chirho, &mut action_chirho)
        .is_err());
    assert_eq!(action_chirho.calls_chirho, 1);
    assert!(handle_chirho.try_acquire_chirho().is_ok());
    action_chirho.refuse_chirho = false;
    adapter_chirho
        .with_elected_run_admission_scope_chirho(&root_chirho, &mut action_chirho)
        .unwrap();
    assert_eq!(action_chirho.calls_chirho, 2);
    std::fs::remove_dir_all(root_chirho).unwrap();
}

#[test]
fn an_unwarmed_or_dropped_elector_never_enters_admission_chirho() {
    for warm_chirho in [false, true] {
        let root_chirho = temp_root_chirho("run-admission-no-authority");
        let elector_chirho = elector_for_root_chirho(&root_chirho, warm_chirho);
        issue_elected_writer_fence_for_root_chirho(&root_chirho, 1).unwrap();
        let handle_chirho = elector_chirho.local_append_authority_handle_chirho();
        let adapter_chirho =
            ElectedHeadTransitionAdapterChirho::new_chirho(&root_chirho, handle_chirho.clone())
                .unwrap();
        if warm_chirho {
            drop(elector_chirho);
        }
        let mut action_chirho = ProbeActionChirho {
            root_chirho: &root_chirho,
            handle_chirho: &handle_chirho,
            calls_chirho: 0,
            refuse_chirho: false,
        };
        assert!(adapter_chirho
            .with_elected_run_admission_scope_chirho(&root_chirho, &mut action_chirho)
            .is_err());
        assert_eq!(action_chirho.calls_chirho, 0);
        std::fs::remove_dir_all(root_chirho).unwrap();
    }
}
