// For God so loved the world, that he gave his only begotten Son, that whosoever believeth in him should not perish, but have everlasting life. - John 3:16 (KJV)

//! Shutdown behavior for a full bounded resident mailbox.
use super::*;

#[test]
fn full_mailbox_with_derived_sender_cannot_lose_shutdown_chirho() {
    let (command_sender_chirho, command_receiver_chirho) = sync_channel(1);
    let derived_sender_chirho = command_sender_chirho.clone();
    let (reply_sender_chirho, _reply_receiver_chirho) = sync_channel(1);
    command_sender_chirho
        .send(ResidentEffectJournalCommandChirho::EffectIntentCutChirho {
            reply_chirho: reply_sender_chirho,
        })
        .expect("fill the bounded mailbox before shutdown");

    let actor_thread_chirho = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(25));
        assert!(matches!(
            command_receiver_chirho.recv(),
            Ok(ResidentEffectJournalCommandChirho::EffectIntentCutChirho { .. })
        ));
        assert!(matches!(
            command_receiver_chirho.recv(),
            Ok(ResidentEffectJournalCommandChirho::ShutdownChirho)
        ));
    });
    let (completion_sender_chirho, completion_receiver_chirho) = sync_channel(1);
    std::thread::spawn(move || {
        shutdown_resident_effect_journal_actor_chirho(
            Some(command_sender_chirho),
            Some(actor_thread_chirho),
        );
        let _completion_result_chirho = completion_sender_chirho.send(());
    });

    completion_receiver_chirho
        .recv_timeout(Duration::from_secs(1))
        .expect("blocking shutdown send survives mailbox backpressure");
    drop(derived_sender_chirho);
}
