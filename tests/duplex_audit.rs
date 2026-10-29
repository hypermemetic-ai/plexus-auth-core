//! BIDIR-8: every typed refusal of a duplex call is one audit record
//! (`AuditRecordKind::DuplexRefused { call, reason }`), handed to the sink
//! through a bounded queue: a full queue drops the record and counts it, and
//! never waits — the frame path is never held by the audit.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use plexus_auth_core::audit::{AuditQueue, AuditRecord, AuditRecordKind, AuditSink};
use plexus_auth_core::duplex::{CallRef, DuplexRefusalCode};
use plexus_auth_core::AuthContext;
use serde_json::Value;

const ADA: &str = "key:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[derive(Default)]
struct Kept(Mutex<Vec<AuditRecord>>);
#[async_trait]
impl AuditSink for Kept {
    async fn write(&self, record: AuditRecord) {
        self.0.lock().unwrap().push(record);
    }
}

const EVERY: [DuplexRefusalCode; 8] = [
    DuplexRefusalCode::Forbidden,
    DuplexRefusalCode::Unauthenticated,
    DuplexRefusalCode::TooManyCalls,
    DuplexRefusalCode::NotThisCall,
    DuplexRefusalCode::PastCredit,
    DuplexRefusalCode::TooMuchInput,
    DuplexRefusalCode::PersonRequired,
    DuplexRefusalCode::InputClosed,
];

#[tokio::test]
async fn each_refusal_is_one_record_off_the_frame_path() {
    let sink = Arc::new(Kept::default());
    let (queue, drain) = AuditQueue::new(64, sink.clone());
    let drained = tokio::spawn(drain);
    let ada = AuthContext::for_principal(&ADA.parse().unwrap(), "sess-ada", vec![], Value::Null);
    for (i, code) in EVERY.into_iter().enumerate() {
        let call = CallRef { conn: 7, subscription: i as u64 };
        assert!(queue.offer(AuditRecord::duplex_refused(call, code, Some(&ada), "runs.append_log")), "{code:?} taken");
    }
    drop(queue);
    drained.await.unwrap();
    let kept = sink.0.lock().unwrap();
    assert_eq!(kept.len(), EVERY.len(), "exactly one record per refusal");
    for (i, (r, code)) in kept.iter().zip(EVERY).enumerate() {
        assert_eq!(r.kind, AuditRecordKind::DuplexRefused { call: CallRef { conn: 7, subscription: i as u64 }, reason: code });
        assert_eq!(r.method.as_str(), "runs.append_log");
        assert_eq!(r.originator.as_ref().map(|u| u.as_str()), Some(ADA), "who was refused");
        assert!(matches!(r.decision, plexus_auth_core::audit::AuditDecision::Deny { .. }));
        // The code goes on the record as its wire spelling.
        let json = serde_json::to_value(&r.kind).unwrap();
        assert_eq!(json["duplex_refused"]["reason"], code.as_str(), "{json}");
    }
}

/// A sink that never finishes a write: the queue fills behind it.
struct Stuck;
#[async_trait]
impl AuditSink for Stuck {
    async fn write(&self, _: AuditRecord) {
        std::future::pending::<()>().await
    }
}

#[tokio::test]
async fn a_full_queue_drops_and_counts_and_never_waits() {
    let (queue, drain) = AuditQueue::new(4, Arc::new(Stuck));
    let _drain = tokio::spawn(drain);
    let call = CallRef { conn: 1, subscription: 1 };
    let at = Instant::now();
    let taken = (0..1000).filter(|_| queue.offer(AuditRecord::duplex_refused(call, DuplexRefusalCode::PastCredit, None, "runs.append_log"))).count();
    let took = at.elapsed();
    // At most the capacity plus the one the stuck sink holds.
    assert!(taken <= 5, "taken {taken}");
    assert_eq!(queue.dropped(), 1000 - taken as u64, "every one not taken is counted");
    assert!(took < Duration::from_millis(50), "never waits: {took:?} for 1,000 offers");
}

#[test]
fn the_old_kinds_read_as_they_did() {
    // Additive: a record written before BIDIR-8 still reads.
    let k: AuditRecordKind = serde_json::from_str("\"scope_check\"").unwrap();
    assert_eq!(k, AuditRecordKind::ScopeCheck);
    let k: AuditRecordKind = serde_json::from_str("\"forward_policy_applied\"").unwrap();
    assert_eq!(k, AuditRecordKind::ForwardPolicyApplied);
}
