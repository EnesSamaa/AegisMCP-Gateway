//! High-throughput append-only audit ledger with lock-free mpsc queue.

use aegis_core::AuditEntry;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// High-throughput async append-only ledger for cryptographic audit records.
#[derive(Clone)]
pub struct AuditLedger {
    next_seq: Arc<AtomicU64>,
    tx: mpsc::UnboundedSender<AuditEntry>,
    entries: Arc<RwLock<Vec<AuditEntry>>>,
    by_request_id: Arc<RwLock<HashMap<String, usize>>>,
}

impl AuditLedger {
    /// Creates a new `AuditLedger` spawning a background persistence worker loop.
    #[must_use]
    pub fn new() -> Self {
        let (tx, mut rx) = mpsc::unbounded_channel::<AuditEntry>();
        let entries = Arc::new(RwLock::new(Vec::new()));
        let by_request_id = Arc::new(RwLock::new(HashMap::new()));
        let next_seq = Arc::new(AtomicU64::new(1));

        let entries_clone = Arc::clone(&entries);
        let req_index_clone = Arc::clone(&by_request_id);

        tokio::spawn(async move {
            while let Some(entry) = rx.recv().await {
                let mut list = entries_clone.write().await;
                let idx = list.len();
                req_index_clone
                    .write()
                    .await
                    .insert(entry.request_id.clone(), idx);
                list.push(entry);
            }
        });

        Self {
            next_seq,
            tx,
            entries,
            by_request_id,
        }
    }

    /// Asynchronously logs an audit entry without blocking HTTP proxy forwarding.
    pub fn log_entry(
        &self,
        request_id: impl Into<String>,
        timestamp_ns: u64,
        agent_id: impl Into<String>,
        tool_name: impl Into<String>,
        policy_decision: impl Into<String>,
        execution_time_us: u64,
    ) {
        let seq = self.next_seq.fetch_add(1, Ordering::SeqCst);
        let entry = AuditEntry::new(
            seq,
            request_id,
            timestamp_ns,
            agent_id,
            tool_name,
            policy_decision,
            execution_time_us,
        );

        let _ = self.tx.send(entry);
    }

    /// Appends a pre-constructed [`AuditEntry`] into the ledger queue.
    pub fn log(&self, mut entry: AuditEntry) {
        if entry.seq_id == 0 {
            entry.seq_id = self.next_seq.fetch_add(1, Ordering::SeqCst);
        }
        let _ = self.tx.send(entry);
    }

    /// Retrieves an entry by its sequence ID (`seq_id`).
    pub async fn get_by_seq(&self, seq_id: u64) -> Option<AuditEntry> {
        let list = self.entries.read().await;
        list.iter().find(|e| e.seq_id == seq_id).cloned()
    }

    /// Retrieves an entry by its unique `request_id`.
    pub async fn get_by_request_id(&self, request_id: &str) -> Option<AuditEntry> {
        let req_map = self.by_request_id.read().await;
        if let Some(&idx) = req_map.get(request_id) {
            let list = self.entries.read().await;
            list.get(idx).cloned()
        } else {
            None
        }
    }

    /// Returns the total number of logged audit entries in the ledger.
    pub async fn len(&self) -> usize {
        let list = self.entries.read().await;
        list.len()
    }

    /// Checks if the ledger contains any entries.
    pub async fn is_empty(&self) -> bool {
        self.len().await == 0
    }
}

impl Default for AuditLedger {
    fn default() -> Self {
        Self::new()
    }
}
