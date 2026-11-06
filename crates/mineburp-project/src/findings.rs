//! Findings are independent of history rows, so deleting traffic preserves references.
use crate::{ProjectError, ProjectStore, store::now_micros};
use mineburp_core::{Evidence, Finding, FindingStatus, Severity};
use rusqlite::{OptionalExtension, params};
use uuid::Uuid;
impl ProjectStore {
    pub fn list_findings(
        &self,
        status: Option<FindingStatus>,
        severity: Option<Severity>,
    ) -> Result<Vec<Finding>, ProjectError> {
        self.with_reader(|db| {
            let mut statement =
                db.prepare("SELECT payload_json FROM findings ORDER BY rowid DESC")?;
            let rows = statement.query_map([], |r| r.get::<_, String>(0))?;
            let mut findings = Vec::new();
            for row in rows {
                let f: Finding = serde_json::from_str(&row?)
                    .map_err(|e| ProjectError::Corrupt(e.to_string()))?;
                if status.is_none_or(|s| s == f.status) && severity.is_none_or(|s| s == f.severity)
                {
                    findings.push(f);
                }
            }
            Ok(findings)
        })
    }
    pub fn get_finding(&self, id: Uuid) -> Result<Option<Finding>, ProjectError> {
        self.with_reader(|db| {
            let text: Option<String> = db
                .query_row(
                    "SELECT payload_json FROM findings WHERE id=?1",
                    [id.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            text.map(|s| serde_json::from_str(&s).map_err(|e| ProjectError::Corrupt(e.to_string())))
                .transpose()
        })
    }
    pub fn create_finding(&self, mut finding: Finding) -> Result<Finding, ProjectError> {
        self.ensure_writable()?;
        finding.validate().map_err(ProjectError::Corrupt)?;
        finding.id = Uuid::new_v4();
        finding.created_at_micros = now_micros();
        finding.updated_at_micros = finding.created_at_micros;
        self.connection.lock().execute(
            "INSERT INTO findings(id,payload_json) VALUES(?1,?2)",
            params![
                finding.id.to_string(),
                serde_json::to_string(&finding)
                    .map_err(|e| ProjectError::Corrupt(e.to_string()))?
            ],
        )?;
        Ok(finding)
    }
    pub fn update_finding(&self, finding: Finding) -> Result<Finding, ProjectError> {
        self.mutate_finding(finding.id, |old| {
            let created = old.created_at_micros;
            *old = finding;
            old.created_at_micros = created;
        })
    }
    fn mutate_finding(
        &self,
        id: Uuid,
        change: impl FnOnce(&mut Finding),
    ) -> Result<Finding, ProjectError> {
        self.ensure_writable()?;
        let mut db = self.connection.lock();
        let tx = db.transaction()?;
        let text: String = tx.query_row(
            "SELECT payload_json FROM findings WHERE id=?1",
            [id.to_string()],
            |r| r.get(0),
        )?;
        let mut finding: Finding =
            serde_json::from_str(&text).map_err(|e| ProjectError::Corrupt(e.to_string()))?;
        change(&mut finding);
        finding.validate().map_err(ProjectError::Corrupt)?;
        finding.updated_at_micros = now_micros();
        tx.execute(
            "UPDATE findings SET payload_json=?2 WHERE id=?1",
            params![
                id.to_string(),
                serde_json::to_string(&finding)
                    .map_err(|e| ProjectError::Corrupt(e.to_string()))?
            ],
        )?;
        tx.commit()?;
        Ok(finding)
    }
    pub fn delete_finding(&self, id: Uuid) -> Result<(), ProjectError> {
        self.ensure_writable()?;
        self.connection
            .lock()
            .execute("DELETE FROM findings WHERE id=?1", [id.to_string()])?;
        Ok(())
    }
    pub fn add_finding_evidence(
        &self,
        id: Uuid,
        evidence: Evidence,
    ) -> Result<Finding, ProjectError> {
        self.mutate_finding(id, |f| {
            if !f.evidence.contains(&evidence) {
                f.evidence.push(evidence);
            }
        })
    }
    pub fn remove_finding_evidence(
        &self,
        id: Uuid,
        evidence: &Evidence,
    ) -> Result<Finding, ProjectError> {
        self.mutate_finding(id, |f| f.evidence.retain(|e| e != evidence))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ProjectOptions;
    fn fixture() -> Finding {
        Finding {
            id: Uuid::nil(),
            title: "Test".into(),
            severity: Severity::High,
            status: FindingStatus::Open,
            description: String::new(),
            reproduction_steps: String::new(),
            created_at_micros: 0,
            updated_at_micros: 0,
            evidence: vec![],
            tags: vec![],
        }
    }
    #[test]
    fn migrates_v6_and_preserves_dangling_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("findings.mineburp");
        let store = ProjectStore::create(&path, "Findings", ProjectOptions::default()).unwrap();
        store
            .connection
            .lock()
            .execute_batch("DROP TABLE findings; PRAGMA user_version=6;")
            .unwrap();
        drop(store);
        let store = ProjectStore::open(&path, ProjectOptions::default()).unwrap();
        assert_eq!(store.info().schema_version, 8);
        let f = store.create_finding(fixture()).unwrap();
        let evidence = Evidence::Packet(99999);
        store.add_finding_evidence(f.id, evidence.clone()).unwrap();
        store.add_finding_evidence(f.id, evidence.clone()).unwrap();
        assert_eq!(store.get_finding(f.id).unwrap().unwrap().evidence.len(), 1);
        assert!(store.packet_detail(99999).unwrap().is_none());
        assert_eq!(
            store
                .list_findings(Some(FindingStatus::Open), Some(Severity::High))
                .unwrap()
                .len(),
            1
        );
        assert!(
            store
                .list_findings(None, Some(Severity::Low))
                .unwrap()
                .is_empty()
        );
        let mut updated = store.get_finding(f.id).unwrap().unwrap();
        updated.title = "Updated".into();
        assert_eq!(store.update_finding(updated).unwrap().title, "Updated");
        store.remove_finding_evidence(f.id, &evidence).unwrap();
        assert!(
            store
                .get_finding(f.id)
                .unwrap()
                .unwrap()
                .evidence
                .is_empty()
        );
        let mut invalid = fixture();
        invalid.title = "x".repeat(201);
        assert!(store.create_finding(invalid).is_err());
        store.delete_finding(f.id).unwrap();
        assert!(store.get_finding(f.id).unwrap().is_none());
    }
}
