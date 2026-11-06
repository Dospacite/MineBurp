//! Bounded assessment findings and durable references to evidence.
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingStatus {
    #[default]
    Open,
    Confirmed,
    FalsePositive,
    Fixed,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "snake_case")]
pub enum Evidence {
    Packet(i64),
    Connection(Uuid),
    Repeater(Uuid),
    Rule(Uuid),
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    #[serde(default)]
    pub id: Uuid,
    pub title: String,
    #[serde(default)]
    pub severity: Severity,
    #[serde(default)]
    pub status: FindingStatus,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub reproduction_steps: String,
    #[serde(default)]
    pub created_at_micros: i64,
    #[serde(default)]
    pub updated_at_micros: i64,
    #[serde(default)]
    pub evidence: Vec<Evidence>,
    #[serde(default)]
    pub tags: Vec<String>,
}
impl Finding {
    pub fn validate(&self) -> Result<(), String> {
        if self.title.trim().is_empty() || self.title.chars().count() > 200 {
            return Err("Title must contain 1–200 characters".into());
        }
        if self.description.len() > 65536
            || self.reproduction_steps.len() > 65536
            || self.tags.iter().map(String::len).sum::<usize>() > 65536
            || self.tags.len() > 500
        {
            return Err("Text exceeds finding limits".into());
        }
        if self.evidence.len() > 500 {
            return Err("At most 500 evidence links are allowed".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enforces_unicode_title_byte_text_and_evidence_limits() {
        let mut finding: Finding =
            serde_json::from_value(serde_json::json!({"title":"é".repeat(200)})).unwrap();
        assert!(finding.validate().is_ok());
        finding.title.push('é');
        assert!(finding.validate().is_err());
        finding.title = "Test".into();
        finding.description = "a".repeat(65536);
        assert!(finding.validate().is_ok());
        finding.description.push('a');
        assert!(finding.validate().is_err());
        finding.description.clear();
        finding.evidence = vec![Evidence::Packet(1); 500];
        assert!(finding.validate().is_ok());
        finding.evidence.push(Evidence::Packet(2));
        assert!(finding.validate().is_err());
    }
}
