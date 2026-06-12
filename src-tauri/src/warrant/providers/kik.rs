//! Stub: KIK warrant parser.
use std::path::Path;

use crate::warrant::{
    BucketTemplate, ParseError, ParsedReturn, Provider, WarrantParser,
};

pub struct KikWarrantParser;

impl WarrantParser for KikWarrantParser {
    fn provider(&self) -> Provider {
        Provider::Kik
    }

    fn accepts(&self, _path: &Path) -> Result<bool, ParseError> {
        Ok(false)
    }

    fn parse(&self, _path: &Path, _media_dir: &Path) -> Result<ParsedReturn, ParseError> {
        Err(ParseError::NotImplemented)
    }

    fn default_buckets(&self) -> Vec<BucketTemplate> {
        vec![
            BucketTemplate { name: "CSAM".into(), color: "#ef4444".into(), description: None },
            BucketTemplate { name: "Chats of Interest".into(), color: "#82C341".into(), description: None },
            BucketTemplate { name: "Group Activity".into(), color: "#6c8aed".into(), description: None },
            BucketTemplate { name: "Unrelated".into(), color: "#6b7280".into(), description: None },
            BucketTemplate { name: "Needs Follow-Up".into(), color: "#f59e0b".into(), description: None },
        ]
    }
}
