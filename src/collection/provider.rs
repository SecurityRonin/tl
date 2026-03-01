use crate::collection::manifest::ArtifactManifest;
use crate::collection::path::NormalizedPath;
use anyhow::Result;

#[derive(Debug, Clone, Default)]
pub struct CollectionMetadata {
    pub hostname: String,
    pub collection_timestamp: String,
    pub source_tool: String,
}

pub trait CollectionProvider: Send + Sync {
    fn discover(&self) -> ArtifactManifest;
    fn open_file(&self, path: &NormalizedPath) -> Result<Vec<u8>>;
    fn metadata(&self) -> CollectionMetadata;
}
