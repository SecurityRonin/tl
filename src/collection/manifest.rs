use crate::collection::path::NormalizedPath;

#[derive(Debug, Default)]
pub struct ArtifactManifest {
    pub mft: Option<NormalizedPath>,
    pub mft_mirr: Option<NormalizedPath>,
    pub usnjrnl_j: Option<NormalizedPath>,
    pub usnjrnl_max: Option<NormalizedPath>,
    pub logfile: Option<NormalizedPath>,
    pub boot: Option<NormalizedPath>,
    pub secure_sds: Option<NormalizedPath>,
    pub registry_hives: Vec<RegistryHiveEntry>,
    pub event_logs: Vec<NormalizedPath>,
    pub prefetch: Vec<NormalizedPath>,
    pub lnk_files: Vec<NormalizedPath>,
    pub jump_lists_auto: Vec<NormalizedPath>,
    pub jump_lists_custom: Vec<NormalizedPath>,
    pub amcache: Vec<NormalizedPath>,
    pub recycle_bin: Vec<NormalizedPath>,
    pub scheduled_tasks: Vec<NormalizedPath>,
    pub srum: Vec<NormalizedPath>,
    pub wmi_repository: Vec<NormalizedPath>,
    pub all_paths: Vec<NormalizedPath>,
}

#[derive(Debug, Clone)]
pub struct RegistryHiveEntry {
    pub path: NormalizedPath,
    pub hive_type: RegistryHiveType,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RegistryHiveType {
    System,
    Software,
    Sam,
    Security,
    Default,
    NtUser { username: String },
    UsrClass { username: String },
    Amcache,
    Other(String),
}

impl ArtifactManifest {
    pub fn has_mft(&self) -> bool {
        self.mft.is_some()
    }

    pub fn has_usnjrnl(&self) -> bool {
        self.usnjrnl_j.is_some()
    }

    pub fn registry_hives(&self) -> &[RegistryHiveEntry] {
        &self.registry_hives
    }

    pub fn event_logs(&self) -> &[NormalizedPath] {
        &self.event_logs
    }

    pub fn prefetch_files(&self) -> &[NormalizedPath] {
        &self.prefetch
    }

    pub fn lnk_files(&self) -> &[NormalizedPath] {
        &self.lnk_files
    }
}
