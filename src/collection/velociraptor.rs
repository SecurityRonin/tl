use crate::collection::manifest::*;
use crate::collection::path::*;
use crate::collection::provider::*;
use anyhow::{Context, Result};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use zip::ZipArchive;

pub struct VelociraptorProvider {
    zip_path: PathBuf,
    manifest: ArtifactManifest,
    meta: CollectionMetadata,
}

impl VelociraptorProvider {
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open collection: {}", path.display()))?;
        let mut archive =
            ZipArchive::new(file).context("Failed to read zip archive")?;

        let mut manifest = ArtifactManifest::default();

        // Scan all entries and classify
        for i in 0..archive.len() {
            let entry = archive.by_index(i)?;
            let zip_path = entry.name().to_string();

            if let Some(norm) = normalize_velociraptor_path(&zip_path) {
                classify_artifact(&norm, &mut manifest);
                manifest.all_paths.push(norm);
            }
        }

        // Extract metadata from filename
        let meta = extract_metadata_from_filename(path);

        Ok(Self {
            zip_path: path.to_path_buf(),
            manifest,
            meta,
        })
    }
}

impl CollectionProvider for VelociraptorProvider {
    fn discover(&self) -> ArtifactManifest {
        let mut m = ArtifactManifest::default();
        for p in &self.manifest.all_paths {
            classify_artifact(p, &mut m);
        }
        m.all_paths = self.manifest.all_paths.clone();
        m
    }

    fn open_file(&self, path: &NormalizedPath) -> Result<Vec<u8>> {
        let file = File::open(&self.zip_path)?;
        let mut archive = ZipArchive::new(file)?;
        let mut entry = archive.by_name(path.original_zip_path())?;
        let mut buf = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut buf)?;
        Ok(buf)
    }

    fn metadata(&self) -> CollectionMetadata {
        self.meta.clone()
    }
}

fn classify_artifact(path: &NormalizedPath, manifest: &mut ArtifactManifest) {
    let win = path.windows_path();
    let lower = win.to_lowercase();

    // NTFS core artifacts
    if lower.ends_with(r"\$mft") && !lower.contains("mftmirr") {
        manifest.mft = Some(path.clone());
    } else if lower.ends_with(r"\$mftmirr") {
        manifest.mft_mirr = Some(path.clone());
    } else if lower.ends_with("$usnjrnl:$j") || lower.ends_with("$usnjrnl%3a$j") {
        manifest.usnjrnl_j = Some(path.clone());
    } else if lower.ends_with("$usnjrnl:$max") || lower.ends_with("$usnjrnl%3a$max") {
        manifest.usnjrnl_max = Some(path.clone());
    } else if lower.ends_with(r"\$logfile") {
        manifest.logfile = Some(path.clone());
    } else if lower.ends_with(r"\$boot") {
        manifest.boot = Some(path.clone());
    } else if lower.ends_with("$secure:$sds") || lower.ends_with("$secure%3a$sds") {
        manifest.secure_sds = Some(path.clone());
    }
    // Event logs
    else if lower.ends_with(".evtx") {
        manifest.event_logs.push(path.clone());
    }
    // Prefetch
    else if lower.ends_with(".pf") && lower.contains("prefetch") {
        manifest.prefetch.push(path.clone());
    }
    // LNK files
    else if lower.ends_with(".lnk") {
        manifest.lnk_files.push(path.clone());
    }
    // Jump Lists
    else if lower.ends_with(".automaticdestinations-ms") {
        manifest.jump_lists_auto.push(path.clone());
    } else if lower.ends_with(".customdestinations-ms") {
        manifest.jump_lists_custom.push(path.clone());
    }
    // Registry hives — Amcache (must be before generic registry checks)
    else if lower.ends_with("amcache.hve") {
        manifest.amcache.push(path.clone());
        manifest.registry_hives.push(RegistryHiveEntry {
            path: path.clone(),
            hive_type: RegistryHiveType::Amcache,
        });
    }
    // Registry hives — SYSTEM
    else if lower.ends_with(r"\system") && lower.contains("config") {
        manifest.registry_hives.push(RegistryHiveEntry {
            path: path.clone(),
            hive_type: RegistryHiveType::System,
        });
    }
    // Registry hives — SOFTWARE
    else if lower.ends_with(r"\software") && lower.contains("config") {
        manifest.registry_hives.push(RegistryHiveEntry {
            path: path.clone(),
            hive_type: RegistryHiveType::Software,
        });
    }
    // Registry hives — SAM
    else if lower.ends_with(r"\sam") && lower.contains("config") {
        manifest.registry_hives.push(RegistryHiveEntry {
            path: path.clone(),
            hive_type: RegistryHiveType::Sam,
        });
    }
    // Registry hives — SECURITY
    else if lower.ends_with(r"\security") && lower.contains("config") {
        manifest.registry_hives.push(RegistryHiveEntry {
            path: path.clone(),
            hive_type: RegistryHiveType::Security,
        });
    }
    // Registry hives — DEFAULT
    else if lower.ends_with(r"\default") && lower.contains("config") {
        manifest.registry_hives.push(RegistryHiveEntry {
            path: path.clone(),
            hive_type: RegistryHiveType::Default,
        });
    }
    // Registry hives — NTUSER.DAT
    else if lower.ends_with("ntuser.dat") {
        let username = extract_username_from_path(win);
        manifest.registry_hives.push(RegistryHiveEntry {
            path: path.clone(),
            hive_type: RegistryHiveType::NtUser { username },
        });
    }
    // Registry hives — UsrClass.dat
    else if lower.ends_with("usrclass.dat") {
        let username = extract_username_from_path(win);
        manifest.registry_hives.push(RegistryHiveEntry {
            path: path.clone(),
            hive_type: RegistryHiveType::UsrClass { username },
        });
    }
    // Recycle Bin
    else if lower.contains("$recycle.bin") && lower.contains("$i") {
        manifest.recycle_bin.push(path.clone());
    }
    // Scheduled Tasks
    else if lower.contains(r"system32\tasks\") && !lower.ends_with(r"\tasks") {
        manifest.scheduled_tasks.push(path.clone());
    }
    // SRUM database
    else if lower.contains(r"\sru\") && lower.ends_with("srudb.dat") {
        manifest.srum.push(path.clone());
    }
    // WMI repository
    else if lower.contains(r"\wbem\repository\") && lower.ends_with("objects.data") {
        manifest.wmi_repository.push(path.clone());
    }
    // PowerShell console history
    else if lower.contains("consolehost_history.txt") {
        manifest.powershell_history.push(path.clone());
    }
    // Windows Timeline
    else if lower.ends_with("activitiescache.db") {
        manifest.activities_cache.push(path.clone());
    }
    // RDP Bitmap Cache
    else if lower.contains(r"\cache\") && lower.ends_with(".bmc") {
        manifest.rdp_bitmap_cache.push(path.clone());
    }
    // Browser history databases
    else if (lower.ends_with("history") || lower.ends_with("places.sqlite"))
        && (lower.contains("chrome") || lower.contains("edge") || lower.contains("firefox") || lower.contains("mozilla"))
    {
        manifest.browser_history.push(path.clone());
    }
}

fn extract_username_from_path(win_path: &str) -> String {
    let parts: Vec<&str> = win_path.split('\\').collect();
    for (i, part) in parts.iter().enumerate() {
        if part.eq_ignore_ascii_case("Users") && i + 1 < parts.len() {
            return parts[i + 1].to_string();
        }
    }
    "unknown".to_string()
}

fn extract_metadata_from_filename(path: &Path) -> CollectionMetadata {
    let filename = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("");

    // Pattern: Collection-<hostname>-<timestamp>
    let (hostname, timestamp) = if let Some(rest) = filename.strip_prefix("Collection-") {
        // Find the first occurrence of -202 which marks the start of the timestamp
        if let Some(idx) = rest.find("-202") {
            let host = &rest[..idx];
            let ts = &rest[idx + 1..];
            (host.to_string(), ts.to_string())
        } else {
            (rest.to_string(), String::new())
        }
    } else {
        (filename.to_string(), String::new())
    };

    CollectionMetadata {
        hostname,
        collection_timestamp: timestamp,
        source_tool: "Velociraptor".to_string(),
    }
}
