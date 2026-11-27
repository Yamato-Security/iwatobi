//! Optional native detection interchange. Never feeds normalized records into Sigma.
use crate::{
    correlate::{BaseHit, CorrelationHit},
    detect::ScanResult,
    event::ParsedEvent,
    input::{self, ScanTarget},
    rules::{RuleMeta, RuleSet},
};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{self, BufRead, Read, Write},
    path::{Path, PathBuf},
};

pub fn hash(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buf = [0; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

/// Snapshot YAML bytes before rule loading, including multi-document correlation files.
pub fn rule_inventory(path: &Path) -> io::Result<BTreeMap<PathBuf, String>> {
    crate::rules::collect_rule_files(path)
        .into_iter()
        .map(|p| hash(&p).map(|h| (p, h)))
        .collect()
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct BindingManifest {
    acquisition_id: Option<String>,
    #[serde(default)]
    sources: Vec<Binding>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    input_path: PathBuf,
    collection_id: String,
    path: String,
    sha256: String,
}

struct Source {
    path: PathBuf,
    before: Option<String>,
    binding: Option<Binding>,
    mtime: Option<String>,
}

pub struct Export {
    output: PathBuf,
    run_id: String,
    started_at: String,
    acquisition: Value,
    sources: BTreeMap<String, Source>,
    source_reports: Vec<Value>,
    locations: BTreeMap<(String, usize), Value>,
    alerts: Vec<Value>,
    rules: BTreeMap<PathBuf, String>,
    rules_path: PathBuf,
    settings: Value,
}

impl Export {
    pub fn new(
        output: &Path,
        manifest: Option<&Path>,
        targets: &[ScanTarget],
        rules_path: &Path,
        rules: BTreeMap<PathBuf, String>,
        settings: Value,
    ) -> io::Result<Self> {
        if output.exists() {
            return Err(io::Error::other("forensic output already exists"));
        }
        let manifest_path = manifest.map(fs::canonicalize).transpose()?;
        let doc: BindingManifest = match manifest {
            Some(p) => serde_json::from_slice(&fs::read(p)?)?,
            None => BindingManifest::default(),
        };
        if doc
            .acquisition_id
            .as_ref()
            .is_some_and(|s| s.trim().is_empty())
        {
            return Err(io::Error::other("empty acquisition ID"));
        }
        let acquisition = match doc.acquisition_id {
            Some(id) => json!({"id": id, "status": "supplied"}),
            None => json!({"id": null, "status": "unbound"}),
        };
        let mut bindings = BTreeMap::new();
        let mut destinations = BTreeSet::new();
        for mut b in doc.sources {
            if b.collection_id.is_empty()
                || b.path.is_empty()
                || b.path.starts_with('/')
                || b.path.contains('\\')
                || b.path
                    .split('/')
                    .any(|s| s.is_empty() || s == "." || s == "..")
                || b.sha256.len() != 64
                || !b.sha256.bytes().all(|c| c.is_ascii_hexdigit())
            {
                return Err(io::Error::other("invalid source binding"));
            }
            b.sha256.make_ascii_lowercase();
            if !destinations.insert((b.collection_id.clone(), b.path.clone())) {
                return Err(io::Error::other("ambiguous canonical source binding"));
            }
            let path = if b.input_path.is_absolute() {
                b.input_path.clone()
            } else {
                manifest_path
                    .as_ref()
                    .unwrap()
                    .parent()
                    .unwrap()
                    .join(&b.input_path)
            };
            if bindings.insert(fs::canonicalize(path)?, b).is_some() {
                return Err(io::Error::other("duplicate input binding"));
            }
        }
        let mut sources = BTreeMap::new();
        for target in targets {
            let binding = fs::canonicalize(&target.path)
                .ok()
                .and_then(|p| bindings.remove(&p));
            let before = hash(&target.path).ok();
            if let Some(b) = &binding
                && before.as_deref() != Some(&b.sha256)
            {
                return Err(io::Error::other(format!(
                    "source hash mismatch: {}",
                    target.path.display()
                )));
            }
            let mtime = fs::metadata(&target.path)
                .and_then(|m| m.modified())
                .ok()
                .map(|t| chrono::DateTime::<chrono::Utc>::from(t).to_rfc3339());
            sources.insert(
                target.display_name.clone(),
                Source {
                    path: target.path.clone(),
                    before,
                    binding,
                    mtime,
                },
            );
        }
        if !bindings.is_empty() {
            return Err(io::Error::other(
                "manifest contains inputs not selected for this scan",
            ));
        }
        Ok(Self {
            output: output.into(),
            run_id: uuid::Uuid::new_v4().to_string(),
            started_at: chrono::Utc::now().to_rfc3339(),
            acquisition,
            sources,
            source_reports: vec![],
            locations: BTreeMap::new(),
            alerts: vec![],
            rules,
            rules_path: rules_path.into(),
            settings,
        })
    }

    pub fn source(&mut self, target: &ScanTarget, result: &ScanResult, rules: &RuleSet) {
        let source = &self.sources[&target.display_name];
        let after = hash(&source.path).ok();
        let stable = source.before.is_some() && source.before == after;
        let mut raw: BTreeMap<usize, BTreeSet<&str>> = BTreeMap::new();
        for d in &result.detections {
            raw.entry(d.line).or_default().insert(&d.event.raw);
        }
        for m in &result.base_hits {
            if let Some(e) = &m.native {
                raw.entry(m.line).or_default().insert(&e.raw);
            }
        }
        let mut matching = BTreeSet::new();
        if stable
            && result.read_error.is_none()
            && let Ok(mut reader) = input::open_reader(&source.path)
        {
            let mut buf = Vec::new();
            let mut line_no = 0;
            let mut compatible = true;
            loop {
                buf.clear();
                match reader.read_until(b'\n', &mut buf) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => {
                        compatible = false;
                        break;
                    }
                }
                line_no += 1;
                // Python's universal-newline reader also splits bare CR. Iwatobi does not.
                // One such byte invalidates subsequent shared line coordinates in this file.
                compatible &= buf
                    .iter()
                    .enumerate()
                    .all(|(i, b)| *b != b'\r' || buf.get(i + 1) == Some(&b'\n'));
                let line = input::decode_line(&buf, line_no == 1);
                if raw
                    .get(&line_no)
                    .is_some_and(|records| records.iter().all(|s| *s == line))
                {
                    matching.insert(line_no);
                }
            }
            if !compatible {
                matching.clear();
            }
        }
        // The second reader is also bounded by the immutable-file assumption; check after it.
        let stable = stable && hash(&source.path).ok() == after;
        for line in raw.keys() {
            let bound = source.binding.is_some() && self.acquisition["status"] == "supplied";
            let exact = stable && bound && matching.contains(line);
            let reference = source.binding.as_ref().map(|b| json!({
                "collection_id": b.collection_id, "path": b.path, "sha256": b.sha256,
                "locator": {"kind": "text_line", "line": line, "coordinate": "decoded_decompressed_1_based"},
                "exact": exact
            }));
            let status = if !stable {
                "source_changed_or_unreadable"
            } else if !bound {
                "unbound"
            } else if !matching.contains(line) {
                "partial"
            } else {
                "exact"
            };
            self.locations.insert(
                (target.display_name.clone(), *line),
                json!({
                    "status": status, "source_refs": reference.into_iter().collect::<Vec<_>>(),
                    "native_location": {"file": target.display_name, "line": line},
                    "coverage": if exact { "single_line" } else { "unqualified_record_extent" }
                }),
            );
        }
        self.source_reports.push(json!({"input_path": target.display_name, "sha256": source.before,
            "binding": source.binding.as_ref().map(|b| json!({"collection_id": b.collection_id, "path": b.path, "sha256": b.sha256})),
            "mtime": source.mtime, "integrity": if stable {"unchanged_before_after"} else {"unresolved"},
            "format": result.format.as_ref().map(|f| f.name()), "events_after_time_filter": result.events,
            "skipped": result.skipped.as_ref().map(ToString::to_string), "read_error": result.read_error,
            "coverage": if result.skipped.is_some() {"not_scanned"} else if result.read_error.is_some() {"partial"} else {"parser_completed_not_full_recognition"}}));
        for d in &result.detections {
            let evidence = self.evidence(&d.file, d.line, Some(&d.event));
            self.alerts.push(json!({"kind": "single", "rule_index": d.rule_index, "rule": rule(&rules.rules[d.rule_index].meta),
                "timestamp": d.event.timestamp.map(|t| t.to_rfc3339()),
                "members": [{"rule": rule(&rules.rules[d.rule_index].meta), "evidence": evidence}],
                "members_total": 1, "members_truncated": false}));
        }
    }

    fn evidence(&self, file: &str, line: usize, native: Option<&ParsedEvent>) -> Value {
        let location = self.locations.get(&(file.into(), line)).cloned().unwrap_or_else(||
            json!({"status": "unresolved", "source_refs": [], "native_location": {"file": file, "line": line}}));
        json!({"location": location, "native": native.map(|e| json!({"raw": e.raw,
            "representation": "iwatobi_decoded_native_not_original_bytes", "match_text": e.match_text,
            "fields": e.fields.iter().map(|(k,v)| json!({"name": k, "value": v.to_json()})).collect::<Vec<_>>(),
            "hostname": e.hostname, "logsource": e.primary_logsource,
            "logsource_tags": e.tags.iter().map(|t| json!({"product": t.product, "category": t.category, "service": t.service})).collect::<Vec<_>>(),
            "timestamp": e.timestamp.map(|t| t.to_rfc3339()), "timestamp_inferred": e.timestamp_inferred,
            "timezone_explicit": e.tz_explicit}))})
    }

    pub fn correlation(&mut self, hit: &CorrelationHit, members: &[&BaseHit], rules: &RuleSet) {
        let corr = &rules.correlations[hit.correlation_index];
        let members: Vec<Value> = members
            .iter()
            .map(|m| {
                json!({
            "base_rule_index": m.base_index,
            "rule": rule(&corr.base_rules[m.base_index].meta),
            "evidence": self.evidence(&m.file, m.line, m.native.as_ref())})
            })
            .collect();
        self.alerts.push(json!({"kind": "correlation", "correlation_index": hit.correlation_index, "rule": rule(&corr.meta),
            "timestamp": hit.timestamp.to_rfc3339(), "first": hit.first.to_rfc3339(),
            "last": hit.last.to_rfc3339(), "count": hit.count, "group_values": hit.group_values,
            "members_total": hit.members.len(), "members_truncated": members.len() != hit.members.len(),
            "members": members}));
    }

    pub fn finish(mut self, skipped_missing_group_by: usize, rules: &RuleSet) -> io::Result<()> {
        for source in self.sources.values() {
            if source.before.is_some() && hash(&source.path).ok() != source.before {
                return Err(io::Error::other(
                    "source changed before publication; forensic export not published",
                ));
            }
        }
        if rule_inventory(&self.rules_path)? != self.rules {
            return Err(io::Error::other(
                "rules changed during scan; forensic export not published",
            ));
        }
        self.alerts.sort_by_key(Value::to_string);
        for (i, alert) in self.alerts.iter_mut().enumerate() {
            let members = alert["members"].as_array().unwrap();
            let exact = members
                .iter()
                .filter(|m| m["evidence"]["location"]["status"] == "exact")
                .count();
            alert["evidence_status"] = json!(if exact == members.len() {
                "exact"
            } else if exact > 0 {
                "partial"
            } else {
                "unresolved"
            });
            alert["exact_members"] = json!(exact);
            alert["id"] = json!(format!("{}:{}", self.run_id, i + 1));
            alert["uac"] = json!({"acquisition": self.acquisition, "run_id": self.run_id});
            alert["event"] = json!({"kind": "alert"});
        }
        self.source_reports.sort_by_key(Value::to_string);
        let doc = json!({"schema": "iwatobi-forensic-1.0.0", "source_reference_profile": "uac-1.0.0",
            "run": {"id": self.run_id, "tool": "iwatobi", "version": env!("CARGO_PKG_VERSION"),
                "started_at": self.started_at, "completed_at": chrono::Utc::now().to_rfc3339(),
                "executable_sha256": hash(&std::env::current_exe()?)?,
                "sigma_dependency": "sigma-rust v0.7.2", "cargo_lock_sha256": format!("{:x}", Sha256::digest(include_bytes!("../Cargo.lock"))),
                "settings": self.settings, "rules": self.rules.iter().map(|(p,h)| json!({"path": p,"sha256":h})).collect::<Vec<_>>(),
                "loaded_rules": rules.rules.iter().map(|r| rule(&r.meta)).collect::<Vec<_>>(),
                "loaded_correlations": rules.correlations.iter().map(|r| json!({"rule": rule(&r.meta),
                    "base_rules": r.base_rules.iter().map(|b| rule(&b.meta)).collect::<Vec<_>>()})).collect::<Vec<_>>(),
                "correlation_hits_skipped_missing_group_by": skipped_missing_group_by},
            "uac": {"acquisition": self.acquisition}, "sources": self.source_reports, "alerts": self.alerts});
        let bytes = serde_json::to_vec_pretty(&doc)?;
        let parent = self
            .output
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let mut file = tempfile::NamedTempFile::new_in(parent)?;
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        file.persist_noclobber(&self.output).map_err(|e| e.error)?;
        Ok(())
    }
}

fn rule(meta: &RuleMeta) -> Value {
    json!({"id": meta.id, "name": meta.title, "level": meta.level, "description": meta.description,
        "source": meta.source.as_ref().map(|(p,h)| json!({"path": p, "sha256": h})),
        "tags": meta.tags, "file": meta.rule_file, "author": meta.author, "status": meta.status,
        "created": meta.date, "modified": meta.modified, "references": meta.references,
        "false_positives": meta.falsepositives})
}
