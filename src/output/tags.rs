// Copyright (C) 2026 Shirofune Security Co., Ltd.
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

//! MITRE ATT&CK tag classification (`config/mitre_tactics.txt`, the same table as Suzaku/Hayabusa).
//!
//! A Sigma rule's `tags` list is split into three output columns:
//! - `MitreTactics`: tactic names abbreviated through the table (`attack.initial-access` → `InitAccess`),
//! - `MitreTags`: technique, software and group IDs (`attack.t1053.003` → `T1053.003`, `attack.s0001`
//!   → `S0001`, `attack.g0001` → `G0001`),
//! - `OtherTags`: everything else, verbatim (`cve.2026-109618`, `detection.threat-hunting`, `car.*`
//!   and `attack.*` names the table does not know).

use regex::Regex;
use std::collections::HashMap;
use std::sync::LazyLock;

pub const DEFAULT_MITRE_TACTICS: &str = include_str!("../../config/mitre_tactics.txt");

/// `attack.t1190`, `attack.t1053.003`, `attack.s0001`, `attack.g0001` (any case). The ID is group 1.
static MITRE_ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^attack\.([tsg]\d{4}(?:\.\d{3})?)$").expect("MITRE_ID is a valid regex")
});

/// A Sigma tag split into the three output columns.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SplitTags {
    /// Abbreviated tactics, e.g. `InitAccess`.
    pub tactics: Vec<String>,
    /// Technique / software / group IDs, e.g. `T1190`, `S0001`, `G0001`.
    pub mitre: Vec<String>,
    /// Everything else, e.g. `cve.2026-109618`.
    pub other: Vec<String>,
}

impl SplitTags {
    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.tactics.is_empty() && self.mitre.is_empty() && self.other.is_empty()
    }
}

/// The parsed tactic table: normalized full tag (lowercase, `_` folded to `-`) → abbreviation.
///
/// Parsed once per run (see `output::TACTIC_TABLE`) so that classifying the tags of every detection
/// does not re-read the table text.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TacticTable {
    map: HashMap<String, String>,
}

impl TacticTable {
    /// Parse the `tag_full_str,tag_output_str` CSV. The header row, blank lines, `#` comments and
    /// lines without two fields are skipped; a third column (Hayabusa's `html_tag_output_str`) is
    /// ignored. Lookups are case- and separator-insensitive.
    pub fn parse(text: &str) -> Self {
        let mut map = HashMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split(',');
            let (Some(full), Some(abbrev)) = (fields.next(), fields.next()) else {
                continue;
            };
            let key = normalize(full);
            let abbrev = abbrev.trim();
            // `normalize` has folded the header's `_` to `-`.
            if key.is_empty() || key == "tag-full-str" || abbrev.is_empty() {
                continue;
            }
            map.insert(key, abbrev.to_string());
        }
        Self { map }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// The abbreviation of a tactic tag, if the table knows it.
    pub fn abbreviation(&self, tag: &str) -> Option<&str> {
        self.map.get(&normalize(tag)).map(String::as_str)
    }

    /// Split `tags` into the three columns. Duplicates (after abbreviation) are kept once, so a
    /// rule tagged with both `attack.defense-evasion` and `attack.stealth` shows `Stealth` once.
    pub fn split(&self, tags: &[String]) -> SplitTags {
        let mut out = SplitTags::default();
        for tag in tags {
            let tag = tag.trim();
            if tag.is_empty() {
                continue;
            }
            if let Some(abbrev) = self.abbreviation(tag) {
                push_unique(&mut out.tactics, abbrev);
            } else if let Some(id) = MITRE_ID
                .captures(tag)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_ascii_uppercase())
            {
                push_unique(&mut out.mitre, &id);
            } else {
                push_unique(&mut out.other, tag);
            }
        }
        out
    }
}

fn normalize(tag: &str) -> String {
    tag.trim().to_ascii_lowercase().replace('_', "-")
}

fn push_unique(list: &mut Vec<String>, value: &str) {
    if !list.iter().any(|v| v == value) {
        list.push(value.to_string());
    }
}

/// Split rule tags using the tactic table (`tag_full_str,tag_output_str` CSV).
#[cfg(test)]
pub fn split_tags(tags: &[String], tactic_table: &str) -> SplitTags {
    TacticTable::parse(tactic_table).split(tags)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(tags: &[&str]) -> Vec<String> {
        tags.iter().map(|t| t.to_string()).collect()
    }

    #[test]
    fn default_table_parses_every_tactic_row() {
        let table = TacticTable::parse(DEFAULT_MITRE_TACTICS);
        // 16 data rows: the header line is not a tactic.
        assert_eq!(table.len(), 16);
        assert_eq!(
            table.abbreviation("attack.initial-access"),
            Some("InitAccess")
        );
        assert_eq!(table.abbreviation("attack.command-and-control"), Some("C2"));
        assert_eq!(table.abbreviation("attack.impact"), Some("Impact"));
        assert_eq!(table.abbreviation("tag_full_str"), None);
        assert_eq!(table.abbreviation("attack.t1190"), None);
    }

    #[test]
    fn brief_examples() {
        let tags = strings(&[
            "attack.initial-access",
            "attack.t1190",
            "attack.t1053.003",
            "attack.s0001",
            "attack.g0001",
            "attack.not-a-real-tactic",
            "cve.2026-109618",
            "detection.threat-hunting",
            "car.2013-01-002",
        ]);
        let split = split_tags(&tags, DEFAULT_MITRE_TACTICS);
        assert_eq!(split.tactics, vec!["InitAccess"]);
        assert_eq!(split.mitre, vec!["T1190", "T1053.003", "S0001", "G0001"]);
        assert_eq!(
            split.other,
            vec![
                "attack.not-a-real-tactic",
                "cve.2026-109618",
                "detection.threat-hunting",
                "car.2013-01-002"
            ]
        );
    }

    #[test]
    fn case_and_separator_are_normalized() {
        let split = split_tags(
            &strings(&[
                "attack.Initial_Access",
                "ATTACK.T1190",
                " attack.privilege_escalation ",
                "attack.t1053.003 ",
            ]),
            DEFAULT_MITRE_TACTICS,
        );
        assert_eq!(split.tactics, vec!["InitAccess", "PrivEsc"]);
        assert_eq!(split.mitre, vec!["T1190", "T1053.003"]);
        assert!(split.other.is_empty());
    }

    #[test]
    fn duplicates_after_abbreviation_are_kept_once() {
        let split = split_tags(
            &strings(&[
                "attack.defense-evasion",
                "attack.stealth",
                "attack.t1190",
                "attack.t1190",
                "cve.1",
                "cve.1",
            ]),
            DEFAULT_MITRE_TACTICS,
        );
        assert_eq!(split.tactics, vec!["Stealth"]);
        assert_eq!(split.mitre, vec!["T1190"]);
        assert_eq!(split.other, vec!["cve.1"]);
    }

    #[test]
    fn id_shapes_that_are_not_mitre_ids_go_to_other() {
        let split = split_tags(
            &strings(&[
                "attack.t119",       // too short
                "attack.t11900",     // too long
                "attack.t1190.1",    // sub-technique needs three digits
                "attack.ta0001",     // tactic IDs are not in the ID column
                "attack.t1190.001a", // trailing junk
                "attack.x0001",      // unknown letter
            ]),
            DEFAULT_MITRE_TACTICS,
        );
        assert!(split.tactics.is_empty());
        assert!(split.mitre.is_empty());
        assert_eq!(split.other.len(), 6);
    }

    #[test]
    fn table_parsing_tolerates_header_comments_blanks_and_extra_columns() {
        let text = "tag_full_str,tag_output_str,html_tag_output_str\n\n# comment\nattack.credential-access,CredAccess,07. CredAccess\nbroken line without comma\nattack.discovery,  Disc  \n,NoKey\nattack.nothing,\n";
        let table = TacticTable::parse(text);
        assert_eq!(table.len(), 2);
        assert_eq!(
            table.abbreviation("attack.credential-access"),
            Some("CredAccess")
        );
        assert_eq!(table.abbreviation("attack.discovery"), Some("Disc"));
        assert_eq!(table.abbreviation("attack.nothing"), None);
    }

    #[test]
    fn empty_table_passes_tactics_through_as_other_tags() {
        let table = TacticTable::parse("");
        assert!(table.is_empty());
        let split = table.split(&strings(&["attack.initial-access", "attack.t1190"]));
        assert!(split.tactics.is_empty());
        assert_eq!(split.mitre, vec!["T1190"]);
        assert_eq!(split.other, vec!["attack.initial-access"]);
    }

    #[test]
    fn empty_and_blank_tags() {
        let split = split_tags(&strings(&["", "   "]), DEFAULT_MITRE_TACTICS);
        assert!(split.is_empty());
        assert_eq!(split_tags(&[], DEFAULT_MITRE_TACTICS), SplitTags::default());
    }
}
