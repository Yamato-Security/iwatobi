//! Sigma log sources.
//!
//! Every parsed event carries a *set* of [`LogSourceTag`]s (an sshd line in `auth.log` is at the
//! same time `linux/syslog`, `linux/auth` and `linux/sshd`). A rule's `logsource` (a
//! [`LogSourceSpec`]) matches an event when one of the event's tags satisfies every field the rule
//! specifies, so a rule with only `product: linux` matches every syslog-family event while
//! `service: sshd` only matches sshd lines.

use std::fmt;

/// One log source identity an event can have. Fields are the Sigma `logsource` fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LogSourceTag {
    pub product: Option<&'static str>,
    pub category: Option<&'static str>,
    pub service: Option<&'static str>,
}

impl LogSourceTag {
    pub const fn new(
        product: Option<&'static str>,
        category: Option<&'static str>,
        service: Option<&'static str>,
    ) -> Self {
        Self {
            product,
            category,
            service,
        }
    }

    pub const fn linux(service: &'static str) -> Self {
        Self::new(Some("linux"), None, Some(service))
    }

    pub const fn linux_category(category: &'static str) -> Self {
        Self::new(Some("linux"), Some(category), None)
    }

    // syslog family
    pub const LINUX_SYSLOG: Self = Self::linux("syslog");
    pub const LINUX_AUTH: Self = Self::linux("auth");
    pub const LINUX_SSHD: Self = Self::linux("sshd");
    pub const LINUX_CRON: Self = Self::linux("cron");
    pub const LINUX_SUDO: Self = Self::linux("sudo");
    pub const LINUX_VSFTPD: Self = Self::linux("vsftpd");
    pub const LINUX_CLAMAV: Self = Self::linux("clamav");
    pub const LINUX_GUACAMOLE: Self = Self::linux("guacamole");
    // Linux audit daemon records (`/var/log/audit/audit.log`)
    pub const LINUX_AUDITD: Self = Self::linux("auditd");
    // Sysmon for Linux: the service, and the Sigma category of each event ID
    pub const LINUX_SYSMON: Self = Self::linux("sysmon");
    pub const LINUX_PROCESS_CREATION: Self = Self::linux_category("process_creation");
    pub const LINUX_NETWORK_CONNECTION: Self = Self::linux_category("network_connection");
    pub const LINUX_PROCESS_TERMINATION: Self = Self::linux_category("process_termination");
    pub const LINUX_RAW_ACCESS_THREAD: Self = Self::linux_category("raw_access_thread");
    pub const LINUX_FILE_EVENT: Self = Self::linux_category("file_event");
    pub const LINUX_FILE_DELETE: Self = Self::linux_category("file_delete");
    pub const LINUX_SYSMON_STATUS: Self = Self::linux_category("sysmon_status");
    pub const LINUX_SYSMON_ERROR: Self = Self::linux_category("sysmon_error");
    // web server access logs (Sigma `category: webserver`)
    pub const WEBSERVER: Self = Self::new(None, Some("webserver"), None);
    pub const APACHE_WEBSERVER: Self = Self::new(Some("apache"), Some("webserver"), None);
    pub const NGINX_WEBSERVER: Self = Self::new(Some("nginx"), Some("webserver"), None);
    pub const APACHE_ACCESS: Self = Self::new(Some("apache"), None, Some("access"));
    pub const NGINX_ACCESS: Self = Self::new(Some("nginx"), None, Some("access"));
    // web server error logs (SigmaHQ `service: apache` / `service: nginx`, taxonomy `service: error`)
    pub const APACHE_ERROR: Self = Self::new(Some("apache"), None, Some("apache"));
    pub const APACHE_ERROR_CANONICAL: Self = Self::new(Some("apache"), None, Some("error"));
    pub const NGINX_ERROR: Self = Self::new(Some("nginx"), None, Some("nginx"));
    pub const NGINX_ERROR_CANONICAL: Self = Self::new(Some("nginx"), None, Some("error"));
    // PHP
    pub const PHP_ERROR_LOG: Self = Self::new(Some("php"), None, Some("error_log"));
    pub const PHP_FPM: Self = Self::new(Some("php"), None, Some("fpm"));

    /// Short name for the `LogSource` column: `linux/sshd`, `webserver`, `apache`, `php/error_log`.
    pub fn display(&self) -> String {
        match (self.product, self.category, self.service) {
            (Some(p), _, Some(s)) if p == s => p.to_string(),
            (Some(p), _, Some(s)) => format!("{p}/{s}"),
            (Some(p), Some(c), None) => format!("{p}/{c}"),
            (None, Some(c), _) => c.to_string(),
            (Some(p), None, None) => p.to_string(),
            (None, None, Some(s)) => s.to_string(),
            (None, None, None) => "-".to_string(),
        }
    }
}

/// Every tag the parsers can produce. A rule whose logsource cannot be satisfied by any of these is
/// unsupported and skipped at load time.
pub const SUPPORTED_TAGS: &[LogSourceTag] = &[
    LogSourceTag::LINUX_SYSLOG,
    LogSourceTag::LINUX_AUTH,
    LogSourceTag::LINUX_SSHD,
    LogSourceTag::LINUX_CRON,
    LogSourceTag::LINUX_SUDO,
    LogSourceTag::LINUX_VSFTPD,
    LogSourceTag::LINUX_CLAMAV,
    LogSourceTag::LINUX_GUACAMOLE,
    LogSourceTag::LINUX_AUDITD,
    LogSourceTag::LINUX_SYSMON,
    LogSourceTag::LINUX_PROCESS_CREATION,
    LogSourceTag::LINUX_NETWORK_CONNECTION,
    LogSourceTag::LINUX_PROCESS_TERMINATION,
    LogSourceTag::LINUX_RAW_ACCESS_THREAD,
    LogSourceTag::LINUX_FILE_EVENT,
    LogSourceTag::LINUX_FILE_DELETE,
    LogSourceTag::LINUX_SYSMON_STATUS,
    LogSourceTag::LINUX_SYSMON_ERROR,
    LogSourceTag::WEBSERVER,
    LogSourceTag::APACHE_WEBSERVER,
    LogSourceTag::NGINX_WEBSERVER,
    LogSourceTag::APACHE_ACCESS,
    LogSourceTag::NGINX_ACCESS,
    LogSourceTag::APACHE_ERROR,
    LogSourceTag::APACHE_ERROR_CANONICAL,
    LogSourceTag::NGINX_ERROR,
    LogSourceTag::NGINX_ERROR_CANONICAL,
    LogSourceTag::PHP_ERROR_LOG,
    LogSourceTag::PHP_FPM,
];

/// A rule's `logsource` triple, lowercased. Also used as the key of the live-analysis location
/// table and for grouping rules by log source.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct LogSourceSpec {
    pub product: Option<String>,
    pub category: Option<String>,
    pub service: Option<String>,
}

impl LogSourceSpec {
    pub fn new(product: Option<&str>, category: Option<&str>, service: Option<&str>) -> Self {
        let norm = |v: Option<&str>| {
            v.map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
        };
        Self {
            product: norm(product),
            category: norm(category),
            service: norm(service),
        }
    }

    /// The logsource of a parsed Sigma rule.
    pub fn from_rule(rule: &sigma_rust::Rule) -> Self {
        Self::new(
            rule.logsource.product.as_deref(),
            rule.logsource.category.as_deref(),
            rule.logsource.service.as_deref(),
        )
    }

    /// True when the rule specifies nothing (matches every event).
    pub fn is_empty(&self) -> bool {
        self.product.is_none() && self.category.is_none() && self.service.is_none()
    }

    /// Every field the spec sets must equal the tag's field (case-insensitive).
    pub fn matches_tag(&self, tag: &LogSourceTag) -> bool {
        fn ok(spec: &Option<String>, tag: Option<&str>) -> bool {
            match spec {
                None => true,
                Some(s) => tag.is_some_and(|t| t.eq_ignore_ascii_case(s)),
            }
        }
        ok(&self.product, tag.product)
            && ok(&self.category, tag.category)
            && ok(&self.service, tag.service)
    }

    pub fn matches_any(&self, tags: &[LogSourceTag]) -> bool {
        tags.iter().any(|t| self.matches_tag(t))
    }

    /// Whether any log format iwatobi parses can produce an event this spec matches.
    pub fn is_supported(&self) -> bool {
        self.matches_any(SUPPORTED_TAGS)
    }
}

impl fmt::Display for LogSourceSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        if let Some(p) = &self.product {
            parts.push(format!("product: {p}"));
        }
        if let Some(c) = &self.category {
            parts.push(format!("category: {c}"));
        }
        if let Some(s) = &self.service {
            parts.push(format!("service: {s}"));
        }
        if parts.is_empty() {
            write!(f, "(any)")
        } else {
            write!(f, "{}", parts.join(", "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_only_rule_matches_every_linux_tag() {
        let spec = LogSourceSpec::new(Some("linux"), None, None);
        assert!(spec.matches_any(&[LogSourceTag::LINUX_SYSLOG]));
        assert!(spec.matches_any(&[LogSourceTag::LINUX_CRON]));
        assert!(!spec.matches_any(&[LogSourceTag::APACHE_ERROR]));
    }

    #[test]
    fn service_rule_needs_the_specific_tag() {
        let spec = LogSourceSpec::new(Some("linux"), None, Some("sshd"));
        let sshd_line = [
            LogSourceTag::LINUX_SYSLOG,
            LogSourceTag::LINUX_AUTH,
            LogSourceTag::LINUX_SSHD,
        ];
        let cron_line = [LogSourceTag::LINUX_SYSLOG, LogSourceTag::LINUX_CRON];
        assert!(spec.matches_any(&sshd_line));
        assert!(!spec.matches_any(&cron_line));
    }

    #[test]
    fn sigmahq_service_only_and_category_only_specs_match() {
        assert!(
            LogSourceSpec::new(None, None, Some("apache")).matches_tag(&LogSourceTag::APACHE_ERROR)
        );
        assert!(
            LogSourceSpec::new(None, Some("webserver"), None)
                .matches_tag(&LogSourceTag::APACHE_WEBSERVER)
        );
        assert!(
            LogSourceSpec::new(Some("apache"), None, Some("error"))
                .matches_tag(&LogSourceTag::APACHE_ERROR_CANONICAL)
        );
        assert!(
            LogSourceSpec::new(Some("PHP"), None, Some("Error_Log"))
                .matches_tag(&LogSourceTag::PHP_ERROR_LOG)
        );
    }

    #[test]
    fn unsupported_logsources_are_detected() {
        assert!(LogSourceSpec::new(Some("linux"), Some("process_creation"), None).is_supported());
        assert!(LogSourceSpec::new(Some("linux"), None, Some("auditd")).is_supported());
        assert!(LogSourceSpec::new(Some("linux"), Some("network_connection"), None).is_supported());
        assert!(
            !LogSourceSpec::new(Some("windows"), Some("process_creation"), None).is_supported()
        );
        assert!(!LogSourceSpec::new(Some("linux"), Some("registry_set"), None).is_supported());
        assert!(!LogSourceSpec::new(None, Some("proxy"), None).is_supported());
        assert!(!LogSourceSpec::new(Some("windows"), None, Some("security")).is_supported());
        assert!(LogSourceSpec::new(Some("linux"), None, None).is_supported());
        assert!(LogSourceSpec::new(None, None, Some("nginx")).is_supported());
    }

    #[test]
    fn display_names() {
        assert_eq!(LogSourceTag::LINUX_SSHD.display(), "linux/sshd");
        assert_eq!(LogSourceTag::WEBSERVER.display(), "webserver");
        assert_eq!(LogSourceTag::APACHE_ERROR.display(), "apache");
        assert_eq!(LogSourceTag::PHP_ERROR_LOG.display(), "php/error_log");
        assert_eq!(LogSourceTag::LINUX_AUDITD.display(), "linux/auditd");
        assert_eq!(
            LogSourceTag::LINUX_PROCESS_CREATION.display(),
            "linux/process_creation"
        );
        assert_eq!(
            LogSourceSpec::new(Some("linux"), None, Some("cron")).to_string(),
            "product: linux, service: cron"
        );
    }
}
