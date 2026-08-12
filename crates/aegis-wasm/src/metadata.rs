//! WASM Plugin Metadata and Semantic Versioning.

use crate::error::WasmError;
use semver::Version;
use serde::{Deserialize, Serialize};

/// Metadata record associated with a WASI 0.2 policy plugin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginMetadata {
    /// Unique plugin identifier (e.g. "pii-filter").
    pub plugin_id: String,
    /// Semantic version string (e.g. "1.2.0").
    pub version: String,
    /// Author or Organization name.
    pub author: String,
    /// Hex-encoded SHA-256 hash of the WASM binary.
    pub sha256_hash: String,
    /// Optional minimum gateway version required.
    pub min_gateway_version: Option<String>,
}

impl PluginMetadata {
    /// Creates a new `PluginMetadata` instance.
    #[must_use]
    pub fn new(
        plugin_id: impl Into<String>,
        version: impl Into<String>,
        author: impl Into<String>,
        sha256_hash: impl Into<String>,
    ) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            version: version.into(),
            author: author.into(),
            sha256_hash: sha256_hash.into(),
            min_gateway_version: None,
        }
    }

    /// Parses and returns the [`semver::Version`] representation of the plugin version.
    ///
    /// # Errors
    ///
    /// Returns [`WasmError::InvalidMetadata`] if version string is not valid semver.
    pub fn parsed_version(&self) -> Result<Version, WasmError> {
        Version::parse(&self.version)
            .map_err(|e| WasmError::InvalidMetadata(format!("Invalid semver '{}': {e}", self.version)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_metadata_semver_parsing() {
        let meta = PluginMetadata::new("pii-filter", "1.2.0", "AegisTeam", "hash-123");
        let ver = meta.parsed_version().expect("Valid semver");
        assert_eq!(ver.major, 1);
        assert_eq!(ver.minor, 2);
        assert_eq!(ver.patch, 0);
    }
}
