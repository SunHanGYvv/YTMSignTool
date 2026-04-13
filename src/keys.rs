use std::collections::HashSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureKey {
    pub index: u8,
    pub rindex: u8,
    #[serde(rename = "key")]
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecureKeys {
    pub keys: Vec<SecureKey>,
}

impl SecureKeys {
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let cfg: SecureKeys = serde_json::from_str(&content)?;
        let mut seen = HashSet::new();
        for key in &cfg.keys {
            if !seen.insert(key.index) {
                return Err(anyhow::anyhow!(
                    "keys file: duplicate key index {}",
                    key.index
                ));
            }
        }
        Ok(cfg)
    }

    pub fn get_max_key_slot(&self) -> Option<usize> {
        self.keys
            .iter()
            .filter(|k| !k.data.is_empty())
            .map(|k| k.index as usize)
            .max()
    }

    pub fn get_key_by_index(&self, index: u8) -> Option<Vec<u8>> {
        for key in &self.keys {
            if key.index == index {
                if key.data.is_empty() {
                    return None;
                }
                return hex::decode(&key.data).ok();
            }
        }
        None
    }

    pub fn empty_template_32() -> Self {
        Self {
            keys: (0u8..=31u8)
                .map(|index| SecureKey {
                    index,
                    rindex: 31u8 - index,
                    data: String::new(),
                })
                .collect(),
        }
    }

    pub fn write_to_file_pretty(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }
}
