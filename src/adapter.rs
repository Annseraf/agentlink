//! Wire types for the text-only conversation transport.

use serde::{Deserialize, Serialize};

pub const VERSION: u16 = 1;
pub const MAX_TEXT_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    ConversationText,
    AgentInvocation,
    Tools,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Descriptor {
    pub version: u16,
    pub capabilities: Vec<Capability>,
}

impl Descriptor {
    pub fn require(&self, capability: Capability) -> Result<(), ContractError> {
        if self.version != VERSION {
            return Err(ContractError::UnsupportedVersion);
        }
        if !self.capabilities.contains(&capability) {
            return Err(ContractError::UnsupportedCapability);
        }
        Ok(())
    }
}

/// These identifiers are engine-assigned or resolved through an authenticated
/// registration. A caller's claim to these values does not grant access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub tenant: String,
    pub adapter: String,
    pub room: String,
    pub thread: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TextEnvelope {
    pub version: u16,
    pub binding: Binding,
    pub correlation_id: String,
    pub text: String,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractError {
    UnsupportedVersion,
    UnsupportedCapability,
    BindingMismatch,
    InvalidEnvelope,
    Timeout,
}

fn valid_id(id: &str) -> bool {
    (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

impl TextEnvelope {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.version != VERSION {
            return Err(ContractError::UnsupportedVersion);
        }
        let binding = &self.binding;
        if [
            binding.tenant.as_str(),
            &binding.adapter,
            &binding.room,
            &self.correlation_id,
        ]
        .into_iter()
        .chain(binding.thread.as_deref())
        .any(|id| !valid_id(id))
            || self.text.trim().is_empty()
            || self.text.len() > MAX_TEXT_BYTES
        {
            return Err(ContractError::InvalidEnvelope);
        }
        Ok(())
    }

    /// Check a reply against the binding persisted for the original request.
    /// Delivery still requires current authorization and durable deduplication.
    pub fn validate_reply(&self, original: &Self) -> Result<(), ContractError> {
        original.validate()?;
        self.validate()?;
        if self.binding != original.binding || self.correlation_id != original.correlation_id {
            return Err(ContractError::BindingMismatch);
        }
        Ok(())
    }
}
