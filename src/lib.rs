//! pylae-verify — clean-room verification of Pylae audit-evidence bundles.
//!
//! Implements the Pylae Evidence Format Specification's STRUCTURAL (keyless)
//! verification level using only standard cryptography. Shares no source with
//! the Pylae product. See the binary (`main.rs`) for the CLI.

pub mod bundle;
pub mod canonical;
pub mod chain;
pub mod verify;

/// The version of `docs/EVIDENCE-FORMAT.md` this build implements. A test
/// reads the vendored document's header, so the two cannot drift silently.
pub const SPEC_VERSION: &str = "0.1";
