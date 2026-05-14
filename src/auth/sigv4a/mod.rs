//! Strict-mode inbound SigV4A (`AWS4-ECDSA-P256-SHA256`) verification.
//!
//! Sibling of [`crate::auth::sigv4`]. SigV4A shares canonical-request
//! construction, header/skew validation, and credential resolution with
//! plain SigV4 HMAC; it differs in (1) the per-credential signing key,
//! which is an ECDSA P-256 scalar derived from the access key id and
//! secret access key via an SP 800-108 counter-mode KDF, (2) the
//! regionless credential scope (`<yyyymmdd>/s3/aws4_request`), (3) the
//! signed region-set parameter, and (4) the signature wire format
//! (lowercase hex of DER-encoded ECDSA-P256/SHA-256, variable length up
//! to 144 hex chars).
//!
//! This commit (PR 5 commit 1) adds the crypto primitives only. Header /
//! presigned / streaming verifiers land in subsequent commits.

pub mod crypto;

pub const SIGV4A_ALGORITHM: &str = "AWS4-ECDSA-P256-SHA256";
