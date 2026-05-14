//! SigV4A crypto primitives: SP 800-108 counter-mode KDF that turns an
//! AWS access-key / secret-access-key pair into a P-256 signing scalar,
//! plus DER signature parsing and ECDSA verification helpers.
//!
//! The KDF matches `aws_sigv4::sign::v4a::generate_signing_key` (aws-sigv4
//! 1.4.3 `src/sign/v4a.rs`). Both produce the same scalar bytes for the
//! same `(access_key_id, secret_access_key)` input; that is verified by
//! the `kdf_matches_aws_sigv4_*` tests below. The structure is:
//!
//! ```text
//!   input_key   = b"AWS4A" || secret_access_key
//!   counter     = 1..=254  (single byte, increments only on the rare
//!                          k0 > N-2 retry path)
//!   fixed_input = b"AWS4-ECDSA-P256-SHA256" || 0x00
//!                 || access_key_id || counter
//!                 || 0x00000100  (BE i32, L = 256 bits)
//!   message     = 0x00000001 || fixed_input   (BE i32 i = 1)
//!   k0          = HMAC-SHA256(input_key, message)  (32 bytes, BE)
//!   if k0 <= N-2  →  scalar = k0 + 1 (mod 2^256), return scalar
//!   else           →  counter += 1, retry
//! ```
//!
//! `N` is the order of the P-256 group from FIPS 186-5. `N - 2` is
//! precomputed below.
//!
//! Public-facing entry points:
//! - [`derive_sigv4a_verifying_key`] — turns `(akid, secret)` into a
//!   verifying key for inbound signature checks; the private scalar is
//!   built, used to derive the public key, then dropped (no signing
//!   capability is exposed).
//! - [`parse_der_signature_hex`] — strict lowercase-hex of DER-shaped
//!   ECDSA signature, max 144 hex chars. Used for header and presigned
//!   signatures.
//! - [`parse_streaming_der_signature_hex_padded`] — same but trims AWS
//!   CRT's `*`-to-144 padding before decoding. Used for aws-chunked
//!   streaming chunk / trailer signatures.
//! - [`verify_sigv4a_der_signature`] — ECDSA-P256/SHA-256 verify, taking
//!   the message bytes (the SigV4A string-to-sign, NOT a prehash).

use hmac::{Hmac, KeyInit, Mac};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use sha2::Sha256;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

const SIGV4A_KDF_LABEL: &[u8] = b"AWS4-ECDSA-P256-SHA256";

/// `N - 2` for the NIST P-256 curve (big-endian), precomputed.
///
/// `N = ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551`
/// (FIPS 186-5 / SP 800-186 section 3.2.1.3). Subtracting 2 only touches
/// the last byte (`0x51 → 0x4f`).
const N_MINUS_2_BE: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x4f,
];

/// Maximum hex length of a DER-encoded ECDSA-P256/SHA-256 signature.
///
/// DER ECDSA P-256 signatures top out at 72 bytes (the absolute upper
/// bound: `0x30 0x46 0x02 0x21 r(33) 0x02 0x21 s(33)`), so the lowercase
/// hex encoding fits in 144 characters. AWS CRT's streaming chunk /
/// trailer signatures right-pad with `*` to this fixed width on the wire;
/// header / presigned signatures are unpadded but never longer than this.
pub const MAX_SIGV4A_DER_SIGNATURE_HEX_LEN: usize = 144;

#[derive(Debug, thiserror::Error)]
pub enum SigV4aCryptoError {
    #[error("KDF failed to derive a valid P-256 scalar within 254 attempts")]
    KdfExhausted,
    #[error("derived scalar is not a valid P-256 signing key")]
    InvalidDerivedScalar,
    #[error(
        "signature hex is not lowercase, even length, and within {MAX_SIGV4A_DER_SIGNATURE_HEX_LEN} bytes"
    )]
    InvalidSignatureHex,
    #[error("signature is not valid DER")]
    InvalidDerSignature,
    #[error("signature verification failed")]
    VerificationFailed,
}

/// P-256 verifying key derived from `(access_key_id, secret_access_key)`.
///
/// Wraps `p256::ecdsa::VerifyingKey` so the public-key bytes aren't
/// renderable through the default `Debug` (which would leak the raw key
/// material into traces). Cloning is cheap; the inner type is `Copy`.
#[derive(Clone)]
pub struct SigV4aVerifyingKey(VerifyingKey);

impl std::fmt::Debug for SigV4aVerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigV4aVerifyingKey(<P-256>)")
    }
}

/// Run the SigV4A KDF and return the derived P-256 private scalar.
///
/// The returned bytes are `Zeroizing`-wrapped so the scalar is wiped from
/// the stack/heap when dropped. Caller is expected to either build a
/// `SigningKey` (test helpers) or — in production — discard the scalar
/// immediately after deriving the verifying key.
pub fn derive_sigv4a_private_scalar(
    access_key_id: &str,
    secret_access_key: &str,
) -> Result<Zeroizing<[u8; 32]>, SigV4aCryptoError> {
    let mut input_key = Zeroizing::new(Vec::with_capacity(5 + secret_access_key.len()));
    input_key.extend_from_slice(b"AWS4A");
    input_key.extend_from_slice(secret_access_key.as_bytes());

    // SP 800-108 counter is a single byte (1..=254 in the AWS spec). aws-sigv4
    // uses `u8::checked_add` and asserts the loop never reaches 255 in
    // practice; we match that by capping at 254 and returning KdfExhausted
    // if the scalar is still out-of-range. With a uniformly distributed
    // HMAC output, the probability of needing even one retry is ~2^-128, so
    // KdfExhausted is effectively unreachable on legitimate inputs.
    for counter in 1u8..=254 {
        let mut fixed_input =
            Vec::with_capacity(SIGV4A_KDF_LABEL.len() + 1 + access_key_id.len() + 1 + 4);
        fixed_input.extend_from_slice(SIGV4A_KDF_LABEL);
        fixed_input.push(0x00);
        fixed_input.extend_from_slice(access_key_id.as_bytes());
        fixed_input.push(counter);
        fixed_input.extend_from_slice(&256_i32.to_be_bytes());

        let mut message = Vec::with_capacity(4 + fixed_input.len());
        message.extend_from_slice(&1_i32.to_be_bytes());
        message.extend_from_slice(&fixed_input);

        let mut mac =
            HmacSha256::new_from_slice(&input_key[..]).expect("HMAC accepts any key size");
        mac.update(&message);
        // Convert the HMAC output directly into a Zeroizing<[u8; 32]>
        // buffer. The KDF tag is sensitive: for the accepted-counter
        // case it's `k0`, one `+1` away from the actual ECDSA signing
        // scalar; even rejected-counter outputs are secret derivation
        // material that an attacker with memory access could combine
        // with the access-key id to narrow the secret. Zeroizing-on-
        // drop matches the discipline in `auth::sigv4::derive_signing_key`
        // for HMAC kSigning. Without the wrapper, the un-zeroized
        // `GenericArray` temporary from `into_bytes()` would land on
        // the stack and only be released when the frame is overwritten.
        let k0: Zeroizing<[u8; 32]> = Zeroizing::new(mac.finalize().into_bytes().into());

        if be_less_or_equal(&k0[..], &N_MINUS_2_BE) {
            return Ok(be_add_one(&k0));
        }
    }
    Err(SigV4aCryptoError::KdfExhausted)
}

/// Derive the SigV4A verifying key from `(access_key_id, secret_access_key)`.
///
/// Performs the KDF, builds a `p256::ecdsa::SigningKey`, derives its
/// `VerifyingKey`, and drops the scalar. The returned value is suitable
/// to keep on a verification context — it carries only public material.
pub fn derive_sigv4a_verifying_key(
    access_key_id: &str,
    secret_access_key: &str,
) -> Result<SigV4aVerifyingKey, SigV4aCryptoError> {
    let scalar = derive_sigv4a_private_scalar(access_key_id, secret_access_key)?;
    let signing_key = p256::ecdsa::SigningKey::from_bytes(&scalar[..])
        .map_err(|_| SigV4aCryptoError::InvalidDerivedScalar)?;
    let verifying_key = VerifyingKey::from(&signing_key);
    Ok(SigV4aVerifyingKey(verifying_key))
}

/// Parse the lowercase hex of a DER-encoded ECDSA-P256/SHA-256 signature
/// as used in SigV4A `Authorization` headers and `X-Amz-Signature` query
/// parameters.
///
/// Strictness mirrors the HMAC SigV4 parser: lowercase only, even length,
/// no whitespace, and bounded at `MAX_SIGV4A_DER_SIGNATURE_HEX_LEN`. Empty
/// strings are rejected because AWS never emits an empty signature.
///
/// **DER-validates at parse time.** Returning successfully means the
/// bytes are a structurally valid ECDSA P-256 DER signature; the caller
/// gets `Vec<u8>` rather than the parsed `Signature` so other layers can
/// log the raw bytes for diagnostics, but a subsequent
/// [`verify_sigv4a_der_signature`] call can safely assume DER-validity
/// (its `from_der` re-parse is now belt-and-suspenders, not the only
/// gate). This is the layering the wire-format error codes depend on:
/// malformed DER must surface as `InvalidSignatureHex` /
/// `InvalidDerSignature` (mapped to `AuthorizationHeaderMalformed` /
/// `MalformedFrame` at the parser layer), and `SignatureDoesNotMatch`
/// is reserved for crypto-mismatch on valid DER.
pub fn parse_der_signature_hex(signature_hex: &str) -> Result<Vec<u8>, SigV4aCryptoError> {
    // `% 2 != 0` rather than `len().is_multiple_of(2)` so we don't
    // require Rust 1.87+. The repo has no `rust-version` floor and
    // `edition = "2024"` puts the language baseline at 1.85.
    #[allow(clippy::manual_is_multiple_of)]
    let odd_len = signature_hex.len() % 2 != 0;
    if signature_hex.is_empty() || odd_len || signature_hex.len() > MAX_SIGV4A_DER_SIGNATURE_HEX_LEN
    {
        return Err(SigV4aCryptoError::InvalidSignatureHex);
    }
    if signature_hex
        .bytes()
        .any(|b| !(b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
    {
        return Err(SigV4aCryptoError::InvalidSignatureHex);
    }
    let bytes = hex::decode(signature_hex).map_err(|_| SigV4aCryptoError::InvalidSignatureHex)?;
    // DER-validate inline. Without this, raw `r||s` (128 hex chars) and
    // arbitrary non-DER lowercase hex slip through parsing and collapse
    // into `SignatureDoesNotMatch` at verify time — wrong wire-format
    // error code. Validating here keeps `InvalidDerSignature` on the
    // shape-malformed path so the parser layer can map it to
    // `AuthorizationHeaderMalformed`.
    Signature::from_der(&bytes).map_err(|_| SigV4aCryptoError::InvalidDerSignature)?;
    Ok(bytes)
}

/// Parse a SigV4A streaming chunk / trailer signature.
///
/// AWS CRT emits two shapes on the wire:
///
/// - **Unpadded:** lowercase hex of a valid DER ECDSA signature, no
///   `*`, length ≤ `MAX_SIGV4A_DER_SIGNATURE_HEX_LEN` (144).
/// - **Full-width padded:** lowercase hex of a valid DER ECDSA
///   signature followed by `*` characters bringing the TOTAL length
///   to exactly `MAX_SIGV4A_DER_SIGNATURE_HEX_LEN`. Every byte from
///   the first `*` to the end must be `*` (no interspersed stars,
///   no partial padding).
///
/// Partial trailing padding (`<der-hex>` + a handful of stars to a
/// total length below 144) and interspersed `*` are explicitly
/// rejected as `InvalidSignatureHex` — both are nonsensical wire
/// shapes and have never appeared in a legitimate AWS CRT stream.
///
/// The accepted prefix is then DER-validated via
/// [`parse_der_signature_hex`] (which calls `Signature::from_der`
/// inline), so a successful return means the bytes are both a valid
/// hex shape and a structurally valid ECDSA P-256 signature.
pub fn parse_streaming_der_signature_hex_padded(
    signature_hex_with_optional_padding: &str,
) -> Result<Vec<u8>, SigV4aCryptoError> {
    let s = signature_hex_with_optional_padding;

    if s.len() > MAX_SIGV4A_DER_SIGNATURE_HEX_LEN {
        return Err(SigV4aCryptoError::InvalidSignatureHex);
    }

    if let Some(first_star) = s.find('*') {
        // Padding present → strict AWS CRT shape: total width must be
        // exactly the fixed-width max, and every byte from the first
        // `*` through the end must be `*`. This forbids partial
        // padding (`<der><*-run shorter than 144>`) and interspersed
        // stars (`30*44...`) explicitly, rather than letting them
        // fall into the indirect lowercase-hex check inside
        // `parse_der_signature_hex`.
        if s.len() != MAX_SIGV4A_DER_SIGNATURE_HEX_LEN {
            return Err(SigV4aCryptoError::InvalidSignatureHex);
        }
        if !s.as_bytes()[first_star..].iter().all(|b| *b == b'*') {
            return Err(SigV4aCryptoError::InvalidSignatureHex);
        }
        parse_der_signature_hex(&s[..first_star])
    } else {
        // No padding — accept any valid DER hex up to MAX.
        parse_der_signature_hex(s)
    }
}

/// Verify an ECDSA-P256/SHA-256 signature over `string_to_sign`.
///
/// `string_to_sign` is the SigV4A pre-hash input (the four-line auth STS
/// for header / presigned auth, or the streaming STS for chunk / trailer
/// frames) — the verifier hashes it internally per RFC 6979 / ECDSA, so
/// callers must NOT pre-hash.
///
/// Returns `InvalidDerSignature` for non-DER input and
/// `VerificationFailed` for valid DER that doesn't match. Production
/// callers should pre-validate with [`parse_der_signature_hex`] so the
/// `InvalidDerSignature` path is unreachable here and any error is the
/// real crypto-mismatch.
pub fn verify_sigv4a_der_signature(
    verifying_key: &SigV4aVerifyingKey,
    string_to_sign: &[u8],
    signature_der: &[u8],
) -> Result<(), SigV4aCryptoError> {
    let sig =
        Signature::from_der(signature_der).map_err(|_| SigV4aCryptoError::InvalidDerSignature)?;
    verifying_key
        .0
        .verify(string_to_sign, &sig)
        .map_err(|_| SigV4aCryptoError::VerificationFailed)
}

/// Big-endian `a <= b` for fixed-size byte slices. Used to compare the
/// raw KDF output against `N - 2`. Equal-length slices only.
fn be_less_or_equal(a: &[u8], b: &[u8]) -> bool {
    debug_assert_eq!(a.len(), b.len());
    for (x, y) in a.iter().zip(b.iter()) {
        match x.cmp(y) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    true
}

/// `a + 1` for a 32-byte big-endian scalar. Used in the KDF post-step to
/// turn `k0` (which may legitimately be zero) into the actual private
/// scalar. Wrapping at 2^256 is acceptable because the caller has already
/// confirmed `a <= N - 2`, so `a + 1` is in `[1, N - 1]` and never
/// overflows.
fn be_add_one(a: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new(*a);
    let mut carry: u16 = 1;
    for i in (0..32).rev() {
        let sum = u16::from(out[i]) + carry;
        out[i] = (sum & 0xff) as u8;
        carry = sum >> 8;
        if carry == 0 {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};

    /// AWS-published SigV4A example credentials from the IAM signing docs.
    /// Used as the cross-check between our KDF and aws-sigv4's
    /// `generate_signing_key`.
    const EXAMPLE_AKID: &str = "AKISORANDOMAASORANDOM";
    const EXAMPLE_SECRET: &str = "q+jcrXGc+0zWN6uzclKVhvMmUsIfRPa4rlRandom";

    fn aws_reference_scalar(akid: &str, secret: &str) -> [u8; 32] {
        let key = aws_sigv4::sign::v4a::generate_signing_key(akid, secret);
        let bytes = key.as_ref();
        assert_eq!(bytes.len(), 32);
        let mut out = [0u8; 32];
        out.copy_from_slice(bytes);
        out
    }

    /// The KDF must match `aws_sigv4::sign::v4a::generate_signing_key`
    /// bit-for-bit for legitimate inputs. Drift here would mean our
    /// derived verifying key is the wrong public key for the credential,
    /// and every legitimate SigV4A request would fail with
    /// `SignatureDoesNotMatch`. Bug-revert reasoning: if someone alters
    /// the KDF inputs (label, counter placement, `L`, BE bytes) without
    /// noticing, this assertion fails immediately.
    #[test]
    fn kdf_matches_aws_sigv4_for_example_credentials() {
        let ours = derive_sigv4a_private_scalar(EXAMPLE_AKID, EXAMPLE_SECRET).expect("derives");
        let theirs = aws_reference_scalar(EXAMPLE_AKID, EXAMPLE_SECRET);
        assert_eq!(&ours[..], &theirs[..]);
    }

    /// Same KDF cross-check on a separate input — guards against a bug
    /// where the KDF happens to coincidentally match aws-sigv4 only for
    /// a single credential pair.
    #[test]
    fn kdf_matches_aws_sigv4_for_iam_doc_credentials() {
        let akid = "AKIAIOSFODNN7EXAMPLE";
        let secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let ours = derive_sigv4a_private_scalar(akid, secret).expect("derives");
        let theirs = aws_reference_scalar(akid, secret);
        assert_eq!(&ours[..], &theirs[..]);
    }

    /// The derived verifying key must match the public key of the
    /// signing key aws-sigv4 produces. We round-trip via a sign /
    /// verify: aws-sigv4 signs a message with the scalar, we verify with
    /// the verifying key derived through our own pipeline.
    #[test]
    fn verifying_key_round_trips_against_aws_sigv4_signature() {
        let vk = derive_sigv4a_verifying_key(EXAMPLE_AKID, EXAMPLE_SECRET).expect("derives");
        let scalar = aws_reference_scalar(EXAMPLE_AKID, EXAMPLE_SECRET);
        let signing_key = SigningKey::from_bytes(&scalar).expect("signing key");
        let message = b"AWS4-ECDSA-P256-SHA256\n20260101T120000Z\n20260101/s3/aws4_request\n00";
        let sig: Signature = signing_key.sign(message);
        let der = sig.to_der();
        verify_sigv4a_der_signature(&vk, message, der.as_ref()).expect("verifies");
    }

    /// Tampered messages must NOT verify. Without this, the verifier
    /// would accept arbitrary `string_to_sign` once a real signature is
    /// observed for *some* message under the same key.
    #[test]
    fn verifying_rejects_tampered_message() {
        let vk = derive_sigv4a_verifying_key(EXAMPLE_AKID, EXAMPLE_SECRET).expect("derives");
        let scalar = aws_reference_scalar(EXAMPLE_AKID, EXAMPLE_SECRET);
        let signing_key = SigningKey::from_bytes(&scalar).expect("signing key");
        let message = b"original-string-to-sign";
        let sig: Signature = signing_key.sign(message);
        let der = sig.to_der();
        let err = verify_sigv4a_der_signature(&vk, b"tampered-string-to-sign", der.as_ref())
            .expect_err("tampered message must fail");
        assert!(matches!(err, SigV4aCryptoError::VerificationFailed));
    }

    #[test]
    fn parse_der_signature_hex_accepts_valid_der() {
        let scalar = aws_reference_scalar(EXAMPLE_AKID, EXAMPLE_SECRET);
        let signing_key = SigningKey::from_bytes(&scalar).expect("signing key");
        let sig: Signature = signing_key.sign(b"some-message");
        let der_hex = hex::encode(sig.to_der().as_ref());
        let parsed = parse_der_signature_hex(&der_hex).expect("parses");
        assert_eq!(parsed, hex::decode(&der_hex).unwrap());
    }

    #[test]
    fn parse_der_signature_hex_rejects_uppercase() {
        let scalar = aws_reference_scalar(EXAMPLE_AKID, EXAMPLE_SECRET);
        let signing_key = SigningKey::from_bytes(&scalar).expect("signing key");
        let sig: Signature = signing_key.sign(b"some-message");
        let der_hex = hex::encode_upper(sig.to_der().as_ref());
        let err = parse_der_signature_hex(&der_hex).expect_err("uppercase");
        assert!(matches!(err, SigV4aCryptoError::InvalidSignatureHex));
    }

    #[test]
    fn parse_der_signature_hex_rejects_odd_length() {
        let err = parse_der_signature_hex("abc").expect_err("odd-length");
        assert!(matches!(err, SigV4aCryptoError::InvalidSignatureHex));
    }

    #[test]
    fn parse_der_signature_hex_rejects_empty() {
        let err = parse_der_signature_hex("").expect_err("empty");
        assert!(matches!(err, SigV4aCryptoError::InvalidSignatureHex));
    }

    #[test]
    fn parse_der_signature_hex_rejects_over_max_length() {
        let too_long = "a".repeat(MAX_SIGV4A_DER_SIGNATURE_HEX_LEN + 2);
        let err = parse_der_signature_hex(&too_long).expect_err("over-max");
        assert!(matches!(err, SigV4aCryptoError::InvalidSignatureHex));
    }

    /// Raw 64-byte `r||s` (128 hex chars) is well-formed lowercase hex
    /// but is NOT DER. The parser MUST reject it at parse time so the
    /// wire-format error code stays on the malformed-auth path; if the
    /// reject only fires inside `verify_sigv4a_der_signature`, the
    /// client sees `SignatureDoesNotMatch` instead of
    /// `AuthorizationHeaderMalformed` — wrong layering, no caller can
    /// tell whether it was a shape bug or a crypto miss.
    ///
    /// Bug-revert reasoning: dropping the
    /// `Signature::from_der(&bytes).map_err(...)?` call inside
    /// `parse_der_signature_hex` flips this test from
    /// `InvalidDerSignature` back to `Ok(_)`.
    #[test]
    fn parse_der_signature_hex_rejects_raw_r_s_encoding() {
        let raw_rs_hex = "00".repeat(64);
        let err = parse_der_signature_hex(&raw_rs_hex).expect_err("raw r||s must reject at parse");
        assert!(matches!(err, SigV4aCryptoError::InvalidDerSignature));
    }

    /// Arbitrary non-DER lowercase hex (right length, valid hex shape,
    /// but no DER ASN.1 structure) must also reject at parse time. Guards
    /// the layering: malformed DER stays on the
    /// `InvalidDerSignature` → `AuthorizationHeaderMalformed` path, not
    /// the `SignatureDoesNotMatch` path.
    #[test]
    fn parse_der_signature_hex_rejects_arbitrary_non_der_hex() {
        // 70 lowercase hex bytes — well-formed shape, but not DER.
        let hex = "deadbeef".repeat(17) + "be";
        let err = parse_der_signature_hex(&hex).expect_err("non-DER must reject at parse");
        assert!(matches!(err, SigV4aCryptoError::InvalidDerSignature));
    }

    #[test]
    fn parse_streaming_der_signature_hex_padded_trims_star_padding() {
        let scalar = aws_reference_scalar(EXAMPLE_AKID, EXAMPLE_SECRET);
        let signing_key = SigningKey::from_bytes(&scalar).expect("signing key");
        let sig: Signature = signing_key.sign(b"some-message");
        let der_hex = hex::encode(sig.to_der().as_ref());
        assert!(der_hex.len() <= MAX_SIGV4A_DER_SIGNATURE_HEX_LEN);
        let padded = format!(
            "{}{}",
            der_hex,
            "*".repeat(MAX_SIGV4A_DER_SIGNATURE_HEX_LEN - der_hex.len())
        );
        let trimmed = parse_streaming_der_signature_hex_padded(&padded).expect("parses");
        assert_eq!(trimmed, hex::decode(&der_hex).unwrap());
    }

    #[test]
    fn parse_streaming_der_signature_hex_padded_rejects_over_max_length() {
        let over = "a".repeat(MAX_SIGV4A_DER_SIGNATURE_HEX_LEN + 1);
        let err = parse_streaming_der_signature_hex_padded(&over).expect_err("over-max");
        assert!(matches!(err, SigV4aCryptoError::InvalidSignatureHex));
    }

    /// `<valid-DER-hex>` followed by `*` characters that DON'T bring
    /// the total length to exactly `MAX_SIGV4A_DER_SIGNATURE_HEX_LEN`
    /// must reject. AWS CRT padding is either absent or fixed-width
    /// to 144; partial trailing padding is nonsensical wire shape
    /// and has never appeared in a legitimate stream. Without the
    /// explicit length-equality guard, the trim-and-DER-validate
    /// path would accept this input — not a crypto bypass (the
    /// trimmed DER still verifies) but wire-format laxness that
    /// hides real client bugs.
    ///
    /// Bug-revert reasoning: removing the
    /// `s.len() != MAX_SIGV4A_DER_SIGNATURE_HEX_LEN` guard inside
    /// the `Some(first_star) = s.find('*')` branch flips this from
    /// `InvalidSignatureHex` to `Ok(_)`.
    #[test]
    fn test_streaming_padding_partial_rejected() {
        // The partial-padding rejection fires BEFORE DER validation
        // (`s.len() != MAX_SIGV4A_DER_SIGNATURE_HEX_LEN` is checked
        // inside the `Some(first_star)` branch up front), so a short
        // hex prefix + a few stars suffices as a fixture — there's
        // no need to construct a real DER signature first. Pick a
        // total length well below 144 so the partial-padding
        // condition is unambiguous.
        let padded = format!("{}{}", "deadbeef", "*".repeat(4));
        assert!(padded.len() < MAX_SIGV4A_DER_SIGNATURE_HEX_LEN);
        let err = parse_streaming_der_signature_hex_padded(&padded)
            .expect_err("partial padding must reject");
        assert!(matches!(err, SigV4aCryptoError::InvalidSignatureHex));
    }

    /// A `*` interspersed in the middle of the hex (so non-trailing)
    /// must reject as `InvalidSignatureHex`. The check fires
    /// explicitly via the "every byte from first_star through end
    /// must be `*`" rule, NOT indirectly through
    /// `parse_der_signature_hex`'s lowercase-hex failure on the
    /// trimmed prefix. Explicit rejection makes the contract clearer
    /// and keeps the error variant on the padding-shape path.
    #[test]
    fn test_streaming_padding_interspersed_star_rejected() {
        // First star at byte 4, total length exactly 144, but byte 5
        // is hex (not `*`) — so the trailing-only rule fails.
        let mut buf = String::with_capacity(MAX_SIGV4A_DER_SIGNATURE_HEX_LEN);
        buf.push_str("3044");
        buf.push('*');
        // Fill the rest with hex digits then a star — proves the
        // explicit "all-stars-from-first-star" check fires.
        let remaining = MAX_SIGV4A_DER_SIGNATURE_HEX_LEN - buf.len();
        buf.push_str(&"a".repeat(remaining - 1));
        buf.push('*');
        assert_eq!(buf.len(), MAX_SIGV4A_DER_SIGNATURE_HEX_LEN);
        let err = parse_streaming_der_signature_hex_padded(&buf)
            .expect_err("interspersed star must reject");
        assert!(matches!(err, SigV4aCryptoError::InvalidSignatureHex));
    }

    /// `<valid-DER-hex>` with NO padding (length < 144) is the
    /// "unpadded" wire shape and must continue to be accepted. Pins
    /// the no-padding branch so a future refactor that requires
    /// padding doesn't accidentally reject unpadded clients.
    #[test]
    fn test_streaming_no_padding_accepted() {
        let scalar = aws_reference_scalar(EXAMPLE_AKID, EXAMPLE_SECRET);
        let signing_key = SigningKey::from_bytes(&scalar).expect("signing key");
        let sig: Signature = signing_key.sign(b"some-message");
        let der_hex = hex::encode(sig.to_der().as_ref());
        assert!(der_hex.len() < MAX_SIGV4A_DER_SIGNATURE_HEX_LEN);
        let parsed = parse_streaming_der_signature_hex_padded(&der_hex).expect("unpadded ok");
        assert_eq!(parsed, hex::decode(&der_hex).unwrap());
    }

    #[test]
    fn be_less_or_equal_works_at_boundaries() {
        let mut almost_n_minus_2 = N_MINUS_2_BE;
        almost_n_minus_2[31] -= 1;
        assert!(be_less_or_equal(&almost_n_minus_2, &N_MINUS_2_BE));
        assert!(be_less_or_equal(&N_MINUS_2_BE, &N_MINUS_2_BE));
        let mut just_over = N_MINUS_2_BE;
        just_over[31] += 1;
        assert!(!be_less_or_equal(&just_over, &N_MINUS_2_BE));
    }

    #[test]
    fn be_add_one_carries_correctly() {
        let mut a = [0u8; 32];
        a[31] = 0xff;
        a[30] = 0x00;
        let out = be_add_one(&a);
        assert_eq!(out[31], 0x00);
        assert_eq!(out[30], 0x01);
    }
}
