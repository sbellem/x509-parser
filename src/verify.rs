use crate::prelude::*;
use crate::signature_algorithm::RsaSsaPssParams;
use asn1_rs::{Any, BitString, DerParser};
use oid_registry::{
    OID_EC_P256, OID_NIST_EC_P384, OID_NIST_EC_P521, OID_NIST_HASH_SHA256, OID_NIST_HASH_SHA384,
    OID_NIST_HASH_SHA512, OID_PKCS1_RSASSAPSS, OID_PKCS1_SHA1WITHRSA, OID_PKCS1_SHA256WITHRSA,
    OID_PKCS1_SHA384WITHRSA, OID_PKCS1_SHA512WITHRSA, OID_SHA1_WITH_RSA, OID_SIG_ECDSA_WITH_SHA256,
    OID_SIG_ECDSA_WITH_SHA384, OID_SIG_ECDSA_WITH_SHA512, OID_SIG_ED25519,
};

#[cfg(feature = "verify-rc-p521")]
use p521::ecdsa::{VerifyingKey, Signature as P521Signature};
#[cfg(feature = "verify-rc-p521")]
use p521::ecdsa::signature::Verifier;
//#[cfg(feature = "verify-rc-p521")]
//use p521::elliptic_curve::sec1::ToEncodedPoint;

// Since the `signature` object is similar in ring and in aws-lc-rs, we just use simple logic
// to determine which one to use.
// If both verify and verify-aws features are enabled, aws will be used.
#[cfg(feature = "verify-aws")]
use aws_lc_rs::signature;
#[cfg(all(feature = "verify", not(feature = "verify-aws")))]
use ring::signature;

/// Verify the cryptographic signature of the raw data (can be a certificate, a CRL or a CSR).
///
/// `public_key` is the public key of the **signer**.
///
/// Not all algorithms are supported, this function is limited to what `aws_lc_rs` or `ring` supports,
/// but now also supports ECDSA with P-521 via RustCrypto if the `verify-rc-p521` feature is enabled.
pub fn verify_signature(
    public_key: &SubjectPublicKeyInfo,
    signature_algorithm: &AlgorithmIdentifier,
    signature_value: &BitString,
    raw_data: &[u8],
) -> Result<(), X509Error> {
    let AlgorithmIdentifier {
        algorithm: signature_algorithm,
        parameters: signature_algorithm_parameters,
    } = &signature_algorithm;

    // --- P-521 ECDSA Support (RustCrypto) ---
    #[cfg(feature = "verify-rc-p521")]
    {
        // OID for ECDSA with SHA-512 and secp521r1
        if *signature_algorithm == OID_SIG_ECDSA_WITH_SHA512 {
            // Is the curve P-521?
            let curve_oid = public_key.algorithm.parameters.as_ref()
                .and_then(|p| p.as_oid().ok());
            if curve_oid == Some(OID_NIST_EC_P521) {
                // Get public key bytes (uncompressed SEC1)
                let pubkey_bytes = public_key.subject_public_key.as_raw_slice();
                // The bitstring usually starts with 0x04 (uncompressed marker)
                let verifying_key = VerifyingKey::from_sec1_bytes(pubkey_bytes)
                    .map_err(|_| X509Error::InvalidSPKI)?;
                // Signature is ASN.1 DER encoded
                let signature_bytes = signature_value.as_raw_slice();
                let signature = P521Signature::from_der(signature_bytes)
                    .map_err(|_| X509Error::InvalidSignatureValue)?;
                // Message is the raw_data (tbsCertificate)
                verifying_key.verify(raw_data, &signature)
                    .map_err(|_| X509Error::SignatureVerificationError)?;
                return Ok(());
            }
        }
    }
    // --- End P-521 Patch ---

    // identify verification algorithm
    let verification_alg: &dyn signature::VerificationAlgorithm = if *signature_algorithm
        == OID_PKCS1_SHA1WITHRSA
        || *signature_algorithm == OID_SHA1_WITH_RSA
    {
        &signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY
    } else if *signature_algorithm == OID_PKCS1_SHA256WITHRSA {
        &signature::RSA_PKCS1_2048_8192_SHA256
    } else if *signature_algorithm == OID_PKCS1_SHA384WITHRSA {
        &signature::RSA_PKCS1_2048_8192_SHA384
    } else if *signature_algorithm == OID_PKCS1_SHA512WITHRSA {
        &signature::RSA_PKCS1_2048_8192_SHA512
    } else if *signature_algorithm == OID_PKCS1_RSASSAPSS {
        get_rsa_pss_verification_algo(signature_algorithm_parameters)
            .ok_or(X509Error::SignatureUnsupportedAlgorithm)?
    } else if *signature_algorithm == OID_SIG_ECDSA_WITH_SHA256 {
        get_ec_curve_sha(&public_key.algorithm, 256)
            .ok_or(X509Error::SignatureUnsupportedAlgorithm)?
    } else if *signature_algorithm == OID_SIG_ECDSA_WITH_SHA384 {
        get_ec_curve_sha(&public_key.algorithm, 384)
            .ok_or(X509Error::SignatureUnsupportedAlgorithm)?
    } else if *signature_algorithm == OID_SIG_ED25519 {
        &signature::ED25519
    } else {
        return Err(X509Error::SignatureUnsupportedAlgorithm);
    };
    // get public key
    let key = signature::UnparsedPublicKey::new(
        verification_alg,
        public_key.subject_public_key.as_raw_slice(),
    );
    // verify signature
    key.verify(raw_data, signature_value.as_raw_slice())
        .or(Err(X509Error::SignatureVerificationError))
}

/// Find the verification algorithm for the given EC curve and SHA digest size
///
/// Not all algorithms are supported, we are limited to what `aws_lc_rs`  or `ring`supports.
fn get_ec_curve_sha(
    pubkey_alg: &AlgorithmIdentifier,
    sha_len: usize,
) -> Option<&'static dyn signature::VerificationAlgorithm> {
    let curve_oid = pubkey_alg.parameters.as_ref()?.as_oid().ok()?;
    if curve_oid == OID_EC_P256 {
        match sha_len {
            256 => Some(&signature::ECDSA_P256_SHA256_ASN1),
            384 => Some(&signature::ECDSA_P256_SHA384_ASN1),
            _ => None,
        }
    } else if curve_oid == OID_NIST_EC_P384 {
        match sha_len {
            256 => Some(&signature::ECDSA_P384_SHA256_ASN1),
            384 => Some(&signature::ECDSA_P384_SHA384_ASN1),
            _ => None,
        }
    } else {
        None
    }
}

/// Find the verification algorithm for the given RSA-PSS parameters
///
/// Not all algorithms are supported, we are limited to what `aws_lc_rs` or `ring` supports.
/// Notably, the SHA-1 hash algorithm is not supported.
fn get_rsa_pss_verification_algo(
    params: &Option<Any>,
) -> Option<&'static dyn signature::VerificationAlgorithm> {
    let params = params.as_ref()?;
    let (_, params) =
        RsaSsaPssParams::from_der_content(&params.header, params.data.clone()).ok()?;
    let hash_algo = params.hash_algorithm_oid();

    if *hash_algo == OID_NIST_HASH_SHA256 {
        Some(&signature::RSA_PSS_2048_8192_SHA256)
    } else if *hash_algo == OID_NIST_HASH_SHA384 {
        Some(&signature::RSA_PSS_2048_8192_SHA384)
    } else if *hash_algo == OID_NIST_HASH_SHA512 {
        Some(&signature::RSA_PSS_2048_8192_SHA512)
    } else {
        None
    }
}
