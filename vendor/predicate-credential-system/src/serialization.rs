//! Serialization of protocol objects: their byte encoding on the wire and, with the cargo
//! feature `serde`, JSON-friendly text forms.
//!
//! # Bytes
//!
//! The wire format is the arkworks **compressed** canonical encoding, **validated**, without
//! trailing bytes: [`to_bytes`], [`from_bytes`] and the blanket trait [`WireFormat`].
//!
//! Implementation notes (not claims of the paper; the paper only asks to "reject malformed
//! input", construction box, `VerifyAtt` step 3 and `VerifyProof` step 3):
//!
//! * Compressed decoding with validation checks that a point is on the curve and in the
//!   prime-order subgroup and that a scalar is canonical (`< p`), so `z` and `z + p` are never
//!   both accepted. Uncompressed input is never accepted by this crate: for BLS12-381 the
//!   uncompressed validated path of arkworks 0.6.0 skips the curve equation.
//! * arkworks validation **accepts** the identity point and the zero scalar. Every
//!   non-degeneracy requirement of the paper (`T ≠ 1`, `σ'_1 ≠ 1`, ...) is therefore an explicit
//!   check in the verifier of the corresponding relation, never a property of decoding. This is
//!   about the VALUES of a statement. One parameter type adds a check of its own to validated
//!   decoding: [`DY`](crate::kiprf::DY) refuses the identity in the place of its
//!   generator, for liveness and not for soundness (module docs of [`crate::kiprf::dy`],
//!   "Degenerate parameters"); its verifier-side check stays in place all the same.
//! * `deserialize_*` reads a prefix of its input; [`from_bytes`] additionally rejects leftovers,
//!   so every accepted byte string is the unique encoding of the value it decodes to.
//!
//! # Text forms (cargo feature `serde`)
//!
//! Implementation note: nothing here is part of the paper. The canonical wire format of this
//! crate stays the byte encoding above (and the fixed-format compact codec of [`crate::pcs`]);
//! the `serde` layer wraps it for consumers whose messages and stores are JSON (`serde_json`,
//! JCS-canonicalised documents, multibase strings). Its items are `to_multibase`,
//! `from_multibase` and the `#[serde(with = …)]` adapters `canonical`, `secret` and `utf8_label`.
//!
//! ## Two shapes
//!
//! * **Opaque.** A value with a canonical encoding is ONE string: the multibase **base58btc**
//!   text (prefix `z`) of its compressed canonical bytes, the convention of a W3C Data Integrity
//!   `proofValue`. Keys, credentials, pre-credentials, shown credentials, public parameters, tag
//!   parameters, [`FSProof`](crate::sigma::FSProof) and the secrets are opaque.
//! * **Structured.** [`Predicate`](crate::pcs::Predicate),
//!   [`Attestation`](crate::pcs::Attestation), [`IssuanceProof`](crate::pcs::IssuanceProof) and
//!   [`RootRequest`](crate::pcs::RootRequest) are JSON objects with camelCase members whose leaves
//!   are opaque strings, so that a policy engine can read, say, the `phi` of every attestation
//!   without decoding group elements:
//!
//! ```json
//! { "tag": "z…", "shown": "z…", "phi": "z…", "proof": "z…" }
//! ```
//!
//! ## Code that is generic over the base or the tag
//!
//! The `Serialize` / `Deserialize` impls of keys, credentials and the like exist per base
//! (`PSVerificationKey`, `BBSPreCredential`, …), not on the associated types of the traits:
//! adding `serde` bounds to `CredentialBase` behind a feature would change the trait for every
//! implementor. Generic code uses the adapters instead, which work for anything with a canonical
//! encoding:
//!
//! ```
//! use predicate_credential_system::cred::CredentialBase;
//!
//! #[derive(serde::Serialize, serde::Deserialize)]
//! #[serde(bound = "")]
//! struct JoinReply<B: CredentialBase> {
//!     #[serde(with = "predicate_credential_system::serialization::canonical")]
//!     pre_credential: B::PreCredential,
//! }
//! ```
//!
//! ## Strictness
//!
//! Decoding accepts exactly what encoding produces: base58btc only (any other multibase prefix is
//! an error), compressed canonical bytes, validated group elements (on the curve and in the
//! prime-order subgroup), canonical scalars, no trailing bytes, no unknown members. One object
//! therefore has one JSON form, as it has one binary form. As everywhere in this crate, decoding
//! says nothing about the VALIDITY of an object: the verifiers decide that, and they re-validate
//! what they are given.
//!
//! ## Secrets
//!
//! [`UserSecretKey`](crate::pcs::UserSecretKey), [`HelperSecretKey`](crate::pcs::HelperSecretKey), [`IssuanceState`](crate::pcs::IssuanceState), [`Credential`](crate::pcs::Credential) (it carries `m_aux`)
//! and the signing keys of the bases implement the traits as well, because a consumer has to
//! keep them somewhere (an issuance state, for instance, lives from `Prove` until the helper
//! answers). Their text form IS the secret: serialize them only into protected storage and
//! never into logs or messages. The buffers this module owns are wiped after use; copies made
//! inside `serde`, `multibase` or the chosen data format are out of its reach.
//!
//! ## Example
//!
//! ```
//! use predicate_credential_system::pcs::Predicate;
//!
//! let f = Predicate::new(5, b"members".to_vec());
//! let json = serde_json::to_string(&f).unwrap();
//! assert_eq!(json, r#"{"threshold":5,"label":"members"}"#);
//! assert_eq!(serde_json::from_str::<Predicate>(&json).unwrap(), f);
//! ```

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::error::Error;

/// Encodes `value` in the compressed canonical encoding.
///
/// # Errors
/// [`Error::Serialization`] if the value's serializer fails (arkworks group and field elements
/// never do when writing into memory).
pub fn to_bytes<T: CanonicalSerialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::with_capacity(value.compressed_size());
    value.serialize_compressed(&mut bytes)?;
    Ok(bytes)
}

/// Decodes a value from its compressed canonical encoding, with full validation, and rejects
/// trailing bytes.
///
/// # Errors
/// [`Error::Serialization`] for malformed, non-canonical, off-curve or wrong-subgroup input and
/// [`Error::TrailingBytes`] if `bytes` continues after the value.
pub fn from_bytes<T: CanonicalDeserialize>(bytes: &[u8]) -> Result<T, Error> {
    let mut reader = bytes;
    let value = T::deserialize_compressed(&mut reader)?;
    if reader.is_empty() {
        Ok(value)
    } else {
        Err(Error::TrailingBytes)
    }
}

/// Method-call sugar for [`to_bytes`] / [`from_bytes`], implemented for every canonically
/// serializable type (in particular for every public protocol object of this crate).
pub trait WireFormat: CanonicalSerialize + CanonicalDeserialize + Sized {
    /// See [`to_bytes`].
    ///
    /// # Errors
    /// See [`to_bytes`].
    fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        to_bytes(self)
    }

    /// See [`from_bytes`].
    ///
    /// # Errors
    /// See [`from_bytes`].
    fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        from_bytes(bytes)
    }
}

impl<T: CanonicalSerialize + CanonicalDeserialize> WireFormat for T {}

#[cfg(test)]
mod tests {
    use ark_bls12_381::{Fr, G1Affine, G1Projective};
    use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
    use ark_ff::{BigInteger, PrimeField, Zero};

    use super::*;

    #[test]
    fn round_trip_and_sizes() {
        let p = G1Projective::generator() * Fr::from(7u64);
        let bytes = p.to_bytes().unwrap();
        assert_eq!(bytes.len(), 48);
        assert_eq!(G1Projective::from_bytes(&bytes).unwrap(), p);
        // projective and affine encodings coincide
        assert_eq!(p.into_affine().to_bytes().unwrap(), bytes);

        let s = Fr::from(123_456_789u64);
        let bytes = s.to_bytes().unwrap();
        assert_eq!(bytes.len(), 32);
        assert_eq!(Fr::from_bytes(&bytes).unwrap(), s);
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut bytes = Fr::from(5u64).to_bytes().unwrap();
        bytes.push(0);
        assert_eq!(Fr::from_bytes(&bytes), Err(Error::TrailingBytes));
    }

    #[test]
    fn truncated_input_is_rejected() {
        let bytes = G1Affine::generator().to_bytes().unwrap();
        assert!(matches!(
            G1Affine::from_bytes(&bytes[..47]),
            Err(Error::Serialization(_))
        ));
        assert!(matches!(
            G1Affine::from_bytes(&[]),
            Err(Error::Serialization(_))
        ));
    }

    #[test]
    fn non_canonical_scalar_is_rejected() {
        // the modulus itself is the smallest non-canonical encoding
        let modulus = Fr::MODULUS.to_bytes_le();
        assert_eq!(modulus.len(), 32);
        assert!(matches!(
            Fr::from_bytes(&modulus),
            Err(Error::Serialization(_))
        ));
        assert!(matches!(
            Fr::from_bytes(&[0xff; 32]),
            Err(Error::Serialization(_))
        ));
    }

    #[test]
    fn malformed_point_is_rejected() {
        // all-zero bytes are not a valid compressed BLS12-381 point (the compression flag is unset)
        assert!(matches!(
            G1Affine::from_bytes(&[0u8; 48]),
            Err(Error::Serialization(_))
        ));
    }

    /// Documents the hazard the module docs warn about: decoding does NOT reject the identity.
    #[test]
    fn identity_decodes_successfully() {
        let bytes = G1Affine::zero().to_bytes().unwrap();
        assert_eq!(bytes[0], 0xc0);
        assert!(G1Affine::from_bytes(&bytes).unwrap().is_zero());
        assert!(Fr::from_bytes(&[0u8; 32]).unwrap().is_zero());
    }
}

// ---------------------------------------------------------------------------------------------
// Text forms (cargo feature `serde`)
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "serde")]
pub use self::text::{canonical, from_multibase, secret, to_multibase, utf8_label};

/// The `serde` layer (module docs, "Text forms"). One private module, so that a single `cfg`
/// switches it off; its public items are re-exported above.
#[cfg(feature = "serde")]
mod text {
    use ark_ec::{PrimeGroup, pairing::Pairing};
    use ark_ff::PrimeField;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use zeroize::Zeroizing;

    use crate::{
        cred::{
            CredentialBase, SigmaFriendlyCredentialBase,
            bbs::{
                BBSCredential, BBSPreCredential, BBSPublicParams, BBSShownCredential,
                BBSSigningKey, BBSVerificationKey,
            },
            eq::{
                EQCredential, EQPreCredential, EQShownCredential, EQSigningKey, EQVerificationKey,
            },
            mac::{MACCredential, MACKey, MACPreCredential, MACPublicParams, MACShownCredential},
            ps::{
                PSCredential, PSPreCredential, PSShownCredential, PSSigningKey, PSVerificationKey,
            },
        },
        error::Error,
        hash::HashToGroup,
        kiprf::{DDH, DY, PCSTag},
        pcs::{Credential, HelperSecretKey, IssuanceState, PublicParameters, UserSecretKey},
        sigma::FSProof,
    };

    /// The one multibase base this module emits and accepts: base58btc, prefix `z`.
    const BASE: multibase::Base = multibase::Base::Base58Btc;

    /// The multibase base58btc text (`z…`) of `bytes`.
    #[must_use]
    pub fn to_multibase(bytes: &[u8]) -> String {
        multibase::encode(BASE, bytes)
    }

    /// The bytes of a multibase base58btc text; the inverse of [`to_multibase`].
    ///
    /// # Errors
    /// [`Error::Serialization`] if `text` is not multibase or uses another base than base58btc.
    pub fn from_multibase(text: &str) -> Result<Vec<u8>, Error> {
        match multibase::decode(text) {
            Ok((BASE, bytes)) => Ok(bytes),
            Ok((base, bytes)) => {
                drop(Zeroizing::new(bytes));
                Err(Error::Serialization(format!(
                    "multibase base {base:?} is not accepted, expected base58btc (prefix 'z')"
                )))
            }
            Err(e) => Err(Error::Serialization(format!("invalid multibase text: {e}"))),
        }
    }

    /// `#[serde(with = "predicate_credential_system::serialization::canonical")]`: any value with a canonical encoding as
    /// one opaque multibase string (compressed, validated, no trailing bytes).
    pub mod canonical {
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
        use serde::{Deserialize, Deserializer, Serializer, de::Error as _, ser::Error as _};

        use super::{from_multibase, to_multibase};
        use crate::serialization;

        /// Serializes `value` as the multibase text of its compressed canonical bytes.
        ///
        /// # Errors
        /// The serializer's error if the value cannot be encoded.
        pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
        where
            T: CanonicalSerialize + ?Sized,
            S: Serializer,
        {
            let bytes = serialization::to_bytes(value).map_err(S::Error::custom)?;
            serializer.serialize_str(&to_multibase(&bytes))
        }

        /// Deserializes a value from the multibase text of its compressed canonical bytes.
        ///
        /// # Errors
        /// The deserializer's error for anything but the strict form described in the
        /// [module docs](crate::serialization).
        pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
        where
            T: CanonicalDeserialize,
            D: Deserializer<'de>,
        {
            let text = String::deserialize(deserializer)?;
            let bytes = from_multibase(&text).map_err(D::Error::custom)?;
            serialization::from_bytes(&bytes).map_err(D::Error::custom)
        }
    }

    /// As [`canonical`], for secrets: the buffers this module owns are wiped after use.
    pub mod secret {
        use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
        use serde::{Deserialize, Deserializer, Serializer, de::Error as _, ser::Error as _};
        use zeroize::Zeroizing;

        use super::{from_multibase, to_multibase};
        use crate::serialization;

        /// Serializes the secret `value` as the multibase text of its compressed canonical bytes.
        ///
        /// # Errors
        /// The serializer's error if the value cannot be encoded.
        pub fn serialize<T, S>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
        where
            T: CanonicalSerialize + ?Sized,
            S: Serializer,
        {
            let bytes = Zeroizing::new(serialization::to_bytes(value).map_err(S::Error::custom)?);
            serialize_bytes(&bytes, serializer)
        }

        /// Serializes already encoded secret bytes.
        pub(super) fn serialize_bytes<S: Serializer>(
            bytes: &[u8],
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            let text = Zeroizing::new(to_multibase(bytes));
            serializer.serialize_str(&text)
        }

        /// The decoded bytes of a secret, in a buffer that is wiped on drop.
        pub(super) fn deserialize_bytes<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Zeroizing<Vec<u8>>, D::Error> {
            let text = Zeroizing::new(String::deserialize(deserializer)?);
            from_multibase(&text)
                .map(Zeroizing::new)
                .map_err(D::Error::custom)
        }

        /// Deserializes a secret from the multibase text of its compressed canonical bytes.
        ///
        /// # Errors
        /// The deserializer's error for anything but the strict form described in the
        /// [module docs](crate::serialization).
        pub fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
        where
            T: CanonicalDeserialize,
            D: Deserializer<'de>,
        {
            let bytes = deserialize_bytes(deserializer)?;
            serialization::from_bytes(&bytes).map_err(D::Error::custom)
        }
    }

    /// `#[serde(with = "…")]` for the label of a [`Predicate`](crate::pcs::Predicate): a JSON
    /// string. Labels are byte strings in this crate and names in practice; a label that is not
    /// UTF-8 has no JSON form and is a serialization error (its canonical encoding still works).
    pub mod utf8_label {
        use serde::{Deserialize, Deserializer, Serializer, ser::Error as _};

        /// Serializes a UTF-8 label as a string.
        ///
        /// # Errors
        /// The serializer's error if the label is not valid UTF-8.
        pub fn serialize<S: Serializer>(label: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
            let text = core::str::from_utf8(label).map_err(|_| {
                S::Error::custom("a predicate label that is not UTF-8 has no JSON form")
            })?;
            serializer.serialize_str(text)
        }

        /// Deserializes a label from a string.
        ///
        /// # Errors
        /// The deserializer's error if the value is not a string.
        pub fn deserialize<'de, D: Deserializer<'de>>(
            deserializer: D,
        ) -> Result<Vec<u8>, D::Error> {
            String::deserialize(deserializer).map(String::into_bytes)
        }
    }

    /// Opaque implementations through [`canonical`] / [`secret`].
    macro_rules! opaque {
        ($adapter:ident: $( impl[$($generics:tt)*] $ty:ty; )+) => {$(
            impl<$($generics)*> Serialize for $ty {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    $adapter::serialize(self, serializer)
                }
            }

            impl<'de, $($generics)*> Deserialize<'de> for $ty {
                fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                    $adapter::deserialize(deserializer)
                }
            }
        )+};
    }

    opaque! { canonical:
        impl[F: PrimeField] FSProof<F>;
        impl[E: Pairing, B: SigmaFriendlyCredentialBase<E>, T: PCSTag<E::G1>] PublicParameters<E, B, T>;
        impl[G: PrimeGroup, H: HashToGroup<G>] DDH<G, H>;
        impl[G: PrimeGroup] DY<G>;
        impl[E: Pairing] PSVerificationKey<E>;
        impl[E: Pairing] PSCredential<E>;
        impl[E: Pairing] PSPreCredential<E>;
        impl[E: Pairing] PSShownCredential<E>;
        impl[E: Pairing] BBSPublicParams<E>;
        impl[E: Pairing] BBSVerificationKey<E>;
        impl[E: Pairing] BBSCredential<E>;
        impl[E: Pairing] BBSPreCredential<E>;
        impl[E: Pairing] BBSShownCredential<E>;
        impl[E: Pairing] EQVerificationKey<E>;
        impl[E: Pairing] EQCredential<E>;
        impl[E: Pairing] EQPreCredential<E>;
        impl[E: Pairing] EQShownCredential<E>;
        impl[G: PrimeGroup] MACPublicParams<G>;
        impl[G: PrimeGroup] MACCredential<G>;
        impl[G: PrimeGroup] MACPreCredential<G>;
        impl[G: PrimeGroup] MACShownCredential<G>;
    }

    opaque! { secret:
        impl[E: Pairing] UserSecretKey<E>;
        impl[B: CredentialBase] HelperSecretKey<B>;
        impl[E: Pairing, B: SigmaFriendlyCredentialBase<E>] Credential<E, B>;
        impl[E: Pairing] PSSigningKey<E>;
        impl[E: Pairing] BBSSigningKey<E>;
        impl[E: Pairing] EQSigningKey<E>;
        impl[G: PrimeGroup] MACKey<G>;
    }

    // `st_iss` has no derived canonical encoding (its hidden message is rebuilt from `usk` and
    // `m_aux`), so it goes through its own `to_bytes` / `from_bytes`.
    impl<E: Pairing, B: SigmaFriendlyCredentialBase<E>> Serialize for IssuanceState<E, B> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let bytes = self.to_bytes().map_err(serde::ser::Error::custom)?;
            secret::serialize_bytes(&bytes, serializer)
        }
    }

    impl<'de, E: Pairing, B: SigmaFriendlyCredentialBase<E>> Deserialize<'de> for IssuanceState<E, B> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            let bytes = secret::deserialize_bytes(deserializer)?;
            Self::from_bytes(&bytes).map_err(serde::de::Error::custom)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn multibase_text_is_base58btc_only() {
            let text = to_multibase(&[1, 2, 3]);
            assert!(text.starts_with('z'));
            assert_eq!(from_multibase(&text).unwrap(), vec![1, 2, 3]);
            // the same bytes under another base are refused: one object, one text form
            let other = multibase::encode(multibase::Base::Base64Url, [1, 2, 3]);
            assert!(matches!(
                from_multibase(&other),
                Err(Error::Serialization(_))
            ));
            assert!(matches!(
                from_multibase("not multibase"),
                Err(Error::Serialization(_))
            ));
            assert!(matches!(from_multibase(""), Err(Error::Serialization(_))));
        }
    }
}
