//! Predicates, the predicate encoding `EncPred`, and public attribute policies (paper §5.1,
//! "Scheme description" and Def. "Threshold authorization relation").
//!
//! | paper | here |
//! |---|---|
//! | the predicate family `F = {f_k}_{k ∈ N}` | [`Predicate`] |
//! | the canonical serialization `⟨f⟩` | [`Predicate::canonical_bytes`] |
//! | `EncPred(f) := H_0("predicate" ‖ ⟨f⟩)` | [`enc_pred`] |
//! | the root predicate `f_root` (Remark "Chaining and the base case") | [`Predicate::root`] |
//! | the public attribute policy `P : M_pub^k → {0,1}` | [`AttributePolicy`], [`AcceptAll`] (`P ≡ 1`), [`AllowList`], closures |

use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use crate::{error::Error, hash::h0_predicate};

/// A threshold predicate `f_k`: it "checks that the witness contains `k` attestations from
/// pairwise-distinct certified attesters for the identifier at hand" (§5.1).
///
/// Implementation note: the paper's family is indexed by `k` alone. A deployment needs more than
/// one predicate per threshold (the paper assumes "coarse", "community- or role-level"
/// predicates, and a distinguished root predicate `f_root`), so a predicate here is the pair of
/// the threshold and an application-chosen label. Both enter `⟨f⟩`, hence `EncPred(f)` and the
/// Fiat-Shamir context of an issuance proof.
///
/// A predicate with threshold `0` is a **root predicate** ([`Self::root`]). The ordinary
/// `Prove → VerifyProof → Issue` path rejects it ([`Error::ZeroThreshold`]): with `k = 0` the
/// routine `CheckAtts_P` accepts the empty list, and every key would get a credential without a
/// single endorser. Root credentials are issued through the explicitly named root path of
/// [`PCS`](super::PCS) and nowhere else.
#[derive(
    Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, CanonicalSerialize, CanonicalDeserialize,
)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
pub struct Predicate {
    /// The threshold `k`: the exact number of attestations an issuance proof for this predicate
    /// carries. `0` marks a root predicate.
    pub threshold: u32,
    /// An application-chosen label, e.g. the name of a community or role. Public.
    #[cfg_attr(feature = "serde", serde(with = "crate::serialization::utf8_label"))]
    pub label: Vec<u8>,
}

impl Predicate {
    /// The predicate `f_k` with the threshold `k = threshold` and the given label.
    #[must_use]
    pub fn new(threshold: u32, label: impl Into<Vec<u8>>) -> Self {
        Self {
            threshold,
            label: label.into(),
        }
    }

    /// A root predicate `f_root` (Remark "Chaining and the base case"): threshold `0`.
    #[must_use]
    pub fn root(label: impl Into<Vec<u8>>) -> Self {
        Self::new(0, label)
    }

    /// Whether this is a root predicate (threshold `0`).
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.threshold == 0
    }

    /// The canonical serialization `⟨f⟩`: the threshold as a 4-byte little-endian integer, the
    /// length of the label as an 8-byte little-endian integer, the label.
    ///
    /// The map is injective: the first twelve bytes determine the threshold and the length of
    /// the label, and the remaining bytes are the label. (These are also the bytes of the derived
    /// compressed canonical encoding of a `Predicate`; a unit test pins both.)
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + 8 + self.label.len());
        bytes.extend_from_slice(&self.threshold.to_le_bytes());
        // `usize` is at most 64 bits wide on every supported target, so the cast is lossless.
        bytes.extend_from_slice(&(self.label.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&self.label);
        bytes
    }
}

/// `EncPred(f) := H_0("predicate" ‖ ⟨f⟩)`, the "public, deterministic, collision-resistant
/// predicate encoding" of §5.1 into `M_pub = Z_p`, for the deployment label `deployment` (the
/// oracle `H_0` is bound to it, see [`crate::hash`]). "The encoding is public and is not assumed
/// to hide `f`."
///
/// Defined for every predicate, root predicates included: attesters show root credentials, and
/// `VerifyCred` takes any `f`.
///
/// # Errors
/// Implementation note: [`Error::DegenerateInput`] if `EncPred(f) = 0`. `Σ-EQ` certifies
/// `(g_1, g_1^usk, g_1^φ)` and needs `g_1^φ ≠ 1`; the event has probability `1/p` for a random
/// oracle, and refusing it for every base keeps `EncPred` independent of the base.
pub fn enc_pred<F: PrimeField>(deployment: &[u8], f: &Predicate) -> Result<F, Error> {
    let phi: F = h0_predicate(deployment, &f.canonical_bytes());
    if phi.is_zero() {
        return Err(Error::DegenerateInput("EncPred(f) = 0"));
    }
    Ok(phi)
}

/// A public attribute policy `P : M_pub^k → {0,1}` over the predicate labels `(φ_j)_{j ∈ [k]}`
/// that the attestations of an issuance proof disclose (Def. "Threshold authorization
/// relation"): "The policy `P` determines which revealed predicate labels are admissible,
/// including whether credentials carrying the root tag `φ_root` count toward a threshold".
///
/// The policy is evaluated by `CheckAtts_P`, i.e. by `Prove` and by `VerifyProof`. It is the
/// VERIFIER's policy that decides: a policy is not part of `pp` or of the Fiat-Shamir
/// contexts, so a proof made under a laxer policy is simply rejected by `CheckAtts_P` of a
/// stricter verifier.
///
/// Implemented by [`AcceptAll`], by [`AllowList`] and by every closure `Fn(&[F]) -> bool`.
pub trait AttributePolicy<F> {
    /// `P((φ_j)_{j ∈ [k]})`, with the labels in the order of the attestations. Deterministic;
    /// must not panic.
    fn accepts(&self, phis: &[F]) -> bool;
}

/// The policy `P ≡ 1`: "take `P ≡ 1` when no attribute restriction is required" (Def.
/// "Threshold authorization relation"). Root credentials count toward every threshold.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AcceptAll;

impl<F> AttributePolicy<F> for AcceptAll {
    fn accepts(&self, _phis: &[F]) -> bool {
        true
    }
}

/// The policy that accepts iff EVERY disclosed label `φ_j` is on a list of admissible values
/// `EncPred(f)`. Leaving `φ_root` off the list means that root credentials do not count toward
/// a threshold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllowList<F> {
    allowed: Vec<F>,
}

impl<F: PrimeField> AllowList<F> {
    /// The policy that admits exactly the given values of `EncPred`.
    #[must_use]
    pub fn new(allowed: impl IntoIterator<Item = F>) -> Self {
        Self {
            allowed: allowed.into_iter().collect(),
        }
    }

    /// The policy that admits attesters whose credentials were issued under one of
    /// `predicates`, in the deployment `deployment` (the label that is given to `Setup`).
    ///
    /// # Errors
    /// Propagates [`enc_pred`].
    pub fn from_predicates<'a>(
        deployment: &[u8],
        predicates: impl IntoIterator<Item = &'a Predicate>,
    ) -> Result<Self, Error> {
        predicates
            .into_iter()
            .map(|f| enc_pred(deployment, f))
            .collect::<Result<Vec<F>, Error>>()
            .map(Self::new)
    }

    /// The admissible values of `EncPred`.
    #[must_use]
    pub fn allowed(&self) -> &[F] {
        &self.allowed
    }
}

impl<F: PartialEq> AttributePolicy<F> for AllowList<F> {
    fn accepts(&self, phis: &[F]) -> bool {
        phis.iter().all(|phi| self.allowed.contains(phi))
    }
}

/// "[...] any public policy over `{φ_j}_j` can be checked at no extra cost" (§5.1): a closure
/// is a policy.
impl<F, C> AttributePolicy<F> for C
where
    C: Fn(&[F]) -> bool,
{
    fn accepts(&self, phis: &[F]) -> bool {
        self(phis)
    }
}

#[cfg(test)]
mod tests {
    use ark_bls12_381::Fr;
    use ark_ff::Zero;

    use super::*;
    use crate::{hash::h0_predicate, serialization::WireFormat};

    const DEPLOYMENT: &[u8] = b"predicate-unit-tests";

    #[test]
    fn canonical_bytes_are_as_documented_and_equal_the_derived_encoding() {
        let f = Predicate::new(0x0102_0304, b"ab".to_vec());
        let mut expected = vec![0x04, 0x03, 0x02, 0x01];
        expected.extend_from_slice(&2u64.to_le_bytes());
        expected.extend_from_slice(b"ab");
        assert_eq!(f.canonical_bytes(), expected);

        for f in [
            Predicate::root(Vec::new()),
            Predicate::root(b"root".to_vec()),
            Predicate::new(1, Vec::new()),
            Predicate::new(u32::MAX, vec![0u8; 300]),
            f,
        ] {
            let bytes = f.to_bytes().unwrap();
            assert_eq!(f.canonical_bytes(), bytes);
            assert_eq!(Predicate::from_bytes(&bytes).unwrap(), f);
        }
    }

    /// `⟨f⟩` is injective: the decoder of the previous test is a left inverse. Here, on
    /// predicates that are close to each other (bytes moved between the threshold and the label,
    /// a label and its zero-padded version, neighbouring thresholds and labels, a root predicate
    /// and a threshold predicate with the same label), the encodings and the values of `EncPred`
    /// are pairwise distinct.
    #[test]
    fn close_predicates_have_distinct_encodings() {
        let predicates = [
            Predicate::new(0x6162_6364, Vec::new()),
            Predicate::new(0, b"dcba".to_vec()),
            Predicate::new(0x64, b"cba".to_vec()),
            Predicate::new(0, b"a".to_vec()),
            Predicate::new(0, b"a\0".to_vec()),
            Predicate::new(0, b"\0a".to_vec()),
            Predicate::new(4, b"m".to_vec()),
            Predicate::new(5, b"m".to_vec()),
            Predicate::new(5, b"n".to_vec()),
            Predicate::root(b"m".to_vec()),
            Predicate::root(Vec::new()),
            Predicate::new(1, Vec::new()),
        ];
        for (i, a) in predicates.iter().enumerate() {
            for b in &predicates[i + 1..] {
                assert_ne!(a, b);
                assert_ne!(a.canonical_bytes(), b.canonical_bytes(), "{a:?} vs {b:?}");
                assert_ne!(
                    enc_pred::<Fr>(DEPLOYMENT, a).unwrap(),
                    enc_pred::<Fr>(DEPLOYMENT, b).unwrap(),
                    "{a:?} vs {b:?}"
                );
            }
        }
    }

    #[test]
    fn enc_pred_is_h0_on_the_canonical_bytes_and_deployment_bound() {
        let f = Predicate::new(3, b"members".to_vec());
        let phi: Fr = enc_pred(DEPLOYMENT, &f).unwrap();
        assert_eq!(phi, h0_predicate::<Fr>(DEPLOYMENT, &f.canonical_bytes()));
        assert_eq!(phi, enc_pred::<Fr>(DEPLOYMENT, &f.clone()).unwrap());
        assert!(!phi.is_zero());
        assert_ne!(phi, enc_pred::<Fr>(b"another deployment", &f).unwrap());
        // defined for root predicates too
        let root = Predicate::root(b"members".to_vec());
        assert!(root.is_root() && !f.is_root());
        assert_ne!(enc_pred::<Fr>(DEPLOYMENT, &root).unwrap(), phi);
    }

    #[test]
    fn policies() {
        let f = Predicate::new(2, b"members".to_vec());
        let g = Predicate::new(2, b"guests".to_vec());
        let root = Predicate::root(b"root".to_vec());
        let phi = |p: &Predicate| enc_pred::<Fr>(DEPLOYMENT, p).unwrap();

        // P ≡ 1
        assert!(AcceptAll.accepts(&[phi(&f), phi(&root)]));
        assert!(AttributePolicy::<Fr>::accepts(&AcceptAll, &[]));

        // an allow list: every label has to be on it
        let list = AllowList::<Fr>::from_predicates(DEPLOYMENT, [&f, &g]).unwrap();
        assert_eq!(list, AllowList::new([phi(&f), phi(&g)]));
        assert_eq!(list.allowed(), &[phi(&f), phi(&g)]);
        assert!(list.accepts(&[phi(&f)]));
        assert!(list.accepts(&[phi(&g), phi(&f), phi(&f)]));
        assert!(list.accepts(&[]));
        assert!(!list.accepts(&[phi(&root)]));
        assert!(!list.accepts(&[phi(&f), phi(&root)]));
        assert!(!list.accepts(&[phi(&root), phi(&f)]));
        // the list is over EncPred of THIS deployment
        let elsewhere = AllowList::<Fr>::from_predicates(b"elsewhere", [&f, &g]).unwrap();
        assert!(!elsewhere.accepts(&[phi(&f)]));
        // the empty list admits nothing but the empty sequence
        assert!(!AllowList::<Fr>::new([]).accepts(&[phi(&f)]));

        // a closure: "at most one root credential"
        let phi_root = phi(&root);
        let at_most_one_root =
            move |phis: &[Fr]| phis.iter().filter(|p| **p == phi_root).count() <= 1;
        assert!(at_most_one_root.accepts(&[phi(&f), phi_root]));
        assert!(!at_most_one_root.accepts(&[phi_root, phi(&f), phi_root]));
    }
}
