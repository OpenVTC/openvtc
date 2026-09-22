//! The Fiat-Shamir contexts `ctx_j` and `ctx_0` of the construction box, and the digest of `pp`
//! that leads each of them.
//!
//! | paper | here |
//! |---|---|
//! | `ctx_j := (pp, hvk, id, φ_j, T_j, cred*_j)` (`Attest` step 10, `VerifyAtt` step 5) | [`PCS::attestation_context`] |
//! | `ctx_0 := (pp, hvk, f_k, id, C, T_0, (att_j)_{j ∈ [k]})` (`Prove` step 10, `VerifyProof` step 4) | [`PCS::issuance_context`] |
//! | (no counterpart: the context of a root request) | [`PCS::root_context`] |
//!
//! "The verifier reconstructs the commitments and hashes the complete public statement `ctx`;
//! hence tags and shown credentials used by the relation are bound to the proof even when not
//! repeated in its serialized transcript" (§5.1). Accordingly:
//!
//! * **A verifier always REBUILDS its context** from the public statement and never takes one
//!   from the prover: "a verifier that instead accepts a context array alongside the proof [...]
//!   verifies a `π_0` bound to nothing" (§5.5). The functions are public because they are
//!   functions of public data, and because a test harness that plays a cheating prover needs
//!   the challenge an honest verifier will compute.
//! * The contexts are [`Transcript`] digests: every component is an injectively framed item
//!   (implementation note; the paper gives the tuples, not their encoding). With the oracle
//!   suffix first and `(label, value)` items after it, values in their compressed canonical
//!   encoding:
//!
//!   | digest | oracle suffix | items |
//!   |---|---|---|
//!   | `pp` | `/PCS-PP` | `label`, `pp-sigma`, `pp-tag`, `c0`, `format` (four 8-byte little-endian constants of the instantiation) |
//!   | `ctx_j` | `/PCS-CTX-ATT` | `pp` (the digest), `hvk`, `id`, `phi`, `T`, `cred*` |
//!   | `ctx_0` | `/PCS-CTX-ISSUE` | `pp`, `hvk`, `f` (`⟨f_k⟩`), `id`, `C`, `T0`, then one item `att` per attestation |
//!   | root request | `/PCS-CTX-ROOT` | `pp`, `hvk`, `f` (`⟨f_root⟩`), `id`, `C`, `T0` |
//! * **Three labels.** The contexts of attestations, issuance proofs and root requests are
//!   transcripts of three different oracles, so a proof made for one role never verifies in
//!   another, whatever the statements are. In particular a root request is not an issuance proof
//!   for a threshold predicate with zero attestations.
//! * **`pp` leads.** `pp` enters as [`PublicParameters::digest`], computed once per instance,
//!   and it covers the deployment label: the algebraic parameters alone do not determine the
//!   deployment (`pp_Σ` is empty for `Σ-PS` and `Σ-EQ`, and `pp_Tag` of `Tag_DY` is the same
//!   generator everywhere), while `H_1` has no deployment input of its own ([`crate::hash`]).
//! * `f_k` itself enters `ctx_0`, not only `φ = EncPred(f_k)` (implementation note: `φ` is a hash
//!   and does not tell the verifier the threshold `k`).
//! * The attribute policy `P` is NOT part of a context: it is the verifier's own input of
//!   `CheckAtts_P` and not a component of `pp`.

use ark_ec::pairing::Pairing;

use super::{
    construction::PCS,
    predicate::Predicate,
    types::{Attestation, PublicParameters},
};
use crate::{cred::SigmaFriendlyCredentialBase, error::Error, hash::Transcript, kiprf::PCSTag};

/// Oracle suffix of the digest of `pp`.
const PP_SUFFIX: &[u8] = b"/PCS-PP";
/// Oracle suffix of `ctx_j`.
const ATTESTATION_SUFFIX: &[u8] = b"/PCS-CTX-ATT";
/// Oracle suffix of `ctx_0`.
const ISSUANCE_SUFFIX: &[u8] = b"/PCS-CTX-ISSUE";
/// Oracle suffix of the context of a root request.
const ROOT_SUFFIX: &[u8] = b"/PCS-CTX-ROOT";

impl<E, B, T> PublicParameters<E, B, T>
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<E::G1>,
{
    /// The digest of `pp` that leads every Fiat-Shamir context: the deployment label (which
    /// stands for `EncPred`, `H_0`, `H_1`), `pp_Σ`, `pp_Tag` and `c_0`, each as a framed item in
    /// its canonical encoding.
    ///
    /// Implementation note: the digest also covers ONE item with the constants of the
    /// instantiation that fix the format of the proofs: the numbers of witness variables of the
    /// base, whether `C` is reconstructed from `id`, and whether `id` is a plain discrete
    /// logarithm. `pp_Σ` is empty for `Σ-PS` and for `Σ-EQ` alike; with this item two
    /// instantiations that share a deployment label and a tag still have different digests.
    /// (For the instantiations of this crate any one of the constants would do.)
    ///
    /// # Errors
    /// [`Error::Serialization`] if a parameter cannot be serialized.
    pub fn digest(&self) -> Result<[u8; 32], Error> {
        let mut transcript = Transcript::new(PP_SUFFIX);
        transcript.append_bytes(b"label", &self.label);
        transcript.append_serializable(b"pp-sigma", &self.pp_sigma)?;
        transcript.append_serializable(b"pp-tag", &self.pp_tag)?;
        transcript.append_serializable(b"c0", &self.c0)?;
        // `usize` is at most 64 bits wide on every supported target, so the casts are lossless.
        let format = [
            B::POSSESSION_VARIABLES as u64,
            B::ISSUANCE_VARIABLES as u64,
            u64::from(B::REQUIRES_DLOG_IDENTITY),
            u64::from(T::IDENTITY_IS_DLOG),
        ];
        transcript.append_bytes(b"format", &format.map(u64::to_le_bytes).concat());
        Ok(transcript.digest())
    }
}

impl<E, B, T, P> PCS<E, B, T, P>
where
    E: Pairing,
    B: SigmaFriendlyCredentialBase<E>,
    T: PCSTag<E::G1>,
{
    /// A transcript of the oracle `suffix` that starts with `pp` and `hvk`.
    fn context(&self, suffix: &[u8], hvk: &B::VerificationKey) -> Result<Transcript, Error> {
        let mut transcript = Transcript::new(suffix);
        transcript.append_bytes(b"pp", &self.pp_digest);
        transcript.append_serializable(b"hvk", hvk)?;
        Ok(transcript)
    }

    /// `ctx_j := (pp, hvk, id, φ_j, T_j, cred*_j)` (construction box, `Attest` step 10 and
    /// `VerifyAtt` step 5).
    ///
    /// # Errors
    /// [`Error::Serialization`] if a component cannot be serialized.
    pub fn attestation_context(
        &self,
        hvk: &B::VerificationKey,
        id: &E::G1,
        phi: &E::ScalarField,
        tag: &E::G1,
        shown: &B::ShownCredential,
    ) -> Result<Vec<u8>, Error> {
        self.attestation_context_with_app(hvk, id, phi, tag, shown, None)
    }

    /// `ctx_j` extended by an APPLICATION CONTEXT `app_j` (implementation note, not in the
    /// paper): the caller's bytes, e.g. the deployment's statement metadata, a validity window
    /// or a serial, appended as one last framed item under its own name. The attester and every
    /// verifier must supply the same bytes; the verifier takes them from its own copy of the
    /// public data and never from the prover. This is the paper's first remedy for replay
    /// (Remark "Attestations are standing endorsements": a context in the attestation challenge).
    ///
    /// `None` produces exactly [`Self::attestation_context`], so attestations made without an
    /// application context are unchanged. `Some(&[])` is a context of its own, distinct from
    /// `None`: the item is appended, and it is empty.
    ///
    /// # Errors
    /// [`Error::Serialization`] if a component cannot be serialized.
    pub fn attestation_context_with_app(
        &self,
        hvk: &B::VerificationKey,
        id: &E::G1,
        phi: &E::ScalarField,
        tag: &E::G1,
        shown: &B::ShownCredential,
        app: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let mut transcript = self.context(ATTESTATION_SUFFIX, hvk)?;
        transcript.append_serializable(b"id", id)?;
        transcript.append_serializable(b"phi", phi)?;
        transcript.append_serializable(b"T", tag)?;
        transcript.append_serializable(b"cred*", shown)?;
        if let Some(app) = app {
            transcript.append_bytes(b"app", app);
        }
        Ok(transcript.digest().to_vec())
    }

    /// `ctx_0 := (pp, hvk, f_k, id, C, T_0, (att_j)_{j ∈ [k]})` (construction box, `Prove` step
    /// 10 and `VerifyProof` step 4). `f_k` enters as `⟨f_k⟩`; the attestations enter one by one,
    /// in order, as the last items, each completely (`T_j`, `cred*_j`, `φ_j` and `π_j`). Every
    /// item is framed, so their number is determined as well.
    ///
    /// # Errors
    /// [`Error::Serialization`] if a component cannot be serialized.
    pub fn issuance_context(
        &self,
        hvk: &B::VerificationKey,
        f: &Predicate,
        id: &E::G1,
        c: &B::IssuanceEncoding,
        t0: &E::G1,
        attestations: &[Attestation<E, B>],
    ) -> Result<Vec<u8>, Error> {
        self.issuance_context_with_app(hvk, f, id, c, t0, attestations, None, None)
    }

    /// `ctx_0` extended by application contexts (implementation note, not in the paper): the
    /// context `app_j` of every attestation, in order, and the proof's own `app_0` (e.g. a
    /// verifier challenge and an audience), each as a framed item after the attestations.
    ///
    /// `att_apps` binds `π_0` to the contexts under which the attestations were checked, so a
    /// prover cannot present an attestation's metadata under one context to `CheckAtts_P` and
    /// under another to `π_0`. `None` for both produces exactly [`Self::issuance_context`].
    /// When `att_apps` is `Some`, it holds one entry per attestation (the callers check this).
    ///
    /// # Errors
    /// [`Error::Serialization`] if a component cannot be serialized.
    #[allow(clippy::too_many_arguments)]
    pub fn issuance_context_with_app(
        &self,
        hvk: &B::VerificationKey,
        f: &Predicate,
        id: &E::G1,
        c: &B::IssuanceEncoding,
        t0: &E::G1,
        attestations: &[Attestation<E, B>],
        att_apps: Option<&[&[u8]]>,
        app: Option<&[u8]>,
    ) -> Result<Vec<u8>, Error> {
        let mut transcript = self.context(ISSUANCE_SUFFIX, hvk)?;
        transcript.append_bytes(b"f", &f.canonical_bytes());
        transcript.append_serializable(b"id", id)?;
        transcript.append_serializable(b"C", c)?;
        transcript.append_serializable(b"T0", t0)?;
        for attestation in attestations {
            transcript.append_serializable(b"att", attestation)?;
        }
        if let Some(att_apps) = att_apps {
            for att_app in att_apps {
                transcript.append_bytes(b"att-app", att_app);
            }
        }
        if let Some(app) = app {
            transcript.append_bytes(b"app", app);
        }
        Ok(transcript.digest().to_vec())
    }

    /// `ctx_root = ("root", pp, hvk, f_root, id, C, T_0)`, the context of a root request (Remark
    /// "Chaining and the base case"), under a label of its own; see
    /// [`RootRequest`](super::RootRequest).
    ///
    /// # Errors
    /// [`Error::Serialization`] if a component cannot be serialized.
    pub fn root_context(
        &self,
        hvk: &B::VerificationKey,
        f_root: &Predicate,
        id: &E::G1,
        c: &B::IssuanceEncoding,
        t0: &E::G1,
    ) -> Result<Vec<u8>, Error> {
        let mut transcript = self.context(ROOT_SUFFIX, hvk)?;
        transcript.append_bytes(b"f", &f_root.canonical_bytes());
        transcript.append_serializable(b"id", id)?;
        transcript.append_serializable(b"C", c)?;
        transcript.append_serializable(b"T0", t0)?;
        Ok(transcript.digest().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use ark_ec::PrimeGroup;
    use ark_ff::One;

    use super::*;
    use crate::{
        hash::{HashToGroup, bls12_381::G1Hasher},
        pcs::{
            PredicateCredentialSystem, SetupParams,
            test_support::{BBS, DDH, DY, E, Fixture, G1, PS, SPSEQ},
        },
    };

    type Fr = ark_bls12_381::Fr;

    /// `pp` leads every context, and its digest covers the deployment LABEL. `Σ-PS` with
    /// `Tag_DY` is the pair whose algebraic parameters are the same in every deployment.
    #[test]
    fn the_digest_of_pp_covers_the_label_and_the_instantiation() {
        let setup =
            |label: &[u8]| PCS::<E, PS, DY>::setup(SetupParams::new(label.to_vec())).unwrap();
        let (a, b) = (setup(b"context/a"), setup(b"context/b"));
        // pp_Σ is `()` for Σ-PS, and pp_Tag is the generator g_1
        assert_eq!(a.pp.pp_tag, b.pp.pp_tag);
        assert_ne!(a.pp.c0, b.pp.c0);
        assert_ne!(a.pp_digest, b.pp_digest);
        // deterministic, and what the instance stores
        assert_eq!(a.pp_digest, setup(b"context/a").pp_digest);
        assert_eq!(a.pp_digest, a.pp.digest().unwrap());
        assert_eq!(a.parameters_digest(), &a.pp_digest);

        // c_0 alone does not stand for the label: the label is an item of its own
        let mut relabelled = a.pp.clone();
        relabelled.label = b"context/b".to_vec();
        assert_ne!(relabelled.digest().unwrap(), a.pp_digest);
        assert_ne!(relabelled.digest().unwrap(), b.pp_digest);
        let mut other_c0 = a.pp.clone();
        other_c0.c0 += Fr::one();
        assert_ne!(other_c0.digest().unwrap(), a.pp_digest);
        // pp_Σ and pp_Tag are items of their own as well. (For parameters that `Setup` derived
        // they are functions of the label; the digest is defined for every value of the type.)
        let bbs = PCS::<E, BBS, DDH>::setup(SetupParams::new(b"context/a".to_vec())).unwrap();
        let mut other_generators = bbs.pp.clone();
        other_generators.pp_sigma.h3 += G1::generator();
        assert_ne!(other_generators.digest().unwrap(), bbs.pp_digest);
        let mut unprogrammed = bbs.pp.clone();
        unprogrammed.pp_tag = DDH::new(G1Hasher::new(b"context/a").unwrap());
        assert_ne!(unprogrammed.pp_tag, bbs.pp.pp_tag);
        assert_ne!(unprogrammed.digest().unwrap(), bbs.pp_digest);

        // Σ-PS and Σ-EQ have the same (empty) pp_Σ; with the same label and the same tag their
        // digests differ all the same. So do those of the two tags under one base.
        let label = b"context/shared".to_vec();
        let ps = PCS::<E, PS, DDH>::setup(SetupParams::new(label.clone())).unwrap();
        let eq = PCS::<E, SPSEQ, DDH>::setup(SetupParams::new(label.clone())).unwrap();
        let bbs = PCS::<E, BBS, DDH>::setup(SetupParams::new(label.clone())).unwrap();
        let ps_dy = PCS::<E, PS, DY>::setup(SetupParams::new(label)).unwrap();
        assert_eq!(ps.pp.pp_tag, eq.pp.pp_tag);
        let digests = [ps.pp_digest, eq.pp_digest, bbs.pp_digest, ps_dy.pp_digest];
        for (i, a) in digests.iter().enumerate() {
            for b in &digests[i + 1..] {
                assert_ne!(a, b);
            }
        }
    }

    /// `ctx_j = (pp, hvk, id, φ_j, T_j, cred*_j)`: every component matters.
    #[test]
    fn every_component_of_the_attestation_context_matters() {
        let mut fixture = Fixture::<PS, DDH>::new(b"context/att", 0xc7c7_0001);
        let (id, _) = fixture.pcs.user_keygen(&mut fixture.rng).unwrap();
        let att = fixture.attestations(1, &id).remove(0);
        let (pcs, hvk) = (&fixture.pcs, &fixture.hvk);
        let ctx = pcs
            .attestation_context(hvk, &id, &att.phi, &att.tag, &att.shown)
            .unwrap();
        assert_eq!(ctx.len(), 32);
        assert_eq!(
            ctx,
            pcs.attestation_context(hvk, &id, &att.phi, &att.tag, &att.shown)
                .unwrap()
        );

        let g = G1::generator();
        let (other_hvk, _) = pcs.helper_keygen(&mut fixture.rng);
        let mut other_shown = att.shown.clone();
        other_shown.sigma_2 += g;
        let mut swapped = att.shown.clone();
        core::mem::swap(&mut swapped.sigma_1, &mut swapped.sigma_2);
        let elsewhere =
            PCS::<E, PS, DDH>::setup(SetupParams::new(b"context/att2".to_vec())).unwrap();
        let variants = [
            elsewhere.attestation_context(hvk, &id, &att.phi, &att.tag, &att.shown),
            pcs.attestation_context(&other_hvk, &id, &att.phi, &att.tag, &att.shown),
            pcs.attestation_context(hvk, &(id + g), &att.phi, &att.tag, &att.shown),
            pcs.attestation_context(hvk, &id, &(att.phi + Fr::one()), &att.tag, &att.shown),
            pcs.attestation_context(hvk, &id, &att.phi, &(att.tag + g), &att.shown),
            pcs.attestation_context(hvk, &id, &att.phi, &att.tag, &other_shown),
            pcs.attestation_context(hvk, &id, &att.phi, &att.tag, &swapped),
            // id and T_j are both elements of G_1: their ROLES are part of the context
            pcs.attestation_context(hvk, &att.tag, &att.phi, &id, &att.shown),
        ];
        let mut seen = vec![ctx];
        for variant in variants {
            let variant = variant.unwrap();
            assert!(!seen.contains(&variant));
            seen.push(variant);
        }
    }

    /// `ctx_0 = (pp, hvk, f_k, id, C, T_0, (att_j)_j)`: every component matters, including `f_k`
    /// itself (label AND threshold), every part of every attestation, their order and number.
    #[test]
    fn every_component_of_the_issuance_context_matters() {
        let mut fixture = Fixture::<PS, DDH>::new(b"context/issue", 0xc7c7_0002);
        let (id, _) = fixture.pcs.user_keygen(&mut fixture.rng).unwrap();
        let atts = fixture.attestations(2, &id);
        let (pcs, hvk) = (&fixture.pcs, &fixture.hvk);
        let g = G1::generator();
        let f = Predicate::new(2, b"members".to_vec());
        let (c, t0) = (g * Fr::from(5u64), g * Fr::from(7u64));
        let ctx = pcs.issuance_context(hvk, &f, &id, &c, &t0, &atts).unwrap();
        assert_eq!(ctx.len(), 32);

        let (other_hvk, _) = pcs.helper_keygen(&mut fixture.rng);
        let elsewhere =
            PCS::<E, PS, DDH>::setup(SetupParams::new(b"context/issue2".to_vec())).unwrap();
        let reversed: Vec<_> = atts.iter().rev().cloned().collect();
        let mut other_response = atts.clone();
        other_response[1].proof.responses[0] += Fr::one();
        let mut other_challenge = atts.clone();
        other_challenge[0].proof.challenge += Fr::one();
        let mut other_phi = atts.clone();
        other_phi[0].phi += Fr::one();
        let mut other_tag = atts.clone();
        other_tag[1].tag += g;
        let mut other_shown = atts.clone();
        other_shown[1].shown.sigma_1 += g;
        let variants = [
            elsewhere.issuance_context(hvk, &f, &id, &c, &t0, &atts),
            pcs.issuance_context(&other_hvk, &f, &id, &c, &t0, &atts),
            pcs.issuance_context(
                hvk,
                &Predicate::new(2, b"guests".to_vec()),
                &id,
                &c,
                &t0,
                &atts,
            ),
            pcs.issuance_context(
                hvk,
                &Predicate::new(3, b"members".to_vec()),
                &id,
                &c,
                &t0,
                &atts,
            ),
            pcs.issuance_context(hvk, &f, &(id + g), &c, &t0, &atts),
            pcs.issuance_context(hvk, &f, &id, &(c + g), &t0, &atts),
            pcs.issuance_context(hvk, &f, &id, &c, &(t0 + g), &atts),
            // C and T_0 are both elements of G_1: their roles are part of the context
            pcs.issuance_context(hvk, &f, &id, &t0, &c, &atts),
            pcs.issuance_context(hvk, &f, &id, &c, &t0, &reversed),
            pcs.issuance_context(hvk, &f, &id, &c, &t0, &atts[..1]),
            pcs.issuance_context(hvk, &f, &id, &c, &t0, &[]),
            pcs.issuance_context(hvk, &f, &id, &c, &t0, &other_response),
            pcs.issuance_context(hvk, &f, &id, &c, &t0, &other_challenge),
            pcs.issuance_context(hvk, &f, &id, &c, &t0, &other_phi),
            pcs.issuance_context(hvk, &f, &id, &c, &t0, &other_tag),
            pcs.issuance_context(hvk, &f, &id, &c, &t0, &other_shown),
        ];
        let mut seen = vec![ctx];
        for variant in variants {
            let variant = variant.unwrap();
            assert!(!seen.contains(&variant));
            seen.push(variant);
        }
    }

    /// The encoding of the digests is the documented one (module docs): this pins the oracle
    /// suffixes, the item labels and their order, none of which another test can see.
    #[test]
    fn contexts_are_encoded_as_documented() {
        let mut fixture = Fixture::<BBS, DDH>::new(b"context/format", 0xc7c7_0004);
        let (id, _) = fixture.pcs.user_keygen(&mut fixture.rng).unwrap();
        let atts = fixture.attestations(2, &id);
        let (pcs, hvk) = (&fixture.pcs, &fixture.hvk);
        let g = G1::generator();
        let (c, t0) = (g * Fr::from(5u64), g * Fr::from(7u64));
        let f = Predicate::new(2, b"members".to_vec());

        fn pp_digest<B, T>(pcs: &PCS<E, B, T>, format: [u64; 4]) -> [u8; 32]
        where
            B: SigmaFriendlyCredentialBase<E>,
            T: PCSTag<G1>,
        {
            let mut t = Transcript::new(b"/PCS-PP");
            t.append_bytes(b"label", pcs.label());
            t.append_serializable(b"pp-sigma", pcs.base_parameters())
                .unwrap();
            t.append_serializable(b"pp-tag", pcs.tag()).unwrap();
            t.append_serializable(b"c0", pcs.identity_point()).unwrap();
            let format: Vec<u8> = format.iter().flat_map(|n| n.to_le_bytes()).collect();
            t.append_bytes(b"format", &format);
            t.digest()
        }
        // format = (possession variables, issuance variables, C := id, id = g_1^usk):
        // Σ-BBS + Tag_DDH, Σ-EQ + Tag_DDH, Σ-PS + Tag_DY
        assert_eq!(pcs.parameters_digest(), &pp_digest(pcs, [4, 1, 0, 1]));
        let eq = PCS::<E, SPSEQ, DDH>::setup(SetupParams::new(b"context/format".to_vec())).unwrap();
        assert_eq!(eq.parameters_digest(), &pp_digest(&eq, [0, 0, 1, 1]));
        let ps_dy = PCS::<E, PS, DY>::setup(SetupParams::new(b"context/format".to_vec())).unwrap();
        assert_eq!(ps_dy.parameters_digest(), &pp_digest(&ps_dy, [0, 1, 0, 0]));

        let start = |suffix: &[u8]| {
            let mut t = Transcript::new(suffix);
            t.append_bytes(b"pp", pcs.parameters_digest());
            t.append_serializable(b"hvk", hvk).unwrap();
            t
        };
        let att = &atts[0];
        let mut t = start(b"/PCS-CTX-ATT");
        t.append_serializable(b"id", &id).unwrap();
        t.append_serializable(b"phi", &att.phi).unwrap();
        t.append_serializable(b"T", &att.tag).unwrap();
        t.append_serializable(b"cred*", &att.shown).unwrap();
        assert_eq!(
            pcs.attestation_context(hvk, &id, &att.phi, &att.tag, &att.shown)
                .unwrap(),
            t.digest()
        );

        let statement = |t: &mut Transcript| {
            t.append_bytes(b"f", &f.canonical_bytes());
            t.append_serializable(b"id", &id).unwrap();
            t.append_serializable(b"C", &c).unwrap();
            t.append_serializable(b"T0", &t0).unwrap();
        };
        let mut t = start(b"/PCS-CTX-ISSUE");
        statement(&mut t);
        for att in &atts {
            t.append_serializable(b"att", att).unwrap();
        }
        assert_eq!(
            pcs.issuance_context(hvk, &f, &id, &c, &t0, &atts).unwrap(),
            t.digest()
        );

        let mut t = start(b"/PCS-CTX-ROOT");
        statement(&mut t);
        assert_eq!(pcs.root_context(hvk, &f, &id, &c, &t0).unwrap(), t.digest());
    }

    /// Attestations, issuance proofs and root requests hash under three different labels: on
    /// literally the same components, the contexts differ.
    #[test]
    fn the_three_roles_have_different_contexts() {
        let fixture = Fixture::<PS, DDH>::new(b"context/roles", 0xc7c7_0003);
        let (pcs, hvk) = (&fixture.pcs, &fixture.hvk);
        let g = G1::generator();
        let (id, c, t0) = (g * Fr::from(3u64), g * Fr::from(5u64), g * Fr::from(7u64));
        for f in [
            Predicate::root(b"f".to_vec()),
            Predicate::new(1, b"f".to_vec()),
        ] {
            let root = pcs.root_context(hvk, &f, &id, &c, &t0).unwrap();
            let issue = pcs.issuance_context(hvk, &f, &id, &c, &t0, &[]).unwrap();
            assert_ne!(root, issue);
            assert_eq!(root, pcs.root_context(hvk, &f, &id, &c, &t0).unwrap());
            // the root context binds its components as well
            for other in [
                pcs.root_context(hvk, &Predicate::root(b"g".to_vec()), &id, &c, &t0),
                pcs.root_context(hvk, &f, &(id + g), &c, &t0),
                pcs.root_context(hvk, &f, &id, &(c + g), &t0),
                pcs.root_context(hvk, &f, &id, &c, &(t0 + g)),
            ] {
                assert_ne!(other.unwrap(), root);
            }
        }
    }
}
