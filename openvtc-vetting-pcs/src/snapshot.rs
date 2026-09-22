//! Storable forms of the member-side engines.
//!
//! openvtc keeps these in its encrypted `ProtectedConfig` between runs, so an application
//! survives a restart: the applicant's key and the attestations it has gathered, the vetter's
//! credential and the tokens it holds.
//!
//! **These carry secrets.** `usk` is the key every tag of its holder is derived from, so a copy
//! of a vetter's snapshot links every attestation that vetter ever made. It belongs wherever
//! the persona keys belong, and in the design's intended shape (§13 C7) it never leaves the
//! VTA at all — this type is the interim, for a client that runs the engine itself.
//!
//! Binary values travel as multibase base58btc over the crate's validated canonical encoding,
//! the same convention as `wire`.

use std::collections::BTreeMap;

use predicate_credential_system::{
    cred::ps::{PSCredential, PSShownCredential},
    pcs::{Attestation, Credential, UserSecretKey},
    serialization::{from_bytes, from_multibase, to_bytes, to_multibase},
};
use serde::{Deserialize, Serialize};

use crate::{
    ProtoError,
    meta::StatementMeta,
    scheme::{Base, E, Fr, G1},
    token::TokenSpend,
    vetter::HiddenAttestation,
};

fn enc<T: ark_serialize::CanonicalSerialize>(v: &T) -> Result<String, ProtoError> {
    Ok(to_multibase(&to_bytes(v)?))
}

fn dec<T: ark_serialize::CanonicalDeserialize>(s: &str) -> Result<T, ProtoError> {
    Ok(from_bytes(&from_multibase(s)?)?)
}

/// One attestation the applicant holds, with what it needs to present it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HeldAttestation {
    pub attestation: String,
    pub meta: StatementMeta,
    pub token_label: String,
    pub token_serial: String,
    pub token_shown: String,
}

impl HeldAttestation {
    pub fn of(att: &HiddenAttestation) -> Result<Self, ProtoError> {
        Ok(Self {
            attestation: enc(&att.attestation)?,
            meta: att.meta.clone(),
            token_label: att.token.label.clone(),
            token_serial: enc(&att.token.serial)?,
            token_shown: enc(&att.token.shown)?,
        })
    }

    pub fn restore(&self) -> Result<HiddenAttestation, ProtoError> {
        Ok(HiddenAttestation {
            attestation: dec::<Attestation<E, Base>>(&self.attestation)?,
            meta: self.meta.clone(),
            token: TokenSpend {
                label: self.token_label.clone(),
                serial: dec::<Fr>(&self.token_serial)?,
                shown: dec::<PSShownCredential<E>>(&self.token_shown)?,
            },
        })
    }
}

/// The applicant's engine, stored. One per application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicantSnapshot {
    /// SECRET: the key the applicant's identifier and proofs are built from.
    pub usk: String,
    pub id: String,
    pub join_did: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub held: Vec<HeldAttestation>,
}

impl ApplicantSnapshot {
    pub fn new(usk: &UserSecretKey<E>, id: &G1, join_did: &str) -> Result<Self, ProtoError> {
        Ok(Self {
            usk: to_multibase(&usk.to_bytes()?),
            id: enc(id)?,
            join_did: join_did.to_string(),
            held: Vec::new(),
        })
    }

    pub(crate) fn parts(
        &self,
    ) -> Result<(UserSecretKey<E>, G1, Vec<HiddenAttestation>), ProtoError> {
        let usk = UserSecretKey::from_scalar(dec::<Fr>(&self.usk)?);
        let held = self
            .held
            .iter()
            .map(HeldAttestation::restore)
            .collect::<Result<Vec<_>, _>>()?;
        Ok((usk, dec::<G1>(&self.id)?, held))
    }
}

/// One token the vetter holds, unspent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HeldToken {
    pub label: String,
    /// SECRET until spent: the serial is what the community records.
    pub serial: String,
    pub minted_tick: u32,
    pub credential: String,
}

/// The vetter's engine, stored. One per community.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VetterSnapshot {
    pub member: String,
    /// SECRET, and the most sensitive value here: every tag this vetter has ever produced is
    /// derived from it, so a copy links their attestations to each other.
    pub usk: String,
    pub id: String,
    /// Root credentials by class label period, e.g. `2026-10`.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub credentials: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tokens: Vec<HeldToken>,
    /// A limit below the community's drip, kept locally and never sent anywhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub personal_limit: Option<usize>,
    /// What was attested, so a rotation can be refreshed without a new session.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub log: Vec<(String, StatementMeta)>,
}

impl VetterSnapshot {
    pub fn new(member: &str, usk: &UserSecretKey<E>, id: &G1) -> Result<Self, ProtoError> {
        Ok(Self {
            member: member.to_string(),
            usk: to_multibase(&usk.to_bytes()?),
            id: enc(id)?,
            credentials: BTreeMap::new(),
            tokens: Vec::new(),
            personal_limit: None,
            log: Vec::new(),
        })
    }

    pub(crate) fn key(&self) -> Result<(UserSecretKey<E>, G1), ProtoError> {
        Ok((
            UserSecretKey::from_scalar(dec::<Fr>(&self.usk)?),
            dec::<G1>(&self.id)?,
        ))
    }

    pub(crate) fn credential(
        &self,
        period: &str,
    ) -> Result<Option<Credential<E, Base>>, ProtoError> {
        self.credentials
            .get(period)
            .map(|c| dec::<Credential<E, Base>>(c))
            .transpose()
    }

    pub(crate) fn put_credential(
        &mut self,
        period: &str,
        cred: &Credential<E, Base>,
    ) -> Result<(), ProtoError> {
        self.credentials.insert(period.to_string(), enc(cred)?);
        Ok(())
    }

    pub(crate) fn record(&mut self, id: &G1, meta: &StatementMeta) -> Result<(), ProtoError> {
        self.log.push((enc(id)?, meta.clone()));
        Ok(())
    }
}

impl HeldToken {
    pub(crate) fn of(
        label: &str,
        serial: &Fr,
        minted_tick: u32,
        cred: &PSCredential<E>,
    ) -> Result<Self, ProtoError> {
        Ok(Self {
            label: label.to_string(),
            serial: enc(serial)?,
            minted_tick,
            credential: enc(cred)?,
        })
    }

    pub(crate) fn parts(&self) -> Result<(Fr, PSCredential<E>), ProtoError> {
        Ok((
            dec::<Fr>(&self.serial)?,
            dec::<PSCredential<E>>(&self.credential)?,
        ))
    }
}
