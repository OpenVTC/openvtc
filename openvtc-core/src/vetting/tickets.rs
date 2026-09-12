//! Vetting Tickets: how a vetter lets someone ask them for vetting (design §8).
//!
//! A vetter never takes unsolicited requests. They hand a ticket to a person
//! out of band — read aloud at a conference desk, pasted into a chat, shown as
//! a QR code — and only a request carrying a live ticket gets any answer.
//!
//! A ticket has two forms:
//!
//! - the **code**, `XXXX-XXXX` in Crockford base32. Forty bits, short enough to
//!   say, and therefore guessable in principle. A wrong code is never answered,
//!   so a guesser cannot even learn that the vetter exists, and wrong codes are
//!   throttled per sender and overall ([`GuessThrottle`]);
//! - the **scanned** form, a ticket id and a 32-byte secret. Nobody guesses
//!   that by accident, so a wrong secret is answered with `invalidTicket` and
//!   the applicant learns to ask for a fresh one.
//!
//! Tickets are client-local in V0. Moving them to the VTA
//! (`vetting/tickets/*`) is V1.

use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vta_sdk::protocols::vetting::{
    TicketPresentation, VETTING_REQUEST_ERR_INVALID_TICKET, VettingMethod,
};

use crate::config::account::PersonaId;

/// Crockford base32: no `I`, `L`, `O` or `U`, so nothing is misheard.
pub const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// How long a ticket lives unless the vetter says otherwise.
pub const DEFAULT_VALIDITY: Duration = Duration::days(14);

/// The window wrong codes are counted over.
pub const GUESS_WINDOW: Duration = Duration::hours(1);

/// Wrong codes one sender may send in [`GUESS_WINDOW`] before every further
/// code from them is ignored, right or wrong.
pub const MAX_WRONG_CODES_PER_SENDER: usize = 5;

/// Wrong codes from everyone together in [`GUESS_WINDOW`]. A sender who mints a
/// fresh DID per guess gets past the per-sender limit; this bounds them too.
/// Scanned tickets are unaffected, so a real applicant is never locked out.
pub const MAX_WRONG_CODES: usize = 60;

/// One ticket, as the vetter keeps it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Ticket {
    /// `ticketId` in the scanned form.
    pub id: String,
    /// `XXXX-XXXX`.
    pub code: String,
    /// 32 bytes, base64url.
    pub secret: String,
    /// The community the ticket is for.
    pub community: String,
    /// The vetter's member persona in that community.
    pub persona: PersonaId,
    /// Methods the vetter offers on this ticket; empty means any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub methods: Vec<VettingMethod>,
    /// Requests it can still admit. A conference-desk ticket has more than one.
    pub uses_left: u32,
    /// When it was made.
    pub created_at: DateTime<Utc>,
    /// After this it admits nothing.
    pub expires_at: DateTime<Utc>,
    /// The vetter's own note ("LPC desk", "for Alice").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl Ticket {
    /// Mint a ticket. `uses` is at least one.
    #[must_use]
    pub fn issue(
        community: impl Into<String>,
        persona: PersonaId,
        methods: Vec<VettingMethod>,
        uses: u32,
        validity: Duration,
        now: DateTime<Utc>,
    ) -> Ticket {
        let mut code = [0u8; 5];
        OsRng.fill_bytes(&mut code);
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        Ticket {
            id: format!("vt-{}", Uuid::new_v4().simple()),
            code: encode_code(code),
            secret: BASE64_URL_SAFE_NO_PAD.encode(secret),
            community: community.into(),
            persona,
            methods,
            uses_left: uses.max(1),
            created_at: now,
            expires_at: now + validity,
            label: None,
        }
    }

    /// It can still admit a request.
    #[must_use]
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.uses_left > 0 && now < self.expires_at
    }

    /// It offers `method`, or the applicant expressed no preference.
    #[must_use]
    pub fn offers(&self, method: Option<VettingMethod>) -> bool {
        self.methods.is_empty() || method.is_none_or(|m| self.methods.contains(&m))
    }

    /// The spoken form, as an applicant presents it.
    #[must_use]
    pub fn code_presentation(&self) -> TicketPresentation {
        TicketPresentation::Code {
            code: self.code.clone(),
        }
    }

    /// The scanned form, as an applicant presents it.
    #[must_use]
    pub fn scanned_presentation(&self) -> TicketPresentation {
        TicketPresentation::Scanned {
            ticket_id: self.id.clone(),
            secret: self.secret.clone(),
        }
    }
}

/// Forty bits → `XXXX-XXXX`.
fn encode_code(bytes: [u8; 5]) -> String {
    let bits = bytes
        .iter()
        .fold(0u64, |acc, byte| (acc << 8) | u64::from(*byte));
    let mut out = String::with_capacity(9);
    for i in 0..8 {
        if i == 4 {
            out.push('-');
        }
        out.push(char::from(
            CROCKFORD[((bits >> (35 - 5 * i)) & 0x1f) as usize],
        ));
    }
    out
}

/// Read a code the way a person types it: any case, with or without the dash
/// or spaces, and with the letters Crockford reads as digits (`O` → `0`,
/// `I`/`L` → `1`). `None` if it cannot be a code at all.
#[must_use]
pub fn normalise_code(input: &str) -> Option<String> {
    let mut chars = String::with_capacity(8);
    for c in input.chars() {
        let c = match c.to_ascii_uppercase() {
            '-' | ' ' => continue,
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        };
        if !c.is_ascii() || !CROCKFORD.contains(&(c as u8)) {
            return None;
        }
        chars.push(c);
    }
    (chars.len() == 8).then(|| format!("{}-{}", &chars[..4], &chars[4..]))
}

/// Equal-length comparison that does not stop at the first difference.
fn constant_time_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// Recent wrong codes.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct GuessThrottle {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    wrong: Vec<WrongCode>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
struct WrongCode {
    sender: String,
    at: DateTime<Utc>,
}

impl GuessThrottle {
    /// Nothing recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.wrong.is_empty()
    }

    fn prune(&mut self, now: DateTime<Utc>) {
        self.wrong.retain(|w| now - w.at < GUESS_WINDOW);
    }

    fn allows(&self, sender: &str) -> bool {
        self.wrong.len() < MAX_WRONG_CODES
            && self.wrong.iter().filter(|w| w.sender == sender).count() < MAX_WRONG_CODES_PER_SENDER
    }

    fn record(&mut self, sender: &str, now: DateTime<Utc>) {
        self.wrong.push(WrongCode {
            sender: sender.to_string(),
            at: now,
        });
    }
}

/// What a presented ticket earns the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redemption {
    /// A live ticket matches. Nothing is consumed yet: the request may still
    /// be refused for another reason, and a refused request should not cost
    /// the applicant their ticket. Call [`consume`] once it is accepted.
    Matched {
        /// The matching ticket.
        ticket_id: String,
    },
    /// Say nothing at all.
    Silent,
    /// Refuse with this `vetting/request` error code.
    Refused(&'static str),
}

/// Check a presented ticket against `persona`'s tickets for `community`.
pub fn check(
    tickets: &[Ticket],
    throttle: &mut GuessThrottle,
    presented: &TicketPresentation,
    sender: &str,
    community: &str,
    persona: PersonaId,
    now: DateTime<Utc>,
) -> Redemption {
    match presented {
        TicketPresentation::Code { code } => {
            throttle.prune(now);
            if !throttle.allows(sender) {
                return Redemption::Silent;
            }
            let found = normalise_code(code).and_then(|code| {
                tickets.iter().find(|t| {
                    t.persona == persona
                        && t.community == community
                        && t.is_live(now)
                        && constant_time_eq(&t.code, &code)
                })
            });
            match found {
                Some(ticket) => Redemption::Matched {
                    ticket_id: ticket.id.clone(),
                },
                None => {
                    throttle.record(sender, now);
                    Redemption::Silent
                }
            }
        }
        TicketPresentation::Scanned { ticket_id, secret } => {
            match tickets
                .iter()
                .find(|t| &t.id == ticket_id && t.persona == persona)
            {
                Some(ticket)
                    if ticket.community == community
                        && ticket.is_live(now)
                        && constant_time_eq(&ticket.secret, secret) =>
                {
                    Redemption::Matched {
                        ticket_id: ticket.id.clone(),
                    }
                }
                _ => Redemption::Refused(VETTING_REQUEST_ERR_INVALID_TICKET),
            }
        }
    }
}

/// Spend one use of the ticket. `false` if it is gone.
pub fn consume(tickets: &mut [Ticket], ticket_id: &str) -> bool {
    match tickets
        .iter_mut()
        .find(|t| t.id == ticket_id && t.uses_left > 0)
    {
        Some(ticket) => {
            ticket.uses_left -= 1;
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vta_sdk::protocols::vetting::VettingRequestBody;

    const COMMUNITY: &str = "did:web:vtc.example";

    fn ticket(persona: PersonaId, now: DateTime<Utc>) -> Ticket {
        Ticket::issue(COMMUNITY, persona, vec![], 1, DEFAULT_VALIDITY, now)
    }

    #[test]
    fn both_forms_satisfy_the_request_schema() {
        let t = ticket(PersonaId::new(), Utc::now());
        for presented in [t.code_presentation(), t.scanned_presentation()] {
            let body = VettingRequestBody {
                community: COMMUNITY.into(),
                requirements_digest: None,
                join_did: "did:key:zApplicant".into(),
                ticket: Some(presented),
                introduction: None,
                preferred_method: None,
                languages: vec![],
                message: None,
                availability: None,
                ext: None,
            };
            body.check_shape("did:key:zApplicant").unwrap();
        }
    }

    #[test]
    fn a_code_is_read_the_way_people_type_it() {
        assert_eq!(normalise_code("k7qf 2m9x").as_deref(), Some("K7QF-2M9X"));
        assert_eq!(normalise_code("K7QF-2M9X").as_deref(), Some("K7QF-2M9X"));
        assert_eq!(normalise_code("o1il-0000").as_deref(), Some("0111-0000"));
        assert_eq!(normalise_code("K7QF-2M9"), None);
        assert_eq!(normalise_code("K7QF-2M9U"), None, "U is not Crockford");
    }

    #[test]
    fn the_right_code_matches_and_is_spent_only_when_consumed() {
        let persona = PersonaId::new();
        let now = Utc::now();
        let mut tickets = vec![ticket(persona, now)];
        let mut throttle = GuessThrottle::default();
        let presented = TicketPresentation::Code {
            code: tickets[0].code.to_lowercase(),
        };
        let r = check(
            &tickets,
            &mut throttle,
            &presented,
            "did:key:zA",
            COMMUNITY,
            persona,
            now,
        );
        let Redemption::Matched { ticket_id } = r else {
            panic!("expected a match, got {r:?}");
        };
        assert_eq!(tickets[0].uses_left, 1);
        assert!(consume(&mut tickets, &ticket_id));
        assert_eq!(
            check(
                &tickets,
                &mut throttle,
                &presented,
                "did:key:zA",
                COMMUNITY,
                persona,
                now
            ),
            Redemption::Silent,
            "a spent ticket admits nothing"
        );
    }

    #[test]
    fn wrong_codes_get_silence_and_then_nothing_at_all() {
        let persona = PersonaId::new();
        let now = Utc::now();
        let tickets = vec![ticket(persona, now)];
        let mut throttle = GuessThrottle::default();
        let wrong = TicketPresentation::Code {
            code: "0000-0000".into(),
        };
        for _ in 0..MAX_WRONG_CODES_PER_SENDER {
            assert_eq!(
                check(
                    &tickets,
                    &mut throttle,
                    &wrong,
                    "did:key:zGuesser",
                    COMMUNITY,
                    persona,
                    now
                ),
                Redemption::Silent
            );
        }
        // The throttled sender now gets silence even for the right code…
        let right = tickets[0].code_presentation();
        assert_eq!(
            check(
                &tickets,
                &mut throttle,
                &right,
                "did:key:zGuesser",
                COMMUNITY,
                persona,
                now
            ),
            Redemption::Silent
        );
        // …while someone else is unaffected, and the window passes.
        assert!(matches!(
            check(
                &tickets,
                &mut throttle,
                &right,
                "did:key:zApplicant",
                COMMUNITY,
                persona,
                now
            ),
            Redemption::Matched { .. }
        ));
        assert!(matches!(
            check(
                &tickets,
                &mut throttle,
                &right,
                "did:key:zGuesser",
                COMMUNITY,
                persona,
                now + GUESS_WINDOW
            ),
            Redemption::Matched { .. }
        ));
    }

    #[test]
    fn a_wrong_secret_is_refused_rather_than_ignored() {
        let persona = PersonaId::new();
        let now = Utc::now();
        let tickets = vec![ticket(persona, now)];
        let mut throttle = GuessThrottle::default();
        let presented = TicketPresentation::Scanned {
            ticket_id: tickets[0].id.clone(),
            secret: "A".repeat(43),
        };
        assert_eq!(
            check(
                &tickets,
                &mut throttle,
                &presented,
                "did:key:zA",
                COMMUNITY,
                persona,
                now
            ),
            Redemption::Refused(VETTING_REQUEST_ERR_INVALID_TICKET)
        );
        assert!(throttle.is_empty(), "scanned tickets are not guesses");
    }

    #[test]
    fn a_ticket_admits_only_its_own_community_persona_and_window() {
        let persona = PersonaId::new();
        let now = Utc::now();
        let tickets = vec![ticket(persona, now)];
        let right = tickets[0].scanned_presentation();
        let mut throttle = GuessThrottle::default();
        let refused = Redemption::Refused(VETTING_REQUEST_ERR_INVALID_TICKET);
        let run = |throttle: &mut GuessThrottle, community, persona, at| {
            check(
                &tickets,
                throttle,
                &right,
                "did:key:zA",
                community,
                persona,
                at,
            )
        };
        assert_eq!(run(&mut throttle, "did:web:other", persona, now), refused);
        assert_eq!(
            run(&mut throttle, COMMUNITY, PersonaId::new(), now),
            refused
        );
        assert_eq!(
            run(&mut throttle, COMMUNITY, persona, now + DEFAULT_VALIDITY),
            refused
        );
        assert!(matches!(
            run(&mut throttle, COMMUNITY, persona, now),
            Redemption::Matched { .. }
        ));
    }

    #[test]
    fn a_ticket_can_restrict_the_method() {
        let mut t = ticket(PersonaId::new(), Utc::now());
        assert!(t.offers(Some(VettingMethod::Video)));
        t.methods = vec![VettingMethod::InPerson];
        assert!(t.offers(None));
        assert!(t.offers(Some(VettingMethod::InPerson)));
        assert!(!t.offers(Some(VettingMethod::Video)));
    }
}
