//! Integration tests for DIDComm message type handling.
//!
//! Verifies that protocol URL ↔ MessageType conversions work correctly
//! and that the message type system is self-consistent.

use openvtc_core::MessageType;

/// All known message types and their expected protocol URLs.
const ALL_TYPES: &[(&str, &str)] = &[
    (
        "https://linuxfoundation.org/openvtc/1.0/relationship-request",
        "RelationshipRequest",
    ),
    (
        "https://linuxfoundation.org/openvtc/1.0/relationship-request-reject",
        "RelationshipRequestRejected",
    ),
    (
        "https://linuxfoundation.org/openvtc/1.0/relationship-request-accept",
        "RelationshipRequestAccepted",
    ),
    (
        "https://linuxfoundation.org/openvtc/1.0/relationship-request-finalize",
        "RelationshipRequestFinalize",
    ),
    ("https://didcomm.org/trust-ping/2.0/ping", "TrustPing"),
    (
        "https://didcomm.org/trust-ping/2.0/ping-response",
        "TrustPong",
    ),
    ("https://firstperson.network/vrc/1.0/request", "VRCRequest"),
    (
        "https://firstperson.network/vrc/1.0/rejected",
        "VRCRequestRejected",
    ),
    ("https://firstperson.network/vrc/1.0/issued", "VRCIssued"),
];

#[test]
fn all_message_types_roundtrip_through_url() {
    for (url, expected_variant) in ALL_TYPES {
        let mt = MessageType::try_from(*url)
            .unwrap_or_else(|_| panic!("Failed to parse URL '{url}' into MessageType"));

        // Verify variant name via Debug
        let debug = format!("{mt:?}");
        assert_eq!(
            &debug, expected_variant,
            "URL '{url}' should produce {expected_variant}"
        );

        // Roundtrip: MessageType → URL → MessageType
        let back_to_url: String = mt.clone().into();
        assert_eq!(
            &back_to_url, url,
            "MessageType → String should return original URL"
        );

        let roundtripped =
            MessageType::try_from(back_to_url.as_str()).expect("Roundtripped URL should parse");
        assert_eq!(
            format!("{roundtripped:?}"),
            *expected_variant,
            "Full roundtrip should preserve variant"
        );
    }
}

#[test]
fn unknown_urls_produce_errors() {
    let unknowns = &[
        "",
        "not-a-url",
        "https://example.com/unknown",
        "https://didcomm.org/trust-ping/1.0/ping", // wrong version
    ];

    for url in unknowns {
        assert!(
            MessageType::try_from(*url).is_err(),
            "URL '{url}' should produce an error, not a valid MessageType"
        );
    }
}

#[test]
fn all_message_types_have_non_empty_friendly_names() {
    for (url, _) in ALL_TYPES {
        let mt = MessageType::try_from(*url).unwrap();
        let name = mt.friendly_name();
        assert!(
            !name.is_empty(),
            "Friendly name for {url} should not be empty"
        );
        assert!(
            !name.contains("Unknown"),
            "Friendly name for {url} should not be 'Unknown'"
        );
    }
}
