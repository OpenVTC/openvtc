//! Has the community revoked a vetter's grant?
//!
//! A vetter's acceptance carries their grant as an eligibility presentation.
//! Verifying it (`verify_eligibility_vp`) proves the community issued the grant
//! to that vetter for this request. It cannot say whether the community has
//! since revoked it, because that needs the community's status list, fetched
//! over HTTPS (design §7.1). This is that step, run as a background job after
//! the acceptance is recorded.
//!
//! [`crate::status_list::check_credential_status`] does the reading: it
//! verifies the list's proof (proof sets included) and issuer, decodes the
//! bitstring and reads the bit. This module supplies the fetch. The fetch
//! has finite timeouts (R1.2), accepts only `https`, and bounds what it reads.
//! Its error text says whether the host was unreachable, answered with an
//! error, or sent something that is not a status list (R6.4), because "the
//! community's server is down" and "this is not a status list" call for
//! different things.
//!
//! The answer is advisory, like the eligibility check it follows. The community
//! checks every vetter again when it decides.

use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use reqwest::{Client, Url, header::ACCEPT};
use serde_json::Value;

use crate::status_list::{StatusCheck, check_credential_status};

/// How long to wait for a status list host to accept the connection.
pub const STATUS_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a whole status list fetch may take.
pub const STATUS_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// The largest status list body read. The SDK reads at most 4 MiB of
/// `encodedList`, and a credential around it adds little.
pub const MAX_STATUS_LIST_BYTES: usize = 6 * 1024 * 1024;

/// A grant to check: which request it arrived on, and what to check.
#[derive(Clone, Debug, PartialEq)]
pub struct GrantCheck {
    /// The application.
    pub application_id: String,
    /// Our `vetting/request` document id — the request the acceptance answered.
    pub request_document_id: String,
    /// The vetter.
    pub vetter: String,
    /// The community, which issued the grant and signs its status list.
    pub issuer: String,
    /// The grant's `credentialStatus`.
    pub credential_status: Value,
}

impl GrantCheck {
    /// Fetch the community's status list and read the grant's entry.
    ///
    /// The future is `Send`, so a caller can spawn it. That is why the fetch
    /// hands `fetch_owned` a cloned client and an owned URL: a future that
    /// kept the borrowed `&str` across its `.await` is not provably `Send` for
    /// every lifetime the SDK's `AsyncFn(&str)` may be called with.
    pub async fn run(&self, resolver: &DIDCacheClient) -> StatusCheck {
        let client = match status_client(true, STATUS_FETCH_TIMEOUT) {
            Ok(client) => client,
            Err(e) => return StatusCheck::Unknown(e),
        };
        check_credential_status(
            &self.credential_status,
            &self.issuer,
            async move |url: &str| fetch_owned(client.clone(), url.to_string()).await,
            resolver,
            chrono::Utc::now(),
        )
        .await
    }
}

/// [`fetch_status_list`] over owned arguments, so its future borrows nothing.
fn fetch_owned(
    client: Client,
    url: String,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Value, String>> + Send>> {
    Box::pin(async move { fetch_status_list(&client, &url).await })
}

/// Most redirects a status fetch follows.
const MAX_REDIRECTS: u8 = 3;

/// The HTTP client a status fetch uses: finite connect and total timeouts and
/// at most three redirects. Outside tests (`https_only`) it is also guarded
/// against SSRF: `https` only, every redirect hop re-vetted, no proxy, and a
/// DNS resolver that refuses a name resolving to a loopback, private,
/// link-local or otherwise non-public address (`affinidi-net-guard`'s
/// `public_internet` policy). The URL half of that guard — IP literals and
/// special-use names, which never reach a resolver — is
/// [`status_list_url`]'s.
///
/// A status list URL comes out of a credential someone else wrote, so without
/// this a credential could aim the fetch at this machine or its network.
///
/// # Errors
///
/// Only if the TLS backend cannot start.
pub fn status_client(https_only: bool, timeout: Duration) -> Result<Client, String> {
    let mut builder = Client::builder()
        .connect_timeout(STATUS_CONNECT_TIMEOUT.min(timeout))
        .timeout(timeout)
        .https_only(https_only);
    builder = if https_only {
        let policy = affinidi_net_guard::EgressPolicy::public_internet();
        builder
            .no_proxy()
            .dns_resolver(affinidi_net_guard::guarded_dns_resolver(policy.clone()))
            .redirect(affinidi_net_guard::redirect_policy(
                policy,
                affinidi_net_guard::RedirectMode::ReVet { max: MAX_REDIRECTS },
            ))
    } else {
        builder.redirect(reqwest::redirect::Policy::limited(usize::from(
            MAX_REDIRECTS,
        )))
    };
    builder
        .build()
        .map_err(|e| format!("could not start an HTTP client to check the grant: {e}"))
}

/// A status list URL this client will fetch: `https`, with a host that is not
/// an IP literal or name for a loopback, private, link-local or otherwise
/// non-public address.
///
/// # Errors
///
/// Anything else, named plainly.
pub fn status_list_url(url: &str) -> Result<Url, String> {
    let parsed =
        Url::parse(url).map_err(|_| "the grant's status list URL does not parse".to_string())?;
    if parsed.scheme() != "https" {
        return Err(format!(
            "the grant's status list is not served over https ({})",
            parsed.scheme()
        ));
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err("the grant's status list URL names no host".to_string());
    }
    // A name is re-checked on what it resolves to, by the client's resolver.
    if let Err(e) = affinidi_net_guard::EgressPolicy::public_internet().vet_url(&parsed) {
        return Err(format!(
            "the grant's status list is not on a public host, so it is not fetched ({e})"
        ));
    }
    Ok(parsed)
}

/// Fetch the status list at `url`, which must be `https`.
///
/// # Errors
///
/// A URL that is not `https`, a host that cannot be reached or does not answer
/// in time, a non-success status, a body over [`MAX_STATUS_LIST_BYTES`], or a
/// body that is not JSON — each with its own message.
pub async fn fetch_status_list(client: &Client, url: &str) -> Result<Value, String> {
    let url = status_list_url(url)?;
    fetch_json(client, url).await
}

fn describe_transport_error(host: &str, e: &reqwest::Error) -> String {
    if e.is_timeout() {
        format!("no answer from {host} in time")
    } else if e.is_connect() {
        format!("could not reach {host}: {e}")
    } else if e.is_redirect() {
        format!("{host} redirected the status list somewhere this client will not follow")
    } else {
        format!("reading the status list from {host} failed: {e}")
    }
}

async fn fetch_json(client: &Client, url: Url) -> Result<Value, String> {
    let host = url.host_str().unwrap_or("the status list host").to_string();
    let too_large = || {
        format!(
            "the status list from {host} is larger than {} MiB",
            MAX_STATUS_LIST_BYTES / (1024 * 1024)
        )
    };
    let mut response = client
        .get(url)
        .header(ACCEPT, "application/json")
        .send()
        .await
        .map_err(|e| describe_transport_error(&host, &e))?;
    let status = response.status();
    if !status.is_success() {
        return Err(format!(
            "{host} answered HTTP {} for the status list",
            status.as_u16()
        ));
    }
    if response
        .content_length()
        .is_some_and(|n| n > MAX_STATUS_LIST_BYTES as u64)
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| describe_transport_error(&host, &e))?
    {
        if body.len() + chunk.len() > MAX_STATUS_LIST_BYTES {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body)
        .map_err(|e| format!("what {host} sent is not a status list (not JSON: {e})"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    async fn test_resolver() -> DIDCacheClient {
        DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .expect("resolver")
    }

    /// The check is spawned by the TUI, so its future must be `Send`.
    #[tokio::test]
    async fn the_check_can_be_spawned() {
        fn assert_send<F: std::future::Future + Send>(_: F) {}
        let check = GrantCheck {
            application_id: String::new(),
            request_document_id: String::new(),
            vetter: String::new(),
            issuer: String::new(),
            credential_status: Value::Null,
        };
        let resolver = test_resolver().await;
        assert_send(check.run(&resolver));
    }

    #[test]
    fn only_https_status_lists_are_fetched() {
        assert!(status_list_url("https://vtc.example.com/v1/status-lists/revocation").is_ok());
        assert!(
            status_list_url("http://vtc.example.com/list")
                .unwrap_err()
                .contains("not served over https")
        );
        assert!(status_list_url("file:///etc/passwd").is_err());
        assert!(status_list_url("not a url").is_err());
    }

    /// A status list URL comes out of someone else's credential: it may not
    /// aim the fetch at this machine, its network, or a metadata service.
    #[test]
    fn a_status_list_on_a_non_public_host_is_not_fetched() {
        for url in [
            "https://127.0.0.1/list",
            "https://localhost/list",
            "https://10.0.0.5/list",
            "https://192.168.1.1/list",
            "https://169.254.169.254/latest/meta-data",
            "https://[::1]/list",
            "https://[fc00::1]/list",
            "https://printer.local/list",
        ] {
            let error = status_list_url(url).unwrap_err();
            assert!(error.contains("not on a public host"), "{url}: {error}");
        }
    }

    /// The URL half is not the only guard: the production client's resolver
    /// refuses a name that resolves to a non-public address, before any
    /// connection.
    #[tokio::test]
    async fn the_production_client_refuses_a_name_that_resolves_to_loopback() {
        let client = status_client(true, Duration::from_secs(2)).unwrap();
        let error = client
            .get("https://localhost:9/list")
            .send()
            .await
            .unwrap_err();
        assert!(
            affinidi_net_guard::blocked_in_chain(&error).is_some(),
            "{error:?}"
        );
    }

    async fn serve(response: ResponseTemplate) -> (MockServer, Url) {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(response)
            .mount(&server)
            .await;
        let url = Url::parse(&server.uri()).unwrap();
        (server, url)
    }

    fn test_client(timeout: Duration) -> Client {
        status_client(false, timeout).unwrap()
    }

    #[tokio::test]
    async fn a_list_is_read_as_json() {
        let (_server, url) =
            serve(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "id": "x" }))).await;
        let value = fetch_json(&test_client(STATUS_FETCH_TIMEOUT), url)
            .await
            .unwrap();
        assert_eq!(value["id"], "x");
    }

    #[tokio::test]
    async fn failures_say_which_kind_of_failure_they_are() {
        let client = test_client(Duration::from_millis(300));

        let (_s, url) = serve(ResponseTemplate::new(404)).await;
        assert!(
            fetch_json(&client, url)
                .await
                .unwrap_err()
                .contains("answered HTTP 404")
        );

        let (_s, url) = serve(ResponseTemplate::new(200).set_body_string("<html>")).await;
        assert!(
            fetch_json(&client, url)
                .await
                .unwrap_err()
                .contains("not JSON")
        );

        let (_s, url) = serve(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({}))
                .set_delay(Duration::from_secs(2)),
        )
        .await;
        assert!(
            fetch_json(&client, url)
                .await
                .unwrap_err()
                .contains("in time")
        );

        let (_s, url) =
            serve(ResponseTemplate::new(200).set_body_bytes(vec![b' '; MAX_STATUS_LIST_BYTES + 1]))
                .await;
        assert!(
            fetch_json(&test_client(STATUS_FETCH_TIMEOUT), url)
                .await
                .unwrap_err()
                .contains("larger than")
        );

        // Nothing listens on port 9 of localhost.
        let unreachable = Url::parse("http://127.0.0.1:9/list").unwrap();
        let error = fetch_json(&client, unreachable).await.unwrap_err();
        assert!(
            error.contains("could not reach") || error.contains("in time"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_grant_without_a_usable_status_entry_is_not_called_active() {
        let check = GrantCheck {
            application_id: "a".into(),
            request_document_id: "r".into(),
            vetter: "did:key:zVetter".into(),
            issuer: "did:key:zCommunity".into(),
            credential_status: serde_json::json!({
                "type": "BitstringStatusListEntry",
                "statusPurpose": "revocation",
                "statusListIndex": "7",
                "statusListCredential": "http://vtc.example.com/list"
            }),
        };
        let result = check.run(&test_resolver().await).await;
        assert!(
            matches!(&result, StatusCheck::Unknown(reason) if reason.contains("https")),
            "{result:?}"
        );
    }
}
