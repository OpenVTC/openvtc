//! Reading answers from endpoints a peer advertised.
//!
//! A community's join manifest and an election's ballot box are fetched from
//! URLs taken out of someone else's DID document, before anything they send
//! has been verified. The clients are already hardened (finite timeouts, no
//! redirects, no proxy, guarded DNS); this caps how much of an answer is read,
//! so a hostile or broken endpoint cannot make the client buffer whatever it
//! can stream before the timeout.

/// Why an answer could not be read.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CappedRead {
    /// The body was larger than the cap. The endpoint answered; what it sent
    /// is not something this client will read.
    TooLarge { max: usize },
    /// The connection failed part-way through the body.
    Read(String),
}

impl std::fmt::Display for CappedRead {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge { max } => write!(f, "the answer is larger than {max} bytes"),
            Self::Read(e) => write!(f, "reading the answer failed: {e}"),
        }
    }
}

/// Read `response` as UTF-8 text, refusing a body over `max` bytes. A
/// `Content-Length` over the cap is refused before any of the body is read.
pub(crate) async fn read_text_capped(
    response: reqwest::Response,
    max: usize,
) -> Result<String, CappedRead> {
    if response.content_length().is_some_and(|n| n > max as u64) {
        return Err(CappedRead::TooLarge { max });
    }
    let bytes = vta_sdk::http::read_body_capped(response, max)
        .await
        .map_err(|e| match e {
            vta_sdk::http::ForeignFetchError::BodyTooLarge { max } => CappedRead::TooLarge { max },
            other => CappedRead::Read(other.to_string()),
        })?;
    // Lossy, as `Response::text` is: a stray invalid byte should not hide a
    // refusal the endpoint spelled out.
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// The cap for a peer-advertised endpoint's answer: vta-sdk's default for
/// foreign fetches. A manifest or a ballot-box answer is a few KiB.
pub(crate) const MAX_FOREIGN_ANSWER: usize = vta_sdk::http::DEFAULT_MAX_FOREIGN_BODY;

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    /// Serves one HTTP response with `body` (and, when `declare` is set, a
    /// matching `Content-Length`; otherwise chunked) and returns its URL.
    async fn serve_once(body: Vec<u8>, declare: bool) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            if declare {
                let head = format!(
                    "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = sock.write_all(head.as_bytes()).await;
                let _ = sock.write_all(&body).await;
            } else {
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n",
                    )
                    .await;
                for chunk in body.chunks(4096) {
                    let _ = sock
                        .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                        .await;
                    let _ = sock.write_all(chunk).await;
                    let _ = sock.write_all(b"\r\n").await;
                }
                let _ = sock.write_all(b"0\r\n\r\n").await;
            }
        });
        format!("http://{addr}/")
    }

    async fn fetch(url: &str) -> reqwest::Response {
        reqwest::Client::new().get(url).send().await.unwrap()
    }

    #[tokio::test]
    async fn a_body_within_the_cap_is_read() {
        let url = serve_once(b"{\"ok\":true}".to_vec(), true).await;
        assert_eq!(
            read_text_capped(fetch(&url).await, 64).await.unwrap(),
            "{\"ok\":true}"
        );
    }

    #[tokio::test]
    async fn a_declared_oversize_body_is_refused() {
        let url = serve_once(vec![b'a'; 10_000], true).await;
        assert_eq!(
            read_text_capped(fetch(&url).await, 1_000).await,
            Err(CappedRead::TooLarge { max: 1_000 })
        );
    }

    /// No `Content-Length` to check up front: the cap applies while reading.
    #[tokio::test]
    async fn an_undeclared_oversize_body_is_refused() {
        let url = serve_once(vec![b'a'; 20_000], false).await;
        assert_eq!(
            read_text_capped(fetch(&url).await, 1_000).await,
            Err(CappedRead::TooLarge { max: 1_000 })
        );
    }
}
