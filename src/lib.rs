pub mod base64;
mod errors;
pub use errors::*;

use http_body_util::BodyExt as _;
use hyper::{header::HeaderValue, Method};
use rustls_pki_types::{pem::PemObject as _, CertificateDer};
use serde::{de::DeserializeOwned, Serialize};

// Re-exports
pub use hyper;
pub use hyper_rustls;
pub use hyper_util;
pub use rustls;
pub use rustls_pki_types;
pub use serde;
pub use serde_json;

pub type RequestBody = http_body_util::Full<hyper::body::Bytes>;
pub type HttpsConnector =
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>;

type HttpsClient<C> = hyper_util::client::legacy::Client<C, RequestBody>;

// https://github.com/rustls/hyper-rustls/blob/main/examples/client.rs

#[derive(Clone, Debug)]
pub struct LndRestClient<C> {
    macaroon_header: HeaderValue,
    address: String,
    client: HttpsClient<C>,
}

impl<C> std::fmt::Display for LndRestClient<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "LndRestClient({})", self.address)
    }
}

async fn read_body_json<O: DeserializeOwned>(
    body: &mut hyper::body::Incoming,
) -> Result<O, BodyReadError> {
    // TODO stream response body directly to a json parser without intermediate buffering
    let mut buf = Vec::with_capacity(4096);
    while let Some(frame) = body.frame().await {
        match frame {
            Err(e) => return Err(BodyReadError::HttpFailure(e)),
            Ok(frame) => {
                if let Some(chunk) = frame.data_ref() {
                    // TODO declare constant
                    if buf.len() + chunk.len() > 100 * 1024 * 1024 {
                        return Err(BodyReadError::TooLarge);
                    }
                    buf.extend(chunk);

                    // TODO: delimit by newlines here for subscription endpoints
                }
            }
        }
    }
    let output: O = serde_json::from_slice(&buf)?;
    Ok(output)
}

pub fn self_signed_https_connector(
    tls_cert_pem: &[u8],
) -> Result<HttpsConnector, InvalidCertificateError> {
    let mut root_store = rustls::RootCertStore::empty();
    let root_cert_der = CertificateDer::from_pem_slice(tls_cert_pem)?;
    root_store.add(root_cert_der)?;

    let https = HttpsConnector::builder()
        .with_tls_config(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        )
        .https_only()
        .enable_http1()
        .build();
    Ok(https)
}

impl LndRestClient<HttpsConnector> {
    pub fn new_with_self_signed_cert(
        address: String,
        macaroon: &[u8],
        tls_cert_pem: &[u8],
    ) -> Result<Self, InvalidCertificateError> {
        Ok(LndRestClient::new_with_connector(
            address,
            macaroon,
            self_signed_https_connector(tls_cert_pem)?,
        ))
    }
}

impl<C> LndRestClient<C>
where
    C: hyper_util::client::legacy::connect::Connect + Clone + Send + Sync + 'static,
{
    pub fn new_with_connector(address: String, macaroon: &[u8], connector: C) -> Self {
        // TODO: allow non-tokio runtime?
        let client = hyper_util::client::legacy::Builder::new(hyper_util::rt::TokioExecutor::new())
            .build(connector);

        let macaroon_header = HeaderValue::from_str(&hex::encode(macaroon)).unwrap();

        LndRestClient {
            macaroon_header,
            address,
            client,
        }
    }

    pub fn new_request(
        &self,
        method: Method,
        endpoint: &str,
        body: RequestBody,
    ) -> Result<hyper::Request<RequestBody>, RequestError> {
        hyper::Request::builder()
            .method(method.clone())
            .uri(format!("https://{}{}", self.address, endpoint))
            .header("Grpc-Metadata-Macaroon", &self.macaroon_header)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .body(body)
            .map_err(|e| RequestError {
                method,
                endpoint: endpoint.to_string(),
                cause: RequestErrorCause::RequestConstruction(e),
            })
    }

    pub async fn process_request<O: DeserializeOwned>(
        &self,
        request: hyper::Request<RequestBody>,
    ) -> Result<O, RequestError> {
        let endpoint = request.uri().path().to_string();
        let method = request.method().clone();

        let mut response = self
            .client
            .request(request)
            .await
            .map_err(|e| RequestError {
                endpoint: endpoint.clone(),
                method: method.clone(),
                cause: RequestErrorCause::HttpFailure(e),
            })?;

        if !response.status().is_success() {
            return Err(RequestError {
                endpoint,
                method,
                cause: RequestErrorCause::BadStatusCode {
                    status: response.status(),
                    details: read_body_json(response.body_mut()).await.ok(),
                },
            });
        }

        read_body_json(response.body_mut())
            .await
            .map_err(|e| RequestError {
                endpoint,
                method,
                cause: RequestErrorCause::BodyReadFailure(e),
            })
    }

    pub async fn get<O: DeserializeOwned>(&self, endpoint: &str) -> Result<O, RequestError> {
        let empty_body = RequestBody::new(hyper::body::Bytes::new());
        let req = self.new_request(Method::GET, endpoint, empty_body)?;
        self.process_request(req).await
    }

    pub async fn post<B: Serialize, O: DeserializeOwned>(
        &self,
        endpoint: &str,
        body: B,
    ) -> Result<O, RequestError> {
        let serialized_body = serde_json::to_vec(&body).map_err(|e| RequestError {
            endpoint: endpoint.to_string(),
            method: Method::POST,
            cause: RequestErrorCause::RequestBodySerialize(e),
        })?;
        let body = RequestBody::new(hyper::body::Bytes::from(serialized_body));
        let req = self.new_request(Method::POST, endpoint, body)?;
        self.process_request(req).await
    }

    pub async fn delete<B: Serialize, O: DeserializeOwned>(
        &self,
        endpoint: &str,
        body: B,
    ) -> Result<O, RequestError> {
        let serialized_body = serde_json::to_vec(&body).map_err(|e| RequestError {
            endpoint: endpoint.to_string(),
            method: Method::DELETE,
            cause: RequestErrorCause::RequestBodySerialize(e),
        })?;
        let body = RequestBody::new(hyper::body::Bytes::from(serialized_body));
        let req = self.new_request(Method::POST, endpoint, body)?;
        self.process_request(req).await
    }
}
