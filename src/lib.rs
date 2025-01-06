#[cfg(feature = "base64")]
pub mod base64;
mod errors;
mod stream;

pub use errors::*;
pub use stream::*;

use http_body_util::BodyExt as _;
use hyper::{header::HeaderValue, Method};
use hyper_util::client::legacy::Client as HyperClient;
use serde::{de::DeserializeOwned, Serialize};

// Re-exports
pub use hyper;
pub use hyper_openssl;
pub use hyper_util;
pub use openssl;
pub use serde;
pub use serde_json;

// type alias/re-export
pub use hyper_util::client::legacy::connect::{Connect, HttpConnector};
pub type RequestBody = http_body_util::Full<hyper::body::Bytes>;
pub type HttpsConnector = hyper_openssl::client::legacy::HttpsConnector<HttpConnector>;

/// A simple alias trait
pub trait Connector: Connect + Clone + Send + Sync + 'static {}
impl<C> Connector for C where C: Connect + Clone + Send + Sync + 'static {}

#[derive(Clone, Debug)]
pub struct LndRestClient<C> {
    macaroon_header: HeaderValue,
    address: String,
    client: HyperClient<C, RequestBody>,
    scheme: &'static str,
}

impl<C> std::fmt::Display for LndRestClient<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "LndRestClient({}://{})", self.scheme, self.address)
    }
}

pub fn self_signed_https_connector(
    tls_cert_pem: &[u8],
) -> Result<HttpsConnector, InvalidCertificateError> {
    use openssl::{
        ssl::{SslConnector, SslMethod},
        x509::{store::X509StoreBuilder, X509},
    };

    let root_store = {
        let mut builder = X509StoreBuilder::new()?;
        builder.add_cert(X509::from_pem(tls_cert_pem)?)?;
        builder.build()
    };

    let mut ssl_builder = SslConnector::builder(SslMethod::tls_client())?;
    ssl_builder.set_cert_store(root_store);

    let mut http = HttpConnector::new();
    http.enforce_http(false);

    let https = HttpsConnector::with_connector(http, ssl_builder)?;
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

impl<C: Connector> LndRestClient<C> {
    pub fn new_with_connector(address: String, macaroon: &[u8], connector: C) -> Self {
        // TODO: allow non-tokio runtime?
        let client = hyper_util::client::legacy::Builder::new(hyper_util::rt::TokioExecutor::new())
            .build(connector);

        let macaroon_header = HeaderValue::from_str(&hex::encode(macaroon)).unwrap();

        LndRestClient {
            macaroon_header,
            address,
            client,
            scheme: "https",
        }
    }

    pub fn unsafe_use_plaintext_http_scheme(&mut self) {
        self.scheme = "http";
    }

    pub fn set_macaroon(&mut self, macaroon: &[u8]) {
        self.macaroon_header = HeaderValue::from_str(&hex::encode(macaroon)).unwrap();
    }

    pub fn new_request(
        &self,
        method: Method,
        endpoint: &str,
        body: RequestBody,
    ) -> Result<hyper::Request<RequestBody>, RequestError> {
        hyper::Request::builder()
            .method(method.clone())
            .uri(format!("{}://{}{}", self.scheme, self.address, endpoint))
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

        let response = self
            .client
            .request(request)
            .await
            .map_err(|e| RequestError {
                endpoint: endpoint.clone(),
                method: method.clone(),
                cause: RequestErrorCause::HttpFailure(e),
            })?;

        let status = response.status();

        // TODO: limit reader
        let resp_body = response
            .into_body()
            .collect()
            .await
            .map_err(|e| RequestError {
                endpoint: endpoint.clone(),
                method: method.clone(),
                cause: RequestErrorCause::BodyReadFailure(BodyReadError::HttpFailure(e)),
            })?;

        if !status.is_success() {
            let details: Option<LndErrorResponse> =
                serde_json::from_slice(&resp_body.to_bytes()).ok();
            return Err(RequestError {
                endpoint,
                method,
                cause: RequestErrorCause::BadStatusCode { status, details },
            });
        }

        let value: O = serde_json::from_slice(&resp_body.to_bytes()).map_err(|e| RequestError {
            endpoint: endpoint.clone(),
            method: method.clone(),
            cause: RequestErrorCause::BodyReadFailure(BodyReadError::JsonParse(e)),
        })?;
        Ok(value)
    }

    pub async fn process_request_streamed(
        &self,
        request: hyper::Request<RequestBody>,
    ) -> Result<ResponseStream, RequestError> {
        let endpoint = request.uri().path().to_string();
        let method = request.method().clone();

        let response = self
            .client
            .request(request)
            .await
            .map_err(|e| RequestError {
                endpoint: endpoint.clone(),
                method: method.clone(),
                cause: RequestErrorCause::HttpFailure(e),
            })?;

        let status = response.status();
        let resp_body = response.into_body();

        if !status.is_success() {
            // TODO: limit reader
            let body_collected = resp_body.collect().await.map_err(|e| RequestError {
                endpoint: endpoint.clone(),
                method: method.clone(),
                cause: RequestErrorCause::BodyReadFailure(BodyReadError::HttpFailure(e)),
            })?;

            let details: Option<LndErrorResponse> =
                serde_json::from_slice(&body_collected.to_bytes()).ok();
            return Err(RequestError {
                endpoint,
                method,
                cause: RequestErrorCause::BadStatusCode { status, details },
            });
        }

        let stream = ResponseStream::new(method.clone(), endpoint.clone(), resp_body);
        Ok(stream)
    }

    pub async fn get<O: DeserializeOwned>(&self, endpoint: &str) -> Result<O, RequestError> {
        let empty_body = RequestBody::new(hyper::body::Bytes::new());
        let req = self.new_request(Method::GET, endpoint, empty_body)?;
        self.process_request(req).await
    }

    pub async fn get_streamed(&self, endpoint: &str) -> Result<ResponseStream, RequestError> {
        let empty_body = RequestBody::new(hyper::body::Bytes::new());
        let req = self.new_request(Method::GET, endpoint, empty_body)?;
        self.process_request_streamed(req).await
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

    pub async fn post_streamed<B: Serialize>(
        &self,
        endpoint: &str,
        body: B,
    ) -> Result<ResponseStream, RequestError> {
        let serialized_body = serde_json::to_vec(&body).map_err(|e| RequestError {
            endpoint: endpoint.to_string(),
            method: Method::POST,
            cause: RequestErrorCause::RequestBodySerialize(e),
        })?;
        let body = RequestBody::new(hyper::body::Bytes::from(serialized_body));
        let req = self.new_request(Method::POST, endpoint, body)?;
        self.process_request_streamed(req).await
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
