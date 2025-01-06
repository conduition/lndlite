use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

#[derive(Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd, Deserialize, Serialize)]
pub struct LndErrorResponse {
    pub code: u32,
    pub message: String,
    pub details: Vec<String>,
}

impl fmt::Display for LndErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut msg = format!("{} (code {})", self.message, self.code);
        for detail in self.details.iter() {
            msg = format!("{msg}; {detail}");
        }
        f.write_str(&msg)
    }
}

#[derive(Debug)]
pub enum InvalidCertificateError {
    CertificateParseFailed(openssl::error::ErrorStack),
}

impl fmt::Display for InvalidCertificateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            Self::CertificateParseFailed(e) => format!("certificate parsing failed: {e}"),
        };
        write!(f, "invalid TLS certificate: {}", msg)
    }
}

impl Error for InvalidCertificateError {}

impl From<openssl::error::ErrorStack> for InvalidCertificateError {
    fn from(e: openssl::error::ErrorStack) -> Self {
        InvalidCertificateError::CertificateParseFailed(e)
    }
}

#[derive(Debug)]
pub enum BodyReadError {
    HttpFailure(hyper::Error),
    JsonParse(serde_json::Error),
    ErrorEvent(LndErrorResponse),
    TooLarge,
    InvalidUtf8,
}

impl fmt::Display for BodyReadError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            Self::HttpFailure(e) => format!("HTTP protocol error: {e}"),
            Self::JsonParse(e) => format!("JSON parse failed: {e}"),
            Self::ErrorEvent(e) => format!("received error event: {e}"),
            Self::TooLarge => "response body exceeds sane limit".to_string(),
            Self::InvalidUtf8 => "response body contains invalid UTF8 text".to_string(),
        };
        f.write_str(&msg)
    }
}

impl Error for BodyReadError {}

impl From<serde_json::Error> for BodyReadError {
    fn from(e: serde_json::Error) -> Self {
        BodyReadError::JsonParse(e)
    }
}

#[derive(Debug)]
pub enum RequestErrorCause {
    RequestBodySerialize(serde_json::Error),
    RequestConstruction(hyper::http::Error),
    HttpFailure(hyper_util::client::legacy::Error),
    BodyReadFailure(BodyReadError),
    BadStatusCode {
        status: hyper::StatusCode,
        details: Option<LndErrorResponse>,
    },
}

impl fmt::Display for RequestErrorCause {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match self {
            Self::RequestBodySerialize(e) => format!("serializing request body failed: {e}"),
            Self::RequestConstruction(e) => format!("failed to construct request: {e}"),
            Self::HttpFailure(e) => format!("HTTP protocol error: {e}"),
            Self::BodyReadFailure(e) => format!("reading response: {}", e),
            Self::BadStatusCode { status, details } => {
                format!(
                    "unexpected HTTP status {}: {}",
                    status,
                    details
                        .as_ref()
                        .map(|r| r.to_string())
                        .unwrap_or("(unable to parse response error details)".to_string())
                )
            }
        };
        f.write_str(&msg)
    }
}

#[derive(Debug)]
pub struct RequestError {
    pub endpoint: String,
    pub method: hyper::Method,
    pub cause: RequestErrorCause,
}

impl fmt::Display for RequestError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "request {} {} failed: {}",
            self.method, self.endpoint, self.cause
        )
    }
}

impl Error for RequestError {}
