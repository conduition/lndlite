use crate::{HttpConnector, InvalidCertificateError, LndRestClient};

use openssl::{
    ssl::{SslConnector, SslMethod},
    x509::{store::X509StoreBuilder, X509},
};

pub use hyper_openssl;
pub use openssl;
pub type HttpsConnector = hyper_openssl::client::legacy::HttpsConnector<HttpConnector>;

pub fn self_signed_cert_connector(
    tls_cert_pem: &[u8],
) -> Result<HttpsConnector, InvalidCertificateError> {
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
            self_signed_cert_connector(tls_cert_pem)?,
        ))
    }
}
