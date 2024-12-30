use lndlite::{base64::Base64, Connector, HttpConnector, HttpsConnector, LndRestClient};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use tempdir::TempDir;

use std::{fs, io, net, process, thread, time::Duration};

pub struct LND<C> {
    #[allow(dead_code)]
    tempdir: TempDir,
    #[allow(dead_code)]
    child: process::Child,
    addr: net::SocketAddr,
    proto: &'static str,
    connector: C,
}

fn get_unused_bind_address() -> io::Result<net::SocketAddr> {
    net::TcpListener::bind("127.0.0.1:0")?.local_addr()
}

fn wait_for_bind(addr: &net::SocketAddr) {
    for i in 0..100 {
        if net::TcpStream::connect(addr).is_ok() {
            return;
        }
        if i == 99 {
            panic!("timed out waiting to connect to {addr}");
        }
        thread::sleep(Duration::from_millis(100));
    }
}

impl LND<HttpsConnector> {
    pub fn run_regtest() -> io::Result<Self> {
        let tempdir = TempDir::new("lndlite").expect("error making tempdir");
        let addr = get_unused_bind_address()?;

        let mut child: process::Child = process::Command::new("lnd")
            .arg("--bitcoin.regtest")
            .arg("--bitcoin.node=nochainbackend")
            .arg(format!("--lnddir={}", tempdir.path().display()))
            .arg(format!("--restlisten={}", addr))
            .arg(format!("--rpclisten={}", get_unused_bind_address()?))
            .arg("--nolisten")
            .stdout(process::Stdio::null())
            .spawn()?;

        // Give the REST server time to spin up.
        wait_for_bind(&addr);

        let tls_cert_pem = fs::read(tempdir.path().join("tls.cert")).unwrap_or_else(|e| {
            let _ = child.kill();
            panic!("failed to read tls.cert from lnd tempdir: {e}");
        });

        let connector = lndlite::self_signed_https_connector(&tls_cert_pem).unwrap_or_else(|e| {
            let _ = child.kill();
            panic!("tls.cert is invalid: {e}");
        });

        let lnd = LND {
            tempdir,
            child,
            addr,
            proto: "https",
            connector,
        };

        Ok(lnd)
    }
}

impl LND<HttpConnector> {
    pub fn run_regtest() -> io::Result<Self> {
        let tempdir = TempDir::new("lndlite").expect("error making tempdir");
        let addr = get_unused_bind_address()?;

        let child: process::Child = process::Command::new("lnd")
            .arg("--bitcoin.regtest")
            .arg("--bitcoin.node=nochainbackend")
            .arg(format!("--lnddir={}", tempdir.path().display()))
            .arg(format!("--restlisten={}", addr))
            .arg(format!("--rpclisten={}", get_unused_bind_address()?))
            .arg("--no-rest-tls")
            .arg("--nolisten")
            .stdout(process::Stdio::null())
            .spawn()?;

        // Give the REST server time to spin up.
        wait_for_bind(&addr);

        let connector = HttpConnector::new();

        let lnd = LND {
            tempdir,
            child,
            addr,
            proto: "http",
            connector,
        };
        Ok(lnd)
    }
}

impl<C: Connector> LND<C> {
    fn unauthed_client(&self) -> LndRestClient<C>
    where
        C: hyper_util::client::legacy::connect::Connect + Clone + Send + Sync + 'static,
    {
        let mut client =
            LndRestClient::new_with_connector(self.addr.to_string(), &[], self.connector.clone());
        if self.proto == "http" {
            client.unsafe_use_plaintext_http_scheme();
        }
        client
    }
}

impl<C> std::ops::Drop for LND<C> {
    fn drop(&mut self) {
        self.child.kill().expect("failed to kill LND child process");
    }
}

// Initialize an LND instance.
async fn init_wallet<C: Connector>(client: &mut LndRestClient<C>) {
    const XPRIV: &'static str = concat!(
        "tprv8ZgxMBicQKsPdpgo44ctecZXcupSdNCZL5gmLS6FiUzrjqePmp7",
        "KSSdJcCJ2z2w7aAh1poJBEQcLXi82KzeSg2tBZRvwwUynFrux1NUSuBa",
    );

    #[derive(Serialize)]
    struct InitWalletRequest {
        wallet_password: Base64<String>,
        extended_master_key: String,
    }
    #[derive(Deserialize)]
    struct InitWalletResponse {
        admin_macaroon: Base64<Vec<u8>>,
    }

    let InitWalletResponse {
        admin_macaroon: Base64(macaroon),
    } = client
        .post(
            "/v1/initwallet",
            InitWalletRequest {
                wallet_password: Base64("password123".to_string()),
                extended_master_key: XPRIV.to_string(),
            },
        )
        .await
        .expect("failed to initialize LND wallet");

    assert!(!macaroon.is_empty());
    client.set_macaroon(&macaroon);
}

#[derive(Deserialize)]
struct StateUpdate {
    state: String,
}

async fn wait_for_server_active_state<C: Connector>(client: &LndRestClient<C>) {
    let mut state_stream = client
        .get_streamed("/v1/state/subscribe")
        .await
        .expect("failed to subscribe");

    tokio::time::timeout(Duration::from_secs(10), async move {
        while let Some(update) = state_stream.next::<StateUpdate>().await.unwrap() {
            if update.state == "SERVER_ACTIVE" {
                return;
            }
        }
        panic!("never received SERVER_ACTIVE state");
    })
    .await
    .expect("timed out waiting for SERVER_ACTIVE state");
}

#[tokio::test]
async fn state_subscription() {
    let lnd = LND::<HttpsConnector>::run_regtest().expect("failed to run LND");
    let mut client = lnd.unauthed_client();

    let mut state_stream = client
        .get_streamed("/v1/state/subscribe")
        .await
        .expect("failed to subscribe");
    let init_state: StateUpdate = state_stream
        .next()
        .await
        .expect("failed to get state update")
        .expect("should receive initial state update");
    assert_eq!(&init_state.state, "NON_EXISTING");

    init_wallet(&mut client).await;

    let update: StateUpdate = state_stream
        .next()
        .await
        .expect("failed to get state update")
        .expect("should receive second state update");
    assert_eq!(&update.state, "UNLOCKED");

    let update: StateUpdate = state_stream
        .next()
        .await
        .expect("failed to get state update")
        .expect("should receive third state update");
    assert_eq!(&update.state, "RPC_ACTIVE");

    let update: StateUpdate = state_stream
        .next()
        .await
        .expect("failed to get state update")
        .expect("should receive third state update");
    assert_eq!(&update.state, "SERVER_ACTIVE");
}

#[tokio::test]
async fn add_invoice() {
    let lnd = LND::<HttpsConnector>::run_regtest().expect("failed to run LND");
    let mut client = lnd.unauthed_client();
    init_wallet(&mut client).await;
    wait_for_server_active_state(&client).await;

    #[derive(Serialize)]
    struct AddInvoiceRequest {
        value: u64,
        r_preimage: Base64<[u8; 32]>,
    }
    #[derive(Deserialize)]
    struct AddInvoiceResponse {
        r_hash: Base64<[u8; 32]>,
        payment_request: String,
    }

    let preimage = [0x01u8; 32];

    let AddInvoiceResponse {
        r_hash: Base64(r_hash),
        payment_request,
    } = client
        .post(
            "/v1/invoices",
            AddInvoiceRequest {
                value: 10_000,
                r_preimage: Base64(preimage),
            },
        )
        .await
        .expect("failed to add invoice");

    let hashed_preimage: [u8; 32] = Sha256::digest(&preimage).into();
    assert_eq!(r_hash, hashed_preimage);
    assert!(!payment_request.is_empty());
}
