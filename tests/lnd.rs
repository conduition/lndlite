use http_body_util::Full;
use hyper::body::Bytes;
use hyper_util::client::legacy::Client as HyperClient;
use lndlite::{base64::Base64, Connector, HttpConnector, HttpsConnector, LndRestClient};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest as _, Sha256};

use tempdir::TempDir;

use std::{error::Error, fs, io, net, process, sync::Arc, thread, time::Duration};

const BITCOIND_RPC_USERNAME: &str = "regtest";
const BITCOIND_RPC_PASSWORD: &str = "regtest";

const ARBITRARY_REGTEST_ADDRESS: &str = "bcrt1q7nf2d70la3ys27ckf8lgeg67fk4e3dfejuag2y";

const XPRIV_ALICE: &str = concat!(
    "tprv8ZgxMBicQKsPdpgo44ctecZXcupSdNCZL5gmLS6FiUzrjqePmp7",
    "KSSdJcCJ2z2w7aAh1poJBEQcLXi82KzeSg2tBZRvwwUynFrux1NUSuBa",
);
const XPRIV_BOB: &str = concat!(
    "tprv8ZgxMBicQKsPd9SC1iqWttm9G9Km9wdpEUyCBwrvq8eZYXkaEzqW",
    "vMA78dGgvAPcQX4niZsrfDwMCB29HsejgMGT1a2TRquc5zXms75smF8",
);

fn get_unused_bind_address() -> io::Result<net::SocketAddr> {
    net::TcpListener::bind("localhost:0")?.local_addr()
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

/// This represents a handle to temporary resources which should be
/// cleaned up when the test ends.
#[derive(Debug)]
struct Bitcoind {
    #[allow(dead_code)]
    tempdir: TempDir,
    child: process::Child,
    rpc_addr: net::SocketAddr,
    zmq_block_addr: net::SocketAddr,
    zmq_tx_addr: net::SocketAddr,
    client: HyperClient<HttpConnector, Full<Bytes>>,
}

impl Bitcoind {
    fn run_regtest() -> io::Result<Bitcoind> {
        let dir = TempDir::new("lndlite").expect("error making tempdir");
        let rpc_addr = get_unused_bind_address()?;
        let zmq_block_addr = get_unused_bind_address()?;
        let zmq_tx_addr = get_unused_bind_address()?;

        let child: process::Child = process::Command::new("bitcoind")
            .arg("-chain=regtest")
            .arg("-server=1")
            .arg("-txindex=1")
            .arg("-listen=0")
            .arg(format!("-rpcport={}", rpc_addr.port()))
            .arg(format!("-rpcuser={}", BITCOIND_RPC_USERNAME))
            .arg(format!("-rpcpassword={}", BITCOIND_RPC_PASSWORD))
            .arg(format!("-zmqpubrawblock=tcp://{}", zmq_block_addr))
            .arg(format!("-zmqpubrawtx=tcp://{}", zmq_tx_addr))
            .arg(format!("-datadir={}", dir.path().display()))
            .stdout(process::Stdio::null())
            // .stdout(process::Stdio::inherit())
            .spawn()?;

        wait_for_bind(&rpc_addr);

        let hyper_client =
            HyperClient::builder(hyper_util::rt::TokioExecutor::new()).build(HttpConnector::new());

        let bitcoind = Bitcoind {
            tempdir: dir,
            child,
            rpc_addr,
            zmq_block_addr,
            zmq_tx_addr,
            client: hyper_client,
        };

        Ok(bitcoind)
    }

    async fn generate_to_address(
        &self,
        n_blocks: u16,
        btc_address: &str,
    ) -> Result<(), Box<dyn Error>> {
        #[derive(Deserialize)]
        struct JsonRpcError {
            code: i32,
            message: String,
        }

        #[derive(Deserialize)]
        struct JsonRpcResponse {
            error: Option<JsonRpcError>,
        }

        let req_body = Bytes::from(serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "id": "1",
            "method": "generatetoaddress",
            "params": [n_blocks, btc_address],
        }))?);

        let auth_header = format!(
            "Basic {}",
            lndlite::base64::encode_standard(format!(
                "{}:{}",
                BITCOIND_RPC_USERNAME, BITCOIND_RPC_PASSWORD
            ))
        );

        let req = hyper::Request::builder()
            .method("POST")
            .uri(format!("http://{}", self.rpc_addr))
            .header("Authorization", auth_header)
            .header("Accept", "application/json")
            .header("Content-Type", "application/json")
            .body(Full::new(req_body))?;

        loop {
            let response = self.client.request(req.clone()).await?;
            if !response.status().is_success() {
                return Err(format!(
                    "unexpected bitcoin RPC response status {}",
                    response.status()
                )
                .as_str())?;
            }

            let body: JsonRpcResponse = serde_json::from_slice(
                &http_body_util::BodyExt::collect(response.into_body())
                    .await?
                    .to_bytes(),
            )?;

            match body.error {
                Some(err) => {
                    // "Loading block index", retry after delay
                    if err.code == -28 {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                    return Err(
                        format!("JSON-RPC error: {} (code {})", err.message, err.code).as_str(),
                    )?;
                }

                // Success
                None => {
                    return Ok(());
                }
            }
        }
    }
}

impl std::ops::Drop for Bitcoind {
    fn drop(&mut self) {
        self.child
            .kill()
            .expect("failed to kill bitcoind child process");
    }
}

#[tokio::test]
async fn bitcoind_runs_and_mines() {
    Bitcoind::run_regtest()
        .unwrap()
        .generate_to_address(101, ARBITRARY_REGTEST_ADDRESS)
        .await
        .unwrap();
}

struct LND<C> {
    #[allow(dead_code)]
    tempdir: TempDir,
    bitcoind: Arc<Bitcoind>,
    child: process::Child,
    rest_addr: net::SocketAddr,
    p2p_addr: net::SocketAddr,
    proto: &'static str,
    connector: C,
}

fn new_lnd_cmd(
    bitcoind: &Bitcoind,
    tempdir: &TempDir,
    rest_addr: &net::SocketAddr,
    p2p_addr: &net::SocketAddr,
) -> io::Result<process::Command> {
    let mut cmd = process::Command::new("lnd");
    cmd.arg("--bitcoin.regtest")
        .arg("--bitcoin.node=bitcoind")
        .arg(format!("--bitcoind.rpchost={}", bitcoind.rpc_addr))
        .arg(format!("--bitcoind.rpcuser={}", BITCOIND_RPC_USERNAME))
        .arg(format!("--bitcoind.rpcpass={}", BITCOIND_RPC_PASSWORD))
        .arg(format!(
            "--bitcoind.zmqpubrawblock=tcp://{}",
            bitcoind.zmq_block_addr
        ))
        .arg(format!(
            "--bitcoind.zmqpubrawtx=tcp://{}",
            bitcoind.zmq_tx_addr
        ))
        .arg("--bitcoin.defaultchanconfs=1")
        .arg(format!("--lnddir={}", tempdir.path().display()))
        .arg(format!("--restlisten={}", rest_addr))
        .arg(format!("--rpclisten={}", get_unused_bind_address()?))
        .arg(format!("--listen={}", p2p_addr))
        // .stdout(process::Stdio::inherit());
        .stdout(process::Stdio::null());

    Ok(cmd)
}

impl LND<HttpsConnector> {
    fn run_regtest(bitcoind: Arc<Bitcoind>) -> io::Result<Self> {
        let tempdir = TempDir::new("lndlite").expect("error making tempdir");
        let rest_addr = get_unused_bind_address()?;
        let p2p_addr = get_unused_bind_address()?;

        let mut child: process::Child =
            new_lnd_cmd(&bitcoind, &tempdir, &rest_addr, &p2p_addr)?.spawn()?;

        // Give the REST server time to spin up.
        wait_for_bind(&rest_addr);

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
            bitcoind,
            child,
            rest_addr,
            p2p_addr,
            proto: "https",
            connector,
        };

        Ok(lnd)
    }
}

impl LND<HttpConnector> {
    fn run_regtest(bitcoind: Arc<Bitcoind>) -> io::Result<Self> {
        let tempdir = TempDir::new("lndlite").expect("error making tempdir");
        let rest_addr = get_unused_bind_address()?;
        let p2p_addr = get_unused_bind_address()?;

        let child: process::Child = new_lnd_cmd(&bitcoind, &tempdir, &rest_addr, &p2p_addr)?
            .arg("--no-rest-tls")
            .spawn()?;

        // Give the REST server time to spin up.
        wait_for_bind(&rest_addr);

        let connector = HttpConnector::new();

        let lnd = LND {
            tempdir,
            bitcoind,
            child,
            rest_addr,
            p2p_addr,
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
        let mut client = LndRestClient::new_with_connector(
            self.rest_addr.to_string(),
            &[],
            self.connector.clone(),
        );
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
async fn init_wallet<C: Connector>(client: &mut LndRestClient<C>, xpriv: &str) {
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
                extended_master_key: xpriv.to_string(),
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

#[derive(Deserialize)]
struct GetInfoResponse {
    identity_pubkey: String,
    num_peers: usize,
    num_active_channels: usize,
    num_pending_channels: usize,
    synced_to_chain: bool,
}

async fn wait_for_chain_sync<C: Connector>(client: &LndRestClient<C>) {
    while !client
        .get::<GetInfoResponse>("/v1/getinfo")
        .await
        .unwrap()
        .synced_to_chain
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_lnd_state<C: Connector>(client: &LndRestClient<C>, desired_state: &str) {
    let mut state_stream = client
        .get_streamed("/v1/state/subscribe")
        .await
        .expect("failed to subscribe");

    tokio::time::timeout(Duration::from_secs(10), async move {
        while let Some(update) = state_stream.next::<StateUpdate>().await.unwrap() {
            if update.state == desired_state {
                return;
            }
        }
        panic!("never received {desired_state} state");
    })
    .await
    .expect(&format!("timed out waiting for {desired_state} state"));
}

async fn init_wallet_and_wait<C: Connector>(
    client: &mut LndRestClient<C>,
    bitcoind: &Bitcoind,
    xpriv: &str,
) {
    wait_for_lnd_state(client, "NON_EXISTING").await;
    init_wallet(client, xpriv).await;

    // LND will wait forever for the regtest node to "sync" unless it has
    // at least one mined block.
    // https://github.com/lightningnetwork/lnd/blob/a388c1f39d849005b58eae81516b4104929101a6/lnd.go#L702
    bitcoind
        .generate_to_address(1, ARBITRARY_REGTEST_ADDRESS)
        .await
        .expect("failed to mine first block");

    wait_for_lnd_state(client, "SERVER_ACTIVE").await;
}

#[tokio::test]
async fn lnd_https_rest() {
    let bitcoind = Arc::new(Bitcoind::run_regtest().unwrap());
    let lnd = LND::<HttpsConnector>::run_regtest(bitcoind).expect("failed to run LND");
    let mut client = lnd.unauthed_client();
    init_wallet_and_wait(&mut client, &lnd.bitcoind, XPRIV_ALICE).await;

    let info: GetInfoResponse = client
        .get("/v1/getinfo")
        .await
        .expect("failed to get node info");

    assert_eq!(info.num_peers, 0);
    assert_eq!(info.num_active_channels, 0);
    assert_eq!(info.num_pending_channels, 0);
}

#[tokio::test]
async fn lnd_http_rest() {
    let bitcoind = Arc::new(Bitcoind::run_regtest().unwrap());
    let lnd = LND::<HttpConnector>::run_regtest(bitcoind).expect("failed to run LND");
    let mut client = lnd.unauthed_client();
    init_wallet_and_wait(&mut client, &lnd.bitcoind, XPRIV_ALICE).await;

    let info: GetInfoResponse = client
        .get("/v1/getinfo")
        .await
        .expect("failed to get node info");

    assert_eq!(info.num_peers, 0);
    assert_eq!(info.num_active_channels, 0);
    assert_eq!(info.num_pending_channels, 0);
}

#[tokio::test]
async fn state_subscription() {
    let bitcoind = Arc::new(Bitcoind::run_regtest().unwrap());
    let lnd = LND::<HttpsConnector>::run_regtest(bitcoind).expect("failed to run LND");
    let mut client = lnd.unauthed_client();

    let mut state_stream = client
        .get_streamed("/v1/state/subscribe")
        .await
        .expect("failed to subscribe");
    let mut init_state: StateUpdate = state_stream
        .next()
        .await
        .expect("failed to get state update")
        .expect("should receive initial state update");

    if init_state.state == "WAITING_TO_START" {
        init_state = state_stream
            .next()
            .await
            .expect("failed to get state update")
            .expect("should receive next state update");
    }

    assert_eq!(&init_state.state, "NON_EXISTING");

    init_wallet(&mut client, XPRIV_ALICE).await;

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

    lnd.bitcoind
        .generate_to_address(1, ARBITRARY_REGTEST_ADDRESS)
        .await
        .unwrap();

    let update: StateUpdate = state_stream
        .next()
        .await
        .expect("failed to get state update")
        .expect("should receive third state update");
    assert_eq!(&update.state, "SERVER_ACTIVE");
}

#[tokio::test]
async fn lnd_connect_and_open_channel() {
    let bitcoind = Arc::new(Bitcoind::run_regtest().unwrap());

    let lnd2_handle = thread::spawn({
        let bitcoind = Arc::clone(&bitcoind);
        move || LND::<HttpConnector>::run_regtest(bitcoind).expect("failed to run LND")
    });

    let lnd1 = LND::<HttpConnector>::run_regtest(bitcoind.clone()).expect("failed to run LND");
    let lnd2 = lnd2_handle.join().unwrap();

    let mut lnd1_client = lnd1.unauthed_client();
    let mut lnd2_client = lnd2.unauthed_client();
    init_wallet_and_wait(&mut lnd1_client, &bitcoind, XPRIV_ALICE).await;
    init_wallet_and_wait(&mut lnd2_client, &bitcoind, XPRIV_BOB).await;

    #[derive(Deserialize)]
    struct GetAddressResponse {
        address: String,
    }

    #[derive(Deserialize)]
    struct TransactionsEvent {
        dest_addresses: Vec<String>,
    }

    // Give lnd1 some coins
    let GetAddressResponse { address } = lnd1_client
        .get("/v1/newaddress")
        .await
        .expect("failed to get new address");
    bitcoind.generate_to_address(101, &address).await.unwrap();

    let mut lnd1_tx_stream = lnd1_client
        .get_streamed("/v1/transactions/subscribe")
        .await
        .unwrap();
    let TransactionsEvent { dest_addresses } =
        tokio::time::timeout(Duration::from_secs(10), lnd1_tx_stream.next())
            .await
            .expect("timed out waiting for lnd1 to notice new coins")
            .expect("failed to stream next TransactionsEvent")
            .expect("TransactionsEvent not found");
    assert_eq!(dest_addresses, vec![address]);

    // Wait for LND nodes to fully catch up
    wait_for_chain_sync(&lnd1_client).await;
    wait_for_chain_sync(&lnd2_client).await;

    let lnd2_info: GetInfoResponse = lnd2_client
        .get("/v1/getinfo")
        .await
        .expect("failed to get lnd2 info");

    let node_pubkey = hex::decode(&lnd2_info.identity_pubkey).unwrap();

    #[derive(Deserialize)]
    struct ConnectPeerResponse {}

    lnd1_client
        .post::<_, ConnectPeerResponse>(
            "/v1/peers",
            json!({
                "addr": {
                    "pubkey": hex::encode(&node_pubkey),
                    "host": lnd2.p2p_addr.to_string()
                }
            }),
        )
        .await
        .expect("failed to connect to peer");

    #[derive(Serialize)]
    struct OpenChannelRequest {
        node_pubkey: Base64<Vec<u8>>,
        local_funding_amount: String,
        sat_per_vbyte: u64,
    }

    #[derive(Deserialize, Default)]
    struct ChanPending {
        txid: Base64<[u8; 32]>,
        output_index: usize,
    }

    #[derive(Deserialize, Default)]
    struct ChannelPoint {
        funding_txid_bytes: Base64<[u8; 32]>,
        output_index: usize,
    }
    #[derive(Deserialize, Default)]
    struct ChanOpen {
        channel_point: ChannelPoint,
    }
    #[derive(Deserialize)]
    struct OpenChannelUpdate {
        #[serde(default)]
        chan_pending: Option<ChanPending>,
        #[serde(default)]
        chan_open: Option<ChanOpen>,
        #[allow(unused)]
        pending_chan_id: Base64<[u8; 32]>,
    }

    let mut chan_open_stream = lnd1_client
        .post_streamed(
            "/v1/channels/stream",
            OpenChannelRequest {
                node_pubkey: Base64(node_pubkey),
                local_funding_amount: "10000000".to_string(),
                sat_per_vbyte: 1,
            },
        )
        .await
        .unwrap();

    let first_event: OpenChannelUpdate = chan_open_stream
        .next()
        .await
        .expect("failed to get next channel open event")
        .expect("missing first channel open event");

    let chan_pending = first_event
        .chan_pending
        .expect("missing chan_pending field");

    // Mine a block to confirm the channel
    bitcoind
        .generate_to_address(1, &ARBITRARY_REGTEST_ADDRESS)
        .await
        .unwrap();

    let second_event: OpenChannelUpdate = chan_open_stream
        .next()
        .await
        .expect("failed to get next channel open event")
        .expect("missing second channel open event");

    let chan_open = second_event.chan_open.expect("missing chan_open field");
    assert_eq!(
        chan_open.channel_point.funding_txid_bytes,
        chan_pending.txid
    );
    assert_eq!(
        chan_open.channel_point.output_index,
        chan_pending.output_index
    );

    assert!(chan_open_stream
        .next::<serde_json::Value>()
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn lnd_add_invoice() {
    let bitcoind = Arc::new(Bitcoind::run_regtest().unwrap());
    let lnd = LND::<HttpsConnector>::run_regtest(bitcoind).expect("failed to run LND");
    let mut client = lnd.unauthed_client();
    init_wallet_and_wait(&mut client, &lnd.bitcoind, XPRIV_ALICE).await;

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
