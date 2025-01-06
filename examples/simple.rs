use lndlite::{base64::Base64, serde, LndRestClient};
use sha2::{Digest as _, Sha256};

#[derive(serde::Serialize)]
struct InitWalletRequest {
    wallet_password: Base64<String>,
    extended_master_key: String,
}

#[derive(serde::Deserialize)]
struct InitWalletResponse {
    admin_macaroon: Base64<Vec<u8>>,
}

#[derive(serde::Deserialize)]
struct StateUpdate {
    state: String,
}

#[derive(serde::Serialize)]
struct AddInvoiceRequest {
    value: u64,
    r_preimage: Base64<[u8; 32]>,
}

#[derive(serde::Deserialize)]
struct AddInvoiceResponse {
    r_hash: Base64<[u8; 32]>,
    payment_request: String,
}

/// could use a cipherseed mnemonic instead
const XPRIV: &str = concat!(
    "tprv8ZgxMBicQKsPdpgo44ctecZXcupSdNCZL5gmLS6FiUzrjqePmp7",
    "KSSdJcCJ2z2w7aAh1poJBEQcLXi82KzeSg2tBZRvwwUynFrux1NUSuBa",
);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let tls_cert_pem = std::fs::read("/tmp/test/tls.cert")?;
    let mut lnd_client =
        LndRestClient::new_with_self_signed_cert("127.0.0.1:8555".to_string(), b"", &tls_cert_pem)?;

    let InitWalletResponse {
        admin_macaroon: Base64(macaroon),
    } = lnd_client
        .post(
            "/v1/initwallet",
            InitWalletRequest {
                wallet_password: Base64("password123".to_string()),
                extended_master_key: XPRIV.to_string(),
            },
        )
        .await?;

    // We can now access API endpoints protected by macaroon authentication
    lnd_client.set_macaroon(&macaroon);
    println!("wallet unlocked, macaroon: {:?}", macaroon);

    let mut state_stream = lnd_client.get_streamed("/v1/state/subscribe").await?;

    tokio::time::timeout(std::time::Duration::from_secs(10), async move {
        while let Some(update) = state_stream.next::<StateUpdate>().await? {
            println!("LND is in state: {}", update.state);
            if update.state == "SERVER_ACTIVE" {
                return Ok(());
            }
        }
        Ok::<(), lndlite::RequestError>(())
    })
    .await??;

    println!("LND API server is fully active and ready for use");

    let preimage = [0x01u8; 32];

    let AddInvoiceResponse {
        r_hash: Base64(r_hash),
        payment_request,
    } = lnd_client
        .post(
            "/v1/invoices",
            AddInvoiceRequest {
                value: 10_000,
                r_preimage: Base64(preimage),
            },
        )
        .await?;

    let hashed_preimage: [u8; 32] = Sha256::digest(&preimage).into();
    assert_eq!(r_hash, hashed_preimage);
    println!("generated BOLT11 invoice: {}", payment_request);

    Ok(())
}
