# lndlite

_Another LND wrapper, now with 50% less syntactic sugar!_

- Access the [Lightning Network Daemon (LND) REST API](https://lightning.engineering/api-docs/api/lnd/rest-endpoints/) using `hyper` under the hood.
- Fully async
- Supports streamed responses for subscription endpoints
- Pass in a custom HTTP connector interface
- Bring Your Own Types
- Avoid tight coupling


## Example

First, [download and install `lnd`](https://github.com/lightningnetwork/lnd).

```console
curl -L https://github.com/lightningnetwork/lnd/releases/download/v0.18.4-beta/lnd-linux-amd64-v0.18.4-beta.tar.gz |
  sudo tar -C /usr/local/bin -xz --strip-components=1
```

Run LND in regtest mode with no backend (just for example).

```console
lnd --bitcoin.regtest --bitcoin.node=nochainbackend --lnddir=/tmp/test --restlisten=127.0.0.1:8555
```

Now you can install and use `lndlite` in your crate. You'll need an async runtime like [`tokio`](https://tokio.rs).

```rust
use lndlite::{base64::Base64, serde, LndRestClient};

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

/// could use a cipherseed mnemonic instead
const XPRIV: &'static str = concat!(
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

    Ok(())
}
```

```
$ cargo r
   Compiling t v0.1.0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.67s
     Running `target/debug/t`
wallet unlocked, macaroon: [2, 1, 3, 108, 110, 100, 2, 248, 1, 3, 10, 16, 179, 33, 245, 229, 123, 80, 96, 142, 187, 213, 10, 155, 147, 135, 145, 116, 18, 1, 48, 26, 22, 10, 7, 97, 100, 100, 114, 101, 115, 115, 18, 4, 114, 101, 97, 100, 18, 5, 119, 114, 105, 116, 101, 26, 19, 10, 4, 105, 110, 102, 111, 18, 4, 114, 101, 97, 100, 18, 5, 119, 114, 105, 116, 101, 26, 23, 10, 8, 105, 110, 118, 111, 105, 99, 101, 115, 18, 4, 114, 101, 97, 100, 18, 5, 119, 114, 105, 116, 101, 26, 33, 10, 8, 109, 97, 99, 97, 114, 111, 111, 110, 18, 8, 103, 101, 110, 101, 114, 97, 116, 101, 18, 4, 114, 101, 97, 100, 18, 5, 119, 114, 105, 116, 101, 26, 22, 10, 7, 109, 101, 115, 115, 97, 103, 101, 18, 4, 114, 101, 97, 100, 18, 5, 119, 114, 105, 116, 101, 26, 23, 10, 8, 111, 102, 102, 99, 104, 97, 105, 110, 18, 4, 114, 101, 97, 100, 18, 5, 119, 114, 105, 116, 101, 26, 22, 10, 7, 111, 110, 99, 104, 97, 105, 110, 18, 4, 114, 101, 97, 100, 18, 5, 119, 114, 105, 116, 101, 26, 20, 10, 5, 112, 101, 101, 114, 115, 18, 4, 114, 101, 97, 100, 18, 5, 119, 114, 105, 116, 101, 26, 24, 10, 6, 115, 105, 103, 110, 101, 114, 18, 8, 103, 101, 110, 101, 114, 97, 116, 101, 18, 4, 114, 101, 97, 100, 0, 0, 6, 32, 136, 209, 55, 67, 71, 124, 50, 178, 171, 43, 94, 248, 16, 32, 60, 92, 126, 37, 22, 248, 116, 37, 112, 223, 18, 162, 175, 22, 120, 90, 146, 207]
LND is in state: NON_EXISTING
LND is in state: UNLOCKED
LND is in state: RPC_ACTIVE
LND is in state: SERVER_ACTIVE
LND API server is fully active and ready for use
```

## Where are all the types/methods?

This crate is a thin wrapper to encourage correct async usage of the LND REST API with minimal dependencies. Unlike other LND API wrappers, this crate intentionally does not declare or maintain Rust methods and typedefs for the numerous endpoints and data structures available on the [LND API](https://lightning.engineering/api-docs/api/lnd/).

This crate also does not pull in any cryptographic primitives or Bitcoin protocol code: It is solely an HTTPS API wrapper. We bundle only `hyper` for HTTP, `openssl` for TLS, and basic encoding/decoding utilities for UTF8 JSON, such as `serde_json` and `utf8-read` to handle newline-delimited JSON streams.

Users of this crate must declare their own types and then invoke REST API endpoints properly by referencing [the current documentation](https://lightning.engineering/api-docs/api/lnd/rest-endpoints/). This crate is simply a robust REST interface through which one can interact with a running LND server.

The philosophy behind this design is rooted in practical maintenance concerns: It's infeasible for me, a solo developer working in my free time, to keep a library's typedefs up to date with the vast API surface area of LND, with its full-time team of developers, let alone document it all properly.

Most developers who use the LND API only need a few select methods from the dozens of endpoints available. And so instead this crate aims to make this use case possible without the need for constant attentive maintenance. As LND improves and its API changes, as new endpoints are added and old ones are deprecated, I want this crate to remain an evergreen resource for devs who rely on LND.


## Can I use `rustls` instead of `openssl`?

Not safely. `rustls` is so strictly adherent to the TLS specification that it does not accept the self-signed end-entity certificates generated by LND's default configuration.

- https://github.com/lightningnetwork/lnd/issues/5450
- https://github.com/rustls/rustls/issues/124

It is theoretically possible to implement the [`ServerCertVerifier`](https://docs.rs/rustls/0.23.20/rustls/client/danger/trait.ServerCertVerifier.html) trait and manually allow the LND self-signed cert. You would then use [`ClientConfig::dangerous`](https://docs.rs/rustls/0.23.20/rustls/client/struct.ClientConfig.html#method.dangerous) to create a [`hyper_rustls::HttpsConnector`](https://docs.rs/hyper-rustls/latest/hyper_rustls/struct.HttpsConnector.html) (using [`HttpsConnectorBuilder::with_tls_config`](https://docs.rs/hyper-rustls/latest/hyper_rustls/struct.HttpsConnectorBuilder.html#method.with_tls_config)), and finally pass this connector into `lndlite::LndRestClient::new_with_connector`.

But as you can see, this would involve modifying internal implementations of `rustls` which is far too unsafe for a production-grade library.

The "correct" fix is for LND to generate a separate TLS CA certificate, and then use it to sign end-entity certificates which are presented to REST/gRPC clients. However this requires action upstream in LND. Once [this issue](https://github.com/lightningnetwork/lnd/issues/5450) is resolved, please open an issue or a PR in this repo to add `rustls` support.

A second workaround option is for an end-user to generate their own certificate authority (CA) and use it to sign a new certificate, which they can feed to LND. Simply place the end-entity certificate in `~/.lnd/tls.cert` (or wherever your LND data dir is), and restart LND. It will find and use this certificate. This setup follows the TLS specifications, and so a `hyper_rustls::HttpsConnector` should work if passed into `LndRestClient::new_with_connector`, as long as the CA is configured correctly in the `rustls::ClientConfig`.
