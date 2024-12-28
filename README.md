# lndlite

Access the [Lightning Network Daemon (LND) REST API](https://lightning.engineering/api-docs/api/lnd/rest-endpoints/) using the reqwest crate under the hood.

This crate is a thin wrapper to allow proper async usage of the LND REST API. Unlike other LND API wrappers, this crate intentionally does not declare or maintain Rust methods or typedefs for the numerous endpoints and data structures available on the [LND API](https://lightning.engineering/api-docs/api/lnd/). Instead, users of this crate must declare their own types and then invoke the various REST API endpoints properly by referencing [the current documentation](https://lightning.engineering/api-docs/api/lnd/rest-endpoints/).

The philosophy behind this design is rooted in practical maintenance concerns: It's infeasible for me, a solo developer working in my free time, to keep my library's typedefs up to date with the vast API surface area of LND, with its full-time team of developers, not to mention documenting it all properly.

Most developers who use the LND API only need a few select methods from the dozens of endpoints available. And so instead this crate aims to make this use case possible without the need for constant attentive maintenance. As LND improves and its API changes, as new endpoints are added and old ones are deprecated, I want this crate to remain an evergreen resource for devs who rely on LND.
