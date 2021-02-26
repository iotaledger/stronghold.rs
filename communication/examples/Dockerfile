# Copyright 2020 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

FROM rust:latest as build
RUN USER=root cargo new --bin stronghold-communication
WORKDIR /stronghold-communication

COPY ./Cargo.toml ./Cargo.toml

# cache dependencies
RUN cargo build --release
RUN rm src/*.rs
COPY ./src ./src
COPY ./examples ./examples
RUN cargo clean

# build mailbox
RUN cargo build --example relay
FROM rust:latest
WORKDIR /app

# copy the build artifact from the build stage
COPY --from=build /stronghold-communication/target/debug/examples/relay .
ENTRYPOINT ["/app/relay"]
CMD ["start-relay"]
