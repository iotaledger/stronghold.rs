# Copyright 2020 IOTA Stiftung
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
# an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

# select image
FROM rust:latest as build

# create a new empty shell project
RUN USER=root cargo new --bin iota-p2p-poc
WORKDIR /iota-p2p-poc

# copy over manifests
# COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
COPY ./build.rs ./build.rs
COPY ./src/structs.proto ./src/structs.proto

# cache dependencies
RUN cargo build --release
RUN rm src/*.rs

# copy source tree
COPY ./src ./src

RUN cargo clean

# build for release
RUN cargo build --release

# final base
FROM rust:latest

WORKDIR /app

# copy the build artifact from the build stage
COPY --from=build /iota-p2p-poc/target/release/iota-p2p-poc .

# command for starting the container
ENTRYPOINT ["/app/iota-p2p-poc"]