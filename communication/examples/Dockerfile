# Copyright 2020 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0

# Docker manifest for communications multi build
# expects build-args: 
# --build-arg build_target=x86_64-unknown-linux-musl (or another other supported targets)
# --build-arg build_artifact=<artifact> (the artifact to build. eg. "relay" )
# --build-arg build_flags=<flags> (set additional build flags for cargo eg. `--example`, `--release`)

# -- build step
FROM rust:latest as build

WORKDIR /code
ARG build_target==x86_64-unknown-linux-musl
ARG build_artifact
ARG build_flags=--example

ENV build_artifact=${build_artifact}
ENV build_target=${build_target}

ADD . .
RUN cargo clean \
    && cargo build ${build_flags} ${build_artifact}

# -- image creation step
FROM debian:buster-slim

WORKDIR /code
ARG build_target==x86_64-unknown-linux-musl
ARG build_artifact
ENV build_artifact=${build_artifact}
ENV build_target=${build_target}

# copy the build artifact from the build stage
COPY --from=build /code/target/${build_target}/examples/${build_artifact} .
CMD /code/${build_artifact} --multiaddr $MULTIADDR
