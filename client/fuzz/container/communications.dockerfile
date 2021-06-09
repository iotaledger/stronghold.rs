# Copyright 2021 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0
FROM debian:buster-slim

WORKDIR /fuzz
ARG build_target=x86_64-unknown-linux-gnu
ADD ./target/${build_target}/release/comms /fuzz/comms

CMD ["/fuzz/comms"]