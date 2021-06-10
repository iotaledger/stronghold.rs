# Copyright 2021 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0
FROM debian:buster-slim

WORKDIR /fuzz

ARG build_target
ARG artifact_name
ENV artifact_name=${artifact_name}
ADD ./target/${build_target}/${artifact_name} /fuzz/${artifact_name}

CMD /fuzz/${artifact_name}