# Copyright 2021 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0
FROM debian:buster-slim

WORKDIR /fuzz

ARG BUILD_TARGET
ARG ARTIFACT_NAME
ENV ARTIFACT_NAME=${ARTIFACT_NAME}
ADD ./target/${BUILD_TARGET}/${ARTIFACT_NAME} /fuzz/${ARTIFACT_NAME}
RUN sh -c env

CMD ["bash", "-c","/fuzz/${ARTIFACT_NAME}","-rss_limit_mb=800","-jobs=0", "-max_len=1000"]
