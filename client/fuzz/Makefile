# Copyright 2021 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0
# ---
# simple make file to launch three containers: redis(config), listener(listener), p2p(p2p)
# --


help:
	@printf "Client P2P-Network Fuzzer Setup\n"
	@printf "### \n"
	@printf "Run 'make build' to build every container.\n"
	@printf "You need rust's nightly toolchain to compile the fuzz targets\n"
	@printf "and libsodium as third party dependency\n"

build: build.fuzz.p2p build.fuzz.listener

stop:
	@docker stop listener config p2p || printf "No containers running\n"

launch: build stop
	docker run --rm -d --name config --network stronghold redis
	docker run --rm -d --name listener --network stronghold  stronghold-listener
	docker run --rm -d --name p2p --network stronghold  stronghold-p2p

build.fuzz.p2p:
	@cargo fuzz build p2p
	@docker build -t stronghold-p2p \
	--build-arg artifact_name=p2p \
	--build-arg build_target=x86_64-unknown-linux-gnu/release .

build.fuzz.listener:
	@cargo build --bin listen
	@docker build -t stronghold-listener \
	--build-arg artifact_name=listen \
	--build-arg build_target=debug .