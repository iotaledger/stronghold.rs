# Copyright 2021 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0
# ---
# simple make file to launch two containers: snapshot(fuzz), vault(fuzz)
# --

help:
	@printf "Engine Fuzzer Setup\n"
	@printf "### \n"
	@printf "Run 'make build' to build every container.\n"
	@printf "You need rust's nightly toolchain to compile the fuzz targets\n"
	@printf "and libsodium as third party dependency\n"

build: build.fuzz.snapshot build.fuzz.vault

stop:
	@docker stop vault_fuzz snapshot || printf "No containers running\n"

launch: build stop
	docker run --rm -d --name vault_fuzz --network stronghold stronghold-vault-fuzz
	docker run --rm -d --name snapshot --network stronghold  stronghold-snapshot-fuzz

build.fuzz.snapshot:
	@cargo fuzz build
	@docker build -t stronghold-snapshot-fuzz \
	--build-arg artifact_name=snapshot \
	--build-arg build_target=x86_64-unknown-linux-gnu/release .

build.fuzz.vault:
	@cargo fuzz build
	@docker build -t stronghold-vault-fuzz \
	--build-arg artifact_name=vault_fuzz \
	--build-arg build_target=x86_64-unknown-linux-gnu/release .