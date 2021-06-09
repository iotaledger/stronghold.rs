# Copyright 2021 IOTA Stiftung
# SPDX-License-Identifier: Apache-2.0
# ---
# simple make file to launch three containers: redis(config), listener(listener), communications(communications)
# cold be moved to a docker-compose file
# --
 
build: build.fuzz.communications build.fuzz.listener

build.fuzz.communications:
	cargo fuzz build comms
	docker build -t stronghold-communications -f ./container/communications.dockerfile .

build.fuzz.listener:
	cargo build --bin listen
	docker build -t stronghold-listener -f ./container/listener.dockerfile .

launch:
	docker run --rm -d --name config --network stronghold redis
	docker run --rm -d --name listener --network stronghold  stronghold-listener
	docker run --rm -d --name communications --network stronghold  stronghold-communications
