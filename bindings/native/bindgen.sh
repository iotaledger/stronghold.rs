#!/usr/bin/env bash
set -euo pipefail

cbindgen --config cbindgen.toml --crate stronghold_native --output go/dist/stronghold_native.h --lang c
cbindgen --config cbindgen.toml --crate stronghold_native --output go/dist/stronghold_native.hpp --lang c++
