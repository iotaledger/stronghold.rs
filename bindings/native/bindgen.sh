#!/usr/bin/env bash
set -euo pipefail

cbindgen --config cbindgen.toml --crate stronghold_native --output stronghold_native.h --lang c
cbindgen --config cbindgen.toml --crate stronghold_native --output stronghold_native.hpp --lang c++
