#/bin/bash

cbindgen --config cbindgen.toml --crate stronghold_native --output native.h --lang c
cbindgen --config cbindgen.toml --crate stronghold_native --output native.hpp --lang c++
