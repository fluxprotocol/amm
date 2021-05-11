#!/bin/bash
set -e
cd ../
bash build.sh
cp target/wasm32-unknown-unknown/release/amm.wasm res/
